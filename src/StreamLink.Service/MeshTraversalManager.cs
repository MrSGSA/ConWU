using System.Net;
using StreamLink.Core;

namespace StreamLink.Service;

// One runner-owned scheduler, never a polling loop per peer. Tick is called by
// MeshRunner; all mutable negotiation state remains on that loop. Slow endpoint
// preparation, HTTP and cleanup run independently and are joined on shutdown.
internal sealed partial class MeshTraversalManager : IAsyncDisposable
{
    sealed class Entry(MeshMember peer, MeshTraversalCapabilities remote, Guid attempt, TraversalProfile profile, CancellationToken token)
    {
        public readonly MeshMember Peer = peer;
        public readonly MeshTraversalCapabilities Remote = remote;
        public readonly Guid Attempt = attempt;
        public readonly TraversalProfile Profile = profile;
        public readonly CancellationTokenSource Stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        public readonly long Began = Environment.TickCount64;
        public long Deadline;
        public Task<IMeshCandidateResource>? Gathering;
        public IMeshCandidateResource? Resource;
        public Task<IPreparedMeshPath>? Preparing;
        public Task<MeshTraversalCandidate>? Measuring;
        public MeshTraversalAttempt? Actor;
        public MeshTraversalMessage? Offer;
        public MeshTraversalCandidate? RemoteCandidate;
        public Task? Activating, Closing;
        // The old selected actor stays available for rollback until its actual
        // Router path retires. Closing a failed upgrade never cancels this owner.
        public Entry? Previous;
        public Task? Retiring;
        public bool Upgrade;
        public bool Standby, StandbyRetained;
        public bool ExplorationStatsLogged;
        public Guid Acknowledged;
    }
    readonly MeshProfile mesh;
    readonly MeshRouter router;
    readonly IMeshTraversalDiscovery discovery;
    readonly IMeshCandidateFactory factory;
    readonly MeshRequestBudget budget;
    readonly Action<string> log;
    readonly CancellationToken token;
    readonly Dictionary<int, Entry> entries = [];
    readonly Dictionary<int, MeshTraversalMessage> inbox = [];
    readonly Dictionary<int, MeshTraversalMessage> outbox = [];
    readonly Dictionary<int, (Guid Boot, long Sequence)> received = [];
    readonly Dictionary<int, int> failures = [];
    readonly Dictionary<int, long> retryAt = [];
    readonly Dictionary<int, long> explicitPriority = [];
    readonly Dictionary<int, (Guid Path, long Since)> degradedSince = [];
    readonly Dictionary<int, long> upgradeAt = [];
    readonly Dictionary<int, MeshPairOpportunity> opportunities = [];
    readonly Dictionary<int, TraversalProfile[]> methods = [];
    readonly HashSet<int> legacyPending = [];
    readonly HashSet<int> owned = [];
    Task? sending;
    MeshTraversalMessage[] batch = [];
    long sequence, revision = DateTime.UtcNow.Ticks, nextSend;
    int cursor, sendFailures;
    bool disposed;
    public MeshTraversalCapabilities Capabilities { get; }
    public bool Owns(int slot) => owned.Contains(slot);
    public void ObserveLegacyPending(int slot, bool pending) { if (pending) legacyPending.Add(slot); else legacyPending.Remove(slot); }
    public bool KeepLegacyAttempt(int slot) => !discovery.SupportsTraversal || !opportunities.TryGetValue(slot, out var window) || window.Open;
    public bool BeginLegacyAttempt(int slot) => !discovery.SupportsTraversal || !opportunities.TryGetValue(slot, out var window) ||
        window.Begin(TraversalProfile.LegacyExplicit, Environment.TickCount64);
    public string? WaitingDetail(int slot) => opportunities.TryGetValue(slot, out var window) && !window.Open && !window.Connected
        ? $"本轮未找到直连（NoDirectPathWithinBudget），{Math.Max(0, (window.RetryAt - Environment.TickCount64 + 999) / 1000)} 秒后后台重试" : null;
    public bool HasPendingControl => outbox.Count > 0 || entries.Values.Any(e => e.Closing == null &&
        (e.Actor?.Outbound is {} m && m.MessageId != e.Acknowledged || e.Actor is { Predicting: true } a && a.Phase is not (MeshAttemptPhase.Selected or MeshAttemptPhase.Cancelled)));
    public bool FreshPredictionInProgress => entries.Values.Any(e => e.Closing == null && e.Actor is { Predicting: true, PredictionBegan: > 0 } a &&
        a.Phase is not (MeshAttemptPhase.Selected or MeshAttemptPhase.Cancelled));
    public MeshTraversalManager(MeshProfile mesh, MeshRouter router, IMeshTraversalDiscovery discovery,
        IMeshCandidateFactory factory, MeshRequestBudget budget, Action<string> log, CancellationToken token)
    {
        this.mesh = mesh; this.router = router; this.discovery = discovery; this.factory = factory; this.budget = budget; this.log = log; this.token = token;
        var allowed = factory.Profiles.Where(router.Selection.Allows).Distinct().ToArray();
        Capabilities = new(1, allowed.Contains(TraversalProfile.FakeTcpHttpSo) ? 1 : 0, router.BootId, allowed, BackgroundUpgrade: 1,
            UdpIpv6: allowed.Contains(TraversalProfile.UdpDirect) && factory.SupportsUdpIpv6 ? 1 : 0,
            FakeTcpIpv6: allowed.Contains(TraversalProfile.FakeTcpHttpSo) && factory.SupportsFakeTcpIpv6 ? 1 : 0,
            TcpPrediction: allowed.Contains(TraversalProfile.FakeTcpHttpSo) && factory.SupportsTcpPrediction ? 1 : 0,
            TcpPeerReflexive: allowed.Contains(TraversalProfile.FakeTcpHttpSo) && factory.SupportsTcpPeerReflexive ? 1 : 0,
            UdpExploration: allowed.Contains(TraversalProfile.UdpDirect) && factory.SupportsUdpExploration ? 1 : 0,
            QualityFeedback: factory.SupportsQualityFeedback ? 1 : 0,
            StandbyPaths: factory.SupportsStandbyPaths ? 1 : 0,PathDiagnostics:factory.SupportsPathDiagnostics?1:0,DiagnosticMbps:factory.DiagnosticMbps);
        MeshTraversal.ValidateCapabilities(Capabilities);
    }
    public void Receive(MeshTraversalMessage[]? messages)
    {
        foreach (var message in messages ?? []) {
            if (message.ToSlot != mesh.Self.Slot || message.ToBoot != Capabilities.BootId) continue;
            var member = mesh.Directory?.Members.FirstOrDefault(m => m.Slot == message.FromSlot);
            if (member == null) continue;
            try {
                MeshTraversal.Verify(mesh.Pair.Network, member, mesh.Self, message);
                if (inbox.TryGetValue(member.Slot, out var old) && old.FromBoot == message.FromBoot && old.Sequence >= message.Sequence) continue;
                inbox[member.Slot] = message;
            } catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException) { log("已拒绝无效打洞控制消息"); }
        }
    }
    public void Tick(IReadOnlyDictionary<int, MeshAnnouncement> announcements, string localExplicit)
    {
        if (disposed) return;
        long now = Environment.TickCount64, utc = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var members = mesh.Directory?.Members.Where(m => m.Slot != mesh.Self.Slot).OrderBy(m => m.Slot).ToArray() ?? [];
        var statuses = router.Status().ToDictionary(s => s.Slot);
        bool Healthy(int slot) => statuses.GetValueOrDefault(slot)?.Connected == true;
        MeshTraversalCapabilities? Remote(int slot) => announcements.TryGetValue(slot, out var a) && a.Expires > utc ? a.Traversal : null;
        bool HasExplicit(int slot) {
            string remote = announcements.TryGetValue(slot, out var a) && a.Expires > utc ? a.Endpoint : "";
            string key = localExplicit + "|" + remote;
            if (key == "|") { explicitPriority.Remove(slot); return false; }
            if (remote.Length > 0 && opportunities.TryGetValue(slot, out var window) &&
                window.Count(TraversalProfile.LegacyExplicit) >= 2 && !legacyPending.Contains(slot)) return false;
            if (!explicitPriority.TryGetValue(slot, out long since))
                explicitPriority[slot] = since = opportunities.TryGetValue(slot, out var opportunity) ? opportunity.Began : now;
            // A candidate refresh does not reset an unsuccessful fast path's
            // entire priority window. Healthy legacy paths are checked separately.
            return now - since < 15000;
        }
        foreach (var peer in members) {
            var remote = Remote(peer.Slot);
            var common = remote == null ? [] : Capabilities.Profiles.Intersect(remote.Profiles).ToArray();
            // Old peers retain the compatible path. A new peer's shared window
            // starts before admission, so waiting for another peer counts too.
            if (discovery.SupportsTraversal && common.Length > 0) {
                if (!opportunities.TryGetValue(peer.Slot, out var window)) opportunities[peer.Slot] = window = new();
                if (window.Observe(remote!.BootId, Healthy(peer.Slot), now)) {
                    explicitPriority.Remove(peer.Slot);
                    log($"设备 {peer.Slot} 开始直连机会窗 {window.Id:N}（60 秒，含排队与准备）");
                }
                methods[peer.Slot] = announcements.GetValueOrDefault(peer.Slot)?.Endpoint.Length > 0
                    ? [TraversalProfile.LegacyExplicit, .. common] : common;
            } else if (opportunities.TryGetValue(peer.Slot, out var existing) && Healthy(peer.Slot)) existing.Observe(existing.Boot, true, now);
            if (opportunities.TryGetValue(peer.Slot, out var current) && current.Open && now >= current.Deadline) EndOpportunity(peer.Slot, now);
        }
        foreach (var peer in members) {
            var path = router.Paths(peer.Slot).FirstOrDefault(p => p.Active && p.Stage == NominationStage.Selected);
            if (Healthy(peer.Slot) && path != null) {
                if (!activeSince.TryGetValue(peer.Slot, out var active) || active.Path != path.PathId) activeSince[peer.Slot] = (path.PathId, now);
            } else activeSince.Remove(peer.Slot);
            if (Healthy(peer.Slot) && path?.Profile == TraversalProfile.UdpDirect) {
                if (!degradedSince.TryGetValue(peer.Slot, out var seen) || seen.Path != path.PathId)
                    degradedSince[peer.Slot] = (path.PathId, now);
            } else degradedSince.Remove(peer.Slot);
        }
        bool UpgradeDue(int slot, TraversalProfile kind) => kind == TraversalProfile.FakeTcpHttpSo && Healthy(slot) &&
            degradedSince.TryGetValue(slot, out var degraded) && now - degraded.Since >= TraversalLimits.UpgradeResidenceMs &&
            now >= upgradeAt.GetValueOrDefault(slot) && Remote(slot) is { BackgroundUpgrade: 1 } remote && remote.Profiles.Contains(kind) && Capabilities.Profiles.Contains(kind);
        bool ForegroundWaiting() => entries.Values.Any(e => e.Closing != null || e.Actor?.Phase is not (MeshAttemptPhase.Selected or MeshAttemptPhase.Standby)) ||
            members.Any(p => !Healthy(p.Slot) && !entries.ContainsKey(p.Slot) &&
                opportunities.GetValueOrDefault(p.Slot)?.Next(methods.GetValueOrDefault(p.Slot) ?? [], now) != null &&
                Remote(p.Slot) is {} remote && remote.Profiles.Intersect(Capabilities.Profiles).Any() && !HasExplicit(p.Slot));
        bool Eligible(int slot, TraversalProfile kind, bool standby = false) => Healthy(slot)
            ? (standby ? StandbyDue(slot, kind, Remote(slot)) : UpgradeDue(slot, kind)) && !ForegroundWaiting()
            : !HasExplicit(slot);
        foreach (var pair in entries.ToArray()) {
            int slot = pair.Key; var e = pair.Value;
            if (e.Closing != null) {
                if (e.Closing.IsCompleted) {
                    ObserveCleanup(e);
                    if (e.Previous != null) { entries[slot] = e.Previous; e.Previous = null; }
                    else entries.Remove(slot);
                }
                continue;
            }
            try {
                if (!members.Contains(e.Peer)) { Fail(e, "成员已撤销", PredictionOutcome.Cancelled); continue; }
                if (e.Actor?.Phase != MeshAttemptPhase.Selected && Remote(slot) is {} current && current.BootId != e.Remote.BootId) { Fail(e, "对端已重启", PredictionOutcome.Cancelled); continue; }
                if (e.Actor?.Phase is not (MeshAttemptPhase.Selected or MeshAttemptPhase.Standby) && now >= e.Deadline) { Fail(e, "本轮超时"); continue; }
                if (e.Gathering?.IsCompleted == true) {
                    e.Resource = e.Gathering.GetAwaiter().GetResult(); e.Gathering = null;
                    e.Actor = e.Offer == null
                        ? MeshTraversalAttempt.Offer(mesh, e.Peer, Capabilities, e.Remote, e.Profile, e.Resource.Candidate, ++revision, () => Interlocked.Increment(ref sequence), e.Attempt, discovery.SupportsQualityFeedback, discovery.SupportsStandbyPaths,discovery.SupportsPathDiagnostics)
                        : MeshTraversalAttempt.Answer(mesh, e.Peer, Capabilities, e.Remote, e.Offer, e.Resource.Candidate, () => Interlocked.Increment(ref sequence), discovery.SupportsQualityFeedback, discovery.SupportsStandbyPaths,discovery.SupportsPathDiagnostics);
                }
                if (e.Actor?.Phase == MeshAttemptPhase.Reserving && e.Resource!.PredictionControlReady(8)) e.Actor.Reserved(e.Resource.PredictionReady);
                if (e.Measuring?.IsCompleted == true) { e.Actor!.Measured(e.Measuring.GetAwaiter().GetResult()); e.Measuring = null; }
                if (e.Actor is { Predicting: true, PredictionBegan: > 0 } predicting && predicting.Phase != MeshAttemptPhase.Selected && predicting.PredictionRemaining <= TimeSpan.Zero)
                    throw new IOException("预测整轮8秒期限已结束");
                if (e.Actor is { Exploring: true } exploring && exploring.Phase != MeshAttemptPhase.Selected && e.Resource!.ExplorationRemaining <= TimeSpan.Zero)
                    throw new IOException("UDP 探索整轮12秒期限已结束");
                if (e.Actor is { Exploring: true } && e.Actor.Phase != MeshAttemptPhase.Selected && Healthy(slot) &&
                    router.Paths(slot).Any(p => p.Active && p.Stage == NominationStage.Selected && p.AttemptId != e.Attempt))
                    throw new IOException("已有健康路径，取消 UDP 高成本探索");
                if (e.Preparing?.IsCompleted == true) {
                    var path = e.Preparing.GetAwaiter().GetResult(); RequireRoundTime(e); e.Actor!.Prepared(path); e.Preparing = null;
                }
                if (e.Activating?.IsCompleted == true) { e.Activating.GetAwaiter().GetResult(); e.Activating = null; }
                e.Actor?.ObserveRouter();
                if (e.Actor?.Phase == MeshAttemptPhase.Standby && !e.StandbyRetained) {
                    e.Stop.CancelAfter(Timeout.InfiniteTimeSpan); e.StandbyRetained = true;
                    log($"设备 {slot} 独立备用已双向认证，最多保留120秒；当前业务路径继续使用；attempt={e.Attempt:N}");
                }
                if (e.Actor?.Phase == MeshAttemptPhase.Standby && !Healthy(slot)) {
                    Fail(e, "原路径失效，备用尚无质量批准；重新执行前台直连", PredictionOutcome.Cancelled); continue;
                }
                if (e.Actor?.Phase == MeshAttemptPhase.Cancelled) { Fail(e, "路径验证失败"); continue; }
                if (e.Actor?.Phase == MeshAttemptPhase.Selected && !Healthy(slot)) { Fail(e, "已选路径失效，重新收集端点"); continue; }
                if (e.Actor?.Phase == MeshAttemptPhase.Selected) { failures[slot] = 0; e.Resource?.FinishPrediction(PredictionOutcome.PathAuthenticated); LogExploration(e); }
                if (e.Actor?.Phase == MeshAttemptPhase.Selected && e.Previous != null && e.Retiring == null &&
                    !router.Paths(slot).Any(p => p.AttemptId == e.Previous.Attempt)) {
                    e.Retiring = Close(e.Previous); e.Previous = null;
                }
                BeginPreparation(e);
            } catch (Exception ex) { Fail(e, ex.Message + $"；阶段={e.Actor?.Phase}"); }
        }
        foreach (int slot in owned.Where(s => !entries.ContainsKey(s)).ToArray())
            if (router.ReleaseTraversalReservation(slot)) owned.Remove(slot);
        foreach (int slot in received.Keys.Concat(explicitPriority.Keys).Concat(degradedSince.Keys).Concat(upgradeAt.Keys).Concat(opportunities.Keys).Concat(activeSince.Keys).Distinct().Where(s => !members.Any(m => m.Slot == s)).ToArray()) { received.Remove(slot); inbox.Remove(slot); retryAt.Remove(slot); failures.Remove(slot); explicitPriority.Remove(slot); degradedSince.Remove(slot); upgradeAt.Remove(slot); opportunities.Remove(slot); methods.Remove(slot); legacyPending.Remove(slot); activeSince.Remove(slot); standbyNext.Remove(slot); }

        // Process signed messages before starting fresh work. An Offer waiting
        // for admission stays in the bounded per-peer inbox, not another task.
        foreach (var pair in inbox.OrderBy(p => (p.Key - cursor + 256) % 256).ToArray()) {
            int slot = pair.Key; var m = pair.Value;
            if (m.Expires <= utc) { inbox.Remove(slot); continue; }
            var peer = members.FirstOrDefault(p => p.Slot == slot); var remote = Remote(slot);
            if (peer == null || remote == null || remote.BootId != m.FromBoot) continue;
            if (received.TryGetValue(slot, out var seen) && seen.Boot == m.FromBoot && seen.Sequence >= m.Sequence) { inbox.Remove(slot); continue; }
            try {
                bool standby = m.Candidate?.Standby == true;
                if (standby && (!discovery.SupportsStandbyPaths || Capabilities.StandbyPaths != 1 || remote.StandbyPaths != 1))
                    throw new IOException("协调服务或双方未授权独立备用路径");
                if (m.Stage is not (MeshTraversalStage.Cancel or MeshTraversalStage.Selected) &&
                    (m.Candidate?.PeerReflexive == true || m.PeerCandidate?.PeerReflexive == true) &&
                    (!discovery.SupportsTcpPeerReflexive || Capabilities.TcpPeerReflexive != 1 || remote.TcpPeerReflexive != 1))
                    throw new IOException("协调服务或双方未授权本轮 TCP 来源学习消息");
                if (m.Stage is not (MeshTraversalStage.Cancel or MeshTraversalStage.Selected) &&
                    (m.Candidate?.Exploration != null || m.PeerCandidate?.Exploration != null) &&
                    (!discovery.SupportsUdpExploration || Capabilities.UdpExploration != 1 || remote.UdpExploration != 1))
                    throw new IOException("协调服务或双方未授权本轮 UDP 探索消息");
                if (entries.TryGetValue(slot, out var e)) {
                    if (e.Closing != null) continue;
                    if (m.AttemptId != e.Attempt && m.Stage == MeshTraversalStage.Offer && e.Actor?.Phase != MeshAttemptPhase.Selected) {
                        // A newer authenticated leader Offer supersedes its old
                        // attempt even if the old Cancel was coalesced in transit.
                        // Keep the Offer queued until all losing resources close.
                        MeshTraversalAttempt.ValidateOffer(mesh, peer, Capabilities, remote, m, discovery.SupportsStandbyPaths);
                        Fail(e, "对端已开始下一候选，先释放上一轮资源", PredictionOutcome.Cancelled); continue;
                    }
                    if (m.AttemptId != e.Attempt && m.Stage == MeshTraversalStage.Offer && e.Actor?.Phase == MeshAttemptPhase.Selected) {
                        MeshTraversalAttempt.ValidateOffer(mesh, peer, Capabilities, remote, m, discovery.SupportsStandbyPaths);
                        if (e.Previous != null || !CanAdmit(slot, m.Profile, standby) || !Eligible(slot, m.Profile, standby) || !router.ReserveTraversal(slot, m.Profile, standby)) continue;
                        Start(peer, remote, m.AttemptId, m.Profile, m, e); cursor = slot + 1;
                    }
                    else if (m.AttemptId == e.Attempt && e.Actor != null) {
                        bool changed = e.Actor.Receive(m);
                        if (changed) e.RemoteCandidate = e.Actor.RemoteCandidate;
                        BeginPreparation(e);
                        if (e.Actor.Phase == MeshAttemptPhase.Starting && e.Actor.Context.ProtocolClient == false && e.Activating == null) {
                            RequireRoundTime(e); e.Activating = e.Actor.ActivateAndRegister(router, e.Stop.Token);
                        }
                        if (e.Actor.Phase == MeshAttemptPhase.Cancelled) Fail(e, "对端取消本轮", PredictionOutcome.Cancelled);
                    }
                } else if (m.Stage == MeshTraversalStage.Offer) {
                    MeshTraversalAttempt.ValidateOffer(mesh, peer, Capabilities, remote, m, discovery.SupportsStandbyPaths);
                    if (!CanAdmit(slot, m.Profile, standby) || !Eligible(slot, m.Profile, standby) || !router.ReserveTraversal(slot, m.Profile, standby)) continue;
                    Start(peer, remote, m.AttemptId, m.Profile, m); cursor = slot + 1;
                }
                received[slot] = (m.FromBoot, m.Sequence); inbox.Remove(slot);
            } catch (Exception ex) when (ex is IOException or FormatException or System.Security.Cryptography.CryptographicException or InvalidOperationException) {
                if (ex is IOException && entries.TryGetValue(slot, out var failed) && failed.Attempt == m.AttemptId) Fail(failed, ex.Message);
                inbox.Remove(slot); log($"设备 {slot} 打洞状态被拒绝：{ex.Message}");
            }
        }
        if (discovery.SupportsTraversal) foreach (var peer in members.OrderBy(p => Healthy(p.Slot)).ThenBy(p => (p.Slot - cursor + 256) % 256)) {
            var remote = Remote(peer.Slot);
            entries.TryGetValue(peer.Slot, out var previous);
            if (peer.Slot < mesh.Self.Slot || remote == null ||
                previous != null && (previous.Closing != null || previous.Actor?.Phase != MeshAttemptPhase.Selected || previous.Previous != null)) continue;
            if (previous != null && !Healthy(peer.Slot)) continue;
            var common = Capabilities.Profiles.Where(p => remote.Profiles.Contains(p)).OrderBy(p => p == TraversalProfile.FakeTcpHttpSo ? 0 : 1).ToArray();
            if (common.Length == 0) continue;
            bool standby = Healthy(peer.Slot) && !UpgradeDue(peer.Slot, TraversalProfile.FakeTcpHttpSo);
            var next = Healthy(peer.Slot) ? standby ? StandbyProfile(peer.Slot, remote) : TraversalProfile.FakeTcpHttpSo : opportunities.GetValueOrDefault(peer.Slot)?.Next(methods.GetValueOrDefault(peer.Slot) ?? common, now);
            if (next == null || next == TraversalProfile.LegacyExplicit) continue;
            var kind = next.Value;
            if (!CanAdmit(peer.Slot, kind, standby) || !Eligible(peer.Slot, kind, standby) || !router.ReserveTraversal(peer.Slot, kind, standby)) continue;
            Start(peer, remote, Guid.NewGuid(), kind, null, previous, standby); cursor = peer.Slot + 1;
        }
        foreach (var peer in members) if (!Healthy(peer.Slot) && !entries.ContainsKey(peer.Slot) && !legacyPending.Contains(peer.Slot) &&
            opportunities.TryGetValue(peer.Slot, out var window) && window.Open &&
            methods.TryGetValue(peer.Slot, out var available) && available.Length > 0 && window.Next(available, now) == null)
            EndOpportunity(peer.Slot, now);
        Flush();
        foreach (var e in entries.Values) router.DescribeTraversal(e.Peer.Slot,
            announcements.GetValueOrDefault(e.Peer.Slot)?.Name ?? "", e.Actor?.Phase switch {
                MeshAttemptPhase.Offering => "等待对端准备直连",
                MeshAttemptPhase.Preparing => "正在准备本机直连",
                MeshAttemptPhase.Ready => "等待双方启动",
                MeshAttemptPhase.Starting => "正在验证直连路径",
                MeshAttemptPhase.Selected => "已验证直连",
                MeshAttemptPhase.Standby => "已直连，独立备用已认证（未切换）",
                MeshAttemptPhase.Cancelled => "本轮未找到直连，等待重试",
                MeshAttemptPhase.Reserving or MeshAttemptPhase.AwaitMeasure => "正在预约预测源端点",
                MeshAttemptPhase.Measuring or MeshAttemptPhase.AwaitMeasured => "正在交换新鲜 TCP 观察",
                MeshAttemptPhase.AwaitReady => "等待对端预测资源就绪",
                _ => "正在探测可用端点"
            });
    }
    bool CanAdmit(int slot, TraversalProfile? kind = null, bool standby = false) => discovery.SupportsTraversal &&
        (standby ? discovery.SupportsStandbyPaths && !entries.Values.Any(e => e.Standby && e.Actor?.Phase != MeshAttemptPhase.Selected) :
            degradedSince.ContainsKey(slot) ? Environment.TickCount64 >= retryAt.GetValueOrDefault(slot) :
            opportunities.TryGetValue(slot, out var window) && (kind is {} profile ? window.CanBegin(profile, Environment.TickCount64) : window.Open)) &&
        entries.Values.Count(e => e.Actor?.Phase is not (MeshAttemptPhase.Selected or MeshAttemptPhase.Standby)) < TraversalLimits.LightPeers &&
        (kind != TraversalProfile.FakeTcpHttpSo || entries.Values.All(e => e.Profile != kind || e.Actor?.Phase is MeshAttemptPhase.Selected or MeshAttemptPhase.Standby));
    void Start(MeshMember peer, MeshTraversalCapabilities remote, Guid attempt, TraversalProfile kind, MeshTraversalMessage? offer, Entry? previous = null, bool standby = false)
    {
        standby |= offer?.Candidate?.Standby == true;
        var e = new Entry(peer, remote, attempt, kind, token) { Offer = offer, RemoteCandidate = offer?.Candidate, Previous = previous, Standby = standby, Upgrade = !standby && degradedSince.ContainsKey(peer.Slot) };
        if (!e.Upgrade && !e.Standby && (!opportunities.TryGetValue(peer.Slot, out var window) || !window.Begin(kind, Environment.TickCount64))) {
            e.Stop.Dispose(); throw new InvalidOperationException("当前直连机会窗没有可用轮次或剩余时间");
        }
        e.Deadline = e.Upgrade || e.Standby ? e.Began + TraversalLimits.PairOpportunityMs : opportunities[peer.Slot].Deadline;
        if (e.Standby) standbyNext[peer.Slot] = e.Began + TraversalLimits.UpgradeCooldownMs;
        if (e.Upgrade) upgradeAt[peer.Slot] = Environment.TickCount64 + TraversalLimits.UpgradeCooldownMs;
        e.Stop.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(1, e.Deadline - Environment.TickCount64))); owned.Add(peer.Slot); entries[peer.Slot] = e;
        try {
            var endpoint = offer?.Candidate is {} candidate ? IPEndPoint.Parse(candidate.Endpoint) : null;
            bool allow6 = kind == TraversalProfile.UdpDirect
                ? discovery.SupportsUdpIpv6 && remote.UdpIpv6 == 1 && Capabilities.UdpIpv6 == 1
                : discovery.SupportsFakeTcpIpv6 && remote.FakeTcpIpv6 == 1 && Capabilities.FakeTcpIpv6 == 1;
            if (endpoint?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !allow6)
                throw new IOException("协调服务不支持 IPv6 候选");
            if (e.Standby) {
                if (!discovery.SupportsStandbyPaths || Capabilities.StandbyPaths != 1 || remote.StandbyPaths != 1) throw new IOException("备用路径权限未齐备");
                e.Gathering = factory.GatherStandby(peer, kind, attempt, allow6, offer?.Candidate, e.Stop.Token);
            }
            else {
            bool prediction = !e.Upgrade && discovery.SupportsTcpPrediction && Capabilities.TcpPrediction == 1 && remote.TcpPrediction == 1;
            if (offer?.Candidate?.Prediction != null && !prediction) throw new IOException("协调服务或双方未授权预测扩展");
            bool sourceLearning = discovery.SupportsTcpPeerReflexive && Capabilities.TcpPeerReflexive == 1 && remote.TcpPeerReflexive == 1;
            if (offer?.Candidate?.PeerReflexive == true && !sourceLearning) throw new IOException("协调服务或双方未授权 TCP 来源学习");
            bool exploration = !e.Upgrade && kind == TraversalProfile.UdpDirect && discovery.SupportsUdpExploration && Capabilities.UdpExploration == 1 && remote.UdpExploration == 1 &&
                e.Deadline - Environment.TickCount64 >= UdpProbeGroup.DurationMs;
            if (offer?.Candidate?.Exploration != null && !exploration) throw new IOException("协调服务、双方或机会窗未授权 UDP 探索");
            e.Gathering = factory.GatherEnhanced(peer, kind, attempt, allow6, offer?.Candidate,
                e.Upgrade ? 1 : opportunities[peer.Slot].Count(kind), prediction, sourceLearning, exploration, () => !router.Status().Any(s => s.Slot == peer.Slot && s.Connected), e.Stop.Token);
            }
        }
        catch (Exception ex) { e.Gathering = Task.FromException<IMeshCandidateResource>(ex); }
        log($"设备 {peer.Slot} " + (e.Standby ? $"保留当前直连，后台准备独立 {kind} 备用" : e.Upgrade ? "保留 UDP 直连，后台尝试 FakeTCP" : $"开始 {kind} 同端点候选观察") +
            $"；attempt={attempt:N}；机会窗={(e.Standby ? "standby-prepare" : e.Upgrade ? "background-upgrade" : opportunities[peer.Slot].Id.ToString("N"))}；剩余 {Math.Max(0, e.Deadline - Environment.TickCount64)} ms");
    }
    void BeginPreparation(Entry e)
    {
        if (e.Closing == null && e.Actor?.Phase == MeshAttemptPhase.Measuring && e.Measuring == null)
            e.Measuring = e.Resource!.MeasurePrediction(e.Actor.PredictionBegan, e.Stop.Token);
        if (e.Closing == null && e.Actor?.Phase == MeshAttemptPhase.Preparing && e.Preparing == null) {
            e.RemoteCandidate = e.Actor.RemoteCandidate;
            // Kept independently from the inbox so admission/async preparation
            // cannot discard the authenticated endpoint when consuming Ready.
            if (e.RemoteCandidate?.Id != e.Actor.Context.RemoteCandidateId) throw new IOException("缺少本轮已认证远端候选");
            RequireRoundTime(e); e.Preparing = e.Resource!.PrepareCandidate(e.Actor.Context, e.RemoteCandidate, e.Stop.Token);
        }
    }
    static void RequireRoundTime(Entry e)
    {
        if (e.Actor is { Exploring: true }) {
            if (e.Resource!.ExplorationRemaining <= TimeSpan.Zero || e.Deadline <= Environment.TickCount64) throw new IOException("UDP 探索共享期限已结束");
            return;
        }
        if (e.Actor is { Predicting: true, PredictionBegan: > 0 } predicting) {
            if (predicting.PredictionRemaining <= TimeSpan.Zero || e.Deadline <= Environment.TickCount64) throw new IOException("预测共享期限已结束");
            return;
        }
        if (e.Deadline - Environment.TickCount64 < MeshPairOpportunity.RoundMs(e.Profile))
            throw new IOException("机会窗剩余时间不足以完成新的握手轮次");
    }
    void LogExploration(Entry e)
    {
        if (e.ExplorationStatsLogged || e.Resource?.ExplorationStats is not {} statistics) return;
        e.ExplorationStatsLogged = true;
        log($"设备 {e.Peer.Slot} UDP 探索实际成本：" + System.Text.Json.JsonSerializer.Serialize(statistics));
    }
    void EndOpportunity(int slot, long now)
    {
        var window = opportunities[slot];
        if (window.End(now, Random.Shared.Next(0, 2000)))
            log($"设备 {slot} 机会窗 {window.Id:N} 结束：NoDirectPathWithinBudget；进入后台退避；elapsedMs={now - window.Began}；" +
                $"legacy={window.Count(TraversalProfile.LegacyExplicit)},so={window.Count(TraversalProfile.FakeTcpHttpSo)},udp={window.Count(TraversalProfile.UdpDirect)}");
    }
    void Flush()
    {
        long now = Environment.TickCount64;
        if (sending?.IsCompleted == true) {
            try {
                sending.GetAwaiter().GetResult(); sendFailures = 0;
                foreach (var m in batch) {
                    if (outbox.GetValueOrDefault(m.ToSlot)?.MessageId == m.MessageId) outbox.Remove(m.ToSlot);
                    if (entries.TryGetValue(m.ToSlot, out var e) && e.Actor?.Outbound?.MessageId == m.MessageId) {
                        e.Acknowledged = m.MessageId;
                        if (e.Closing == null && m.Stage == MeshTraversalStage.Measure && e.Actor.Phase == MeshAttemptPhase.AwaitMeasure) {
                            e.Actor.BeginMeasurement(); BeginPreparation(e);
                        }
                        if (e.Closing == null && m.Stage == MeshTraversalStage.Start && e.Activating == null) {
                            try { RequireRoundTime(e); e.Activating = e.Actor.ActivateAndRegister(router, e.Stop.Token); }
                            catch (Exception ex) { Fail(e, ex.Message); }
                        }
                    }
                }
            } catch (Exception ex) when (!token.IsCancellationRequested) {
                nextSend = now + Math.Min(10000, 1000L << Math.Min(sendFailures++, 3)); log("打洞控制发送重试：" + ex.GetType().Name);
            }
            sending = null;
        }
        if (sending != null || now < nextSend || !discovery.SupportsTraversal) return;
        foreach (var e in entries.Values) if (e.Actor?.Outbound is {} m && m.MessageId != e.Acknowledged &&
            (m.Stage != MeshTraversalStage.Measure || e.Resource!.PredictionControlReady(8))) Queue(m);
        foreach (int slot in outbox.Where(p => p.Value.Expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() || mesh.Directory?.Members.Any(m => m.Slot == p.Key) != true).Select(p => p.Key).ToArray()) outbox.Remove(slot);
        batch = outbox.Values.OrderBy(m => m.Stage is MeshTraversalStage.Start or MeshTraversalStage.Cancel ? 0 : 1).Take(7).ToArray();
        if (batch.Length > 0 && budget.Take(priority: true)) sending = discovery.PublishTraversal(batch, token);
    }
    void Queue(MeshTraversalMessage m) { if (!outbox.TryGetValue(m.ToSlot, out var old) || m.Sequence > old.Sequence) outbox[m.ToSlot] = m; }
    void Fail(Entry e, string reason, PredictionOutcome predictionOutcome = PredictionOutcome.Failed)
    {
        if (e.Closing != null) return;
        LogExploration(e);
        e.Resource?.FinishPrediction(predictionOutcome);
        e.Actor?.Cancel(); e.Stop.Cancel();
        if (e.Actor?.Outbound is {} cancel) Queue(cancel);
        int count = failures[e.Peer.Slot] = failures.GetValueOrDefault(e.Peer.Slot) + 1;
        if (e.Upgrade) retryAt[e.Peer.Slot] = Environment.TickCount64 + Math.Min(300000, 30000L << Math.Min(count - 1, 4)) + Random.Shared.Next(0, 2000);
        if (e.Upgrade) upgradeAt[e.Peer.Slot] = Math.Max(upgradeAt.GetValueOrDefault(e.Peer.Slot), Environment.TickCount64 + TraversalLimits.UpgradeCooldownMs);
        if (e.Standby) standbyNext[e.Peer.Slot] = Environment.TickCount64 + TraversalLimits.UpgradeCooldownMs;
        log($"设备 {e.Peer.Slot} " + (e.Standby ? $"备用已结束，保留原路径：{reason}" : e.Upgrade ? $"FakeTCP 升级未完成，保留原路径：{reason}" : $"{e.Profile} 候选失败：{reason}；机会窗剩余 {Math.Max(0, e.Deadline - Environment.TickCount64)} ms"));
        e.Closing = Close(e);
    }
    static async Task Close(Entry e)
    {
        e.Stop.Cancel();
        try {
            if (e.Gathering != null) try { e.Resource = await e.Gathering; } catch { }
            if (e.Measuring != null) try { await e.Measuring; } catch { }
            if (e.Preparing != null) try { await (await e.Preparing).DisposeAsync(); } catch { }
            if (e.Activating != null) try { await e.Activating; } catch { }
            try { if (e.Retiring != null) await e.Retiring; }
            finally {
                try { if (e.Actor != null) await e.Actor.DisposeAsync(); }
                finally { if (e.Resource != null) await e.Resource.DisposeAsync(); }
            }
        } finally { e.Stop.Dispose(); }
    }
    void ObserveCleanup(Entry e) { try { e.Closing!.GetAwaiter().GetResult(); } catch (Exception ex) { log("打洞资源清理：" + ex.Message); } }
    public async ValueTask DisposeAsync()
    {
        disposed = true;
        if (sending != null) try { await sending; } catch { }
        foreach (var head in entries.Values) for (Entry? e = head; e != null; e = e.Previous) {
            if (e.Closing == null) e.Closing = Close(e);
            try { await e.Closing; } catch (Exception ex) { log("打洞资源清理：" + ex.Message); }
        }
    }
}
