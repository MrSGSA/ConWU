using System.Net;
using StreamLink.Core;

namespace StreamLink.Service;

// One runner-owned scheduler, never a polling loop per peer. Tick is called by
// MeshRunner; all mutable negotiation state remains on that loop. Slow endpoint
// preparation, HTTP and cleanup run independently and are joined on shutdown.
internal sealed class MeshTraversalManager : IAsyncDisposable
{
    sealed class Entry(MeshMember peer, MeshTraversalCapabilities remote, Guid attempt, TraversalProfile profile, CancellationToken token)
    {
        public readonly MeshMember Peer = peer;
        public readonly MeshTraversalCapabilities Remote = remote;
        public readonly Guid Attempt = attempt;
        public readonly TraversalProfile Profile = profile;
        public readonly CancellationTokenSource Stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        public readonly long Began = Environment.TickCount64;
        public Task<IMeshCandidateResource>? Gathering;
        public IMeshCandidateResource? Resource;
        public Task<IPreparedMeshPath>? Preparing;
        public MeshTraversalAttempt? Actor;
        public MeshTraversalMessage? Offer;
        public MeshTraversalCandidate? RemoteCandidate;
        public Task? Activating, Closing;
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
    readonly HashSet<int> owned = [];
    Task? sending;
    MeshTraversalMessage[] batch = [];
    long sequence, revision = DateTime.UtcNow.Ticks, nextSend;
    int cursor, sendFailures;
    bool disposed;
    public MeshTraversalCapabilities Capabilities { get; }
    public bool Owns(int slot) => owned.Contains(slot);
    public bool HasPendingControl => outbox.Count > 0 || entries.Values.Any(e => e.Closing == null && e.Actor?.Outbound is {} m && m.MessageId != e.Acknowledged);
    public MeshTraversalManager(MeshProfile mesh, MeshRouter router, IMeshTraversalDiscovery discovery,
        IMeshCandidateFactory factory, MeshRequestBudget budget, Action<string> log, CancellationToken token)
    {
        this.mesh = mesh; this.router = router; this.discovery = discovery; this.factory = factory; this.budget = budget; this.log = log; this.token = token;
        Capabilities = new(1, factory.Profiles.Contains(TraversalProfile.FakeTcpHttpSo) ? 1 : 0, router.BootId, factory.Profiles);
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
            if (!explicitPriority.TryGetValue(slot, out long since)) explicitPriority[slot] = since = now;
            // A candidate refresh does not reset an unsuccessful fast path's
            // entire priority window. Healthy legacy paths are checked separately.
            return now - since < 15000;
        }
        foreach (var pair in entries.ToArray()) {
            int slot = pair.Key; var e = pair.Value;
            if (e.Closing != null) {
                if (e.Closing.IsCompleted) { ObserveCleanup(e); entries.Remove(slot); }
                continue;
            }
            try {
                if (!members.Contains(e.Peer)) { Fail(e, "成员已撤销"); continue; }
                if (e.Actor?.Phase != MeshAttemptPhase.Selected && (now - e.Began >= TraversalLimits.PairOpportunityMs ||
                    Remote(slot) is {} current && current.BootId != e.Remote.BootId)) { Fail(e, "本轮超时或对端已重启"); continue; }
                if (e.Gathering?.IsCompleted == true) {
                    e.Resource = e.Gathering.GetAwaiter().GetResult(); e.Gathering = null;
                    e.Actor = e.Offer == null
                        ? MeshTraversalAttempt.Offer(mesh, e.Peer, Capabilities, e.Remote, e.Profile, e.Resource.Candidate, ++revision, () => Interlocked.Increment(ref sequence), e.Attempt)
                        : MeshTraversalAttempt.Answer(mesh, e.Peer, Capabilities, e.Remote, e.Offer, e.Resource.Candidate, () => Interlocked.Increment(ref sequence));
                }
                if (e.Preparing?.IsCompleted == true) {
                    var path = e.Preparing.GetAwaiter().GetResult(); e.Actor!.Prepared(path); e.Preparing = null;
                }
                if (e.Activating?.IsCompleted == true) { e.Activating.GetAwaiter().GetResult(); e.Activating = null; }
                e.Actor?.ObserveRouter();
                if (e.Actor?.Phase == MeshAttemptPhase.Cancelled) { Fail(e, "路径验证失败"); continue; }
                if (e.Actor?.Phase == MeshAttemptPhase.Selected && !Healthy(slot)) { Fail(e, "已选路径失效，重新收集端点"); continue; }
                if (e.Actor?.Phase == MeshAttemptPhase.Selected) failures[slot] = 0;
                BeginPreparation(e);
            } catch (Exception ex) { Fail(e, ex.Message); }
        }
        foreach (int slot in owned.Where(s => !entries.ContainsKey(s)).ToArray())
            if (router.ReleaseTraversalReservation(slot)) owned.Remove(slot);
        foreach (int slot in received.Keys.Concat(explicitPriority.Keys).Distinct().Where(s => !members.Any(m => m.Slot == s)).ToArray()) { received.Remove(slot); inbox.Remove(slot); retryAt.Remove(slot); failures.Remove(slot); explicitPriority.Remove(slot); }

        // Process signed messages before starting fresh work. An Offer waiting
        // for admission stays in the bounded per-peer inbox, not another task.
        foreach (var pair in inbox.OrderBy(p => (p.Key - cursor + 256) % 256).ToArray()) {
            int slot = pair.Key; var m = pair.Value;
            if (m.Expires <= utc) { inbox.Remove(slot); continue; }
            var peer = members.FirstOrDefault(p => p.Slot == slot); var remote = Remote(slot);
            if (peer == null || remote == null || remote.BootId != m.FromBoot) continue;
            if (received.TryGetValue(slot, out var seen) && seen.Boot == m.FromBoot && seen.Sequence >= m.Sequence) { inbox.Remove(slot); continue; }
            try {
                if (entries.TryGetValue(slot, out var e)) {
                    if (e.Closing != null) continue;
                    if (m.AttemptId == e.Attempt && e.Actor != null) {
                        bool changed = e.Actor.Receive(m);
                        if (changed && m.Stage == MeshTraversalStage.Ready) e.RemoteCandidate = m.Candidate;
                        BeginPreparation(e);
                        if (e.Actor.Phase == MeshAttemptPhase.Starting && e.Actor.Context.ProtocolClient == false && e.Activating == null)
                            e.Activating = e.Actor.ActivateAndRegister(router, e.Stop.Token);
                        if (e.Actor.Phase == MeshAttemptPhase.Cancelled) Fail(e, "对端取消本轮");
                    }
                } else if (m.Stage == MeshTraversalStage.Offer) {
                    MeshTraversalAttempt.ValidateOffer(mesh, peer, Capabilities, remote, m);
                    if (!CanAdmit(slot, m.Profile) || Healthy(slot) || HasExplicit(slot) || !router.ReserveTraversal(slot)) continue;
                    Start(peer, remote, m.AttemptId, m.Profile, m); cursor = slot + 1;
                }
                received[slot] = (m.FromBoot, m.Sequence); inbox.Remove(slot);
            } catch (Exception ex) when (ex is IOException or FormatException or System.Security.Cryptography.CryptographicException or InvalidOperationException) {
                inbox.Remove(slot); log($"设备 {slot} 打洞状态被拒绝：{ex.Message}");
            }
        }
        if (discovery.SupportsTraversal) foreach (var peer in members.OrderBy(p => (p.Slot - cursor + 256) % 256)) {
            var remote = Remote(peer.Slot);
            if (peer.Slot < mesh.Self.Slot || entries.ContainsKey(peer.Slot) || !CanAdmit(peer.Slot) || remote == null || Healthy(peer.Slot) || HasExplicit(peer.Slot)) continue;
            var common = Capabilities.Profiles.Where(p => remote.Profiles.Contains(p)).OrderBy(p => p == TraversalProfile.FakeTcpHttpSo ? 0 : 1).ToArray();
            if (common.Length == 0) continue;
            var kind = common[failures.GetValueOrDefault(peer.Slot) % common.Length];
            if (!CanAdmit(peer.Slot, kind) || !router.ReserveTraversal(peer.Slot)) continue;
            Start(peer, remote, Guid.NewGuid(), kind, null); cursor = peer.Slot + 1;
        }
        Flush();
        foreach (var e in entries.Values) router.DescribeTraversal(e.Peer.Slot,
            announcements.GetValueOrDefault(e.Peer.Slot)?.Name ?? "", e.Actor?.Phase switch {
                MeshAttemptPhase.Offering => "等待对端准备直连",
                MeshAttemptPhase.Preparing => "正在准备本机直连",
                MeshAttemptPhase.Ready => "等待双方启动",
                MeshAttemptPhase.Starting => "正在验证直连路径",
                MeshAttemptPhase.Selected => "已验证直连",
                MeshAttemptPhase.Cancelled => "本轮未找到直连，等待重试",
                _ => "正在探测可用端点"
            });
    }
    bool CanAdmit(int slot, TraversalProfile? kind = null) => discovery.SupportsTraversal && Environment.TickCount64 >= retryAt.GetValueOrDefault(slot) &&
        entries.Values.Count(e => e.Actor?.Phase != MeshAttemptPhase.Selected) < TraversalLimits.LightPeers &&
        (kind != TraversalProfile.FakeTcpHttpSo || entries.Values.All(e => e.Profile != kind || e.Actor?.Phase == MeshAttemptPhase.Selected));
    void Start(MeshMember peer, MeshTraversalCapabilities remote, Guid attempt, TraversalProfile kind, MeshTraversalMessage? offer)
    {
        var e = new Entry(peer, remote, attempt, kind, token) { Offer = offer, RemoteCandidate = offer?.Candidate };
        e.Stop.CancelAfter(TraversalLimits.PairOpportunityMs); owned.Add(peer.Slot); entries.Add(peer.Slot, e);
        try { e.Gathering = factory.Gather(peer, kind, attempt, e.Stop.Token); }
        catch (Exception ex) { e.Gathering = Task.FromException<IMeshCandidateResource>(ex); }
        log($"设备 {peer.Slot} 开始 {kind} 同端点候选观察");
    }
    void BeginPreparation(Entry e)
    {
        if (e.Closing == null && e.Actor?.Phase == MeshAttemptPhase.Preparing && e.Preparing == null) {
            // Kept independently from the inbox so admission/async preparation
            // cannot discard the authenticated endpoint when consuming Ready.
            if (e.RemoteCandidate?.Id != e.Actor.Context.RemoteCandidateId) throw new IOException("缺少本轮已认证远端候选");
            e.Preparing = e.Resource!.Prepare(e.Actor.Context, IPEndPoint.Parse(e.RemoteCandidate.Endpoint), e.Stop.Token);
        }
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
                        if (e.Closing == null && m.Stage == MeshTraversalStage.Start && e.Activating == null)
                            e.Activating = e.Actor.ActivateAndRegister(router, e.Stop.Token);
                    }
                }
            } catch (Exception ex) when (!token.IsCancellationRequested) {
                nextSend = now + Math.Min(10000, 1000L << Math.Min(sendFailures++, 3)); log("打洞控制发送重试：" + ex.GetType().Name);
            }
            sending = null;
        }
        if (sending != null || now < nextSend || !discovery.SupportsTraversal) return;
        foreach (var e in entries.Values) if (e.Actor?.Outbound is {} m && m.MessageId != e.Acknowledged) Queue(m);
        foreach (int slot in outbox.Where(p => p.Value.Expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() || mesh.Directory?.Members.Any(m => m.Slot == p.Key) != true).Select(p => p.Key).ToArray()) outbox.Remove(slot);
        batch = outbox.Values.OrderBy(m => m.Stage is MeshTraversalStage.Start or MeshTraversalStage.Cancel ? 0 : 1).Take(7).ToArray();
        if (batch.Length > 0 && budget.Take(priority: true)) sending = discovery.PublishTraversal(batch, token);
    }
    void Queue(MeshTraversalMessage m) { if (!outbox.TryGetValue(m.ToSlot, out var old) || m.Sequence > old.Sequence) outbox[m.ToSlot] = m; }
    void Fail(Entry e, string reason)
    {
        if (e.Closing != null) return;
        e.Actor?.Cancel(); e.Stop.Cancel();
        if (e.Actor?.Outbound is {} cancel) Queue(cancel);
        int count = failures[e.Peer.Slot] = failures.GetValueOrDefault(e.Peer.Slot) + 1;
        retryAt[e.Peer.Slot] = Environment.TickCount64 + Math.Min(300000, 30000L << Math.Min(count - 1, 3)) + Random.Shared.Next(0, 2000);
        log($"设备 {e.Peer.Slot} 本轮未找到可用直连：{reason}");
        e.Closing = Close(e);
    }
    static async Task Close(Entry e)
    {
        e.Stop.Cancel();
        try {
            if (e.Gathering != null) try { e.Resource = await e.Gathering; } catch { }
            if (e.Preparing != null) try { await (await e.Preparing).DisposeAsync(); } catch { }
            if (e.Activating != null) try { await e.Activating; } catch { }
            try { if (e.Actor != null) await e.Actor.DisposeAsync(); }
            finally { if (e.Resource != null) await e.Resource.DisposeAsync(); }
        } finally { e.Stop.Dispose(); }
    }
    void ObserveCleanup(Entry e) { try { e.Closing!.GetAwaiter().GetResult(); } catch (Exception ex) { log("打洞资源清理：" + ex.Message); } }
    public async ValueTask DisposeAsync()
    {
        disposed = true;
        if (sending != null) try { await sending; } catch { }
        foreach (var e in entries.Values) { if (e.Closing == null) e.Closing = Close(e); try { await e.Closing; } catch (Exception ex) { log("打洞资源清理：" + ex.Message); } }
    }
}
