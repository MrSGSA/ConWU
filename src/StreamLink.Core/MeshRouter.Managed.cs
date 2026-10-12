using System.Diagnostics;
using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;

namespace StreamLink.Core;

public sealed partial class MeshRouter
{
    sealed class ManagedPeer
    {
        public readonly Dictionary<Guid, ManagedPath> Paths = [];
        public ManagedPath? Active, Candidate;
        public long LastRevision;
        public PathDiagnosticSession? Diagnostic;
        public long NextDiagnostic;
        public Guid DiagnosticAttempt;
        public ManagedPath? DiagnosticActive, DiagnosticStandby;
        public Guid DiagnosticLocalEpoch;
        public Guid? DiagnosticPeerEpoch;
        public PathQualityAssessment? Quality;
        public PathQualityAgreement? Agreement;
        public long NextQualitySelection;
    }
    sealed class ManagedPath(IMeshDatagramPath transport, ValidatedPathIdentity identity, PathNomination nomination, CancellationToken stop)
    {
        public readonly IMeshDatagramPath Transport = transport;
        public readonly ValidatedPathIdentity Identity = identity;
        public readonly PathNomination Nomination = nomination;
        public readonly PathTrafficObservation Traffic = new(identity);
        public PathDeliveryFeedback? Delivery;
        public readonly TraversalControlRound Budget = transport is ITraversalControlledPath controlled ? controlled.ControlRound : new(TraversalResources.Shared);
        public readonly CancellationTokenSource Stop = CancellationTokenSource.CreateLinkedTokenSource(stop);
        public ManagedPath? Previous;
        public bool Switched, Closing, Retired, PumpFinished;
        public long LastReceive, LastHello, LastPing, ProofAt, ReceiveUntil = long.MaxValue, ReleaseAt = long.MaxValue, CancelledAt;
        public long LastRoundTrip;
        public double? RttMs;
        public long StandbyAt;
        public int DiagnosticMbps;
        public bool AutoQuality;
        public int DiagnosticTiming;
        public TraversalAttemptContext? Context;
        // A pong on another candidate must not refresh this path. Entries are
        // random, path-local and bounded, not inferred from any inbound traffic.
        public readonly Dictionary<long, (long Sent, bool Activity,int BaselineLeg)> PendingRoundTrips = [];
        public int ControlPackets => Budget.Packets;
        public int ControlBytes => Budget.Bytes;
        public string Failure = "";
    }
    readonly HashSet<Task> managedPumps = [];

    // A negotiated peer is managed exclusively by resource identity. Legacy
    // loopback endpoints must first be represented as owned path references;
    // silently mixing the two lifetimes would let the old manager close Active.
    // On exception ownership stays with the caller; on success it moves here.
    public void RegisterPath(int slot, IMeshDatagramPath transport, TraversalAttemptContext context,
        long nominationRevision, TimeSpan remaining, int negotiatedControlVersion, int negotiatedQualityFeedbackVersion = 0, int negotiatedStandbyVersion = 0,int negotiatedDiagnosticMbps=0,int negotiatedAutoQualityVersion=0,int negotiatedDiagnosticTiming=0)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            if (!peers.TryGetValue(slot, out var peer)) throw new IOException("成员不在当前授权列表");
            var original = transport.Identity;
            var identity = original with { ActualLocal = new IPEndPoint(IPAddress.Parse(original.ActualLocal.Address.ToString()), original.ActualLocal.Port),
                ActualRemote = new IPEndPoint(IPAddress.Parse(original.ActualRemote.Address.ToString()), original.ActualRemote.Port) };
            if (negotiatedControlVersion != 1 || negotiatedQualityFeedbackVersion is < 0 or > 1 || negotiatedStandbyVersion is < 0 or > 1 ||
                context.Standby && negotiatedStandbyVersion != 1 || context.NetworkId != profile.Pair.Network || context.LocalNodeId != profile.Self.Device ||
                context.RemoteNodeId != peer.Member.Device || context.LocalBootId != BootId || identity.AttemptId != context.AttemptId ||
                identity.Profile != context.Profile || identity.PathId == Guid.Empty || identity.LeaseId == Guid.Empty || identity.NetworkGeneration == Guid.Empty ||
                identity.ActualLocal.Port == 0 || identity.ActualRemote.Port == 0 || !Enum.IsDefined(identity.Qualification) || transport.Failed)
                throw new IOException("候选能力、成员身份或实际资源无效");
            if (peer.Managed == null && (peer.Active != null || peer.Candidate != null)) throw new IOException("旧路径尚未转交给受管资源所有者");
            var managed = peer.Managed ?? new();
            if (managed.Candidate != null || managed.Paths.Count >= 2) throw new IOException("等待上一候选及退役引用收敛");
            if (nominationRevision <= managed.LastRevision || managed.Paths.ContainsKey(identity.PathId)) throw new IOException("候选提名版本已过期");
            if (identity.Qualification < PathQualification.MtuQualified) throw new IOException("候选尚未通过实际包长验证");
            if (context.Standby) {
                if (managed.Active == null || !ManagedHealthy(peer) || !Selection.Allows(identity.Profile)) throw new IOException("备用资源需要健康Active与本机承载许可");
                if (identity.Profile == TraversalProfile.FakeTcpHttpSo && transport is not IWireControlPath { CountsWireControl: true }) throw new IOException("TCP 备用需要实际捕获计账");
            }
            else if (Selection.Reject(identity.Profile, managed.Active?.Identity.Profile, ManagedHealthy(peer)) is {} reason) throw new IOException(reason);
            if (identity.Profile != TraversalProfile.UdpDirect && peers.Values.Where(p => p.Managed != null).SelectMany(p => p.Managed!.Paths.Values).Any(p =>
                !p.Closing && p.Identity.Profile != TraversalProfile.UdpDirect && p.Identity.ActualLocal.Equals(identity.ActualLocal) && p.Identity.ActualRemote.Equals(identity.ActualRemote)))
                throw new IOException("同一 TCP 四元组已由另一握手或 Active 占用");
            var nomination = new PathNomination(context, identity.PathId, nominationRevision, remaining, identity.Qualification >= PathQualification.MtuQualified);
            if(negotiatedDiagnosticMbps is<0 or>50||negotiatedDiagnosticMbps>0&&(!context.Standby||transport is not IPathDiagnosticWire{SupportsDiagnosticWire:true}))
                throw new IOException("诊断目标未协商或实际路径不支持有界诊断");
            if (negotiatedAutoQualityVersion is < 0 or > 1 || negotiatedAutoQualityVersion == 1 &&
                (negotiatedDiagnosticMbps == 0 || Selection.Policy != PathPolicy.AutoQuality)) throw new IOException("自动质量选路尚未获得独立协商许可");
            var state = new ManagedPath(transport, identity, nomination, stop.Token);
            if(negotiatedDiagnosticTiming is<0 or>1||negotiatedDiagnosticTiming==1&&negotiatedDiagnosticMbps==0)throw new IOException("诊断空载时序未协商");
            state.DiagnosticTiming=negotiatedDiagnosticTiming;
            state.DiagnosticMbps=negotiatedDiagnosticMbps;state.Context=context;state.AutoQuality=negotiatedAutoQualityVersion==1;
            if (negotiatedQualityFeedbackVersion == 1) state.Delivery = new(context);
            peer.Managed = managed; managed.Paths.Add(identity.PathId, state); managed.Candidate = state; managed.LastRevision = nominationRevision;
            peer.Detail = "正在验证并协商直连路径";
            managedPumps.RemoveWhere(t => t.IsCompleted);
            managedPumps.Add(Task.Run(() => ReceiveManaged(peer, state)));
        }
    }
    public MeshPathStatus[] Paths(int slot)
    {
        lock (gate) return peers.TryGetValue(slot, out var peer) && peer.Managed is {} managed ? managed.Paths.Values.Select(p =>
            new MeshPathStatus(p.Identity.PathId, p.Identity.LeaseId, p.Identity.AttemptId, p.Identity.Profile, p.Nomination.Stage,
                p == managed.Active, p.Retired, p.ControlPackets, p.ControlBytes, p.Failure, RoundTripFresh(p), p.RttMs) {
                    WireControl = (p.Transport as IWireControlPath)?.WireControl,
                    SendQueue = (p.Transport as IMeshSendDiagnostics)?.SendQueue,
                    Traffic = p.Traffic.Snapshot(Environment.TickCount64), Delivery = p.Delivery?.Snapshot(), StandbyReady = p.Nomination.StandbyConfirmed && p.Nomination.Stage == NominationStage.Standby
                }).ToArray() : [];
    }
    public void CancelPath(int slot, Guid path)
    {
        lock (gate) if (peers.TryGetValue(slot, out var peer) && peer.Managed?.Paths.TryGetValue(path, out var state) == true) {
            state.Nomination.Cancel(); ReconcileManaged(peer, state, Environment.TickCount64);
        }
    }
    static bool ManagedHealthy(Peer peer) => peer.Link.Connected && peer.Managed?.Active is {} path &&
        (!path.AutoQuality || path.ProofAt != 0 && path.Nomination.PeerAdopted) &&
        !path.Closing && !path.Transport.Failed && path.LastReceive != 0 && Stopwatch.GetElapsedTime(path.LastReceive).TotalSeconds < 12 && RoundTripFresh(path);
    static bool RoundTripFresh(ManagedPath path) => path.LastRoundTrip != 0 && Stopwatch.GetElapsedTime(path.LastRoundTrip).TotalSeconds < 12;
    static bool SendManaged(byte[]? packet, ManagedPath? path) => packet != null && path != null && !path.Closing && !path.Transport.Failed && path.Transport.TrySend(packet);
    void ControlManaged(Peer peer, ManagedPath path, byte[] packet, bool completion)
    {
        if (path.Nomination.StandbyConfirmed) { if (AdmitMaintenance(path, packet.Length)) SendManaged(packet, path); return; }
        if (path.Transport is not IWireControlPath { CountsWireControl: true } && !path.Budget.TrySend(packet.Length, completion)) return;
        // Wire-aware native paths charge the actual IP frame at injection.
        // Other adapters retain their existing control-datagram accounting.
        SendManaged(packet, path);
    }
    static bool AdmitMaintenance(ManagedPath path, int bytes) => path.Transport is IWireControlPath { CountsWireControl: true }
        || TraversalResources.Shared.TrySend(bytes, maintenance: true);
    void NominationReplies(Peer peer, ManagedPath path, byte[][] replies)
    {
        bool wasCancelled = path.Nomination.Stage == NominationStage.Cancelled;
        ReconcileManaged(peer, path, Environment.TickCount64); // switch BEFORE Commit proves it
        // Replace a now-forbidden Commit, but preserve an existing cancellation
        // notice: Tick has already consumed its retransmission interval.
        if (!wasCancelled && path.Nomination.Stage == NominationStage.Cancelled) replies = path.Nomination.Tick();
        foreach (byte[] reply in replies) {
            byte[]? encoded = peer.Link.Control(reply);
            if (encoded != null) ControlManaged(peer, path, encoded, reply[4] >= 3);
        }
    }
    async Task ReceiveManaged(Peer peer, ManagedPath path)
    {
        try {
            while (!path.Stop.IsCancellationRequested) {
                var packet = await path.Transport.Receive(path.Stop.Token);
                lock (gate) {
                    if (path.Closing || !peers.TryGetValue(peer.Member.Slot, out var current) || !ReferenceEquals(current, peer)) break;
                    var message = peer.Link.Receive(packet.Span);
                    if (!message.Authenticated) { peer.Dropped++; continue; }
                    if (packet.Span[4] is >= 4 and <= 7)
                        path.Traffic.Epoch(false, new Guid(packet.Span.Slice(8, 16)), Environment.TickCount64);
                    if (message.Reply != null) {
                        if (ReferenceEquals(peer.Managed!.Candidate, path)) ControlManaged(peer, path, message.Reply, true);
                        else if (AdmitMaintenance(path, message.Reply.Length)) SendManaged(message.Reply, path);
                    }
                    if (packet.Span[4] != 1) path.LastReceive = Stopwatch.GetTimestamp();
                    if (message.PongToken is long nonce && path.PendingRoundTrips.Remove(nonce, out var probe) && Stopwatch.GetElapsedTime(probe.Sent).TotalSeconds < 12) {
                        path.LastRoundTrip = Stopwatch.GetTimestamp(); path.RttMs = Stopwatch.GetElapsedTime(probe.Sent, path.LastRoundTrip).TotalMilliseconds;
                        path.Traffic.RoundTrip(path.RttMs.Value, Environment.TickCount64, probe.Activity);
                        peer.Managed!.Diagnostic?.RoundTrip(path.Identity.PathId,path.RttMs.Value,probe.BaselineLeg);
                    }
                    if (ReferenceEquals(peer.Managed!.Active, path) && message.PongToken is long recoveryNonce)
                        peer.Recovery.Pong(recoveryNonce, Environment.TickCount64);
                    if(message.Diagnostic!=null)peer.Managed!.Diagnostic?.Data(path.Identity.PathId,message.Diagnostic);
                    if (message.Control != null && !QualityControl(peer,path,message.Control,Environment.TickCount64) && !DiagnosticControl(peer,path,message.Control,Environment.TickCount64) && !(ReferenceEquals(peer.Managed!.Active, path) && path.Nomination.PeerAdopted &&
                        path.Delivery?.Control(message.Control, new Guid(packet.Span.Slice(8, 16)), Environment.TickCount64) == true))
                        NominationReplies(peer, path, path.Nomination.Receive(path.Identity.PathId, message.Control));
                    if (message.Packet != null) {
                        bool allowed = ReferenceEquals(peer.Managed!.Active, path) && (!path.AutoQuality || path.ProofAt != 0 && path.Nomination.PeerAdopted) ||
                            path.Retired && Environment.TickCount64 <= path.ReceiveUntil;
                        if (allowed && MeshPackets.Accept(message.Packet, local, peer.Member.Slot) && adapter.Write(message.Packet)) {
                            peer.Received += message.Packet.Length;
                            path.Traffic.Receive(message.Packet.Length, Environment.TickCount64);
                            if (ReferenceEquals(peer.Managed!.Active, path)) path.Delivery?.Receive(new Guid(packet.Span.Slice(8, 16)),
                                BinaryPrimitives.ReadUInt64BigEndian(packet.Span[40..]), message.Packet.Length);
                            if (ReferenceEquals(peer.Managed!.Active, path) && path.ProofAt != 0) peer.Recovery.Business(Environment.TickCount64);
                        }
                        else peer.Dropped++;
                    }
                }
            }
        } catch (Exception ex) when (path.Stop.IsCancellationRequested && ex is OperationCanceledException or ObjectDisposedException) { }
        catch (Exception ex) {
            lock (gate) { path.Failure = "receive-" + ex.GetType().Name; path.Nomination.Cancel(); ReconcileManaged(peer, path, Environment.TickCount64); }
        } finally {
            try { await path.Transport.DisposeAsync(); }
            catch (Exception ex) { lock (gate) path.Failure = "release-" + ex.GetType().Name; }
            lock (gate) { path.PumpFinished = true; if (path.Closing) path.Stop.Dispose(); }
        }
    }
    void ReconcileManaged(Peer peer, ManagedPath path, long now)
    {
        var managed = peer.Managed!;
        if (path.Nomination.StandbyConfirmed && path.StandbyAt == 0) {
            try {
                if (path.Transport is IWireControlPath { CountsWireControl: true } wire) wire.HoldStandbyWireBudget();
                path.StandbyAt = now; path.LastRoundTrip = Stopwatch.GetTimestamp();
            } catch (InvalidOperationException) {
                // A delayed scheduler may miss the actual wire deadline even
                // when a queued authentication reply has just been decoded.
                // Fail this candidate, never the runner or unrelated Active.
                path.Failure = "standby-wire-deadline"; path.Nomination.Cancel();
            }
        }
        if (path.Nomination.Stage == NominationStage.Cancelled) {
            if (path.CancelledAt == 0) path.CancelledAt = now;
            if (ReferenceEquals(managed.Active, path)) {
                var previous = path.Previous;
                managed.Active = previous is { Closing: false } && !previous.Transport.Failed && previous.Nomination.Stage != NominationStage.Cancelled ? previous : null;
                if (managed.Active != null) {
                    managed.Active.Retired = false; managed.Active.ReceiveUntil = managed.Active.ReleaseAt = long.MaxValue;
                    managed.Active.Traffic.Start(now);
                    managed.Active.Delivery?.Reset();
                }
                path.Traffic.Suspend("Cancelled", now);
                path.Delivery?.Reset();
                path.Previous = null;
            }
            peer.Detail = path.Nomination.NeedsResync ? "候选提交未收敛，已回退并等待重新协商" : "候选取消或超时，保留原直连";
            return;
        }
        if (path.Nomination.SwitchRequested && !path.Switched && ReferenceEquals(managed.Candidate, path)) {
            // A formerly silent FakeTCP can recover while UDP is negotiating.
            // Recheck at the actual switch, not only at registration time.
            bool approved = QualityAuthorized(peer, path, now);
            string? reason = path.AutoQuality && !approved ? "质量批准已失效" : Selection.Reject(path.Identity.Profile, managed.Active?.Identity.Profile, ManagedHealthy(peer), approved);
            if (reason != null) {
                path.Failure = reason; path.Nomination.Cancel(); ReconcileManaged(peer, path, now); return;
            }
            path.Previous = managed.Active;
            if (path.Previous != null) { path.Previous.Retired = true; path.Previous.Traffic.Suspend("Replaced", now); path.Previous.Delivery?.Reset(); }
            managed.Active = path; path.Switched = true;
            if (approved) managed.NextQualitySelection = now + TraversalLimits.UpgradeCooldownMs;
        }
        if (path.Switched && path.Nomination.PeerAdopted && path.ProofAt == 0) {
            if (path.AutoQuality && !QualityAuthorized(peer,path,now)) {
                path.Failure = "共同提名完成前质量批准已失效"; path.Nomination.Cancel(); ReconcileManaged(peer,path,now); return;
            }
            if (path.Transport is IWireControlPath wire) wire.SelectWireBudget();
            path.ProofAt = now;
            if (path.AutoQuality && managed.Quality is {} selectedQuality)
                managed.Quality = selectedQuality with { Result = "QualitySelectedDiagnostic", Reason = "SelectedFromQualifiedComparison" };
            path.Traffic.Start(now);
            // The authenticated nomination itself proved a round trip on this
            // actual resource. Duplicate final messages cannot keep refreshing it.
            path.LastRoundTrip = Stopwatch.GetTimestamp();
            peer.Recovery.Select(path.Identity.PathId, now);
            peer.Recovery.Health(ManagedHealthy(peer), now);
            if (path.Previous != null) {
                path.Previous.ReceiveUntil = now + 2000;
                // Keep the resource (not business reception) long enough to
                // roll back if CommitAck/cancellation reconciliation fails.
                path.Previous.ReleaseAt = Math.Max(now + 2000, now + (long)Math.Ceiling(path.Nomination.TimeLeft.TotalMilliseconds) + 2000);
            }
            else if (ReferenceEquals(managed.Candidate, path)) managed.Candidate = null;
        }
    }
    void TickManaged(Peer peer, long now)
    {
        var managed = peer.Managed!;
        foreach (var path in managed.Paths.Values.ToArray()) {
            if (path.Closing) continue;
            if (ReferenceEquals(managed.Active, path)) path.Traffic.Tick(now);
            if (path.Transport.Failed) { path.Failure = "transport-exited"; path.Nomination.Cancel(); }
            if (ReferenceEquals(managed.Candidate, path)) {
                NominationReplies(peer, path, path.Nomination.Tick());
                if (!peer.Link.Connected && now - path.LastHello >= 500 && path.Nomination.TimeLeft > TimeSpan.Zero) {
                    path.LastHello = now; ControlManaged(peer, path, peer.Link.Hello(), false);
                }
                if (path.Nomination.PeerAdopted && (path.Previous == null || path.Nomination.TimeLeft <= TimeSpan.FromSeconds(-2))) managed.Candidate = null;
            }
            ReconcileManaged(peer, path, now);
            if (path.CancelledAt != 0 && now - path.CancelledAt >= 1000 || path.Retired && now >= path.ReleaseAt) {
                RetireManaged(managed, path); continue;
            }
            if ((ReferenceEquals(managed.Active, path) || path.Nomination.StandbyConfirmed && path.Nomination.Stage == NominationStage.Standby) && now - path.LastPing >= 1500) {
                path.LastPing = now;
                long nonce = BitConverter.ToInt64(RandomNumberGenerator.GetBytes(8));
                byte[]? ping = peer.Link.ProbePath(nonce);
                if (ping != null && AdmitMaintenance(path, ping.Length) && SendManaged(ping, path)) {
                    if (path.PendingRoundTrips.Count >= 8) path.PendingRoundTrips.Remove(path.PendingRoundTrips.MinBy(p => p.Value.Sent).Key);
                    path.PendingRoundTrips[nonce] = (Stopwatch.GetTimestamp(), path.Traffic.RecentlyBusy(now),-1);
                    if (path.ProofAt != 0) peer.Recovery.KeepaliveSent(nonce, now);
                }
            }
            if (ReferenceEquals(managed.Active, path) && path.Nomination.PeerAdopted && ManagedHealthy(peer))
                path.Delivery?.Tick(now, body => SendFeedback(peer, path, body, now));
        }
        TickDiagnostic(peer,now);
        TickQuality(peer,now);
    }
    static void RetireManaged(ManagedPeer peer, ManagedPath path)
    {
        if (path.Closing) return;
        path.Traffic.Suspend("Retired", Environment.TickCount64);
        path.Delivery?.Reset();
        path.Closing = true; path.Stop.Cancel(); peer.Paths.Remove(path.Identity.PathId);
        if (path.PumpFinished) path.Stop.Dispose();
        if (ReferenceEquals(peer.Active, path)) peer.Active = null;
        if (ReferenceEquals(peer.Candidate, path)) peer.Candidate = null;
        foreach (var other in peer.Paths.Values) if (ReferenceEquals(other.Previous, path)) other.Previous = null;
        // Cancellation source remains alive until the receive pump has unwound.
    }
    static void CloseManaged(Peer peer)
    {
        peer.Managed?.Diagnostic?.Dispose();
        if (peer.Managed is {} managed) foreach (var path in managed.Paths.Values.ToArray()) RetireManaged(managed, path);
    }
}
