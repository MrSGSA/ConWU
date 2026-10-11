using System.Diagnostics;
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
    }
    sealed class ManagedPath(IMeshDatagramPath transport, ValidatedPathIdentity identity, PathNomination nomination, CancellationToken stop)
    {
        public readonly IMeshDatagramPath Transport = transport;
        public readonly ValidatedPathIdentity Identity = identity;
        public readonly PathNomination Nomination = nomination;
        public readonly TraversalControlRound Budget = transport is ITraversalControlledPath controlled ? controlled.ControlRound : new(TraversalResources.Shared);
        public readonly CancellationTokenSource Stop = CancellationTokenSource.CreateLinkedTokenSource(stop);
        public ManagedPath? Previous;
        public bool Switched, Closing, Retired, PumpFinished;
        public long LastReceive, LastHello, LastPing, ProofAt, ReceiveUntil = long.MaxValue, ReleaseAt = long.MaxValue, CancelledAt;
        public long LastRoundTrip;
        public double? RttMs;
        // A pong on another candidate must not refresh this path. Entries are
        // random, path-local and bounded, not inferred from any inbound traffic.
        public readonly Dictionary<long, long> PendingRoundTrips = [];
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
        long nominationRevision, TimeSpan remaining, int negotiatedControlVersion, PathPolicy policy = PathPolicy.PreferFakeTcp)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            if (!peers.TryGetValue(slot, out var peer)) throw new IOException("成员不在当前授权列表");
            var original = transport.Identity;
            var identity = original with { ActualLocal = new IPEndPoint(IPAddress.Parse(original.ActualLocal.Address.ToString()), original.ActualLocal.Port),
                ActualRemote = new IPEndPoint(IPAddress.Parse(original.ActualRemote.Address.ToString()), original.ActualRemote.Port) };
            if (negotiatedControlVersion != 1 || context.NetworkId != profile.Pair.Network || context.LocalNodeId != profile.Self.Device ||
                context.RemoteNodeId != peer.Member.Device || context.LocalBootId != BootId || identity.AttemptId != context.AttemptId ||
                identity.Profile != context.Profile || identity.PathId == Guid.Empty || identity.LeaseId == Guid.Empty || identity.NetworkGeneration == Guid.Empty ||
                identity.ActualLocal.Port == 0 || identity.ActualRemote.Port == 0 || !Enum.IsDefined(identity.Qualification) || transport.Failed)
                throw new IOException("候选能力、成员身份或实际资源无效");
            if (peer.Managed == null && (peer.Active != null || peer.Candidate != null)) throw new IOException("旧路径尚未转交给受管资源所有者");
            var managed = peer.Managed ?? new();
            if (managed.Candidate != null || managed.Paths.Count >= 2) throw new IOException("等待上一候选及退役引用收敛");
            if (nominationRevision <= managed.LastRevision || managed.Paths.ContainsKey(identity.PathId)) throw new IOException("候选提名版本已过期");
            if (identity.Profile == TraversalProfile.UdpDirect && (policy == PathPolicy.FakeTcpOnly ||
                policy == PathPolicy.PreferFakeTcp && ManagedHealthy(peer) && managed.Active!.Identity.Profile != TraversalProfile.UdpDirect))
                throw new IOException("当前策略保留健康 FakeTCP 路径");
            if (identity.Profile != TraversalProfile.UdpDirect && peers.Values.Where(p => p.Managed != null).SelectMany(p => p.Managed!.Paths.Values).Any(p =>
                !p.Closing && p.Identity.Profile != TraversalProfile.UdpDirect && p.Identity.ActualLocal.Equals(identity.ActualLocal) && p.Identity.ActualRemote.Equals(identity.ActualRemote)))
                throw new IOException("同一 TCP 四元组已由另一握手或 Active 占用");
            var nomination = new PathNomination(context, identity.PathId, nominationRevision, remaining, identity.Qualification >= PathQualification.MtuQualified);
            var state = new ManagedPath(transport, identity, nomination, stop.Token);
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
                p == managed.Active, p.Retired, p.ControlPackets, p.ControlBytes, p.Failure, RoundTripFresh(p), p.RttMs)).ToArray() : [];
    }
    public void CancelPath(int slot, Guid path)
    {
        lock (gate) if (peers.TryGetValue(slot, out var peer) && peer.Managed?.Paths.TryGetValue(path, out var state) == true) {
            state.Nomination.Cancel(); ReconcileManaged(peer, state, Environment.TickCount64);
        }
    }
    static bool ManagedHealthy(Peer peer) => peer.Link.Connected && peer.Managed?.Active is {} path &&
        !path.Closing && !path.Transport.Failed && path.LastReceive != 0 && Stopwatch.GetElapsedTime(path.LastReceive).TotalSeconds < 12 && RoundTripFresh(path);
    static bool RoundTripFresh(ManagedPath path) => path.LastRoundTrip != 0 && Stopwatch.GetElapsedTime(path.LastRoundTrip).TotalSeconds < 12;
    static bool SendManaged(byte[]? packet, ManagedPath? path) => packet != null && path != null && !path.Closing && !path.Transport.Failed && path.Transport.TrySend(packet);
    void ControlManaged(Peer peer, ManagedPath path, byte[] packet, bool completion)
    {
        if (!path.Budget.TrySend(packet.Length, completion)) return;
        // Counts every admitted control send, including an enqueue failure; not
        // an account of native SYNs/kernel ACKs, which remain to be integrated.
        SendManaged(packet, path);
    }
    void NominationReplies(Peer peer, ManagedPath path, byte[][] replies)
    {
        ReconcileManaged(peer, path, Environment.TickCount64); // switch BEFORE Commit proves it
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
                    if (message.Reply != null) {
                        if (ReferenceEquals(peer.Managed!.Candidate, path)) ControlManaged(peer, path, message.Reply, true);
                        else if (TraversalResources.Shared.TrySend(message.Reply.Length, maintenance: true)) SendManaged(message.Reply, path);
                    }
                    if (packet.Span[4] != 1) path.LastReceive = Stopwatch.GetTimestamp();
                    if (message.PongToken is long nonce && path.PendingRoundTrips.Remove(nonce, out long sent) && Stopwatch.GetElapsedTime(sent).TotalSeconds < 12) {
                        path.LastRoundTrip = Stopwatch.GetTimestamp(); path.RttMs = Stopwatch.GetElapsedTime(sent, path.LastRoundTrip).TotalMilliseconds;
                    }
                    if (message.Control != null) NominationReplies(peer, path, path.Nomination.Receive(path.Identity.PathId, message.Control));
                    if (message.Packet != null) {
                        bool allowed = ReferenceEquals(peer.Managed!.Active, path) || path.Retired && Environment.TickCount64 <= path.ReceiveUntil;
                        if (allowed && MeshPackets.Accept(message.Packet, local, peer.Member.Slot) && adapter.Write(message.Packet)) peer.Received += message.Packet.Length;
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
        if (path.Nomination.Stage == NominationStage.Cancelled) {
            if (path.CancelledAt == 0) path.CancelledAt = now;
            if (ReferenceEquals(managed.Active, path)) {
                var previous = path.Previous;
                managed.Active = previous is { Closing: false } && !previous.Transport.Failed && previous.Nomination.Stage != NominationStage.Cancelled ? previous : null;
                if (managed.Active != null) { managed.Active.Retired = false; managed.Active.ReceiveUntil = managed.Active.ReleaseAt = long.MaxValue; }
                path.Previous = null;
            }
            peer.Detail = path.Nomination.NeedsResync ? "候选提交未收敛，已回退并等待重新协商" : "候选取消或超时，保留原直连";
            return;
        }
        if (path.Nomination.SwitchRequested && !path.Switched && ReferenceEquals(managed.Candidate, path)) {
            path.Previous = managed.Active;
            if (path.Previous != null) path.Previous.Retired = true;
            managed.Active = path; path.Switched = true;
        }
        if (path.Switched && path.Nomination.PeerAdopted && path.ProofAt == 0) {
            path.ProofAt = now;
            // The authenticated nomination itself proved a round trip on this
            // actual resource. Duplicate final messages cannot keep refreshing it.
            path.LastRoundTrip = Stopwatch.GetTimestamp();
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
            if (ReferenceEquals(managed.Active, path) && now - path.LastPing >= 1500) {
                path.LastPing = now;
                long nonce = BitConverter.ToInt64(RandomNumberGenerator.GetBytes(8));
                byte[]? ping = peer.Link.ProbePath(nonce);
                if (ping != null && TraversalResources.Shared.TrySend(ping.Length, maintenance: true) && SendManaged(ping, path)) {
                    if (path.PendingRoundTrips.Count >= 8) path.PendingRoundTrips.Remove(path.PendingRoundTrips.MinBy(p => p.Value).Key);
                    path.PendingRoundTrips[nonce] = Stopwatch.GetTimestamp();
                }
            }
        }
    }
    static void RetireManaged(ManagedPeer peer, ManagedPath path)
    {
        if (path.Closing) return;
        path.Closing = true; path.Stop.Cancel(); peer.Paths.Remove(path.Identity.PathId);
        if (path.PumpFinished) path.Stop.Dispose();
        if (ReferenceEquals(peer.Active, path)) peer.Active = null;
        if (ReferenceEquals(peer.Candidate, path)) peer.Candidate = null;
        foreach (var other in peer.Paths.Values) if (ReferenceEquals(other.Previous, path)) other.Previous = null;
        // Cancellation source remains alive until the receive pump has unwound.
    }
    static void CloseManaged(Peer peer)
    {
        if (peer.Managed is {} managed) foreach (var path in managed.Paths.Values.ToArray()) RetireManaged(managed, path);
    }
}
