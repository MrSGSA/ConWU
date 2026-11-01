using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Buffers.Binary;

namespace StreamLink.Core;

public sealed record MeshPeerStatus(int Slot, string Ip, string Name, bool Connected, double? RttMs, string Detail, long SentBytes = 0, long ReceivedBytes = 0, long DroppedPackets = 0)
{
    public PeerLiveness? Liveness { get; init; }
    public ConnectionProgress? Connection { get; init; }
    public bool Degraded { get; init; }
    public string TraversalMethod { get; init; } = "None";
    public string ActualTransport { get; init; } = "None";
    public PathRecoverySnapshot? Recovery { get; init; }
    public DatagramQueueStats? SendQueue { get; init; }
    public PathTrafficSnapshot? Traffic { get; init; }
    public PathDeliverySnapshot? Delivery { get; init; }
    public MeshStandbyStatus? Standby { get; init; }
    public PathDiagnosticSessionStatus? Diagnostics{get;init;}
    public PathQualityAssessment? Quality { get; init; }
    public string OuterSource {get;init;}="Unknown";
    public string OuterTarget {get;init;}="Unknown";
    public NativePathDiagnostics? NativeEvidence {get;init;}
    public RouterPeerDrops? LocalDrops { get; init; }
}

// One adapter and one local UDP socket per node. The authenticated source slot
// selects a peer; a member can only deliver packets to this node's own address.
// There is deliberately no route for forwarding another member's packets.
public sealed partial class MeshRouter : IAsyncDisposable
{
    sealed class Peer(MeshMember member, MeshLink link)
    {
        public readonly MeshMember Member = member;
        public byte Host;
        public readonly MeshLink Link = link;
        public IPEndPoint? Candidate, Active;
        public long ActiveReceived, ActiveRoundTrip;
        public readonly Dictionary<long, long> ActivePings = [];
        public KeepaliveObservation LegacyKeepalive = new();
        public readonly Dictionary<IPEndPoint, (long Token, long At, long Sent)> Probes = [];
        public readonly Queue<IPEndPoint> Retired = [];
        public string Name = "", Detail = "等待对端上线";
        public long Sent, Received, Dropped;
        public long NoHealthyPathDrops, SendRejectedDrops, AuthenticationDrops, ReceivePolicyDrops, AdapterWriteDrops;
        public ManagedPeer? Managed;
        public readonly PathRecovery Recovery = new(Environment.TickCount64);
        public Guid LegacyPathId;
        public long NextLegacyControl;
        public bool LegacyTransportFailed;
        public readonly Dictionary<IPEndPoint, bool> NativeControlSources = [];
        public readonly HashSet<IPEndPoint> LegacyListenerSources = [];
        public readonly HashSet<IPEndPoint> CancelledCandidates = [];
        public readonly Queue<IPEndPoint> CancelledOrder = [];
    }
    readonly object gate = new();
    bool legacyListenerControlsWire;
    public void SetLegacyListenerControl(bool controlsWire) { lock (gate) legacyListenerControlsWire = controlsWire; }
    readonly MeshProfile profile;
    readonly IPacketAdapter adapter;
    readonly byte[] local;
    readonly Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    readonly Dictionary<int, Peer> peers = [];
    readonly Dictionary<int, Peer> peersByHost = [];
    readonly CancellationTokenSource stop = new();
    readonly Task transmit, receive, heartbeat;
    int disposed;
    public IPEndPoint LocalEndpoint => (IPEndPoint)socket.LocalEndPoint!;
    public Task Completion { get; }
    public Guid BootId { get; }
    public PathSelection Selection { get; }
    public bool LegacyAllowed => Selection.Allows(profile.Pair.Mode=="udp"?TraversalProfile.UdpDirect:TraversalProfile.FakeTcpHttpSo);
    public MeshRouter(MeshProfile profile, IPacketAdapter adapter, Guid? bootId = null, PathSelection? selection = null)
    {
        Selection = selection ?? new();
        this.profile = profile; this.adapter = adapter;
        try {
            ArgumentNullException.ThrowIfNull(profile);
            if(selection==null) Selection=new(profile.Pair.Mode=="udp"?PathPolicy.UdpOnly:PathPolicy.FakeTcpOnly);
            ArgumentNullException.ThrowIfNull(adapter);
            if (bootId == Guid.Empty) throw new ArgumentException("Router 启动代次无效", nameof(bootId));
            Selection.Validate();
            BootId = bootId ?? Guid.NewGuid();
            local = IPAddress.Parse(profile.LocalIp).GetAddressBytes();
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0)); socket.SendBufferSize = socket.ReceiveBufferSize = 1 << 20;
            // Synchronous sends run under the peer-state guard. A full local UDP
            // buffer must reject one datagram, never hold every peer's heartbeat.
            socket.Blocking = false;
            if (profile.Directory != null) ApplyDirectory(profile.Directory);
        } catch {
            // No pump has started. Failed construction never takes the
            // caller's adapter, but must release its own socket/session keys.
            try { foreach (var peer in peers.Values) peer.Link.Dispose(); }
            finally { socket.Dispose(); stop.Dispose(); }
            throw;
        }
        transmit = Task.Factory.StartNew(Transmit, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        receive = Task.Run(Receive);
        heartbeat = Task.Factory.StartNew(Heartbeat, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        Completion = Watch();
    }
    async Task Watch()
    {
        Task first = await Task.WhenAny(transmit, receive, heartbeat);
        if (!stop.IsCancellationRequested) { stop.Cancel(); await first; throw new IOException("原生数据泵已意外停止"); }
    }
    public void ApplyDirectory(MeshDirectory directory)
    {
        MeshIdentity.ValidateDirectory(directory, profile.Pair.Network, profile.OwnerKey, profile.Directory?.Revision ?? 0);
        if (!directory.Members.Contains(profile.Self)) throw new MeshRevokedException();
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            foreach (int slot in peers.Keys.Where(s => !directory.Members.Contains(peers[s].Member)).ToArray()) { CloseManaged(peers[slot]); peers[slot].Link.Dispose(); peers.Remove(slot); }
            foreach (var member in directory.Members.Where(m => m.Slot != profile.Self.Slot)) {
                if (peers.ContainsKey(member.Slot)) continue;
                byte[] shared = MeshIdentity.SharedKey(profile, member);
                try { peers.Add(member.Slot, new(member, new(profile.Self.Slot, member.Slot, shared)) {Host=IPAddress.Parse(MeshAddressing.Address(profile.Pair.Network,member)).GetAddressBytes()[3]}); } finally { CryptographicOperations.ZeroMemory(shared); }
            }
            profile.Directory = directory;
            peersByHost.Clear();foreach(var peer in peers.Values)peersByHost.Add(peer.Host,peer);
        }
    }
    public void SetCandidate(int slot, IPEndPoint? candidate, string name, string detail)
        => SetCandidate(slot, candidate, name, detail, false);
    public void SetCandidate(int slot, IPEndPoint? candidate, string name, string detail, bool nativeControlsWire)
    {
        if(!LegacyAllowed && candidate != null) throw new InvalidOperationException("兼容入口协议不符合所选传输模式");
        if (candidate != null && !IPAddress.IsLoopback(candidate.Address)) throw new ArgumentException("数据接口仅允许本机 udp2raw");
        lock (gate) if (peers.TryGetValue(slot, out var peer)) {
            if (peer.Managed != null) return; // negotiated paths cannot fall back to legacy auto-promotion
            bool changed = !Equals(peer.Candidate, candidate);
            if (changed && candidate != null && peer.CancelledCandidates.Remove(candidate)) {
                var kept = peer.CancelledOrder.Where(e => !e.Equals(candidate)).ToArray();
                peer.CancelledOrder.Clear(); foreach (var endpoint in kept) peer.CancelledOrder.Enqueue(endpoint);
            }
            peer.Candidate = candidate; peer.Name = name; peer.Detail = detail;
            if (candidate != null) { peer.NativeControlSources[candidate] = nativeControlsWire;peer.LegacyListenerSources.Remove(candidate); }
            foreach (var source in peer.NativeControlSources.Keys.Where(source => !Equals(source, peer.Active) && !Equals(source, peer.Candidate) && !peer.Retired.Contains(source)).ToArray())
                {peer.NativeControlSources.Remove(source);peer.LegacyListenerSources.Remove(source);}
            if (changed && candidate != null && !candidate.Equals(peer.Active)) {
                peer.Probes.Remove(candidate); peer.NextLegacyControl = 0;
            }
        }
    }
    static bool Healthy(Peer peer) => peer.Managed != null ? ManagedHealthy(peer) : peer.Link.Connected && peer.Active != null &&
        Fresh(peer.ActiveReceived) && Fresh(peer.ActiveRoundTrip);
    static bool Fresh(long timestamp) => timestamp != 0 && Stopwatch.GetElapsedTime(timestamp).TotalSeconds < 12;
    static long? Age(long timestamp) => timestamp == 0 ? null : (long)Stopwatch.GetElapsedTime(timestamp).TotalMilliseconds;
    static PeerLiveness Liveness(Peer peer)
    {
        var path = peer.Managed?.Active;
        long received = peer.Managed == null ? peer.ActiveReceived : path?.LastReceive ?? 0;
        long roundTrip = peer.Managed == null ? peer.ActiveRoundTrip : path?.LastRoundTrip ?? 0;
        string reason = Healthy(peer) ? "Healthy" : peer.Managed == null && peer.LegacyTransportFailed ? "TransportExited" : peer.Managed == null && peer.Active == null || peer.Managed != null && path == null ? "WaitingForPath" :
            path?.Transport.Failed == true ? "TransportExited" : !Fresh(received) ? "ReceiveTimedOut" :
            !Fresh(roundTrip) ? "ReturnPathTimedOut" : "SessionNotReady";
        return new(reason, Age(received), Age(roundTrip)) {
            Keepalive = path != null ? KeepaliveStatus(path) : peer.Managed == null && peer.Active != null
                ? peer.LegacyKeepalive.Snapshot(peer.LegacyPathId, peer.ActivePings.Count, budgetMeasured: false) : null
        };
    }
    public bool HasHealthyPath(int slot) { lock (gate) return peers.TryGetValue(slot, out var peer) && Healthy(peer); }
    public bool UsesPath(int slot, IPEndPoint? endpoint)
    {
        lock (gate) return endpoint != null && peers.TryGetValue(slot, out var peer) && peer.Managed == null && Healthy(peer) && endpoint.Equals(peer.Active);
    }
    public void CancelLegacyCandidate(int slot, IPEndPoint? endpoint)
    {
        lock (gate) if (endpoint != null && peers.TryGetValue(slot, out var peer) && peer.Managed == null && !endpoint.Equals(peer.Active)) {
            peer.Probes.Remove(endpoint); peer.NativeControlSources.Remove(endpoint);peer.LegacyListenerSources.Remove(endpoint);
            if (peer.CancelledCandidates.Add(endpoint)) peer.CancelledOrder.Enqueue(endpoint);
            while (peer.CancelledOrder.Count > 32) peer.CancelledCandidates.Remove(peer.CancelledOrder.Dequeue());
            if (endpoint.Equals(peer.Candidate)) peer.Candidate = peer.Active;
        }
    }
    // Only a confirmed owner failure may revoke a still-fresh proof. Match the
    // exact local endpoint so retiring another candidate cannot break Active.
    public void FailLegacyTransport(int slot,IPEndPoint? endpoint)
    {
        lock(gate)if(endpoint!=null&&peers.TryGetValue(slot,out var peer)&&peer.Managed==null){
            if(endpoint.Equals(peer.Active)){
                peer.Active=null;peer.ActiveReceived=peer.ActiveRoundTrip=0;peer.ActivePings.Clear();
                peer.LegacyTransportFailed=true;peer.NextLegacyControl=0;
                peer.Recovery.Break("TransportExited",Environment.TickCount64);
            }
            CancelLegacyCandidate(slot,endpoint);
        }
    }
    public void FailLegacyListener()
    {
        lock(gate){
            legacyListenerControlsWire=false;
            foreach(var peer in peers.Values.Where(p=>p.Managed==null))
                foreach(var endpoint in peer.LegacyListenerSources.ToArray())FailLegacyTransport(peer.Member.Slot,endpoint);
        }
    }
    void Challenge(Peer peer, IPEndPoint endpoint)
    {
        if (endpoint.Equals(peer.Active)) return;
        bool found = peer.Probes.TryGetValue(endpoint, out var probe);
        if (found && Stopwatch.GetElapsedTime(probe.Sent).TotalSeconds < 1) return;
        if (!peer.Probes.ContainsKey(endpoint) && peer.Probes.Count >= 4) peer.Probes.Remove(peer.Probes.MinBy(p => p.Value.At).Key);
        long now = Stopwatch.GetTimestamp();
        bool reuse = found && Stopwatch.GetElapsedTime(probe.At).TotalSeconds < 5;
        long nonce = reuse ? probe.Token : BitConverter.ToInt64(RandomNumberGenerator.GetBytes(8));
        byte[]? frame = peer.Link.ProbePath(nonce);
        if (frame != null && SendLegacyControl(peer, frame, endpoint)) peer.Probes[endpoint] = (nonce, reuse ? probe.At : now, now);
    }
    public MeshPeerStatus[] Status()
    {
        lock (gate) return peers.Values.OrderBy(p => p.Member.Slot).Select(p => {
            bool healthy = Healthy(p), udp = p.Managed?.Active?.Identity.Profile == TraversalProfile.UdpDirect || p.Managed == null && profile.Pair.Mode == "udp";
            bool degraded = healthy && udp && Selection.Policy != PathPolicy.UdpOnly;
            return new MeshPeerStatus(p.Member.Slot, MeshAddressing.Address(profile.Pair.Network, p.Member), p.Name.Length > 0 ? p.Name : $"设备 {p.Member.Slot}", healthy,
                p.Managed != null ? p.Managed.Active?.RttMs : p.Link.RttMs, healthy ? udp ? "UDP 直连 · 目标负载质量单独评估" : "P2P 直连" : p.Detail,
                p.Sent, p.Received, p.Dropped) { Degraded = degraded, Liveness = Liveness(p),
                    TraversalMethod = !healthy ? "None" : p.Managed?.Active?.Identity.Profile switch {
                        TraversalProfile.FakeTcpHttpSo => OperatingSystem.IsWindows() && p.Managed?.Active?.Transport is NativeDatagramPath {Diagnostics.PeerSource.Learned:true} ? "FakeTCP-SO+source-learning" : "FakeTCP-SO",
                        TraversalProfile.UdpDirect => "UDP-same-socket", _ => "ExplicitEntry" },
                    ActualTransport = !healthy ? "None" : udp ? "UDP_DIRECT" : "FakeTCP+HTTP",
                    OuterSource=p.Managed?.Active?.Identity.ActualLocal.ToString()??"Unknown",
                    OuterTarget=p.Managed?.Active?.Identity.ActualRemote.ToString()??"Unknown",
                    NativeEvidence=OperatingSystem.IsWindows()?(p.Managed?.Active?.Transport as NativeDatagramPath)?.Diagnostics:null,
                    LocalDrops = new(p.NoHealthyPathDrops, p.SendRejectedDrops, p.AuthenticationDrops, p.ReceivePolicyDrops, p.AdapterWriteDrops),
                    Recovery = p.Recovery.Snapshot(Environment.TickCount64),
                    SendQueue = (p.Managed?.Active?.Transport as IMeshSendDiagnostics)?.SendQueue,
                    Traffic = p.Managed?.Active?.Traffic.Snapshot(Environment.TickCount64),
                    Delivery = p.Managed?.Active?.Delivery?.Snapshot(), Standby = StandbyStatus(p),Diagnostics=p.Managed?.Diagnostic?.Status(),Quality=p.Managed?.Quality };
        }).ToArray();
    }
    bool Send(byte[]? packet, IPEndPoint? endpoint)
    {
        if (packet == null || endpoint == null) return false;
        try { return socket.SendTo(packet, endpoint) == packet.Length; }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.WouldBlock or SocketError.NoBufferSpaceAvailable or SocketError.TimedOut or SocketError.ConnectionReset or SocketError.ConnectionRefused) { Interlocked.Increment(ref legacySendRejected); return false; }
    }
    bool SendLegacyControl(Peer peer, byte[]? packet, IPEndPoint? endpoint, bool maintenance = false)
        => LegacyAllowed && packet != null && endpoint != null && (peer.NativeControlSources.GetValueOrDefault(endpoint) ||
            !peer.NativeControlSources.ContainsKey(endpoint) && legacyListenerControlsWire ||
            TraversalResources.Shared.TrySend(packet.Length, maintenance)) && Send(packet, endpoint);
    void Transmit()
    {
        var buffer = new byte[MeshLink.Mtu];
        while (!stop.IsCancellationRequested) {
            int count = adapter.Read(buffer,stop.Token); if (count == 0) continue;
            var packet = buffer.AsSpan(0, count); int slot = MeshPackets.Destination(packet, local); if (slot == 0) continue;
            lock (gate) if (peersByHost.TryGetValue(slot,out var peer)) {
                byte[]? encoded = Healthy(peer) ? peer.Link.Data(packet) : null;
                if (encoded != null) peer.Managed?.Active?.Traffic.Epoch(true, new Guid(encoded.AsSpan(8, 16)), Environment.TickCount64);
                bool delivered = encoded != null && (peer.Managed != null ? SendManaged(encoded, peer.Managed.Active) : LegacyAllowed && Send(encoded, peer.Active));
                peer.Managed?.Active?.Traffic.Send(count, delivered, Environment.TickCount64);
                if (delivered && encoded != null) peer.Managed?.Active?.Delivery?.Send(new Guid(encoded.AsSpan(8, 16)),
                    BinaryPrimitives.ReadUInt64BigEndian(encoded.AsSpan(40)), count, Environment.TickCount64);
                if (delivered) peer.Sent += count;
                else {
                    peer.Dropped++;
                    if (encoded == null) peer.NoHealthyPathDrops++; else peer.SendRejectedDrops++;
                    peer.Recovery.Break("BusinessSendRejected", Environment.TickCount64);
                }
            }
        }
    }
    async Task Receive()
    {
        var buffer = new byte[2048];
        int batch = 0;
        while (!stop.IsCancellationRequested) {
            // ReceiveFromAsync can complete synchronously for an entire flood.
            // Bound each turn, including rejected frames, so other peers run.
            if (++batch > ReceiveBatch) { batch = 1; Interlocked.Increment(ref receiveYields); await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding); }
            SocketReceiveFromResult received;
            try { received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), stop.Token); }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize) { continue; }
            if (received.ReceivedBytes < MeshLink.Overhead || !IPAddress.IsLoopback(((IPEndPoint)received.RemoteEndPoint).Address)) continue;
            lock (gate) if (peers.TryGetValue(buffer[5], out var peer)) {
                if (!LegacyAllowed) { peer.Dropped++; peer.ReceivePolicyDrops++; continue; }
                if (peer.Managed != null) continue; // managed data arrives through its registered resource only
                if (peer.CancelledCandidates.Contains((IPEndPoint)received.RemoteEndPoint)) { peer.Dropped++; peer.ReceivePolicyDrops++; continue; }
                var result = peer.Link.Receive(buffer.AsSpan(0, received.ReceivedBytes));
                if (!result.Authenticated) { peer.Dropped++; peer.AuthenticationDrops++; continue; }
                var endpoint = (IPEndPoint)received.RemoteEndPoint;
                if (!peer.NativeControlSources.ContainsKey(endpoint) && peer.NativeControlSources.Count < 16){
                    peer.NativeControlSources[endpoint] = legacyListenerControlsWire;peer.LegacyListenerSources.Add(endpoint);
                }
                if (result.Reply != null) SendLegacyControl(peer, result.Reply, endpoint, maintenance: buffer[4] == 5 && endpoint.Equals(peer.Active));
                if (buffer[4] != 1) {
                    if (endpoint.Equals(peer.Active)) peer.ActiveReceived = Stopwatch.GetTimestamp();
                    else if (result.PongToken is long nonce && peer.Probes.TryGetValue(endpoint, out var probe) && probe.Token == nonce && Stopwatch.GetElapsedTime(probe.At).TotalSeconds < 5) {
                        if (peer.Active != null) { peer.Retired.Enqueue(peer.Active); while (peer.Retired.Count > 8) peer.Retired.Dequeue(); }
                        peer.Active = endpoint; peer.ActiveReceived = peer.ActiveRoundTrip = Stopwatch.GetTimestamp(); peer.Probes.Clear(); peer.ActivePings.Clear();
                        peer.LegacyTransportFailed=false;
                        peer.LegacyKeepalive = new();
                        peer.LegacyPathId = Guid.NewGuid(); peer.Recovery.Select(peer.LegacyPathId, Environment.TickCount64);
                    } else if (endpoint.Equals(peer.Candidate) || !Healthy(peer) || !peer.Retired.Contains(endpoint)) Challenge(peer, endpoint);
                }
                if (endpoint.Equals(peer.Active) && result.PongToken is long recoveryNonce) {
                    if (peer.ActivePings.Remove(recoveryNonce, out long sent)) {
                        bool fresh = Fresh(sent); peer.LegacyKeepalive.Reply(fresh);
                        if (fresh) peer.ActiveRoundTrip = Stopwatch.GetTimestamp();
                    }
                    // Recovery has a separate, bounded nonce set for its
                    // business observation probes; do not discard those pongs.
                    peer.Recovery.Pong(recoveryNonce, Environment.TickCount64);
                }
                if(result.Synchronization!=null && endpoint.Equals(peer.Active))ReceiveSynchronization(peer,result.Synchronization);
                if (result.Packet != null) {
                    if (Deliver(peer, result.Packet, MeshPackets.Accept(result.Packet, local, peer.Host))) {
                        peer.Received += result.Packet.Length;
                        if (endpoint.Equals(peer.Active)) peer.Recovery.Business(Environment.TickCount64);
                    }
                }
            }
        }
    }
    void Heartbeat()
    {
        int cursor = 0;
        long due = Environment.TickCount64;
        while (!stop.IsCancellationRequested) {
            long requested = Environment.TickCount64;
            lock (gate) {
            if (stop.IsCancellationRequested) return;
            long now = Environment.TickCount64;
            maintenanceTicks++;
            maximumMaintenanceDelayMs = Math.Max(maximumMaintenanceDelayMs, Math.Max(0, now - due));
            maximumMaintenanceLockWaitMs = Math.Max(maximumMaintenanceLockWaitMs, now - requested);
            lastMaintenance = now;
            var order = peers.Values.ToArray();
            bool legacyServiced = false;
            for (int i = 0; i < order.Length; i++) {
                var peer = order[(i + cursor) % order.Length];
                if (peer.Managed != null) { TickManaged(peer, now); TickRecovery(peer, now); continue; }
                if (!LegacyAllowed) continue;
                TickRecovery(peer, now);
                // Spread legacy search/ordinary keepalive over ticks instead
                // of draining the entire burst before any replies can arrive.
                // Recovery and managed paths still get their own fair turn.
                if (legacyServiced || now < peer.NextLegacyControl || peer.Active == null && peer.Candidate == null) continue;
                legacyServiced = true; peer.NextLegacyControl = now + 1500;
                // Continue probing an unhealthy retained path as well. Only an
                // outstanding nonce returned through this exact Active refreshes
                // outbound proof; inbound data/Hello/another candidate cannot.
                if (peer.Active != null) {
                    peer.LegacyKeepalive.Attempt();
                    byte[]? ping = peer.Link.Ping(out long nonce);
                    if (ping == null) peer.LegacyKeepalive.SessionUnavailable++;
                    else if (SendLegacyControl(peer, ping, peer.Active, maintenance: true)) {
                        if (peer.ActivePings.Count >= 8) {
                            peer.ActivePings.Remove(peer.ActivePings.MinBy(p => p.Value).Key);
                            peer.LegacyKeepalive.PendingEvicted++;
                        }
                        peer.ActivePings[nonce] = peer.LegacyKeepalive.Accept();
                        peer.Recovery.KeepaliveSent(nonce, now);
                    } else peer.LegacyKeepalive.LocalRejected++;
                }
                if (Healthy(peer)) {
                    if (peer.Candidate != null && !peer.Candidate.Equals(peer.Active)) {
                        SendLegacyControl(peer, peer.Link.Hello(), peer.Candidate); Challenge(peer, peer.Candidate);
                    }
                }
                else {
                    byte[] hello = peer.Link.Hello(); SendLegacyControl(peer, hello, peer.Candidate);
                    if (peer.Active != null && !peer.Active.Equals(peer.Candidate)) SendLegacyControl(peer, hello, peer.Active);
                    if (peer.Candidate != null && !peer.Candidate.Equals(peer.Active)) Challenge(peer, peer.Candidate);
                }
            }
            cursor = order.Length == 0 ? 0 : (cursor + 1) % order.Length;
            maximumMaintenanceWorkMs = Math.Max(maximumMaintenanceWorkMs, Environment.TickCount64-now);
            }
            // One dedicated maintenance worker per router, never one per peer.
            // Preserve the 12-second proof and wire budgets; no catch-up burst.
            due = Environment.TickCount64 + 100;
            if (stop.Token.WaitHandle.WaitOne(100)) return;
        }
    }
}
