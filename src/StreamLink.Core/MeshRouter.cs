using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Diagnostics;

namespace StreamLink.Core;

public sealed record MeshPeerStatus(int Slot, string Ip, string Name, bool Connected, double? RttMs, string Detail, long SentBytes = 0, long ReceivedBytes = 0, long DroppedPackets = 0)
{
    public bool Degraded { get; init; }
    public PathRecoverySnapshot? Recovery { get; init; }
}

// One adapter and one local UDP socket per node. The authenticated source slot
// selects a peer; a member can only deliver packets to this node's own address.
// There is deliberately no route for forwarding another member's packets.
public sealed partial class MeshRouter : IAsyncDisposable
{
    sealed class Peer(MeshMember member, MeshLink link)
    {
        public readonly MeshMember Member = member;
        public readonly MeshLink Link = link;
        public IPEndPoint? Candidate, Active;
        public long ActiveReceived;
        public readonly Dictionary<IPEndPoint, (long Token, long At, long Sent)> Probes = [];
        public readonly Queue<IPEndPoint> Retired = [];
        public string Name = "", Detail = "等待对端上线";
        public long Sent, Received, Dropped;
        public ManagedPeer? Managed;
        public readonly PathRecovery Recovery = new(Environment.TickCount64);
        public Guid LegacyPathId;
        public long NextLegacyControl;
    }
    readonly object gate = new();
    readonly MeshProfile profile;
    readonly IPacketAdapter adapter;
    readonly byte[] local;
    readonly Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    readonly Dictionary<int, Peer> peers = [];
    readonly CancellationTokenSource stop = new();
    readonly Task transmit, receive, heartbeat;
    int disposed;
    public IPEndPoint LocalEndpoint => (IPEndPoint)socket.LocalEndPoint!;
    public Task Completion { get; }
    public Guid BootId { get; }
    public PathSelection Selection { get; }
    public MeshRouter(MeshProfile profile, IPacketAdapter adapter, Guid? bootId = null, PathSelection? selection = null)
    {
        if (bootId == Guid.Empty) { socket.Dispose(); throw new ArgumentException("Router 启动代次无效", nameof(bootId)); }
        Selection = selection ?? new();
        try {
            Selection.Validate();
            if (Selection.Policy == PathPolicy.FakeTcpOnly && profile.Pair.Mode != "faketcp") throw new FormatException("仅 FakeTCP 不能接入 UDP 兼容网络");
        } catch { socket.Dispose(); throw; }
        BootId = bootId ?? Guid.NewGuid();
        this.profile = profile; this.adapter = adapter; local = IPAddress.Parse(profile.LocalIp).GetAddressBytes();
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0)); socket.SendBufferSize = socket.ReceiveBufferSize = 1 << 20; socket.SendTimeout = 100;
        if (profile.Directory != null) ApplyDirectory(profile.Directory);
        transmit = Task.Factory.StartNew(Transmit, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        receive = Receive(); heartbeat = Heartbeat(); Completion = Watch();
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
            foreach (int slot in peers.Keys.Where(s => !directory.Members.Contains(peers[s].Member)).ToArray()) { CloseManaged(peers[slot]); peers[slot].Link.Dispose(); peers.Remove(slot); }
            foreach (var member in directory.Members.Where(m => m.Slot != profile.Self.Slot)) {
                if (peers.ContainsKey(member.Slot)) continue;
                byte[] shared = MeshIdentity.SharedKey(profile, member);
                try { peers.Add(member.Slot, new(member, new(profile.Self.Slot, member.Slot, shared))); } finally { CryptographicOperations.ZeroMemory(shared); }
            }
            profile.Directory = directory;
        }
    }
    public void SetCandidate(int slot, IPEndPoint? candidate, string name, string detail)
    {
        if (candidate != null && !IPAddress.IsLoopback(candidate.Address)) throw new ArgumentException("数据接口仅允许本机 udp2raw");
        lock (gate) if (peers.TryGetValue(slot, out var peer)) {
            if (peer.Managed != null) return; // negotiated paths cannot fall back to legacy auto-promotion
            bool changed = !Equals(peer.Candidate, candidate);
            peer.Candidate = candidate; peer.Name = name; peer.Detail = detail;
            if (changed && candidate != null && !candidate.Equals(peer.Active)) {
                peer.Probes.Remove(candidate); peer.NextLegacyControl = 0;
            }
        }
    }
    static bool Healthy(Peer peer) => peer.Managed != null ? ManagedHealthy(peer) : peer.Link.Connected && peer.Active != null && peer.ActiveReceived != 0 && Stopwatch.GetElapsedTime(peer.ActiveReceived).TotalSeconds < 12;
    public bool UsesPath(int slot, IPEndPoint? endpoint)
    {
        lock (gate) return endpoint != null && peers.TryGetValue(slot, out var peer) && peer.Managed == null && Healthy(peer) && endpoint.Equals(peer.Active);
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
        if (frame != null && SendLegacyControl(frame, endpoint)) peer.Probes[endpoint] = (nonce, reuse ? probe.At : now, now);
    }
    public MeshPeerStatus[] Status()
    {
        lock (gate) return peers.Values.OrderBy(p => p.Member.Slot).Select(p => {
            bool healthy = Healthy(p), degraded = healthy && (p.Managed?.Active?.Identity.Profile == TraversalProfile.UdpDirect || p.Managed == null && profile.Pair.Mode == "udp");
            return new MeshPeerStatus(p.Member.Slot, MeshIdentity.Address(profile.Pair.Network, p.Member.Slot), p.Name.Length > 0 ? p.Name : $"设备 {p.Member.Slot}", healthy,
                p.Managed != null ? p.Managed.Active?.RttMs : p.Link.RttMs, healthy ? degraded ? "UDP 降级直连 · 未验证目标负载质量" : "P2P 直连" : p.Detail,
                p.Sent, p.Received, p.Dropped) { Degraded = degraded, Recovery = p.Recovery.Snapshot(Environment.TickCount64) };
        }).ToArray();
    }
    bool Send(byte[]? packet, IPEndPoint? endpoint)
    {
        if (packet == null || endpoint == null) return false;
        try { return socket.SendTo(packet, endpoint) == packet.Length; }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.WouldBlock or SocketError.NoBufferSpaceAvailable or SocketError.TimedOut or SocketError.ConnectionReset or SocketError.ConnectionRefused) { return false; }
    }
    bool SendLegacyControl(byte[]? packet, IPEndPoint? endpoint, bool maintenance = false)
        => packet != null && endpoint != null && TraversalResources.Shared.TrySend(packet.Length, maintenance) && Send(packet, endpoint);
    void Transmit()
    {
        var buffer = new byte[MeshLink.Mtu];
        while (!stop.IsCancellationRequested) {
            int count = adapter.Read(buffer); if (count == 0) continue;
            var packet = buffer.AsSpan(0, count); int slot = MeshPackets.Destination(packet, local); if (slot == 0) continue;
            lock (gate) if (peers.TryGetValue(slot, out var peer)) {
                bool delivered = Healthy(peer) && (peer.Managed != null ? SendManaged(peer.Link.Data(packet), peer.Managed.Active) : Send(peer.Link.Data(packet), peer.Active));
                if (delivered) peer.Sent += count;
                else { peer.Dropped++; peer.Recovery.Break("BusinessSendRejected", Environment.TickCount64); }
            }
        }
    }
    async Task Receive()
    {
        var buffer = new byte[2048];
        while (!stop.IsCancellationRequested) {
            SocketReceiveFromResult received;
            try { received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), stop.Token); }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize) { continue; }
            if (received.ReceivedBytes < MeshLink.Overhead || !IPAddress.IsLoopback(((IPEndPoint)received.RemoteEndPoint).Address)) continue;
            lock (gate) if (peers.TryGetValue(buffer[5], out var peer)) {
                if (peer.Managed != null) continue; // data arrives through its registered resource only
                var result = peer.Link.Receive(buffer.AsSpan(0, received.ReceivedBytes));
                if (!result.Authenticated) { peer.Dropped++; continue; }
                var endpoint = (IPEndPoint)received.RemoteEndPoint;
                if (result.Reply != null) SendLegacyControl(result.Reply, endpoint, maintenance: buffer[4] == 5 && endpoint.Equals(peer.Active));
                if (buffer[4] != 1) {
                    if (endpoint.Equals(peer.Active)) peer.ActiveReceived = Stopwatch.GetTimestamp();
                    else if (result.PongToken is long nonce && peer.Probes.TryGetValue(endpoint, out var probe) && probe.Token == nonce && Stopwatch.GetElapsedTime(probe.At).TotalSeconds < 5) {
                        if (peer.Active != null) { peer.Retired.Enqueue(peer.Active); while (peer.Retired.Count > 8) peer.Retired.Dequeue(); }
                        peer.Active = endpoint; peer.ActiveReceived = Stopwatch.GetTimestamp(); peer.Probes.Clear();
                        peer.LegacyPathId = Guid.NewGuid(); peer.Recovery.Select(peer.LegacyPathId, Environment.TickCount64);
                    } else if (endpoint.Equals(peer.Candidate) || !Healthy(peer) || !peer.Retired.Contains(endpoint)) Challenge(peer, endpoint);
                }
                if (endpoint.Equals(peer.Active) && result.PongToken is long recoveryNonce) peer.Recovery.Pong(recoveryNonce, Environment.TickCount64);
                if (result.Packet != null) {
                    if (MeshPackets.Accept(result.Packet, local, peer.Member.Slot) && adapter.Write(result.Packet)) {
                        peer.Received += result.Packet.Length;
                        if (endpoint.Equals(peer.Active)) peer.Recovery.Business(Environment.TickCount64);
                    } else peer.Dropped++;
                }
            }
        }
    }
    async Task Heartbeat()
    {
        int cursor = 0;
        while (!stop.IsCancellationRequested) {
            long now = Environment.TickCount64;
            lock (gate) {
            var order = peers.Values.ToArray();
            bool legacyServiced = false;
            for (int i = 0; i < order.Length; i++) {
                var peer = order[(i + cursor) % order.Length];
                if (peer.Managed != null) { TickManaged(peer, now); TickRecovery(peer, now); continue; }
                TickRecovery(peer, now);
                // Spread legacy search/ordinary keepalive over ticks instead
                // of draining the entire burst before any replies can arrive.
                // Recovery and managed paths still get their own fair turn.
                if (legacyServiced || now < peer.NextLegacyControl || peer.Active == null && peer.Candidate == null) continue;
                legacyServiced = true; peer.NextLegacyControl = now + 1500;
                if (Healthy(peer)) {
                    byte[]? ping = peer.Link.Ping(out long nonce);
                    if (SendLegacyControl(ping, peer.Active, maintenance: true))
                        peer.Recovery.KeepaliveSent(nonce, now);
                    if (peer.Candidate != null && !peer.Candidate.Equals(peer.Active)) {
                        SendLegacyControl(peer.Link.Hello(), peer.Candidate); Challenge(peer, peer.Candidate);
                    }
                }
                else {
                    byte[] hello = peer.Link.Hello(); SendLegacyControl(hello, peer.Candidate);
                    if (peer.Active != null && !peer.Active.Equals(peer.Candidate)) SendLegacyControl(hello, peer.Active);
                    if (peer.Candidate != null && !peer.Candidate.Equals(peer.Active)) Challenge(peer, peer.Candidate);
                }
            }
            cursor = order.Length == 0 ? 0 : (cursor + 1) % order.Length;
            }
            await Task.Delay(100, stop.Token);
        }
    }
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stop.Cancel();
        Task[] pathPumps;
        lock (gate) { foreach (var peer in peers.Values) CloseManaged(peer); pathPumps = managedPumps.ToArray(); }
        try { await Task.WhenAll(transmit, receive, heartbeat, Completion); } catch (OperationCanceledException) { }
        finally { await Task.WhenAll(pathPumps); lock (gate) { foreach (var peer in peers.Values) peer.Link.Dispose(); peers.Clear(); } socket.Dispose(); adapter.Dispose(); stop.Dispose(); }
    }
}
