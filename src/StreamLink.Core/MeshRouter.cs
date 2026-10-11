using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Diagnostics;

namespace StreamLink.Core;

public sealed record MeshPeerStatus(int Slot, string Ip, string Name, bool Connected, double? RttMs, string Detail, long SentBytes = 0, long ReceivedBytes = 0, long DroppedPackets = 0);

// One adapter and one local UDP socket per node. The authenticated source slot
// selects a peer; a member can only deliver packets to this node's own address.
// There is deliberately no route for forwarding another member's packets.
public sealed class MeshRouter : IAsyncDisposable
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
    public MeshRouter(MeshProfile profile, IPacketAdapter adapter)
    {
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
            foreach (int slot in peers.Keys.Where(s => !directory.Members.Contains(peers[s].Member)).ToArray()) { peers[slot].Link.Dispose(); peers.Remove(slot); }
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
            bool changed = !Equals(peer.Candidate, candidate);
            peer.Candidate = candidate; peer.Name = name; peer.Detail = detail;
            if (changed && candidate != null && !candidate.Equals(peer.Active)) {
                peer.Probes.Remove(candidate); Send(peer.Link.Hello(), candidate); Challenge(peer, candidate);
            }
        }
    }
    static bool Healthy(Peer peer) => peer.Link.Connected && peer.Active != null && peer.ActiveReceived != 0 && Stopwatch.GetElapsedTime(peer.ActiveReceived).TotalSeconds < 12;
    public bool UsesPath(int slot, IPEndPoint? endpoint)
    {
        lock (gate) return endpoint != null && peers.TryGetValue(slot, out var peer) && Healthy(peer) && endpoint.Equals(peer.Active);
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
        if (frame != null) { peer.Probes[endpoint] = (nonce, reuse ? probe.At : now, now); Send(frame, endpoint); }
    }
    public MeshPeerStatus[] Status()
    {
        lock (gate) return peers.Values.OrderBy(p => p.Member.Slot).Select(p => new MeshPeerStatus(p.Member.Slot, MeshIdentity.Address(profile.Pair.Network, p.Member.Slot), p.Name.Length > 0 ? p.Name : $"设备 {p.Member.Slot}", Healthy(p), p.Link.RttMs, Healthy(p) ? "P2P 直连" : p.Detail, p.Sent, p.Received, p.Dropped)).ToArray();
    }
    bool Send(byte[]? packet, IPEndPoint? endpoint)
    {
        if (packet == null || endpoint == null) return false;
        try { return socket.SendTo(packet, endpoint) == packet.Length; }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.WouldBlock or SocketError.NoBufferSpaceAvailable or SocketError.TimedOut or SocketError.ConnectionReset or SocketError.ConnectionRefused) { return false; }
    }
    void Transmit()
    {
        var buffer = new byte[MeshLink.Mtu];
        while (!stop.IsCancellationRequested) {
            int count = adapter.Read(buffer); if (count == 0) continue;
            var packet = buffer.AsSpan(0, count); int slot = MeshPackets.Destination(packet, local); if (slot == 0) continue;
            lock (gate) if (peers.TryGetValue(slot, out var peer)) {
                if (Healthy(peer) && Send(peer.Link.Data(packet), peer.Active)) peer.Sent += count; else peer.Dropped++;
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
                var result = peer.Link.Receive(buffer.AsSpan(0, received.ReceivedBytes));
                if (!result.Authenticated) { peer.Dropped++; continue; }
                var endpoint = (IPEndPoint)received.RemoteEndPoint;
                Send(result.Reply, endpoint);
                if (buffer[4] != 1) {
                    if (endpoint.Equals(peer.Active)) peer.ActiveReceived = Stopwatch.GetTimestamp();
                    else if (result.PongToken is long nonce && peer.Probes.TryGetValue(endpoint, out var probe) && probe.Token == nonce && Stopwatch.GetElapsedTime(probe.At).TotalSeconds < 5) {
                        if (peer.Active != null) { peer.Retired.Enqueue(peer.Active); while (peer.Retired.Count > 8) peer.Retired.Dequeue(); }
                        peer.Active = endpoint; peer.ActiveReceived = Stopwatch.GetTimestamp(); peer.Probes.Clear();
                    } else if (endpoint.Equals(peer.Candidate) || !Healthy(peer) || !peer.Retired.Contains(endpoint)) Challenge(peer, endpoint);
                }
                if (result.Packet != null) {
                    if (MeshPackets.Accept(result.Packet, local, peer.Member.Slot) && adapter.Write(result.Packet)) peer.Received += result.Packet.Length; else peer.Dropped++;
                }
            }
        }
    }
    async Task Heartbeat()
    {
        while (!stop.IsCancellationRequested) {
            lock (gate) foreach (var peer in peers.Values) {
                if (Healthy(peer)) Send(peer.Link.Ping(), peer.Active);
                else {
                    byte[] hello = peer.Link.Hello(); Send(hello, peer.Candidate);
                    if (peer.Active != null && !peer.Active.Equals(peer.Candidate)) Send(hello, peer.Active);
                }
                if (peer.Candidate != null && !peer.Candidate.Equals(peer.Active)) { Send(peer.Link.Hello(), peer.Candidate); Challenge(peer, peer.Candidate); }
            }
            await Task.Delay(1500, stop.Token);
        }
    }
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stop.Cancel();
        try { await Task.WhenAll(transmit, receive, heartbeat, Completion); } catch (OperationCanceledException) { }
        finally { lock (gate) { foreach (var peer in peers.Values) peer.Link.Dispose(); peers.Clear(); } socket.Dispose(); adapter.Dispose(); stop.Dispose(); }
    }
}
