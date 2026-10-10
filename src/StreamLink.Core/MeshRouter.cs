using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

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
        lock (gate) if (peers.TryGetValue(slot, out var peer)) { peer.Candidate = candidate; peer.Name = name; peer.Detail = detail; }
    }
    public MeshPeerStatus[] Status()
    {
        lock (gate) return peers.Values.OrderBy(p => p.Member.Slot).Select(p => new MeshPeerStatus(p.Member.Slot, MeshIdentity.Address(profile.Pair.Network, p.Member.Slot), p.Name.Length > 0 ? p.Name : $"设备 {p.Member.Slot}", p.Link.Connected, p.Link.RttMs, p.Link.Connected ? "P2P 直连" : p.Detail, p.Sent, p.Received, p.Dropped)).ToArray();
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
                if (Send(peer.Link.Data(packet), peer.Active)) peer.Sent += count; else peer.Dropped++;
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
                if (buffer[4] != 1) peer.Active = endpoint;
                Send(result.Reply, endpoint);
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
                if (peer.Link.Connected) Send(peer.Link.Ping(), peer.Active);
                else {
                    byte[] hello = peer.Link.Hello(); Send(hello, peer.Candidate);
                    if (peer.Active != null && !peer.Active.Equals(peer.Candidate)) Send(hello, peer.Active);
                }
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
