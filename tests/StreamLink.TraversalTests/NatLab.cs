using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using StreamLink.Core;

// Deterministic in-process NAT model. This exercises real traversal logic, not
// a claim about a physical router or any particular campus/ISP implementation.
sealed class NatLab
{
    internal sealed class Binding(IPEndPoint external, Port owner)
    {
        public IPEndPoint External = external;
        public Port Owner = owner;
        public HashSet<string> Destinations = [];
    }
    readonly object gate = new();
    readonly Dictionary<string, Binding> bindings = [];
    public static readonly IPEndPoint[] Reflectors = [IPEndPoint.Parse("198.51.100.10:3478"), IPEndPoint.Parse("198.51.100.11:3478"), IPEndPoint.Parse("198.51.100.11:3479")];
    public List<(IPEndPoint Source, IPEndPoint Target, byte[] Packet)> Wire { get; } = [];
    public Port Add(string ip, string mapping, string filtering, int seed, bool stunOnly = false, int maximumPayload = 1472, int localPort = 42000) => new(this, IPAddress.Parse(ip), mapping, filtering, seed, stunOnly, maximumPayload, localPort);
    internal void Send(Port source, byte[] packet, IPEndPoint target)
    {
        lock (gate) {
            string key = source.Mapping switch { "eim" => "*", "adm" => target.Address.ToString(), _ => target.ToString() };
            if (!source.Bindings.TryGetValue(key, out var own)) {
                own = new(new IPEndPoint(source.External, source.NextPort), source); source.NextPort += 7;
                source.Bindings.Add(key, own); bindings.Add(own.External.ToString(), own);
            }
            own.Destinations.Add(target.ToString()); Wire.Add((own.External, target, packet.ToArray()));
            if (Reflectors.Contains(target)) { Deliver(target, own, Reply(packet, own.External)); return; }
            if (source.StunOnly || packet.Length > source.MaximumPayload) return;
            if (bindings.TryGetValue(target.ToString(), out var remote) && !remote.Owner.StunOnly && packet.Length <= remote.Owner.MaximumPayload)
                Deliver(own.External, remote, packet);
        }
    }
    static void Deliver(IPEndPoint source, Binding target, byte[] packet)
    {
        bool permitted = target.Owner.Filtering switch {
            "eif" => true,
            "adf" => target.Destinations.Any(d => IPEndPoint.Parse(d).Address.Equals(source.Address)),
            _ => target.Destinations.Contains(source.ToString())
        };
        if (permitted) target.Owner.Incoming.Writer.TryWrite(new(packet, source));
    }
    internal static byte[] Reply(byte[] request, IPEndPoint observed)
    {
        byte[] response = new byte[32]; request.AsSpan(0, 20).CopyTo(response);
        BinaryPrimitives.WriteUInt16BigEndian(response, 0x0101); BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2), 12);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(20), 0x20); BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(22), 8);
        response[25] = 1; BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(26), (ushort)(observed.Port ^ 0x2112));
        BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(28), BinaryPrimitives.ReadUInt32BigEndian(observed.Address.GetAddressBytes()) ^ 0x2112a442); return response;
    }
    public sealed class Port(NatLab lab, IPAddress external, string mapping, string filtering, int seed, bool stunOnly, int maximumPayload, int localPort) : ITraversalSocket
    {
        // This model drops above its configured maximum; it never fragments.
        // It is NOT evidence of real NIC or NAT DF behavior.
        public bool DontFragment => true;
        internal readonly Channel<TraversalDatagram> Incoming = Channel.CreateUnbounded<TraversalDatagram>();
        internal readonly Dictionary<string, Binding> Bindings = [];
        internal readonly string Mapping = mapping, Filtering = filtering;
        internal readonly IPAddress External = external;
        internal readonly bool StunOnly = stunOnly;
        internal readonly int MaximumPayload = maximumPayload;
        internal int NextPort = seed;
        public Guid Id { get; } = Guid.NewGuid();
        public IPEndPoint Local { get; } = new(IPAddress.Parse("10.200.0." + external.GetAddressBytes()[3]), localPort);
        public bool Disposed { get; private set; }
        public ValueTask Send(ReadOnlyMemory<byte> packet, IPEndPoint remote, CancellationToken token) { token.ThrowIfCancellationRequested(); ObjectDisposedException.ThrowIf(Disposed, this); lab.Send(this, packet.ToArray(), remote); return ValueTask.CompletedTask; }
        public ValueTask<TraversalDatagram> Receive(CancellationToken token) => Incoming.Reader.ReadAsync(token);
        public void Dispose() { Disposed = true; Incoming.Writer.TryComplete(); }
    }
}

sealed class Reflector : IAsyncDisposable
{
    readonly UdpClient socket;
    readonly CancellationTokenSource stop = new();
    readonly Task running;
    public IPEndPoint Endpoint => (IPEndPoint)socket.Client.LocalEndPoint!;
    public Reflector(IPAddress ip) { socket = new(new IPEndPoint(ip, 0)); running = Run(); }
    async Task Run()
    {
        while (!stop.IsCancellationRequested) {
            var request = await socket.ReceiveAsync(stop.Token);
            var response = NatLab.Reply(request.Buffer, request.RemoteEndPoint);
            var unrelated = response.ToArray(); unrelated[8] ^= 1;
            await socket.SendAsync(unrelated, request.RemoteEndPoint, stop.Token);
            // Valid-looking response from a different port must not satisfy the
            // pending transaction, even when the transaction ID matches.
            using var stranger = new UdpClient(new IPEndPoint(Endpoint.Address, 0));
            await stranger.SendAsync(NatLab.Reply(request.Buffer, IPEndPoint.Parse("203.0.113.99:9")), request.RemoteEndPoint, stop.Token);
            await socket.SendAsync(response, request.RemoteEndPoint, stop.Token);
        }
    }
    public async ValueTask DisposeAsync() { stop.Cancel(); try { await running; } catch (OperationCanceledException) { } socket.Dispose(); stop.Dispose(); }
}
