using System.Buffers.Binary;
using System.Net;
using System.Threading.Channels;
using StreamLink.Core;

// Controlled EIM/APDF versus APDM/APDF; not a real NAT classifier.
sealed class UdpExplorationNatWire(int stable)
{
    readonly object gate = new();
    readonly Dictionary<string, Mapping> ingress = [];
    readonly List<Port> sources = [];
    readonly int[] next = [45000, 45000];
    int locals = 43000;
    public int Packets, Reflects;
    internal sealed record Mapping(IPEndPoint Public, Port Source, HashSet<string> Allowed);
    public static readonly IPEndPoint Reflector = IPEndPoint.Parse("198.51.100.10:3478");
    public IPAddress Public(int node) => IPAddress.Parse(node == stable ? "192.0.2.10" : "192.0.2.20");
    public Port[] Sources { get { lock (gate) return sources.ToArray(); } }
    public Port Open(int node) { lock (gate) { var port = new Port(this, node, new(IPAddress.Parse("10.200.0." + (node + 1)), ++locals)); sources.Add(port); return port; } }
    public ValueTask Send(Port port, ReadOnlyMemory<byte> bytes, IPEndPoint target, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (gate) {
            ObjectDisposedException.ThrowIf(port.Closed, port); Packets++;
            string key = port.Node == stable ? "*" : target.ToString();
            if (!port.Mappings.TryGetValue(key, out var mapping)) {
                mapping = new(new(Public(port.Node), next[port.Node]), port, []); next[port.Node] += 7;
                port.Mappings[key] = mapping; ingress[mapping.Public.ToString()] = mapping;
            }
            mapping.Allowed.Add(target.ToString());
            if (target.Equals(Reflector)) { Reflects++; port.Input.Writer.TryWrite(new(Reply(bytes.ToArray(), mapping.Public), target)); return ValueTask.CompletedTask; }
            if (ingress.TryGetValue(target.ToString(), out var recipient) && !recipient.Source.Closed && recipient.Allowed.Contains(mapping.Public.ToString()))
                recipient.Source.Input.Writer.TryWrite(new(bytes.ToArray(), mapping.Public));
            return ValueTask.CompletedTask;
        }
    }
    static byte[] Reply(byte[] request, IPEndPoint source)
    {
        byte[] response = new byte[32]; request.AsSpan(0,20).CopyTo(response); response[0]=1; response[1]=1; response[3]=12;
        response[21]=0x20; response[23]=8; response[25]=1;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(26),(ushort)(source.Port ^ 0x2112));
        BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(28),BinaryPrimitives.ReadUInt32BigEndian(source.Address.GetAddressBytes()) ^ 0x2112a442); return response;
    }
    public sealed class Port(UdpExplorationNatWire wire, int node, IPEndPoint local) : ITraversalSocket
    {
        public int Node => node; public Guid Id { get; } = Guid.NewGuid(); public IPEndPoint Local => local; public bool DontFragment => true;
        internal readonly Dictionary<string, Mapping> Mappings = [];
        public readonly Channel<TraversalDatagram> Input = Channel.CreateBounded<TraversalDatagram>(512); public bool Closed;
        public ValueTask Send(ReadOnlyMemory<byte> p, IPEndPoint remote, CancellationToken token) => wire.Send(this,p,remote,token);
        public ValueTask<TraversalDatagram> Receive(CancellationToken token) => Input.Reader.ReadAsync(token);
        public void Dispose() { Closed=true; Input.Writer.TryComplete(); }
    }
}
