using System.Buffers.Binary;
using System.Net;
using System.Threading.Channels;
using StreamLink.Core;

// An explicit mapping/filter fixture, not a Windows/NAT implementation.
// Multiple hard members share one public IP and get distinct target mappings.
sealed class PeerSourceNatWire(int stable)
{
    readonly object gate = new();
    readonly Dictionary<string, Io> sources = [];
    readonly Dictionary<string, Io> inbound = [];
    int nextPort = 35000;
    public int Packets, Syns;
    public Io[] Ios { get { lock (gate) return sources.Values.ToArray(); } }
    public IPAddress Public(int node) => IPAddress.Parse(node == stable ? "192.0.2.10" : "192.0.2.20");
    public Io Open(int node, IPEndPoint local) {
        lock (gate) { var io = new Io(this, node, local); sources.Add(local.ToString(), io); return io; }
    }
    IPEndPoint Map(Io source, string target) {
        if (source.Mappings.TryGetValue(target, out var existing)) return existing;
        var mapped = new IPEndPoint(Public(source.Node), source.Node == stable ? source.Local.Port : ++nextPort);
        source.Mappings[target] = mapped; inbound[mapped.ToString()] = source; return mapped;
    }
    public IPEndPoint Reflect(IPEndPoint local) { lock (gate) return Map(sources[local.ToString()], "helper"); }
    public bool Send(Io source, ReadOnlySpan<byte> packet) {
        lock (gate) {
            if (!TcpCaptureOwner.Tuple(packet, out _, out var target, true)) throw new IOException("Invalid raw fixture output");
            Packets++; int ip = (packet[0] & 15) * 4; if ((packet[ip + 13] & 2) != 0) Syns++;
            source.Allowed.Add(target.ToString()); var outside = Map(source, target.ToString());
            if (!inbound.TryGetValue(target.ToString(), out var destination)) return true;
            if (destination.Node == stable ? !destination.Allowed.Any(t => IPEndPoint.Parse(t).Address.Equals(outside.Address)) :
                !destination.Mappings.TryGetValue(outside.ToString(), out var reverse) || !reverse.Equals(target)) return true;
            var p = packet.ToArray(); Rewrite(p, outside, destination.Local); destination.Input.Writer.TryWrite(new(p, false)); return true;
        }
    }
    static void Rewrite(byte[] p, IPEndPoint source, IPEndPoint target) {
        int ip = (p[0] & 15) * 4; source.Address.GetAddressBytes().CopyTo(p, 12); target.Address.GetAddressBytes().CopyTo(p, 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(ip), (ushort)source.Port); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(ip + 2), (ushort)target.Port);
        p[10] = p[11] = p[ip + 16] = p[ip + 17] = 0;
        static ushort Sum(ReadOnlySpan<byte> data, uint sum = 0) { for (int i = 0; i < data.Length; i += 2) sum += i + 1 < data.Length ? BinaryPrimitives.ReadUInt16BigEndian(data[i..]) : (uint)data[i] << 8;
            while (sum > 65535) sum = (sum & 65535) + (sum >> 16); return (ushort)~sum; }
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), Sum(p.AsSpan(0, ip)));
        uint pseudo = 6 + (uint)(p.Length - ip); for (int i = 12; i < 20; i += 2) pseudo += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i));
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(ip + 16), Sum(p.AsSpan(ip), pseudo));
    }
    public sealed class Io(PeerSourceNatWire owner, int node, IPEndPoint local) : IEndpointPacketIo {
        public int Node => node; public IPEndPoint Local => local;
        public readonly Dictionary<string, IPEndPoint> Mappings = []; public readonly HashSet<string> Allowed = [];
        public readonly Channel<EndpointPacket> Input = Channel.CreateBounded<EndpointPacket>(1024); public bool Closed;
        public ValueTask<EndpointPacket> Receive(CancellationToken t) => Input.Reader.ReadAsync(t);
        public bool Inject(ReadOnlySpan<byte> p) => owner.Send(this, p); public bool Reinject(EndpointPacket p) => true;
        public void Shutdown() => Input.Writer.TryComplete(); public void Dispose() { Closed = true; Shutdown(); }
    }
}
