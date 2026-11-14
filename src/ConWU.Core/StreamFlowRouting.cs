using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;

namespace StreamLink.Core;

public sealed record StreamFlowPolicy(MeshProfile Mesh, bool Enabled);
public sealed record StreamFlowStatus(bool Negotiated, int Connections, long RejectedPackets)
{
    public bool SplitActive {get;init;}
    public long ReceiveRejectedPackets {get;init;}
}

// Fixed classification, never round-robin individual packets. Unknown flows
// use a stable five-tuple hash; known Sunshine ports isolate input/audio/video.
public static class StreamFlowClassifier
{
    public static byte Lane(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20 || packet[0] >> 4 != 4) return 1;
        int header = (packet[0] & 15) * 4;
        bool fragmented = (BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x3fff) != 0;
        uint hash = 2166136261;
        for (int i = 12; i < 20; i++) hash = (hash ^ packet[i]) * 16777619;
        hash = (hash ^ packet[9]) * 16777619;
        if (!fragmented && packet[9] is 6 or 17 && header >= 20 && packet.Length >= header + 4) {
            int from = BinaryPrimitives.ReadUInt16BigEndian(packet[header..]);
            int to = BinaryPrimitives.ReadUInt16BigEndian(packet[(header + 2)..]);
            if (from == 47999 || to == 47999 || from == 48010 || to == 48010) return 1;
            if (from == 48000 || to == 48000) return 2;
            if (from == 47998 || to == 47998) return 3;
            for (int i = header; i < header + 4; i++) hash = (hash ^ packet[i]) * 16777619;
        }
        return (byte)(1 + hash % 3);
    }
}

// Only process-local carrier owners can install routes. A shared receiver's
// proxy endpoint is an exact-owner alias, not another independent mesh path.
public static class StreamFlowRoutes
{
    internal interface ISession
    {
        string Network { get; }
        int LocalSlot { get; }
        int RemoteSlot { get; }
        bool Negotiated { get; }
        StreamFlowStatus Status { get; }
        bool TrySend(ReadOnlySpan<byte> frame, IPEndPoint? sender = null);
        bool SendPacket(ReadOnlySpan<byte> packet, MeshLink link, IPEndPoint sender, out byte[]? encoded);
    }
    sealed record Route(ISession Session, object Owner);
    static readonly ConcurrentDictionary<IPEndPoint, Route> routes = new();
    internal static void Register(IPEndPoint endpoint, ISession session) => routes[endpoint] = new(session, session);
    internal static void Unregister(ISession session)
    {
        foreach (var item in routes.Where(p => ReferenceEquals(p.Value.Session, session)).ToArray())
            ((ICollection<KeyValuePair<IPEndPoint, Route>>)routes).Remove(item);
    }
    public static IDisposable? Alias(IPEndPoint carrier, IPEndPoint endpoint, string network)
    {
        if (!routes.TryGetValue(carrier, out var found) || found.Session.Network != network) return null;
        var owner = new object(); var value = new Route(found.Session, owner);
        if (!routes.TryAdd(endpoint, value)) return null;
        return new Lease(() => ((ICollection<KeyValuePair<IPEndPoint, Route>>)routes).Remove(new(endpoint, value)));
    }
    static ISession? Find(IPEndPoint? endpoint, string network, int local, int remote) => endpoint != null && routes.TryGetValue(endpoint, out var found) &&
        found.Session.Network == network && found.Session.LocalSlot == local && found.Session.RemoteSlot == remote ? found.Session : null;
    public static bool AllowsLanes(IPEndPoint endpoint, string network, int local, int remote) => Find(endpoint, network, local, remote)?.Negotiated == true;
    public static StreamFlowStatus? Status(IPEndPoint? endpoint, string network, int local, int remote) => Find(endpoint, network, local, remote)?.Status;
    public static bool TrySendPacket(IPEndPoint? endpoint, IPEndPoint sender, string network, int local, int remote,
        ReadOnlySpan<byte> packet, MeshLink link, out byte[]? encoded, out bool accepted)
    {
        encoded = null; accepted = false;
        var session = Find(endpoint, network, local, remote); if (session == null) return false;
        accepted = session.SendPacket(packet, link, sender, out encoded); return true;
    }
    public static bool TrySend(IPEndPoint endpoint, IPEndPoint sender, string network, int local, ReadOnlySpan<byte> frame, out bool accepted)
    {
        accepted = false;
        if (!PairNetworkFrame.IsFrame(frame) || frame.Length < PairNetworkFrame.HeaderSize + MeshLink.Overhead || !frame.Slice(20, 4).SequenceEqual("SLM4"u8)) return false;
        var session = Find(endpoint, network, local, frame[26]);
        if (session == null || frame[25] != local) return false;
        accepted = session.TrySend(frame, sender); return true;
    }
    sealed class Lease(Action release) : IDisposable { int disposed; public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) == 0) release(); } }
}
