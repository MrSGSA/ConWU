using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record TcpObserverPoint(string Id, string Endpoint);
public sealed record TcpProbeSpec(Guid ProbeId, string ObserverId, uint Iss);
public sealed record TcpObserverRequest(int Version, Guid RequestId, Guid TicketId, int Slot, string Device,
    Guid BootId, string Operation, long Expires, TcpProbeSpec[] Probes, string Signature);
public sealed record TcpSynEvidence(Guid ProbeId, string ObserverId, string Target, string State,
    string? Source, long? ObservedAt, int Retransmissions,
    string TcpHandshakeVerified = "NotTested", string LegacyPayloadVerified = "NotTested");
public sealed record TcpObserverReply(int Version, Guid Epoch, Guid TicketId, long Expires,
    TcpObserverPoint[] Points, TcpSynEvidence[] Evidence,
    int CaptureWindowMs = TcpObserverProtocol.WindowSeconds * 1000, bool Final = false, int FreshWindowMs = 0);
// Resource identity and route generation are local diagnostics, never published as candidates.
public sealed record TcpShapeObservation(Guid ResourceId, Guid NetworkGeneration, string Local, string Helper,
    Guid ProbeId, string Target, string? Mapped, long? ObservedAt, long Expires, string State,
    string Protocol = "TCP", string TransportProfile = "udp2raw-http-c4995ea-syn",
    string Confidence = "IssTargetWindowOnly", string Filtering = "Unknown",
    string TcpHandshakeVerified = "NotTested", string LegacyPayloadVerified = "NotTested",
    Guid CaptureOwnerId = default, string InterfaceId = "", long ProbeWindowEndsAt = 0, long LocalProbeStartedAt = 0);

public static class TcpObserverProtocol
{
    public const int Version = 1, WindowSeconds = 8, RetentionSeconds = 60;
    public const int FreshWindowMs = 750;
    static byte[] Data(string network, TcpObserverRequest r) => JsonSerializer.SerializeToUtf8Bytes(new {
        domain = "streamlink-tcp-syn-observation-v1", network, r.Version, r.RequestId, r.TicketId,
        r.Slot, r.Device, r.BootId, r.Operation, r.Expires, r.Probes });
    public static byte[] Fingerprint(string network, TcpObserverRequest r) => SHA256.HashData(Data(network, r));
    public static void Validate(TcpObserverRequest r)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (r.Version != Version || r.RequestId == Guid.Empty || r.BootId == Guid.Empty || r.Slot is < 1 or > 254 ||
            !Guid.TryParseExact(r.Device, "N", out _) || r.Expires <= now || r.Expires > now + 30 ||
            r.Signature is null || r.Signature.Length > 256 || r.Probes is null ||
            r.Operation is not ("catalog" or "register" or "register-fresh" or "read") ||
            (r.Operation == "catalog" ? r.TicketId != Guid.Empty : r.TicketId == Guid.Empty) ||
            (r.Operation == "register" ? r.Probes.Length is < 1 or > 4 :
                r.Operation == "register-fresh" ? r.Probes.Length is < 1 or > 2 : r.Probes.Length != 0) ||
            r.Probes.Any(p => p == null || p.ProbeId == Guid.Empty || p.ObserverId is not { Length: >= 1 and <= 32 }) ||
            r.Probes.Select(p => p.ProbeId).Distinct().Count() != r.Probes.Length ||
            r.Probes.Select(p => p.ObserverId).Distinct().Count() != r.Probes.Length)
            throw new FormatException("TCP 观察请求无效");
    }
    public static TcpObserverRequest Create(MeshProfile profile, Guid boot, string operation, Guid ticket, TcpProbeSpec[]? probes = null)
    {
        var r = new TcpObserverRequest(Version, Guid.NewGuid(), ticket, profile.Self.Slot, profile.Self.Device, boot,
            operation, DateTimeOffset.UtcNow.AddSeconds(25).ToUnixTimeSeconds(), probes ?? [], "");
        Validate(r); return r with { Signature = MeshIdentity.Sign(profile.SigningPrivate, Data(profile.Pair.Network, r)) };
    }
    public static void Verify(string network, MeshMember member, TcpObserverRequest r)
    {
        Validate(r);
        if (member.Slot != r.Slot || member.Device != r.Device || !MeshIdentity.Verify(member.SigningKey, Data(network, r), r.Signature))
            throw new CryptographicException("TCP 观察请求身份无效");
    }
    public static IPEndPoint Endpoint(string text)
    {
        if (text.Length > 64 || !IPEndPoint.TryParse(text, out var ep) || ep.AddressFamily != AddressFamily.InterNetwork ||
            ep.Port < 1024 || ep.Address.GetAddressBytes()[0] is 0 or >= 224)
            throw new FormatException("观察点必须是固定 IPv4:端口（1024–65535）");
        return ep;
    }
    public static void ValidatePoints(TcpObserverPoint[] points)
    {
        if (points.Length is < 1 or > 4 || points.Any(p => p == null || p.Id is not { Length: >= 1 and <= 32 } ||
                p.Id.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-') || p.Endpoint == null) ||
            points.Select(p => p.Id).Distinct().Count() != points.Length) throw new FormatException("观察点列表无效");
        var endpoints = points.Select(p => Endpoint(p.Endpoint)).ToArray();
        if (endpoints.Distinct().Count() != points.Length || endpoints.Select(p => p.Address).Distinct().Count() > 2 ||
            endpoints.GroupBy(p => p.Address).Any(g => g.Count() > 2)) throw new FormatException("观察点至多两个 IP、每 IP 两个端口");
    }
}

// The observer probe uses the existing profile's bare SYN shape, with no custom
// option or SYN payload. It does not implement or alter the HTTP/data sequence rules.
public static class TcpShapeSyn
{
    public static byte[] Create(IPEndPoint source, IPEndPoint target, uint iss, uint timestamp)
    {
        if (source.AddressFamily != AddressFamily.InterNetwork || target.AddressFamily != AddressFamily.InterNetwork || source.Port == 0 || target.Port == 0)
            throw new ArgumentException("IPv4 endpoints required");
        byte[] p = new byte[60]; p[0] = 0x45; p[3] = 60; p[6] = 0x40; p[8] = 64; p[9] = 6;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), (ushort)RandomNumberGenerator.GetInt32(65536));
        source.Address.GetAddressBytes().CopyTo(p, 12); target.Address.GetAddressBytes().CopyTo(p, 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), (ushort)source.Port);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), (ushort)target.Port);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(24), iss);
        RandomNumberGenerator.Fill(p.AsSpan(28, 4)); // ACK flag is clear, same initialization as the legacy client.
        p[32] = 0xa0; p[33] = 2;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(34), (ushort)RandomNumberGenerator.GetInt32(40960, 41472));
        new byte[] { 2, 4, 5, 180, 4, 2, 8, 10 }.CopyTo(p, 40);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(48), timestamp);
        p[56] = 1; p[57] = 3; p[58] = 3; p[59] = 5;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), Checksum(p.AsSpan(0, 20)));
        Span<byte> pseudo = stackalloc byte[52]; p.AsSpan(12, 8).CopyTo(pseudo); pseudo[8] = 0; pseudo[9] = 6; pseudo[10] = 0; pseudo[11] = 40;
        p.AsSpan(20).CopyTo(pseudo[12..]); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(36), Checksum(pseudo));
        return p;
    }
    static ushort Checksum(ReadOnlySpan<byte> p)
    {
        uint sum = 0; for (int i = 0; i < p.Length; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p[i..]);
        while (sum > 65535) sum = (sum & 65535) + (sum >> 16); return (ushort)~sum;
    }
    public static bool Read(ReadOnlySpan<byte> packet, out IPEndPoint source, out IPEndPoint target, out uint iss)
    {
        iss = 0;
        if (!TcpCaptureOwner.Tuple(packet, out source, out target, exactLength: true)) return false;
        int ip = (packet[0] & 15) * 4, tcp = (packet[ip + 12] >> 4) * 4;
        if (packet.Length != ip + tcp || packet[ip + 13] != 2 || (packet[ip + 12] & 15) != 0) return false;
        iss = BinaryPrimitives.ReadUInt32BigEndian(packet[(ip + 4)..]); return true;
    }
}
