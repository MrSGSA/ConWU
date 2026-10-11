using System.Buffers.Binary;
using System.Net;

namespace StreamLink.Core;

public enum PortControlKind { Pcp, NatPmp }
public enum PortMappingProtocol : byte { Tcp = 6, Udp = 17 }
public sealed record PortControlReply(uint Lifetime, uint Epoch, IPEndPoint? External, int Error = 0, bool NatPmpFallback = false);
public sealed class PortControlException(string reason, uint retrySeconds = 0) : IOException(reason)
{ public uint RetrySeconds { get; } = retrySeconds; }

internal static class PortControlProtocol
{
    static ushort U16(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt16BigEndian(b[o..]);
    static uint U32(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt32BigEndian(b[o..]);
    public static uint? PcpAnnounceEpoch(ReadOnlySpan<byte> b)
    {
        // RFC 6887 14.1: lifetime/reserved fields are ignored on reception.
        if (b.Length is < 24 or > 1100 || b.Length % 4 != 0 || b[0] != 2 || b[1] != 0x80 || b[3] != 0) return null;
        for (int at = 24; at < b.Length;) {
            int next = at + 4 + ((U16(b, at + 2) + 3) & ~3);
            if (next > b.Length) return null;
            at = next;
        }
        return U32(b, 8);
    }
    public static byte[] Pcp(IPAddress local, ushort port, PortMappingProtocol protocol, ReadOnlySpan<byte> nonce,
        uint lifetime, IPEndPoint suggested)
    {
        if (port == 0 || nonce.Length != 12 || !Enum.IsDefined(protocol) || !local.IsIPv4MappedToIPv6 && local.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException("Explicit IPv4 mapping required");
        byte[] b = new byte[60]; b[0] = 2; b[1] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), lifetime);
        local.MapToIPv6().GetAddressBytes().CopyTo(b, 8); nonce.CopyTo(b.AsSpan(24)); b[36] = (byte)protocol;
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(40), port);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(42), checked((ushort)suggested.Port));
        suggested.Address.MapToIPv6().GetAddressBytes().CopyTo(b, 44); return b;
    }
    public static byte[] Pmp(ushort port, PortMappingProtocol protocol, uint lifetime, ushort external)
    {
        if (port == 0 || !Enum.IsDefined(protocol)) throw new ArgumentException("Wildcard mappings are forbidden");
        byte[] b = new byte[12]; b[1] = protocol == PortMappingProtocol.Tcp ? (byte)2 : (byte)1;
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4), port); BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(6), external);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(8), lifetime); return b;
    }
    // Source endpoint is checked by the transport before parsing. Unrelated or
    // malformed packets never reset the current retransmission deadline.
    public static PortControlReply? ParsePcp(ReadOnlySpan<byte> b, ReadOnlySpan<byte> request)
    {
        // RFC 6886 version negotiation intentionally has OP=0, not response-bit 128.
        if (b.Length == 8 && b[0] == 0 && b[1] == 0 && U16(b, 2) == 1) return new(0, U32(b, 4), null, NatPmpFallback: true);
        if (b.Length is < 60 or > 1100 || b.Length % 4 != 0 || b[0] != 2 || b[1] != 0x81 ||
            !b.Slice(24, 12).SequenceEqual(request.Slice(24, 12)) || b[36] != request[36] || U16(b, 40) != U16(request, 40)) return null;
        for (int pos = 60; pos < b.Length;) {
            if (b.Length - pos < 4) return null;
            int length = U16(b, pos + 2), next = pos + 4 + ((length + 3) & ~3);
            // RFC 6887 §7.3: clients ignore unrecognized response options,
            // including mandatory-range codes. Structural validity still matters.
            if (next > b.Length) return null;
            pos = next;
        }
        uint lifetime = U32(b, 4), epoch = U32(b, 8);
        if (b[3] != 0) return new(lifetime, epoch, null, b[3]);
        bool deleting = U32(request, 4) == 0;
        if (deleting != (lifetime == 0)) return null; // Ignore delayed create replies during deletion.
        var address = new IPAddress(b.Slice(44, 16));
        if (!deleting && (!address.IsIPv4MappedToIPv6 || address.MapToIPv4().Equals(IPAddress.Any) || U16(b, 42) == 0)) return null;
        return new(lifetime, epoch, deleting ? null : new(address.MapToIPv4(), U16(b, 42)));
    }
    public static PortControlReply? ParsePmp(ReadOnlySpan<byte> b, ReadOnlySpan<byte> request, IPAddress? externalAddress)
    {
        bool addressQuery = request.Length == 2;
        if (b.Length != (addressQuery ? 12 : 16) || b[0] != 0 || b[1] != (request[1] | 128) ||
            !addressQuery && U16(b, 8) != U16(request, 4)) return null;
        ushort error = U16(b, 2); uint epoch = U32(b, 4);
        if (error != 0) return new(0, epoch, null, error);
        if (addressQuery) {
            var address = new IPAddress(b.Slice(8, 4));
            return address.Equals(IPAddress.Any) ? null : new(0, epoch, new(address, 0));
        }
        uint lifetime = U32(b, 12); int port = U16(b, 10);
        if (externalAddress == null || lifetime == 0 || port == 0) return null;
        return new(lifetime, epoch, new(externalAddress, port));
    }
}

internal static class PortControlTiming
{
    public static double InitialRetry(PortControlKind kind, double random) => kind == PortControlKind.Pcp ? 3 * (0.9 + .2 * random) : .25;
    public static double NextRetry(PortControlKind kind, double previous, double random) => kind == PortControlKind.Pcp ? Math.Min(1024, previous * 2) * (.9 + .2 * random) : Math.Min(64, previous * 2);
    public static double PcpRenewFraction(int round, double random) { double part = Math.Pow(.5, Math.Clamp(round, 1, 30)); return 1 - part + part * .25 * random; }
    public static bool EpochChanged(PortControlKind kind, uint prior, uint current, double elapsed)
    {
        if (kind == PortControlKind.NatPmp) return current + 2d < prior + elapsed * .875;
        if (current + 1L < prior) return true;
        long clientDelta = (long)elapsed, serverDelta = (long)current - prior;
        return clientDelta + 2 < serverDelta - serverDelta / 16 || serverDelta + 2 < clientDelta - clientDelta / 16;
    }
}
