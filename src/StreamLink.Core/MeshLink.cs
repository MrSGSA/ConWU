using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace StreamLink.Core;

public sealed record MeshReceive(bool Authenticated, byte[]? Reply = null, byte[]? Packet = null, long? PongToken = null, byte[]? Control = null, byte[]? Diagnostic = null, byte[]? Synchronization = null);

// Authenticated datagrams with independent directional/session keys. No data
// retransmission or in-order delivery: reordered packets within the replay
// window are immediately delivered. Only control handshakes are retried.
public sealed class MeshLink : IDisposable
{
    public const int Mtu = 1280, HeaderSize = 48, Overhead = HeaderSize + 16;
    readonly object gate = new();
    readonly byte local, remote;
    readonly byte[] secret, epoch = RandomNumberGenerator.GetBytes(16);
    AesGcm sendCipher;
    AesGcm? receiveCipher;
    byte[]? remoteEpoch;
    readonly HashSet<string> retired = [];
    readonly ulong[] seen = new ulong[4096];
    ulong counter, highest;
    long lastReceive, pendingPing;
    bool disposed;
    public double? RttMs { get; private set; }
    internal Guid SendEpoch{get{lock(gate)return new(epoch);}}
    internal Guid? ReceiveEpoch{get{lock(gate)return remoteEpoch==null?null:new Guid(remoteEpoch);}}
    public bool Connected { get { lock (gate) return !disposed && remoteEpoch != null && lastReceive != 0 && Stopwatch.GetElapsedTime(lastReceive).TotalSeconds < 12; } }
    public MeshLink(int localSlot, int remoteSlot, byte[] sharedKey)
    {
        if (localSlot is < 1 or > 254 || remoteSlot is < 1 or > 254 || localSlot == remoteSlot || sharedKey.Length != 32) throw new ArgumentException("链路身份无效");
        local = (byte)localSlot; remote = (byte)remoteSlot; secret = sharedKey.ToArray(); sendCipher = Cipher(epoch, local, remote);
    }
    AesGcm Cipher(ReadOnlySpan<byte> session, int from, int to)
    {
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32, session.ToArray(), Encoding.ASCII.GetBytes($"streamlink-datagram-v4/{from}/{to}"));
        try { return new AesGcm(key, 16); } finally { CryptographicOperations.ZeroMemory(key); }
    }
    byte[] Encode(byte kind, ReadOnlySpan<byte> destinationEpoch, ReadOnlySpan<byte> payload)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (payload.Length > Mtu || counter == ulong.MaxValue) throw new IOException("数据包或会话超出限制");
        byte[] result = new byte[Overhead + payload.Length]; "SLM4"u8.CopyTo(result);
        result[4] = kind; result[5] = local; result[6] = remote; epoch.CopyTo(result, 8); destinationEpoch.CopyTo(result.AsSpan(24, 16));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(40), ++counter);
        Span<byte> nonce = stackalloc byte[12]; nonce.Clear(); result.AsSpan(40, 8).CopyTo(nonce[4..]);
        sendCipher.Encrypt(nonce, payload, result.AsSpan(HeaderSize, payload.Length), result.AsSpan(HeaderSize + payload.Length, 16), result.AsSpan(0, HeaderSize));
        return result;
    }
    public byte[] Hello() { lock (gate) return Encode(1, new byte[16], []); }
    public byte[]? Ping() => Ping(out _);
    public byte[]? Ping(out long nonce)
    {
        lock (gate) {
            nonce = 0;
            if (remoteEpoch == null) return null;
            pendingPing = nonce = Stopwatch.GetTimestamp(); Span<byte> body = stackalloc byte[8]; BinaryPrimitives.WriteInt64BigEndian(body, pendingPing); return Encode(5, remoteEpoch, body);
        }
    }
    public byte[]? Data(ReadOnlySpan<byte> packet) { lock (gate) return Connected ? Encode(4, remoteEpoch!, packet) : null; }
    internal byte[]? Synchronize(ReadOnlySpan<byte> payload) { lock(gate) return Connected ? Encode(9,remoteEpoch!,payload) : null; }
    // Only negotiated traversal peers use kind 7. It shares this member's one
    // AEAD counter, session epoch and replay window across every candidate path.
    public byte[]? Control(ReadOnlySpan<byte> payload)
    {
        if (payload.Length is < 1 or > 256) throw new ArgumentException("控制消息大小无效");
        lock (gate) return Connected ? Encode(7, remoteEpoch!, payload) : null;
    }
    // Diagnostic payloads share the logical peer's epoch/counter/replay window.
    // Router permission and a bounded measurement ticket remain separate gates.
    internal byte[]? Diagnostic(ReadOnlySpan<byte> payload)
    {
        if(payload.Length is<512 or>Mtu)throw new ArgumentException("Diagnostic payload outside bounded MTU");
        lock(gate)return Connected?Encode(8,remoteEpoch!,payload):null;
    }
    // A separate nonce for path validation; does not disturb the RTT heartbeat.
    // Uses the existing authenticated Ping/Pong wire format (mesh protocol 4).
    public byte[]? ProbePath(long challenge)
    {
        lock (gate) {
            if (remoteEpoch == null) return null;
            Span<byte> body = stackalloc byte[8]; BinaryPrimitives.WriteInt64BigEndian(body, challenge);
            return Encode(5, remoteEpoch, body);
        }
    }
    public MeshReceive Receive(ReadOnlySpan<byte> message)
    {
        lock (gate) {
            if (disposed || message.Length < Overhead || message.Length > Overhead + Mtu || !message[..4].SequenceEqual("SLM4"u8) || message[5] != remote || message[6] != local || message[7] != 0 || message[4] is < 1 or > 9) return new(false);
            byte kind = message[4]; var senderEpoch = message.Slice(8, 16); var targetEpoch = message.Slice(24, 16);
            if (kind == 1 ? targetEpoch.IndexOfAnyExcept((byte)0) >= 0 : !targetEpoch.SequenceEqual(epoch)) return new(false);
            if ((kind is 1 or 2 or 3) && message.Length != Overhead || (kind is 5 or 6) && message.Length != Overhead + 8) return new(false);
            if (kind == 7 && message.Length is < Overhead + 1 or > Overhead + 256) return new(false);
            if (kind == 8 && message.Length is < Overhead + 512 or > Overhead + Mtu) return new(false);
            bool same = remoteEpoch != null && senderEpoch.SequenceEqual(remoteEpoch);
            if (!same && (kind is >=4 and <=9 || retired.Contains(Convert.ToHexString(senderEpoch)))) return new(false);
            ulong sequence = BinaryPrimitives.ReadUInt64BigEndian(message[40..]); if (sequence == 0) return new(false);
            // Hello cannot replace an established session or advance its replay window.
            if (kind != 1 && same && (sequence <= highest && highest - sequence >= (ulong)seen.Length || seen[sequence % (ulong)seen.Length] == sequence)) return new(false);
            byte[] plain = new byte[message.Length - Overhead]; Span<byte> nonce = stackalloc byte[12]; nonce.Clear(); message.Slice(40, 8).CopyTo(nonce[4..]);
            AesGcm? temporary = null;
            try {
                var cipher = same ? receiveCipher! : temporary = Cipher(senderEpoch, remote, local);
                cipher.Decrypt(nonce, message.Slice(HeaderSize, plain.Length), message[^16..], plain, message[..HeaderSize]);
            } catch (CryptographicException) { return new(false); }
            finally { temporary?.Dispose(); }
            if (!same && retired.Count >= 64) {
                // Bound history without ever allowing a retired epoch again:
                // rotate our own challenge and directional key before clearing.
                RandomNumberGenerator.Fill(epoch); sendCipher.Dispose(); sendCipher = Cipher(epoch, local, remote);
                receiveCipher?.Dispose(); receiveCipher = null; remoteEpoch = null; retired.Clear(); Array.Clear(seen);
                counter = highest = 0; lastReceive = pendingPing = 0; RttMs = null;
                return new(false);
            }
            if (kind == 1) return new(true, Encode(2, senderEpoch, []));
            if (!same) {
                if (remoteEpoch != null) retired.Add(Convert.ToHexString(remoteEpoch));
                remoteEpoch = senderEpoch.ToArray(); receiveCipher?.Dispose(); receiveCipher = Cipher(remoteEpoch, remote, local); Array.Clear(seen); highest = 0;
            }
            seen[sequence % (ulong)seen.Length] = sequence; highest = Math.Max(highest, sequence); lastReceive = Stopwatch.GetTimestamp();
            return kind switch {
                2 => new(true, Encode(3, remoteEpoch!, [])),
                4 => new(true, Packet: plain),
                5 => new(true, Encode(6, remoteEpoch!, plain)),
                6 => Pong(plain),
                7 => new(true, Control: plain),
                8 => new(true, Diagnostic: plain),
                9 => new(true, Synchronization: plain),
                _ => new(true)
            };
        }
    }
    MeshReceive Pong(byte[] payload)
    {
        if (pendingPing != 0 && BinaryPrimitives.ReadInt64BigEndian(payload) == pendingPing) { RttMs = Stopwatch.GetElapsedTime(pendingPing).TotalMilliseconds; pendingPing = 0; }
        return new(true, PongToken: BinaryPrimitives.ReadInt64BigEndian(payload));
    }
    public void Dispose() { lock (gate) { if (disposed) return; disposed = true; sendCipher.Dispose(); receiveCipher?.Dispose(); CryptographicOperations.ZeroMemory(secret); } }
}

public static class MeshPackets
{
    public static bool Valid(ReadOnlySpan<byte> packet)
    {
        if (packet.Length is < 20 or > MeshLink.Mtu || packet[0] >> 4 != 4) return false;
        int header = (packet[0] & 15) * 4;
        if (header < 20 || header > packet.Length || BinaryPrimitives.ReadUInt16BigEndian(packet[2..]) != packet.Length || packet[8] == 0) return false;
        uint sum = 0; for (int i = 0; i < header; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(packet[i..]); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        return sum == 65535;
    }
    public static int Destination(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> local)
        => Valid(packet) && packet.Slice(12, 4).SequenceEqual(local) && packet.Slice(16, 3).SequenceEqual(local[..3]) && packet[19] is >= 1 and <= 254 && packet[19] != local[3] ? packet[19] : 0;
    public static bool Accept(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> local, int peer)
        => Valid(packet) && packet.Slice(16, 4).SequenceEqual(local) && packet.Slice(12, 3).SequenceEqual(local[..3]) && packet[15] == peer;
}
