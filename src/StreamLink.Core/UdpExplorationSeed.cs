using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;

namespace StreamLink.Core;

// A real single-receiver candidate resource held before Offer/Ready. Its first
// observation starts the same twelve-second clock and packet ledger later used
// by all exploratory sources, qualification and nomination.
internal sealed class UdpExplorationSeed : IAsyncDisposable
{
    readonly object gate = new();
    bool transferred, disposed;
    long began;
    public UdpTraversal Owner { get; }
    public TraversalControlRound Round { get; }
    public long Began { get { lock (gate) return began; } }
    public TimeSpan Remaining => Began == 0 ? TimeSpan.FromMilliseconds(UdpProbeGroup.DurationMs) : TimeSpan.FromMilliseconds(UdpProbeGroup.DurationMs) - Stopwatch.GetElapsedTime(Began);
    public UdpExplorationSeed(UdpTraversal owner, TraversalResources machine)
    {
        Owner = owner; Round = new(machine, UdpProbeGroup.PacketLimit, UdpProbeGroup.ByteLimit);
        owner.AttachExplorationSeed(this);
    }
    public bool SendAdmission(int bytes)
    {
        lock (gate) {
            if (disposed || transferred) return false;
            if (began == 0) began = Stopwatch.GetTimestamp();
            return Remaining > TimeSpan.Zero && Round.TrySend(bytes, false);
        }
    }
    internal void Transfer(UdpProbeGroup group, TraversalAttemptContext context, Guid generation, byte[] sharedKey)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed || transferred, this);
            if (began == 0 || Remaining <= TimeSpan.Zero || !ReferenceEquals(group.Round, Round)) throw new IOException("UDP 探索种子已过期或账本不匹配");
            Owner.AdoptExploration(this, group, context, generation, sharedKey); transferred = true;
        }
    }
    public async ValueTask DisposeAsync()
    {
        bool close; lock (gate) { if (disposed) return; disposed = true; close = !transferred; }
        if (close) await Owner.DisposeAsync();
    }
}

public sealed partial class UdpTraversal
{
    UdpExplorationSeed? explorationSeed;
    internal void AttachExplorationSeed(UdpExplorationSeed seed)
    {
        lock (gate) {
            if (disposed != 0 || started != 0 || preparedAttached || pathAttached || group != null || explorationSeed != null ||
                queries.Count != 0 || observing.CurrentCount != 1 || !ReferenceEquals(seed.Owner, this) || !ReferenceEquals(seed.Round.Machine, resources))
                throw new IOException("UDP 种子只能接入尚未使用的同一资源");
            explorationSeed = seed;
        }
    }
    internal void AdoptExploration(UdpExplorationSeed seed, UdpProbeGroup owner, TraversalAttemptContext context, Guid expectedGeneration, byte[] sharedKey)
    {
        _ = PathNomination.ContextDigest(context);
        lock (gate) {
            if (disposed != 0 || resourceClosed || started != 0 || begun != 0 || preparedAttached || pathAttached || payloadReaders != 0 || references != 1 ||
                receiving.IsCompleted || queries.Count != 0 || observing.CurrentCount != 1 || group != null || !ReferenceEquals(seed, explorationSeed) ||
                generation != expectedGeneration || new Guid(attempt) != context.AttemptId || !context.UdpExploration || context.Profile != TraversalProfile.UdpDirect ||
                sharedKey.Length != 32 || Local.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || !socket.DontFragment)
                throw new IOException("UDP 探索接管必须保留当前轮次唯一接收者与源端点");
            byte[] scoped = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedKey, 32, PathNomination.ContextDigest(context), "streamlink-udp-exploration-v1"u8.ToArray());
            byte[] checkKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, scoped, 32, attempt, "streamlink-udp-check-v2"u8.ToArray());
            try {
                owner.Register(probeSource);
                CryptographicOperations.ZeroMemory(key); checkKey.CopyTo(key, 0);
                localSlot = context.ProtocolClient ? (byte)1 : (byte)2; remoteSlot = context.ProtocolClient ? (byte)2 : (byte)1;
                group = owner; round = owner.Round;
            } finally { CryptographicOperations.ZeroMemory(scoped); CryptographicOperations.ZeroMemory(checkKey); }
        }
    }
}
