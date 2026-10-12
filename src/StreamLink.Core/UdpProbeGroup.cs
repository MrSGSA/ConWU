using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace StreamLink.Core;

// Local experimental round shared by every source. Not an EIM detector and
// not a permission to scan: the future product collector must supply verified
// stability/peer authorization before preparing this internal mechanism.
internal sealed class UdpProbeGroup : IDisposable
{
    readonly object gate = new();
    readonly byte[] cookie = RandomNumberGenerator.GetBytes(32);
    readonly List<Guid> sources = [];
    readonly HashSet<Guid> retired = [];
    readonly HashSet<Guid> sourcesSent = [];
    readonly HashSet<int> guessed = [];
    readonly int[] ports;
    readonly IPAddress peer;
    readonly IPEndPoint? fixedPeer;
    Guid winner;
    int cursor, targetCursor;
    long lastDrive;
    public bool Stable { get; }
    public int RequestedSources { get; init; }
    public TraversalControlRound Round { get; }
    public long Started { get; private set; }
    public TimeSpan Remaining => Started == 0 ? TimeSpan.FromMilliseconds(DurationMs) : TimeSpan.FromMilliseconds(DurationMs) - Stopwatch.GetElapsedTime(Started);
    // A preselected source still needs the full-size authenticated Select/Ack.
    // Less than one such datagram cannot complete this wire profile.
    public bool Exhausted => Round.Packets >= PacketLimit || Round.Bytes > ByteLimit - TraversalLimits.UdpRequiredPayload;
    public const int DurationMs = 12000, PacketLimit = 512, ByteLimit = 256 * 1024;
    public UdpProbeGroup(TraversalResources machine, bool stable, IPAddress peer, IPEndPoint? fixedPeer, int[] ports)
    {
        if (peer.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || peer.GetAddressBytes()[0] == 0 ||
            peer.GetAddressBytes()[0] >= 224 || stable && (fixedPeer != null || ports.Length is < 1 or > 256) ||
            !stable && (fixedPeer == null || !fixedPeer.Address.Equals(peer) || fixedPeer.Port <= 0 || ports.Length != 0) ||
            ports.Any(p => p is < 1 or > 65535) || ports.Distinct().Count() != ports.Length) throw new ArgumentException("概率轮次目标无效");
        Stable = stable; this.peer = new(peer.GetAddressBytes()); this.fixedPeer = fixedPeer == null ? null : new(this.peer, fixedPeer.Port);
        this.ports = ports.ToArray(); Round = new(machine, PacketLimit, ByteLimit);
    }
    public void Register(Guid source)
    {
        lock (gate) {
            if (Started != 0 || source == Guid.Empty || sources.Contains(source) || sources.Count >= (Stable ? 1 : 32)) throw new IOException("探索源资源集合已固定或超限");
            sources.Add(source);
        }
    }
    // The first observation starts the same clock later used by checks and
    // nomination. Repeated observations/activation never renew that deadline.
    public void Begin() { lock (gate) { if (sources.Count == 0) throw new IOException("探索没有资源"); if (Started == 0) Started = Stopwatch.GetTimestamp(); } }
    public bool Allows(IPEndPoint endpoint) => endpoint.Address.Equals(peer) && endpoint.Port > 0 && (Stable || endpoint.Equals(fixedPeer));
    public bool Drive(Guid source)
    {
        lock (gate) {
            long now = Environment.TickCount64;
            for (int i = 0; i < sources.Count && retired.Contains(sources[cursor]); i++) cursor = (cursor + 1) % sources.Count;
            if (retired.Contains(source) || sources[cursor] != source || now - lastDrive < 25) return false;
            cursor = (cursor + 1) % sources.Count; lastDrive = now; return true;
        }
    }
    public void Retire(Guid source) { lock (gate) retired.Add(source); }
    public IPEndPoint? NextGuess()
    {
        lock (gate) {
            while (targetCursor < ports.Length && guessed.Contains(ports[targetCursor])) targetCursor++;
            return targetCursor == ports.Length ? null : new(peer, ports[targetCursor]);
        }
    }
    public byte[] Nonce(IPEndPoint endpoint) => HMACSHA256.HashData(cookie, Encoding.ASCII.GetBytes(endpoint.ToString()))[..16];
    public bool BlindResponse(IPEndPoint endpoint, ReadOnlySpan<byte> nonce)
    {
        lock (gate) return Stable && guessed.Contains(endpoint.Port) && Allows(endpoint) && CryptographicOperations.FixedTimeEquals(nonce, Nonce(endpoint));
    }
    public void Admitted(byte kind, IPEndPoint endpoint)
    {
        lock (gate) if (Stable && kind == 1 && ports.Contains(endpoint.Port)) guessed.Add(endpoint.Port);
    }
    public void Sent(Guid source) { lock (gate) sourcesSent.Add(source); }
    public bool PeerProbed { get { lock (gate) return sourcesSent.Count != 0; } }
    public bool Commit(Guid source)
    {
        lock (gate) { if (!sources.Contains(source) || winner != Guid.Empty && winner != source) return false; winner = source; return true; }
    }
    public bool IsWinner(Guid source) { lock (gate) return winner == source; }
    public bool Lost(Guid source) { lock (gate) return winner != Guid.Empty && winner != source; }
    public object Snapshot() { lock (gate) return new { sourcesRequested = RequestedSources, sourcesOpened = sources.Count, sourcesSent = sourcesSent.Count,
        confirmedExternalMappings = (int?)null, uniqueGuessedPorts = guessed.Count, packetsAdmitted = Round.Packets,
        bytesAdmitted = Round.Bytes, winnerSource = winner, elapsedMs = Started == 0 ? 0 : Stopwatch.GetElapsedTime(Started).TotalMilliseconds }; }
    public void Dispose() => CryptographicOperations.ZeroMemory(cookie);
}
