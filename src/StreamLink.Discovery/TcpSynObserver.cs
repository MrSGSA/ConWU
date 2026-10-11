using System.Diagnostics;
using System.Net;
using StreamLink.Core;

namespace StreamLink.Discovery;

// No listener, handshake, callback, relay or payload storage. The only wire
// evidence retained is the source tuple of an authorized, short-lived SYN probe.
public sealed class TcpSynObserver
{
    sealed class Probe(TcpProbeSpec spec, TcpObserverPoint point)
    {
        public readonly TcpProbeSpec Spec = spec;
        public readonly TcpObserverPoint Point = point;
        public string? Source;
        public long? ObservedAt;
        public int Duplicates;
        public bool Ambiguous;
    }
    sealed record Ticket(string Network, int Slot, string Device, Guid Boot, byte[] Fingerprint,
        Guid Id, long Start, long Expires, Probe[] Probes);
    readonly object gate = new();
    readonly Dictionary<Guid, Ticket> tickets = [];
    readonly TcpObserverPoint[] points;
    readonly Guid epoch = Guid.NewGuid();
    bool available;
    public TcpSynObserver(TcpObserverPoint[] points) { TcpObserverProtocol.ValidatePoints(points); this.points = points.Select(p => p with { Endpoint = TcpObserverProtocol.Endpoint(p.Endpoint).ToString() }).ToArray(); }
    public bool Available { get { lock (gate) return available; } }
    // Production only sets ready after the raw socket has an attached, locked filter.
    public void SetAvailable(bool value) { lock (gate) available = value; }
    void Prune()
    {
        foreach (var id in tickets.Where(p => Stopwatch.GetElapsedTime(p.Value.Start).TotalSeconds >= TcpObserverProtocol.RetentionSeconds).Select(p => p.Key).ToArray()) tickets.Remove(id);
    }
    public (int Status, TcpObserverReply? Reply) Request(string network, TcpObserverRequest request)
    {
        lock (gate) {
            Prune();
            if (!available) return (503, null);
            if (request.Operation == "catalog") return (200, new(1, epoch, Guid.Empty, 0, points, []));
            var hash = TcpObserverProtocol.Fingerprint(network, request);
            if (request.Operation == "register") {
                if (tickets.TryGetValue(request.TicketId, out var existing)) {
                    if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(hash, existing.Fingerprint)) return (409, null);
                    return (200, Reply(existing)); // Identical HTTP retry never renews the window.
                }
                if (tickets.Count >= 128 || tickets.Values.Count(t => t.Network == network && t.Slot == request.Slot) >= 2) return (429, null);
                if (request.Probes.Any(p => !points.Any(s => s.Id == p.ObserverId))) return (400, null);
                // Globally reserve ISS+target across the retention interval, including
                // expired captures. A collision cannot be attributed to either member.
                if (request.Probes.Any(p => tickets.Values.Any(t => t.Probes.Any(old => old.Spec.ObserverId == p.ObserverId && old.Spec.Iss == p.Iss)))) return (409, null);
                var added = new Ticket(network, request.Slot, request.Device, request.BootId, hash, request.TicketId,
                    Stopwatch.GetTimestamp(), DateTimeOffset.UtcNow.AddSeconds(TcpObserverProtocol.WindowSeconds).ToUnixTimeMilliseconds(),
                    request.Probes.Select(p => new Probe(p, points.Single(s => s.Id == p.ObserverId))).ToArray());
                tickets.Add(added.Id, added); return (200, Reply(added));
            }
            if (!tickets.TryGetValue(request.TicketId, out var found)) return (404, null);
            if (found.Network != network || found.Slot != request.Slot || found.Device != request.Device || found.Boot != request.BootId) return (403, null);
            return (200, Reply(found));
        }
    }
    TcpObserverReply Reply(Ticket t) => new(1, epoch, t.Id, t.Expires, [], t.Probes.Select(p => new TcpSynEvidence(
        p.Spec.ProbeId, p.Point.Id, p.Point.Endpoint, p.Ambiguous ? "Ambiguous" : p.Source != null ? "SynObserved" :
        Stopwatch.GetElapsedTime(t.Start).TotalSeconds >= TcpObserverProtocol.WindowSeconds ? "NotObserved" : "Pending",
        p.Ambiguous ? null : p.Source, p.ObservedAt, p.Duplicates)).ToArray());
    public void Observe(ReadOnlySpan<byte> packet)
    {
        if (!TcpShapeSyn.Read(packet, out var source, out var target, out uint iss)) return;
        lock (gate) {
            if (!available) return;
            Prune();
            foreach (var t in tickets.Values) {
                if (Stopwatch.GetElapsedTime(t.Start).TotalSeconds >= TcpObserverProtocol.WindowSeconds) continue;
                foreach (var p in t.Probes) {
                    if (p.Spec.Iss != iss || p.Point.Endpoint != target.ToString()) continue;
                    string seen = source.ToString();
                    if (p.Source == null) { p.Source = seen; p.ObservedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); }
                    else if (p.Source != seen) p.Ambiguous = true;
                    else p.Duplicates = Math.Min(p.Duplicates + 1, 255);
                }
            }
        }
    }
}
