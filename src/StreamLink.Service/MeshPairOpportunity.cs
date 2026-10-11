using StreamLink.Core;

namespace StreamLink.Service;

// One monotonic opportunity per pair, including queueing and preparation.
// A refreshed observation or another method cannot restart its deadline.
internal sealed class MeshPairOpportunity
{
    readonly Dictionary<TraversalProfile, int> rounds = [];
    public Guid Boot { get; private set; }
    public Guid Id { get; private set; }
    public long Began { get; private set; }
    public long Deadline { get; private set; }
    public long RetryAt { get; private set; }
    public bool Open { get; private set; }
    public bool Connected { get; private set; }
    public int Failures { get; private set; }
    public string Outcome { get; private set; } = "";
    public int Count(TraversalProfile kind) => rounds.GetValueOrDefault(kind);
    public static int RoundMs(TraversalProfile kind) => kind switch {
        TraversalProfile.LegacyExplicit => 15000, // existing legacy client validation window
        TraversalProfile.FakeTcpHttpSo => TraversalLimits.SoRoundMs,
        TraversalProfile.UdpDirect => TraversalLimits.UdpRoundMs,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };
    public bool Observe(Guid boot, bool healthy, long now)
    {
        if (Boot != boot) { Boot = boot; Open = Connected = false; RetryAt = 0; Failures = 0; }
        if (healthy) { Open = false; Connected = true; RetryAt = 0; Failures = 0; Outcome = "Selected"; return false; }
        Connected = false;
        if (Open || now < RetryAt) return false;
        Id = Guid.NewGuid(); Began = now; Deadline = now + TraversalLimits.PairOpportunityMs;
        rounds.Clear(); Open = true; Outcome = ""; return true;
    }
    public bool CanBegin(TraversalProfile kind, long now) => Open && Count(kind) < 2 && Deadline - now >= RoundMs(kind);
    public bool Begin(TraversalProfile kind, long now)
    {
        if (!CanBegin(kind, now)) return false;
        rounds[kind] = Count(kind) + 1; return true;
    }
    public TraversalProfile? Next(IEnumerable<TraversalProfile> methods, long now) => methods.Distinct()
        .Where(k => CanBegin(k, now)).OrderBy(Count).ThenBy(k => k).Select(k => (TraversalProfile?)k).FirstOrDefault();
    public bool End(long now, int jitterMs)
    {
        if (!Open) return false;
        Open = false; Failures = Math.Min(Failures + 1, 5); Outcome = "NoDirectPathWithinBudget";
        RetryAt = now + Math.Min(300000, 30000L << (Failures - 1)) + Math.Clamp(jitterMs, 0, 1999);
        return true;
    }
}
