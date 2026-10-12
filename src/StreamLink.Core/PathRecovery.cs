namespace StreamLink.Core;

public sealed record PathRecoverySnapshot(Guid EpisodeId, Guid? PathId, string Trigger, long ElapsedMs,
    long? FirstBusinessMs, long? StableBusinessStartMs, long? StableBusinessConfirmedMs,
    int ConsecutiveProbes, int ProbePackets, int BudgetDeferred, int WindowRestarts, string LastInterruption)
{
    public Guid? FirstBusinessPathId { get; init; }
}

// Local monotonic observations only. Business means authenticated inner IP
// accepted by this node's adapter, never a successful enqueue or just a pong.
// This is a recovery observation, not a throughput/loss or QoS qualification.
// The router lock serializes all calls. No timer, receiver or socket is owned.
internal sealed class PathRecovery(long now)
{
    const int IntervalMs = 300, WindowMs = 3000, FreshMs = 1000, RequiredProbes = 10;
    readonly Dictionary<long, long> pending = [];
    Guid episode = Guid.NewGuid(); Guid? path, firstPath;
    long started = now, lastBusiness, lastPong, lastProbeAttempt = long.MinValue / 2;
    long? first, window, stableStart, confirmed;
    int consecutive, probes, deferred, restarts;
    bool healthy;
    string trigger = "ConnectionRequested", interruption = "";
    public void Select(Guid selected, long at)
    {
        if (path == selected) return;
        if (path != null) Break("PathChanged", at);
        path = selected;
    }
    public void Health(bool value, long at)
    {
        if (healthy && !value) Break("BidirectionalHealthLost", at);
        healthy = value;
    }
    public void Break(string reason, long at)
    {
        if (confirmed != null) {
            episode = Guid.NewGuid(); started = at; first = null; firstPath = null; confirmed = stableStart = null;
            probes = deferred = restarts = 0; trigger = reason;
        }
        ResetWindow(reason);
    }
    void ResetWindow(string reason)
    {
        if (window != null) restarts++;
        window = null; consecutive = 0; pending.Clear(); interruption = reason;
    }
    public void Business(long at)
    {
        if (path == null) return;
        Tick(at); if (first == null) { first = at; firstPath = path; } lastBusiness = at;
        if (confirmed == null) window ??= at;
        Confirm(at);
    }
    public void Tick(long at)
    {
        if (confirmed != null) return;
        if (pending.Values.Any(sent => at - sent >= FreshMs)) ResetWindow("ProbeTimeout");
        if (window != null && at - lastBusiness >= FreshMs) ResetWindow("BusinessObservationIdle");
        Confirm(at);
    }
    public bool ProbeDue(long at)
    {
        Tick(at);
        if (path == null || window == null || confirmed != null || pending.Count >= 4 || at - lastProbeAttempt < IntervalMs) return false;
        lastProbeAttempt = at; return true;
    }
    public void ProbeSent(long nonce, long at) { pending[nonce] = at; probes++; }
    public void ProbeDeferred() { deferred++; }
    public void Pong(long nonce, long at)
    {
        Tick(at);
        if (!pending.Remove(nonce, out long sent) || window == null || sent < window) return;
        consecutive++; lastPong = at; Confirm(at);
    }
    void Confirm(long at)
    {
        if (confirmed != null || !healthy || window == null || at - window < WindowMs || at - lastBusiness >= FreshMs ||
            consecutive < RequiredProbes || at - lastPong >= FreshMs || pending.Count != 0) return;
        stableStart = window; confirmed = at;
    }
    public PathRecoverySnapshot Snapshot(long at) => new(episode, path, trigger, Math.Max(0, at - started),
        first - started, stableStart - started, confirmed - started, consecutive, probes, deferred, restarts, interruption) { FirstBusinessPathId = firstPath };
}
