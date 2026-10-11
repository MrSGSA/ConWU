using System.Diagnostics;

namespace StreamLink.Core;

// One local attempt may probe several authorized TCP tuples. They share a
// deadline and control allowance; a new worker never buys another round.
public sealed class NativeAttemptGroup
{
    readonly object gate = new();
    readonly Func<bool> claimFirstProbe;
    readonly TaskCompletionSource rejected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    long started;
    bool checkedClaim, claimed;
    public TraversalControlRound ControlRound { get; }
    public bool ClaimRejected { get { lock (gate) return checkedClaim && !claimed; } }
    public bool Claimed { get { lock (gate) return claimed; } }
    internal Task Rejected => rejected.Task;
    public TimeSpan Remaining { get { lock (gate) return started == 0 ? TimeSpan.Zero : TimeSpan.FromMilliseconds(TraversalLimits.SoRoundMs) - Stopwatch.GetElapsedTime(started); } }
    public NativeAttemptGroup(TraversalResources machine, Func<bool> claimFirstProbe, long roundStartedAt = 0, TraversalControlRound? controlRound = null)
    {
        if (roundStartedAt < 0 || roundStartedAt > Stopwatch.GetTimestamp()) throw new ArgumentOutOfRangeException(nameof(roundStartedAt));
        if (controlRound != null && !ReferenceEquals(controlRound.Machine, machine)) throw new ArgumentException("Round belongs to another machine budget");
        started = roundStartedAt; ControlRound = controlRound ?? new(machine); this.claimFirstProbe = claimFirstProbe ?? throw new ArgumentNullException(nameof(claimFirstProbe));
    }
    internal long Join(long timestamp)
    {
        lock (gate) {
            if (timestamp <= 0) throw new ArgumentOutOfRangeException(nameof(timestamp));
            if (started == 0) started = timestamp;
            return started;
        }
    }
    // Called only after the first packet has obtained a control-budget token,
    // at the broker injection boundary, never at queue/Prepare/Start time.
    internal bool Claim()
    {
        lock (gate) {
            if (started == 0 || Stopwatch.GetElapsedTime(started).TotalMilliseconds >= TraversalLimits.SoRoundMs) return false;
            if (!checkedClaim) {
                checkedClaim = true;
                try { claimed = claimFirstProbe(); }
                finally { if (!claimed) rejected.TrySetResult(); }
            }
            return claimed;
        }
    }
}
