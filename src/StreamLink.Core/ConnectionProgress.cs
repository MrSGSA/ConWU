namespace StreamLink.Core;

// Observation, not a promise of connectivity. Timers are monotonic durations;
// the UI may count down a retry but must never turn a timer into success.
public sealed record ConnectionProgress(string Phase, string Detail, long ElapsedMs = 0,
    int Attempt = 0, int? RetryInSeconds = null, int? RemainingSeconds = null, bool CanRetry = false);

public sealed record PeerLiveness(string Reason, long? ReceiveAgeMs, long? RoundTripAgeMs);
