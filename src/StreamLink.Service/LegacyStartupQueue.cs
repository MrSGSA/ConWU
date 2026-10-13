using StreamLink.Core;

namespace StreamLink.Service;

// Process creation and capability scanning can block synchronously. Keep them
// outside the Runner tick, with one queued startup owner for the whole process.
// A cancelled in-flight constructor is joined and its result disposed; it can
// never publish a late candidate or leak a Job/native child after shutdown.
internal sealed class LegacyStartupQueue
{
    internal static LegacyStartupQueue Shared { get; } = new();
    readonly SemaphoreSlim slot = new(1, 1);
    int waiting;
    internal async Task<IMeshTransport> Start(Func<IMeshTransport> create, CancellationToken token)
    {
        if (Interlocked.Increment(ref waiting) > 16) {
            Interlocked.Decrement(ref waiting); throw new IOException("BudgetExhausted: native startup queue is full");
        }
        try { await slot.WaitAsync(token); }
        finally { Interlocked.Decrement(ref waiting); }
        try {
            token.ThrowIfCancellationRequested();
            var result = await Task.Run(() => { token.ThrowIfCancellationRequested(); return create(); }, CancellationToken.None);
            if (token.IsCancellationRequested) { result.Dispose(); token.ThrowIfCancellationRequested(); }
            return result;
        } finally { slot.Release(); }
    }
}
