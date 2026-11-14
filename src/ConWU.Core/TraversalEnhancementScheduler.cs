namespace StreamLink.Core;

public enum TraversalEnhancementKind { TcpCalibration, TcpPrediction, UdpExploration }
// Local ownership context. This object is never a peer-supplied admission token.
public sealed record TraversalEnhancementScope(string Network, string LocalNode, string RemoteNode, Guid NetworkGeneration);
public sealed record TraversalEnhancementUsage(int Active, int Waiting, int PeakWaiting, long Granted, long Cancelled, long CoolingDown,
    TraversalEnhancementKind? Running, double LastQueueMs, double TotalQueueMs, double MaximumQueueMs);

// A machine owns one scheduler across TCP/UDP and peers. Waiting holds no
// endpoint resources. FIFO grants are bounded and cancelled waiters leave the
// queue; sampling intervals must be outside the lease.
public sealed class TraversalEnhancementScheduler(TimeProvider? clock = null)
{
    readonly object gate = new();
    readonly TimeProvider time = clock ?? TimeProvider.System;
    readonly LinkedList<Waiter> waiting = [];
    readonly Dictionary<TraversalEnhancementScope, long> failures = [];
    Lease? active;
    int peakWaiting;
    long granted, cancelled, coolingDown;
    double lastQueueMs, totalQueueMs, maximumQueueMs;
    public const int MaximumWaiters = 16, FailureCooldownMs = 300000;
    sealed class Waiter(TraversalEnhancementScope scope, TraversalEnhancementKind kind, CancellationToken token, long began)
    {
        public readonly TraversalEnhancementScope Scope = scope;
        public readonly TraversalEnhancementKind Kind = kind;
        public readonly CancellationToken Token = token;
        public readonly long Began = began;
        public readonly TaskCompletionSource<Lease> Completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public LinkedListNode<Waiter>? Node;
        public Lease? Granted;
    }
    void Validate(TraversalEnhancementScope scope, TraversalEnhancementKind kind)
    {
        if (!Enum.IsDefined(kind) || scope.NetworkGeneration == Guid.Empty || string.IsNullOrWhiteSpace(scope.Network) || scope.Network.Length > 128 ||
            string.IsNullOrWhiteSpace(scope.LocalNode) || scope.LocalNode.Length > 128 || string.IsNullOrWhiteSpace(scope.RemoteNode) ||
            scope.RemoteNode.Length > 128 || scope.LocalNode == scope.RemoteNode) throw new ArgumentException("增强任务的本地身份或出口代次无效");
        foreach (var expired in failures.Where(p => time.GetElapsedTime(p.Value).TotalMilliseconds >= FailureCooldownMs).Select(p => p.Key).ToArray()) failures.Remove(expired);
        if (kind == TraversalEnhancementKind.UdpExploration && failures.TryGetValue(scope, out long failed)) {
            coolingDown++; throw new IOException($"EnhancementCoolingDown：同设备对/出口 UDP 探索约 {(FailureCooldownMs - time.GetElapsedTime(failed).TotalMilliseconds + 999) / 1000:F0} 秒后可重试");
        }
    }
    Lease Grant(TraversalEnhancementScope scope, TraversalEnhancementKind kind, double queueMs = 0)
    {
        granted++; lastQueueMs = queueMs; totalQueueMs += queueMs; maximumQueueMs = Math.Max(maximumQueueMs, queueMs);
        return active = new(this, scope, kind);
    }
    public Lease? TryEnter(TraversalEnhancementScope scope, TraversalEnhancementKind kind)
    {
        lock (gate) { Validate(scope, kind); return active == null && waiting.Count == 0 ? Grant(scope, kind) : null; }
    }
    public async Task<Lease> Enter(TraversalEnhancementScope scope, TraversalEnhancementKind kind, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); Waiter request;
        lock (gate) {
            Validate(scope, kind);
            if (active == null && waiting.Count == 0) return Grant(scope, kind);
            if (waiting.Count >= MaximumWaiters) throw new IOException("BudgetExhausted：全机增强任务队列已满");
            request = new(scope, kind, token, time.GetTimestamp()); request.Node = waiting.AddLast(request); peakWaiting = Math.Max(peakWaiting, waiting.Count);
        }
        try {
            var lease = await request.Completion.Task.WaitAsync(token);
            token.ThrowIfCancellationRequested(); return lease;
        } catch {
            Lease? grant;
            lock (gate) {
                if (request.Node?.List != null) { waiting.Remove(request.Node); cancelled++; }
                request.Completion.TrySetCanceled(token); grant = request.Granted;
            }
            grant?.Dispose(); throw;
        }
    }
    void Release(Lease lease)
    {
        lock (gate) {
            if (!ReferenceEquals(active, lease)) return;
            active = null;
            while (waiting.First is {} first) {
                waiting.RemoveFirst(); var next = first.Value;
                if (next.Token.IsCancellationRequested) { cancelled++; next.Completion.TrySetCanceled(next.Token); continue; }
                // A queued attempt must not bypass a failure recorded while it
                // was waiting. Keep TCP independent of UDP-specific cooldown.
                try { Validate(next.Scope, next.Kind); }
                catch (IOException ex) { next.Completion.TrySetException(ex); continue; }
                next.Granted = Grant(next.Scope, next.Kind, time.GetElapsedTime(next.Began).TotalMilliseconds); next.Completion.TrySetResult(next.Granted); break;
            }
        }
    }
    void Failed(Lease lease)
    {
        lock (gate) {
            if (!ReferenceEquals(active, lease) || lease.Kind != TraversalEnhancementKind.UdpExploration) return;
            failures[lease.Scope] = time.GetTimestamp();
            if (failures.Count > 256) failures.Remove(failures.MinBy(p => p.Value).Key);
        }
    }
    public TraversalEnhancementUsage Usage() { lock (gate) return new(active == null ? 0 : 1, waiting.Count, peakWaiting, granted, cancelled, coolingDown,
        active?.Kind, lastQueueMs, totalQueueMs, maximumQueueMs); }
    public sealed class Lease : IDisposable
    {
        readonly TraversalEnhancementScheduler owner;
        internal readonly TraversalEnhancementScope Scope;
        public TraversalEnhancementKind Kind { get; }
        int disposed, failed;
        internal Lease(TraversalEnhancementScheduler owner, TraversalEnhancementScope scope, TraversalEnhancementKind kind)
        { this.owner = owner; Scope = scope; Kind = kind; }
        // Call only after an actual attempt failed, not for cancellation,
        // resource preparation failure or absence of stable-endpoint evidence.
        public void Failed() { if (Volatile.Read(ref disposed) == 0 && Interlocked.Exchange(ref failed, 1) == 0) owner.Failed(this); }
        public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) == 0) owner.Release(this); }
    }
}
