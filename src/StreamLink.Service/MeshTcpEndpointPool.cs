using System.Diagnostics;
using System.Net;
using StreamLink.Core;

namespace StreamLink.Service;

// One retained helper/capture owner per actual source address and reflector.
// Candidate references and native worker references have separate lifetimes.
internal sealed class MeshTcpEndpointPool(Guid generation,
    Func<IPEndPoint, IPEndPoint, IEndpointPacketIo> open,
    TraversalResources? resources = null, EgressPacer? pacer = null) : IAsyncDisposable
{
    readonly SemaphoreSlim gate = new(1);
    readonly Dictionary<string, Entry> entries = [];
    readonly List<TcpCaptureOwner> retiring = [];
    readonly CancellationTokenSource stop = new();
    readonly TraversalResources budget = resources ?? TraversalResources.Shared;
    Task maintenance = Task.CompletedTask;
    bool started, disposed;
    sealed class Entry(TcpEndpointLease lease, TcpCaptureOwner owner)
    {
        public TcpEndpointLease Lease = lease;
        public TcpCaptureOwner Owner = owner;
        public long ObservedAt;
    }
    public sealed class Use(TcpEndpointLease lease, TcpCaptureOwner owner, TcpEndpointLease.Reference reference, IPEndPoint observed) : IDisposable
    {
        public TcpEndpointLease Lease => lease;
        public TcpCaptureOwner Owner => owner;
        public IPEndPoint Observed { get; } = new(observed.Address, observed.Port);
        public void Dispose() => reference.Dispose();
    }
    // Caller cancellation invalidates only a started/ambiguous STUN transaction,
    // never a healthy native path using that source resource.
    public async Task<Use> Acquire(IPAddress source, IPEndPoint reflector, CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
        await gate.WaitAsync(linked.Token);
        try {
            ObjectDisposedException.ThrowIf(disposed, this);
            string key = source + "/" + reflector;
            entries.TryGetValue(key, out var entry);
            if (entry != null && (!entry.Lease.QueryUsable || entry.Owner.Failed)) {
                entries.Remove(key); await Retire(entry); entry = null;
            }
            if (entry == null) {
                using var connect = CancellationTokenSource.CreateLinkedTokenSource(linked.Token); connect.CancelAfter(3500);
                var lease = await TcpEndpointLease.Open(new(source, 0), reflector, generation, connect.Token);
                try { entry = new(lease, new(lease, generation, open, pacer)); await entry.Owner.Ready; }
                catch { lease.Dispose(); throw; }
                entries.Add(key, entry);
            }
            if (!started) { started = true; maintenance = Maintain(); }
            var reference = entry.Lease.AcquireAttempt(generation);
            try {
                while (!budget.TrySend(20)) await Task.Delay(25, linked.Token);
                var observation = await reference.Observe(linked.Token); entry.ObservedAt = Stopwatch.GetTimestamp();
                return new(entry.Lease, entry.Owner, reference, observation.Public);
            } catch { reference.Dispose(); throw; }
        } finally { gate.Release(); }
    }
    async Task Retire(Entry entry)
    {
        retiring.RemoveAll(o => o.Closed.IsCompleted);
        retiring.Add(entry.Owner);
        await entry.Owner.DisposeAsync(); // Existing workers retain capture and tuple ownership.
        entry.Lease.Dispose();
    }
    async Task Maintain()
    {
        try {
            while (true) {
                await Task.Delay(1000, stop.Token); await gate.WaitAsync(stop.Token);
                try {
                    foreach (var item in entries.ToArray()) {
                        var entry = item.Value;
                        if (!entry.Lease.QueryUsable || entry.Owner.Failed) { entries.Remove(item.Key); await Retire(entry); continue; }
                        if (Stopwatch.GetElapsedTime(entry.ObservedAt).TotalSeconds < 15 || !budget.TrySend(20, maintenance: true)) continue;
                        using var reference = entry.Lease.AcquireAttempt(generation);
                        try { await reference.Observe(stop.Token); entry.ObservedAt = Stopwatch.GetTimestamp(); }
                        catch (Exception ex) when (ex is IOException or OperationCanceledException or System.Net.Sockets.SocketException) {
                            entries.Remove(item.Key); await Retire(entry);
                        }
                    }
                } finally { gate.Release(); }
            }
        } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel();
        await maintenance;
        await gate.WaitAsync();
        try {
            if (disposed) return;
            disposed = true;
            foreach (var entry in entries.Values) await Retire(entry);
            entries.Clear();
        } finally { gate.Release(); }
        // MeshRunner disposes paths before its factory; no worker may survive
        // service shutdown. Retiring capture stays owned until workers really exit.
        await Task.WhenAll(retiring.Select(o => o.Closed));
    }
}
