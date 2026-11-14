using System.Net;
using StreamLink.Core;

namespace StreamLink.Service;

// One retained helper/capture owner per actual source address and reflector.
// Only that resource's I/O is serialized: an unresponsive reflector must not
// block candidates or keepalives that use a different retained source.
internal sealed class MeshTcpEndpointPool(Guid generation,
    Func<IPEndPoint, IPEndPoint, IEndpointPacketIo> open,
    TraversalResources? resources = null, EgressPacer? pacer = null, TimeProvider? time = null) : IAsyncDisposable
{
    readonly object gate = new();
    readonly Dictionary<string, Slot> slots = [];
    readonly List<TcpCaptureOwner> retiring = [];
    readonly CancellationTokenSource stop = new();
    readonly TraversalResources budget = resources ?? TraversalResources.Shared;
    readonly TimeProvider clock = time ?? TimeProvider.System;
    Task maintenance = Task.CompletedTask;
    Task? closing;
    bool started, disposed;
    sealed class Slot(string key, IPAddress source, IPEndPoint reflector)
    {
        public readonly string Key = key;
        public readonly IPAddress Source = source;
        public readonly IPEndPoint Reflector = new(reflector.Address, reflector.Port);
        public readonly SemaphoreSlim Io = new(1);
        public Entry? Current;
        public int Users;
    }
    sealed class Entry(TcpEndpointLease lease, TcpCaptureOwner owner)
    {
        public readonly TcpEndpointLease Lease = lease;
        public readonly TcpCaptureOwner Owner = owner;
        public IPEndPoint? Observed;
        public long ObservedTick;
        public DateTimeOffset ObservedAt;
    }
    public sealed class Use(TcpEndpointLease lease, TcpCaptureOwner owner, TcpEndpointLease.Reference reference,
        IPEndPoint observed, DateTimeOffset observedAt) : IDisposable
    {
        public TcpEndpointLease Lease => lease;
        public TcpCaptureOwner Owner => owner;
        public IPEndPoint Observed => new(observed.Address, observed.Port);
        // A cached candidate keeps the real query timestamp, not borrow time.
        public DateTimeOffset ObservedAt => observedAt;
        public void Dispose() => reference.Dispose();
    }
    // Cancellation while queued has not touched the helper stream. Cancelling
    // an actual query makes ONLY that flow unusable; active raw sessions retain
    // their original lease and capture references until their own retirement.
    public async Task<Use> Acquire(IPAddress source, IPEndPoint reflector, CancellationToken token, string? isolation = null, bool standby = false)
    {
        token.ThrowIfCancellationRequested();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
        if (isolation != null && !Guid.TryParseExact(isolation, "N", out _)) throw new ArgumentException("A source partition requires the authenticated peer device ID");
        if (standby && isolation == null) throw new ArgumentException("Standby partition requires the authenticated peer ID");
        string key = source + "/" + reflector + "/" + isolation + (standby ? "/standby" : "");
        bool needsRoom;lock(gate)needsRoom=!slots.ContainsKey(key)&&slots.Count>=TraversalLimits.TcpResources;
        // A changed reflector list must not strand healthy but unused helpers
        // forever. Existing borrow/session references continue to prevent eviction.
        if(needsRoom)await PruneUnused(linked.Token);
        Slot slot;
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (!slots.TryGetValue(key, out slot!)) {
                if (slots.Count >= TraversalLimits.TcpResources) throw new IOException("BudgetExhausted：TCP 源端点池已满");
                slots[key] = slot = new(key, source, reflector);
            }
            slot.Users++;
            if (!started) { started = true; maintenance = Maintain(); }
        }
        bool entered = false;
        try {
            await slot.Io.WaitAsync(linked.Token); entered = true;
            linked.Token.ThrowIfCancellationRequested();
            var entry = slot.Current;
            if (entry != null && (!entry.Lease.QueryUsable || entry.Owner.Failed)) {
                slot.Current = null; await Retire(entry); entry = null;
            }
            if (entry == null) {
                using var connect = CancellationTokenSource.CreateLinkedTokenSource(linked.Token); connect.CancelAfter(3500);
                var lease = await TcpEndpointLease.Open(new(slot.Source, 0), slot.Reflector, generation, connect.Token);
                TcpCaptureOwner? owner = null;
                try {
                    owner = new(lease, generation, open, pacer); await owner.Ready.WaitAsync(linked.Token);
                    slot.Current = entry = new(lease, owner);
                } catch {
                    try { if (owner != null) await owner.DisposeAsync(); }
                    finally { lease.Dispose(); }
                    throw;
                }
            }
            var reference = entry.Lease.AcquireAttempt(generation);
            try {
                if (entry.Observed == null || clock.GetElapsedTime(entry.ObservedTick).TotalMilliseconds >= TraversalLimits.TcpCandidateReuseMs) {
                    while (!budget.TrySend(20)) await Task.Delay(25, linked.Token);
                    await Observe(entry, reference, linked.Token);
                }
                linked.Token.ThrowIfCancellationRequested();
                return new(entry.Lease, entry.Owner, reference, entry.Observed!, entry.ObservedAt);
            } catch {
                reference.Dispose();
                // Do not keep a failed, unused helper occupying a scarce slot
                // until the next maintenance tick before trying another server.
                if (!entry.Lease.QueryUsable || entry.Owner.Failed) { slot.Current = null; await Retire(entry); }
                throw;
            }
        } finally {
            if (entered) slot.Io.Release();
            lock (gate) {
                slot.Users--;
                if (slot.Users == 0 && slot.Current == null) slots.Remove(key);
            }
        }
    }
    async Task Observe(Entry entry, TcpEndpointLease.Reference reference, CancellationToken token)
    {
        var observation = await reference.Observe(token);
        entry.Observed = observation.Public; entry.ObservedTick = clock.GetTimestamp(); entry.ObservedAt = clock.GetUtcNow();
    }
    // Make room for a different strategy without evicting a borrowed candidate,
    // active native worker or in-flight query. No extra TCP quota is invented.
    internal async Task PruneUnused(CancellationToken token)
    {
        Slot[] snapshot; lock (gate) snapshot = slots.Values.Where(s => s.Users == 0).ToArray();
        foreach (var slot in snapshot) {
            token.ThrowIfCancellationRequested(); if (!slot.Io.Wait(0)) continue;
            try {
                if (slot.Current is {} entry && entry.Lease.ReferenceCount == 2 && entry.Owner.Status.Sessions == 0) {
                    slot.Current = null; await Retire(entry);
                }
            } finally {
                slot.Io.Release(); lock (gate) if (slot.Users == 0 && slot.Current == null && slots.GetValueOrDefault(slot.Key) == slot) slots.Remove(slot.Key);
            }
        }
    }
    async Task Retire(Entry entry)
    {
        lock (gate) {
            retiring.RemoveAll(o => o.Closed.IsCompletedSuccessfully);
            retiring.Add(entry.Owner);
        }
        try { await entry.Owner.DisposeAsync(); } // Active workers keep exact tuple ownership.
        finally { entry.Lease.Dispose(); }
    }
    async Task MaintainSlot(Slot slot)
    {
        await slot.Io.WaitAsync(stop.Token);
        try {
            var entry = slot.Current;
            if (entry == null) return;
            if (!entry.Lease.QueryUsable || entry.Owner.Failed) { slot.Current = null; await Retire(entry); return; }
            if (entry.Observed != null && clock.GetElapsedTime(entry.ObservedTick).TotalSeconds < 15 || !budget.TrySend(20, maintenance: true)) return;
            using var reference = entry.Lease.AcquireAttempt(generation);
            try { await Observe(entry, reference, stop.Token); }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or System.Net.Sockets.SocketException) {
                slot.Current = null; await Retire(entry);
            }
        } finally {
            slot.Io.Release();
            lock (gate) {
                if (slot.Users == 0 && slot.Current == null) {
                    string key = slot.Key;
                    if (slots.GetValueOrDefault(key) == slot) slots.Remove(key);
                }
            }
        }
    }
    async Task Maintain()
    {
        try {
            while (true) {
                await Task.Delay(1000, stop.Token);
                Slot[] snapshot; lock (gate) snapshot = slots.Values.ToArray();
                // Per-source serialization also coalesces maintenance with a
                // foreground query; different sources share only the budget.
                await Task.WhenAll(snapshot.Select(MaintainSlot));
            }
        } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    }
    public ValueTask DisposeAsync()
    {
        lock (gate) {
            disposed = true;
            return new(closing ??= Close());
        }
    }
    async Task Close()
    {
        stop.Cancel();
        try { await maintenance; }
        finally {
            Slot[] snapshot; lock (gate) snapshot = slots.Values.ToArray();
            await Task.WhenAll(snapshot.Select(async slot => {
                await slot.Io.WaitAsync();
                try { if (slot.Current is {} entry) { slot.Current = null; await Retire(entry); } }
                finally { slot.Io.Release(); }
            }));
            TcpCaptureOwner[] owners; lock (gate) { slots.Clear(); owners = retiring.ToArray(); }
            // Runner closes paths before its factory; no capture worker may
            // outlive shutdown. An unproven capture close remains a failure.
            await Task.WhenAll(owners.Select(o => o.Closed));
        }
    }
}
