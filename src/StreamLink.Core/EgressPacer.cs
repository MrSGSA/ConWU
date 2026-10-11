using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace StreamLink.Core;

public sealed record EgressPeerStats(string Peer, long SentBytes, long Packets, long OverflowDrops, long Cancelled, long SendFailures);
public sealed record EgressStats(int Mbps, int QueuedBytes, int PeakQueuedBytes, int QueueLimitBytes, long SentBytes,
    long OverflowDrops, long Cancelled, long SendFailures, double MaximumQueueMs, double QueueP95Ms, long PriorityPackets,
    EgressPeerStats[] Peers, string Failure)
{
    public long TimerWaits { get; init; }
    public double TimerWaitMs { get; init; }
    public double BackloggedTokenOverrunBytes { get; init; }
    public int BurstBytes { get; init; }
    public string WorkerPriority { get; init; } = "";
}

// One instance per device runner, shared by all managed sockets/capture owners
// and both IP families. A conservative whole-device budget (not one per peer or
// per source address). Bytes are OUTER IP bytes; never estimated application bps.
public sealed class EgressPacer : IDisposable
{
    const int Quantum = 1536, MaximumDatagram = 4 * Quantum, MaximumFlows = 64;
    readonly object gate = new();
    readonly Dictionary<string, Peer> peers = [];
    readonly List<Peer> order = [];
    readonly AutoResetEvent changed = new(false);
    readonly PreciseTimer timer = new();
    readonly Thread worker;
    readonly string priorityName;
    readonly double rate, priorityRate;
    readonly int limit, reserve, burst;
    double tokens, priorityTokens = 2 * Quantum;
    long at = Stopwatch.GetTimestamp(), sent, overflow, cancelled, failures, priorityPackets;
    readonly long[] histogram = new long[12];
    static readonly double[] buckets = [.1, .25, .5, 1, 2, 5, 10, 20, 50, 100, 500, double.PositiveInfinity];
    double maximumAge;
    long timerWaits; double timerWaitMs, tokenOverrun;
    int cursor, bytes, peak, flowCount;
    bool stopping, disposed;
    string failure = "";
    public int Mbps { get; }
    internal sealed class Peer(string key)
    {
        public readonly string Key = key;
        public readonly LinkedList<Item> Data = [], Control = [];
        public int Bytes, Deficit, References;
        public long Sent, Packets, Overflow, Cancelled, Failures;
    }
    internal sealed record Item(Flow Flow, byte[] Packet, int Bytes, object? Context, long At, bool Priority,
        CancellationToken Token, TaskCompletionSource? Completion);
    // 50 Mbps Windows A/B: a ~2ms credit ceiling plus one AboveNormal sender
    // avoids losing capacity to wakeup jitter, without spin or process-wide
    // priority/timer changes. Retain the old four-packet floor at low rates,
    // cap at eight; no unbounded repayment of missed time. Pacing stays opt-in.
    public EgressPacer(int mbps) : this(mbps, (int)Math.Clamp((long)mbps * 250 / Quantum, 4, 8), ThreadPriority.AboveNormal) { }
    // Bounded A/B parameter, not a user-facing override of the rate envelope.
    internal EgressPacer(int mbps, int burstPackets, ThreadPriority priority = ThreadPriority.Normal)
    {
        if (mbps is < 1 or > 10000) { timer.Dispose(); changed.Dispose(); throw new ArgumentOutOfRangeException(nameof(mbps)); }
        if (burstPackets is < 4 or > 8) { timer.Dispose(); changed.Dispose(); throw new ArgumentOutOfRangeException(nameof(burstPackets)); }
        if (priority is not (ThreadPriority.Normal or ThreadPriority.AboveNormal)) { timer.Dispose(); changed.Dispose(); throw new ArgumentOutOfRangeException(nameof(priority)); }
        Mbps = mbps; rate = mbps * 125000d; priorityRate = Math.Min(8192, rate * .05);
        tokens = burst = burstPackets * Quantum;
        priorityName = priority.ToString();
        limit = Math.Min(1 << 20, (int)(rate * .020)); reserve = Math.Min(2 * Quantum, limit / 4);
        worker = new Thread(Run) { IsBackground = true, Name = "StreamLink egress", Priority = priority }; worker.Start();
    }
    public Flow Register(string peer, Func<ReadOnlyMemory<byte>, object?, bool> send)
    {
        if (string.IsNullOrWhiteSpace(peer) || peer.Length > 128) throw new ArgumentException("出口成员标识无效");
        lock (gate) {
            ObjectDisposedException.ThrowIf(stopping, this);
            if (flowCount >= MaximumFlows) throw new IOException("出口路径资源已满");
            if (peers.Count >= MaximumFlows) foreach (var old in order.Where(p => p.References == 0 && p.Bytes == 0).ToArray()) { peers.Remove(old.Key); order.Remove(old); }
            cursor = order.Count == 0 ? 0 : cursor % order.Count;
            if (!peers.TryGetValue(peer, out var p)) { p = new(peer); peers.Add(peer, p); order.Add(p); }
            p.References++; flowCount++; return new(this, p, send);
        }
    }
    public EgressStats Snapshot()
    {
        lock (gate) {
            long total = histogram.Sum(), count = 0; double p95 = 0;
            for (int i = 0; i < histogram.Length && total > 0; i++) { count += histogram[i]; if (count >= Math.Ceiling(total * .95)) { p95 = double.IsInfinity(buckets[i]) ? maximumAge : buckets[i]; break; } }
            return new(Mbps, bytes, peak, limit, sent, overflow, cancelled, failures, maximumAge, p95, priorityPackets,
                order.Select(p => new EgressPeerStats(p.Key, p.Sent, p.Packets, p.Overflow, p.Cancelled, p.Failures)).ToArray(), failure)
                { TimerWaits = timerWaits, TimerWaitMs = timerWaitMs, BackloggedTokenOverrunBytes = tokenOverrun, BurstBytes = burst, WorkerPriority = priorityName };
        }
    }
    void Drop(Item item, bool capacity)
    {
        bytes -= item.Bytes; item.Flow.peer.Bytes -= item.Bytes;
        if (capacity) { overflow++; item.Flow.peer.Overflow++; } else { cancelled++; item.Flow.peer.Cancelled++; }
        if (item.Token.IsCancellationRequested) item.Completion?.TrySetCanceled(item.Token);
        else item.Completion?.TrySetException(new IOException(capacity ? "egress-queue-full" : "egress-flow-closed"));
    }
    bool Enqueue(Flow flow, ReadOnlySpan<byte> packet, int wireBytes, object? context, bool priority,
        CancellationToken token, TaskCompletionSource? completion)
    {
        if (wireBytes < packet.Length || wireBytes is < 28 or > MaximumDatagram || packet.Length == 0) throw new ArgumentOutOfRangeException(nameof(wireBytes));
        lock (gate) {
            if (stopping || !flow.Alive || token.IsCancellationRequested) return false;
            int ceiling = priority ? limit : limit - reserve;
            // A saturated peer cannot prevent a newly active peer from entering.
            // Evict only a data tail from a more heavily queued peer; no retries.
            while (bytes + wireBytes > ceiling) {
                var victim = order.Where(p => p != flow.peer && p.Bytes > flow.peer.Bytes && p.Data.Count != 0).MaxBy(p => p.Bytes);
                if (victim == null) { overflow++; flow.peer.Overflow++; return false; }
                var tail = victim.Data.Last!; victim.Data.RemoveLast(); Drop(tail.Value, true);
            }
            bool wasEmpty = bytes == 0;
            var item = new Item(flow, packet.ToArray(), wireBytes, context, Stopwatch.GetTimestamp(), priority, token, completion);
            (priority ? flow.peer.Control : flow.peer.Data).AddLast(item);
            bytes += wireBytes; flow.peer.Bytes += wireBytes; peak = Math.Max(peak, bytes);
            if (wasEmpty) changed.Set(); return true;
        }
    }
    void Refill()
    {
        long now = Stopwatch.GetTimestamp(); double elapsed = Stopwatch.GetElapsedTime(at, now).TotalSeconds; at = now;
        if (bytes > 0) tokenOverrun += Math.Max(0, tokens + elapsed * rate - burst);
        tokens = Math.Min(burst, tokens + elapsed * rate);
        priorityTokens = Math.Min(2 * Quantum, priorityTokens + elapsed * priorityRate);
    }
    Item? Select(out bool priority)
    {
        priority = false;
        if (order.Count == 0) return null;
        // Priority remains in the SAME rate/queue budget and has its own small
        // allowance. Exhausted priority flows join normal deficit scheduling.
        for (int i = 0; i < order.Count; i++) {
            var p = order[(cursor + i) % order.Count]; var item = p.Control.First?.Value;
            if (item != null && item.Bytes <= priorityTokens) { priority = true; return item; }
        }
        for (int i = 0; i < order.Count * 5; i++) {
            var p = order[cursor]; var item = p.Data.First?.Value ?? p.Control.First?.Value;
            if (item != null) {
                if (p.Deficit < item.Bytes) p.Deficit += Quantum;
                if (p.Deficit >= item.Bytes) return item;
            } else p.Deficit = 0;
            cursor = (cursor + 1) % order.Count;
        }
        return null;
    }
    void Run()
    {
        try {
            while (true) {
                Item? item; bool priority; double wait = -1;
                lock (gate) {
                    if (stopping) return;
                    Refill(); item = Select(out priority);
                    if (item != null) {
                        // Wake when the next packet is eligible. Artificially
                        // waiting for a larger batch plus the real timer's
                        // rounding loses throughput to the bounded bucket cap.
                        if (tokens < item.Bytes) { wait = (item.Bytes - tokens) / rate; item = null; }
                        else {
                            var p = item.Flow.peer;
                            (item.Priority ? p.Control : p.Data).RemoveFirst();
                            bytes -= item.Bytes; p.Bytes -= item.Bytes; tokens -= item.Bytes;
                            if (priority) { priorityTokens -= item.Bytes; priorityPackets++; }
                            else { p.Deficit -= item.Bytes; if (p.Deficit < (p.Data.First?.Value ?? p.Control.First?.Value)?.Bytes) cursor = (cursor + 1) % order.Count; }
                            double age = Stopwatch.GetElapsedTime(item.At).TotalMilliseconds; maximumAge = Math.Max(maximumAge, age);
                            histogram[Array.FindIndex(buckets, b => age <= b)]++;
                        }
                    }
                }
                if (item == null) { long before = Stopwatch.GetTimestamp(); timer.Wait(changed, wait); if (wait >= 0) lock (gate) { timerWaits++; timerWaitMs += Stopwatch.GetElapsedTime(before).TotalMilliseconds; } continue; }
                bool success = false, abandoned = false; Exception? error = null;
                // Close joins this per-flow send gate BEFORE its underlying
                // resource can close. Other peers never share this lock.
                lock (item.Flow.sendGate) {
                    abandoned = !item.Flow.Alive || item.Token.IsCancellationRequested;
                    if (!abandoned) try { success = item.Flow.send(item.Packet, item.Context); }
                    catch (Exception ex) { error = ex; }
                }
                lock (gate) {
                    if (success) { sent += item.Bytes; item.Flow.peer.Sent += item.Bytes; item.Flow.peer.Packets++; }
                    else if (abandoned) { cancelled++; item.Flow.peer.Cancelled++; }
                    else { failures++; item.Flow.peer.Failures++; }
                }
                if (success) item.Completion?.TrySetResult();
                else if (item.Token.IsCancellationRequested) item.Completion?.TrySetCanceled(item.Token);
                else item.Completion?.TrySetException(error ?? new IOException(abandoned ? "egress-flow-closed" : "egress-send-failed"));
            }
        } catch (Exception ex) { lock (gate) { failure = ex.GetType().Name; stopping = true; Clear(); } }
    }
    void Clear()
    {
        foreach (var p in order) foreach (var queue in new[] { p.Data, p.Control }) { foreach (var i in queue) Drop(i, false); queue.Clear(); }
    }
    void Close(Flow flow)
    {
        lock (gate) {
            if (!flow.Alive) return; flow.Alive = false; flowCount--; flow.peer.References--;
            foreach (var q in new[] { flow.peer.Data, flow.peer.Control }) {
                for (var node = q.First; node != null;) { var next = node.Next; if (node.Value.Flow == flow) { Drop(node.Value, false); q.Remove(node); } node = next; }
            }
            if (!disposed) changed.Set();
        }
        lock (flow.sendGate) { } // finish the one already-dequeued datagram
    }
    public void Dispose()
    {
        lock (gate) { if (disposed) return; disposed = true; stopping = true; Clear(); changed.Set(); }
        worker.Join(); timer.Dispose(); changed.Dispose();
    }
    public sealed class Flow : IDisposable
    {
        readonly EgressPacer owner;
        internal readonly Peer peer;
        internal readonly Func<ReadOnlyMemory<byte>, object?, bool> send;
        internal readonly object sendGate = new();
        volatile bool alive = true;
        internal bool Alive { get => alive; set => alive = value; }
        internal Flow(EgressPacer owner, Peer peer, Func<ReadOnlyMemory<byte>, object?, bool> send) { this.owner = owner; this.peer = peer; this.send = send; }
        public bool TrySend(ReadOnlySpan<byte> packet, int wireBytes, object? context = null, bool priority = false,
            CancellationToken token = default, TaskCompletionSource? completion = null)
            => owner.Enqueue(this, packet, wireBytes, context, priority, token, completion);
        public void Dispose() => owner.Close(this);
    }
    // No global timer-resolution changes and no busy spin. Unsupported systems
    // fail opt-in setup explicitly instead of silently using coarse sleeps.
    sealed class PreciseTimer : WaitHandle
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeWaitHandle CreateWaitableTimerExW(nint attributes, string? name, uint flags, uint access);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetWaitableTimer(SafeWaitHandle timer, in long due, int period, nint callback, nint argument, [MarshalAs(UnmanagedType.Bool)] bool resume);
        public PreciseTimer()
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("出口 pacing 需要 Windows 高精度等待计时器");
            SafeWaitHandle = CreateWaitableTimerExW(0, null, 2, 0x00100002);
            if (SafeWaitHandle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        public void Wait(AutoResetEvent changed, double seconds)
        {
            if (seconds < 0) { changed.WaitOne(); return; }
            long due = -Math.Max(1, (long)Math.Ceiling(seconds * 10000000));
            if (!SetWaitableTimer(SafeWaitHandle, in due, 0, 0, 0, false)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            WaitAny([changed, this]);
        }
    }
}
