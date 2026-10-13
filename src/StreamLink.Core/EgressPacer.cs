using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace StreamLink.Core;

public sealed record EgressPeerStats(string Peer, long SentBytes, long Packets, long OverflowDrops, long Cancelled, long SendFailures);
public sealed record EgressOutletStats(string Outlet, int QueuedBytes, int PeakQueuedBytes, int QueueLimitBytes,
    long SentBytes, EgressPeerStats[] Peers);
public sealed record EgressStats(int Mbps, int QueuedBytes, int PeakQueuedBytes, int QueueLimitBytes, long SentBytes,
    long OverflowDrops, long Cancelled, long SendFailures, double MaximumQueueMs, double QueueP95Ms, long PriorityPackets,
    EgressPeerStats[] Peers, string Failure)
{
    public long TimerWaits { get; init; }
    public double TimerWaitMs { get; init; }
    public double BackloggedTokenOverrunBytes { get; init; }
    public int BurstBytes { get; init; }
    public string WorkerPriority { get; init; } = "";
    public double OldestQueuedMs { get; init; }
    public DatagramSendSnapshot? Accounting { get; init; }
    public EgressOutletStats[] Outlets { get; init; } = [];
    public string RateScope { get; init; } = "WholeDevice";
    public long RetiredOutletSentBytes { get; init; }
}

// One instance per device runner, shared by all managed sockets/capture owners
// and both IP families. A conservative whole-device budget (not one per peer or
// per source address). Bytes are OUTER IP bytes; never estimated application bps.
public sealed class EgressPacer : IDisposable
{
    const int Quantum = 1536, MaximumDatagram = 4 * Quantum, MaximumFlows = 64;
    readonly object gate = new();
    readonly DatagramSendAccounting accounting = new();
    readonly Dictionary<(string Outlet, string Peer), Peer> peers = [];
    readonly List<Peer> order = [];
    readonly List<Outlet> outlets = [];
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
    long retiredOutletSentBytes;
    int cursor, bytes, peak, flowCount;
    bool stopping, disposed, waitingForReadiness, newOutletVisit = true;
    string failure = "";
    public int Mbps { get; }
    internal sealed class Outlet(string key)
    {
        public readonly string Key = key;
        public readonly List<Peer> Peers = [];
        public int Bytes, Peak, Deficit, Cursor;
        public long Sent;
    }
    internal sealed class Peer(string key, Outlet outlet)
    {
        public readonly string Key = key;
        public readonly Outlet Outlet = outlet;
        public readonly LinkedList<Item> Data = [], Control = [];
        public int Bytes, Deficit, References, InFlight;
        public long Sent, Packets, Overflow, Cancelled, Failures;
    }
    internal sealed record Item(Flow Flow, Peer Peer, byte[] Packet, int Bytes, object? Context, long At, bool Priority,
        CancellationToken Token, TaskCompletionSource? Completion, Func<int,double>? Readiness);
    // 50 Mbps Windows A/B: a ~2ms credit ceiling plus one AboveNormal sender
    // avoids losing capacity to wakeup jitter, without spin or process-wide
    // priority/timer changes. Retain the old four-packet floor at low rates,
    // cap at eight; no unbounded repayment of missed time. Pacing stays opt-in.
    public EgressPacer(int mbps) : this(mbps, (int)Math.Clamp((long)mbps * 250 / Quantum, 4, 8), ThreadPriority.AboveNormal) { }
    // Bounded A/B parameter, not a user-facing override of the rate envelope.
    internal EgressPacer(int mbps, int burstPackets, ThreadPriority priority = ThreadPriority.Normal)
    {
        if (mbps is < 0 or > 10000) { timer.Dispose(); changed.Dispose(); throw new ArgumentOutOfRangeException(nameof(mbps)); }
        if (burstPackets is < 4 or > 8) { timer.Dispose(); changed.Dispose(); throw new ArgumentOutOfRangeException(nameof(burstPackets)); }
        if (priority is not (ThreadPriority.Normal or ThreadPriority.AboveNormal)) { timer.Dispose(); changed.Dispose(); throw new ArgumentOutOfRangeException(nameof(priority)); }
        Mbps = mbps; rate = mbps==0?0:mbps * 125000d; priorityRate = mbps==0?8192:Math.Min(8192, rate * .05);
        tokens = burst = burstPackets * Quantum;
        priorityName = priority.ToString();
        limit = mbps==0?128*1024:Math.Min(1 << 20, (int)(rate * .020)); reserve = Math.Min(2 * Quantum, limit / 4);
        worker = new Thread(Run) { IsBackground = true, Name = "StreamLink egress", Priority = priority }; worker.Start();
    }
    public Flow Register(string peer, Func<ReadOnlyMemory<byte>, object?, bool> send)
        => Register(peer, "DeviceShared", send);
    internal Flow RegisterRouted(string peer, Func<object?, string> outlet, Func<ReadOnlyMemory<byte>, object?, bool> send)
    {
        ArgumentNullException.ThrowIfNull(outlet);
        var flow = Register(peer, "Unresolved", send); flow.route = outlet; return flow;
    }
    public Flow Register(string peer, string outlet, Func<ReadOnlyMemory<byte>, object?, bool> send)
    {
        if (string.IsNullOrWhiteSpace(peer) || peer.Length > 128) throw new ArgumentException("出口成员标识无效");
        if (string.IsNullOrWhiteSpace(outlet) || outlet.Length > 128) throw new ArgumentException("出口标识无效");
        ArgumentNullException.ThrowIfNull(send);
        lock (gate) {
            ObjectDisposedException.ThrowIf(stopping, this);
            if (flowCount >= MaximumFlows) throw new IOException("出口路径资源已满");
            Reclaim();
            if (!peers.TryGetValue((outlet, peer), out var p)) {
                if (peers.Count >= 2 * MaximumFlows) throw new IOException("出口分区资源已满");
                var o = outlets.FirstOrDefault(o => o.Key == outlet);
                if (o == null) { o = new(outlet); outlets.Add(o); }
                p = new(peer, o); peers.Add((outlet, peer), p); order.Add(p); o.Peers.Add(p);
            }
            p.References++; flowCount++; return new(this, p, send);
        }
    }
    void Reclaim()
    {
        if (peers.Count >= MaximumFlows) foreach (var old in order.Where(p => p.References == 0 && p.Bytes == 0 && p.InFlight == 0).ToArray()) {
            peers.Remove((old.Outlet.Key, old.Key)); order.Remove(old); old.Outlet.Peers.Remove(old);
        }
        foreach (var o in outlets.Where(o => o.Peers.Count == 0).ToArray()) { retiredOutletSentBytes += o.Sent; outlets.Remove(o); }
        cursor = outlets.Count == 0 ? 0 : cursor % outlets.Count;
        newOutletVisit = true;
        foreach (var o in outlets) o.Cursor = o.Peers.Count == 0 ? 0 : o.Cursor % o.Peers.Count;
    }
    public EgressStats Snapshot()
    {
        lock (gate) {
            long total = histogram.Sum(), count = 0; double p95 = 0;
            for (int i = 0; i < histogram.Length && total > 0; i++) { count += histogram[i]; if (count >= Math.Ceiling(total * .95)) { p95 = double.IsInfinity(buckets[i]) ? maximumAge : buckets[i]; break; } }
            return new(Mbps, bytes, peak, limit, sent, overflow, cancelled, failures, maximumAge, p95, priorityPackets,
                order.GroupBy(p => p.Key).Select(g => new EgressPeerStats(g.Key, g.Sum(p => p.Sent), g.Sum(p => p.Packets),
                    g.Sum(p => p.Overflow), g.Sum(p => p.Cancelled), g.Sum(p => p.Failures))).ToArray(), failure)
                { TimerWaits = timerWaits, TimerWaitMs = timerWaitMs, BackloggedTokenOverrunBytes = tokenOverrun, BurstBytes = burst, WorkerPriority = priorityName,
                    OldestQueuedMs = Oldest(null), Accounting = accounting.Snapshot(),
                    RetiredOutletSentBytes = retiredOutletSentBytes,
                    Outlets = outlets.Select(o => new EgressOutletStats(o.Key, o.Bytes, o.Peak, limit, o.Sent,
                        o.Peers.Select(p => new EgressPeerStats(p.Key, p.Sent, p.Packets, p.Overflow, p.Cancelled, p.Failures)).ToArray())).ToArray() };
        }
    }
    double Oldest(Flow? flow)
    {
        long oldest = 0;
        foreach (var p in order) foreach (var queue in new[] { p.Data, p.Control }) {
            var item = flow == null ? queue.First?.Value : queue.FirstOrDefault(i => ReferenceEquals(i.Flow, flow));
            if (item != null && (oldest == 0 || item.At < oldest)) oldest = item.At;
        }
        return oldest == 0 ? 0 : Stopwatch.GetElapsedTime(oldest).TotalMilliseconds;
    }
    DatagramQueueStats Queue(Flow flow)
    {
        lock (gate) return new("SharedEgress", "OuterIpBytes", limit, Oldest(flow), flow.accounting.Snapshot());
    }
    void Drop(Item item, bool capacity)
    {
        bytes -= item.Bytes; item.Peer.Bytes -= item.Bytes; item.Peer.Outlet.Bytes -= item.Bytes;
        accounting.Drop(item.Bytes, capacity); item.Flow.accounting.Drop(item.Bytes, capacity);
        if (capacity) { overflow++; item.Peer.Overflow++; } else { cancelled++; item.Peer.Cancelled++; }
        if (item.Token.IsCancellationRequested) item.Completion?.TrySetCanceled(item.Token);
        else item.Completion?.TrySetException(new IOException(capacity ? "egress-queue-full" : "egress-flow-closed"));
    }
    bool Enqueue(Flow flow, ReadOnlySpan<byte> packet, int wireBytes, object? context, bool priority,
        CancellationToken token, TaskCompletionSource? completion, Func<int,double>? readiness = null)
    {
        if (wireBytes < packet.Length || wireBytes is < 28 or > MaximumDatagram || packet.Length == 0) throw new ArgumentOutOfRangeException(nameof(wireBytes));
        // Route lookup is cached by its owner and deliberately outside the
        // scheduler lock: NIC/OS lookup must not block other sending peers.
        string outlet = flow.route?.Invoke(context) ?? flow.peer.Outlet.Key;
        if (string.IsNullOrWhiteSpace(outlet) || outlet.Length > 128) throw new ArgumentException("出口标识无效");
        lock (gate) {
            accounting.Offer(wireBytes); flow.accounting.Offer(wireBytes);
            if (stopping || !flow.Alive || token.IsCancellationRequested) {
                accounting.Reject(wireBytes, false); flow.accounting.Reject(wireBytes, false); return false;
            }
            var p = flow.peer;
            if (flow.route != null && outlet != p.Outlet.Key) {
                if (!peers.TryGetValue((outlet, p.Key), out p)) {
                    Reclaim();
                    if (peers.Count >= 2 * MaximumFlows) {
                        overflow++; flow.peer.Overflow++;
                        accounting.Reject(wireBytes, true); flow.accounting.Reject(wireBytes, true); return false;
                    }
                    var o = outlets.FirstOrDefault(o => o.Key == outlet);
                    if (o == null) { o = new(outlet); outlets.Add(o); }
                    p = new(flow.peer.Key, o); peers.Add((outlet, p.Key), p); order.Add(p); o.Peers.Add(p);
                }
                if (flow.members.Add(p)) p.References++;
            }
            int ceiling = priority ? limit : limit - reserve;
            // A saturated peer cannot prevent a newly active peer from entering.
            // Evict only a data tail from a more heavily queued peer; no retries.
            while (bytes + wireBytes > ceiling) {
                var victim = order.Where(v => v != p && v.Bytes > p.Bytes && v.Data.Count != 0).MaxBy(v => v.Bytes);
                if (victim == null) {
                    overflow++; p.Overflow++;
                    accounting.Reject(wireBytes, true); flow.accounting.Reject(wireBytes, true); return false;
                }
                var tail = victim.Data.Last!; victim.Data.RemoveLast(); Drop(tail.Value, true);
            }
            bool wasEmpty = bytes == 0;
            var item = new Item(flow, p, packet.ToArray(), wireBytes, context, Stopwatch.GetTimestamp(), priority, token, completion,readiness);
            (priority ? p.Control : p.Data).AddLast(item);
            accounting.Accept(wireBytes); flow.accounting.Accept(wireBytes);
            bytes += wireBytes; p.Bytes += wireBytes; peak = Math.Max(peak, bytes);
            p.Outlet.Bytes += wireBytes; p.Outlet.Peak = Math.Max(p.Outlet.Peak, p.Outlet.Bytes);
            if (wasEmpty||waitingForReadiness) changed.Set(); return true;
        }
    }
    void Refill()
    {
        long now = Stopwatch.GetTimestamp(); double elapsed = Stopwatch.GetElapsedTime(at, now).TotalSeconds; at = now;
        if (Mbps!=0&&bytes > 0) tokenOverrun += Math.Max(0, tokens + elapsed * rate - burst);
        tokens = Math.Min(burst, tokens + elapsed * rate);
        priorityTokens = Math.Min(2 * Quantum, priorityTokens + elapsed * priorityRate);
    }
    Item? Select(out bool priority,out double blockedWait)
    {
        priority = false;blockedWait=double.PositiveInfinity;
        if (outlets.Count == 0) return null;
        // Priority remains in the SAME rate/queue budget and has its own small
        // allowance. Exhausted priority flows join normal deficit scheduling.
        for (int i = 0; i < outlets.Count; i++) {
            var o = outlets[(cursor + i) % outlets.Count];
            for (int j = 0; j < o.Peers.Count; j++) {
                var p = o.Peers[(o.Cursor + j) % o.Peers.Count]; var item = p.Control.First?.Value;
                if (item != null && item.Bytes <= priorityTokens) { priority = true; return item; }
            }
        }
        // Deficit round robin at the outlet, then at the peer. All outlets
        // still spend the ONE device token bucket; a second NIC adds no rate.
        for (int i = 0; i < outlets.Count * 5; i++) {
            var o = outlets[cursor];
            if (newOutletVisit) { o.Deficit = Math.Min(MaximumDatagram + Quantum, o.Deficit + Quantum); newOutletVisit = false; }
            for (int j = 0; j < o.Peers.Count * 5; j++) {
            var p = o.Peers[o.Cursor]; var item = p.Data.First?.Value ?? p.Control.First?.Value;
            if(item!=null&&!item.Token.IsCancellationRequested&&item.Readiness is{}ready){
                double delay=ready(item.Bytes);
                if(delay>0){
                    blockedWait=Math.Min(blockedWait,delay);
                    // Diagnostics must not delay ordinary maintenance queued
                    // on the same peer after priority credit is exhausted.
                    item=p.Control.First?.Value;
                }
            }
            if (item != null) {
                if (p.Deficit < item.Bytes) p.Deficit += Quantum;
                if (p.Deficit >= item.Bytes) {
                    if (o.Deficit >= item.Bytes) return item;
                    // Preserve the next peer while this outlet waits for its
                    // next credit. Searching smaller packets here would bias
                    // the byte shares and inflate peer deficits on each wait.
                    break;
                }
            } else p.Deficit = 0;
            o.Cursor = (o.Cursor + 1) % o.Peers.Count;
            }
            if (o.Bytes == 0) o.Deficit = 0;
            cursor = (cursor + 1) % outlets.Count;
            newOutletVisit = true;
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
                    Refill(); item = Select(out priority,out var blockedWait);
                    waitingForReadiness=item==null&&double.IsFinite(blockedWait);
                    if(waitingForReadiness)wait=blockedWait;
                    if (item != null) {
                        // Wake when the next packet is eligible. Artificially
                        // waiting for a larger batch plus the real timer's
                        // rounding loses throughput to the bounded bucket cap.
                        if (Mbps!=0&&tokens < item.Bytes) { wait = (item.Bytes - tokens) / rate; item = null; }
                        else {
                            var p = item.Peer;
                            (item.Priority ? p.Control : p.Data).RemoveFirst();
                            bytes -= item.Bytes; p.Bytes -= item.Bytes; p.Outlet.Bytes -= item.Bytes; if(Mbps!=0)tokens -= item.Bytes;
                            accounting.Begin(item.Bytes); item.Flow.accounting.Begin(item.Bytes);
                            p.InFlight++;
                            if (priority) { priorityTokens -= item.Bytes; priorityPackets++; }
                            else {
                                p.Deficit -= item.Bytes; p.Outlet.Deficit -= item.Bytes;
                                if (p.Deficit < (p.Data.First?.Value ?? p.Control.First?.Value)?.Bytes)
                                    p.Outlet.Cursor = (p.Outlet.Cursor + 1) % p.Outlet.Peers.Count;
                            }
                            // Even priority traffic rotates across outlets/peers.
                            if (priority) p.Outlet.Cursor = (p.Outlet.Peers.IndexOf(p) + 1) % p.Outlet.Peers.Count;
                            if (priority) { cursor = (outlets.IndexOf(p.Outlet) + 1) % outlets.Count; newOutletVisit = true; }
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
                // Cancellation can occur inside an already-started socket I/O.
                // Count that explicit cancellation once, rather than calling it
                // a network send failure because the pre-call check was false.
                if (!success && error is OperationCanceledException && (item.Token.IsCancellationRequested || !item.Flow.Alive)) abandoned = true;
                lock (gate) {
                    accounting.Complete(item.Bytes, success, abandoned); item.Flow.accounting.Complete(item.Bytes, success, abandoned);
                    item.Peer.InFlight--;
                    if (success) { sent += item.Bytes; item.Peer.Sent += item.Bytes; item.Peer.Packets++; item.Peer.Outlet.Sent += item.Bytes; }
                    else if (abandoned) { cancelled++; item.Peer.Cancelled++; }
                    else { failures++; item.Peer.Failures++; }
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
            if (!flow.Alive) return; flow.Alive = false; flowCount--;
            foreach (var p in flow.members) {
            p.References--;
            foreach (var q in new[] { p.Data, p.Control }) {
                for (var node = q.First; node != null;) { var next = node.Next; if (node.Value.Flow == flow) { Drop(node.Value, false); q.Remove(node); } node = next; }
            }
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
        internal readonly DatagramSendAccounting accounting = new();
        internal readonly Peer peer;
        internal readonly HashSet<Peer> members = [];
        internal Func<object?, string>? route;
        internal readonly Func<ReadOnlyMemory<byte>, object?, bool> send;
        internal readonly object sendGate = new();
        volatile bool alive = true;
        internal bool Alive { get => alive; set => alive = value; }
        internal Flow(EgressPacer owner, Peer peer, Func<ReadOnlyMemory<byte>, object?, bool> send) { this.owner = owner; this.peer = peer; this.send = send; members.Add(peer); }
        public DatagramQueueStats SendQueue => owner.Queue(this);
        public bool TrySend(ReadOnlySpan<byte> packet, int wireBytes, object? context = null, bool priority = false,
            CancellationToken token = default, TaskCompletionSource? completion = null)
            => owner.Enqueue(this, packet, wireBytes, context, priority, token, completion);
        internal bool TrySendWhenReady(ReadOnlySpan<byte> packet,int wireBytes,object? context,Func<int,double> readiness,CancellationToken token=default)
            => owner.Enqueue(this,packet,wireBytes,context,false,token,null,readiness);
        public void Dispose() => owner.Close(this);
    }
    // No global timer-resolution changes and no busy spin. Unsupported systems
    // fail opt-in setup explicitly instead of silently using coarse sleeps.
    internal sealed class PreciseTimer : WaitHandle
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
