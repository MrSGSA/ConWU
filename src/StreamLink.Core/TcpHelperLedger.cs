using System.Net;

namespace StreamLink.Core;

public enum TcpHelperPurpose { RetainedEndpoint, LegacyEntry, ServerScreening, OneShotQuery }
public sealed record TcpHelperResource(Guid ResourceId, Guid Generation, TcpHelperPurpose Purpose, string Local,
    string Reflector, string State, bool Closed, string Observation, long Queries, long QueryFailures,
    long OutboundPackets, long OutboundBytes, long InboundPackets, long InboundBytes,
    long SynPackets, long ResetPackets, long FinPackets, long PureAckPackets);
public sealed record TcpHelperUsage(int OpenResources, int PeakResources, long Created, long Queries,
    long QueryFailures, long OutboundPackets, long OutboundBytes, long InboundPackets, long InboundBytes,
    int RecentOutboundPackets, long AdmissionWaits, TcpHelperResource[] Resources)
{
    public int PendingTransactions { get; init; }
    public string Scope => "Process-owned kernel TCP helpers; NETWORK-layer observations, not physical NIC totals or native peer traffic";
    public bool CompleteWireAudit => false;
}

// Separate actual resource/observation counts from query admission. A query is
// not a packet: SYN retries, ACKs, segmentation and close packets stay observable
// kernel overhead, never subjected to an application packet-drop limiter.
public sealed class TcpHelperLedger
{
    public static TcpHelperLedger Shared { get; } = new();
    readonly object gate = new();
    readonly TimeProvider time;
    readonly Dictionary<Guid, Handle> active = [];
    readonly Queue<TcpHelperResource> retired = [];
    readonly LinkedList<object> pending = [];
    readonly (long At, int Packets)[] recent = new (long, int)[10];
    long created, queries, queryFailures, sent, sentBytes, received, receivedBytes, waits;
    int peak;
    double tokens = 2;
    long admissionAt;
    public TcpHelperLedger(TimeProvider? time = null) { this.time = time ?? TimeProvider.System; admissionAt = this.time.GetTimestamp(); }
    long Bin() => (long)(time.GetElapsedTime(0, time.GetTimestamp()).TotalMilliseconds / 100);
    int Recent()
    {
        long now = Bin();
        return recent.Where(b => b.At <= now && now - b.At < 10).Sum(b => b.Packets);
    }
    internal Handle Register(Guid id, Guid generation, TcpHelperPurpose purpose, IPEndPoint local, IPEndPoint reflector)
    {
        lock (gate) {
            if (id == Guid.Empty || generation == Guid.Empty || !Enum.IsDefined(purpose) || active.ContainsKey(id) || active.Count >= TraversalLimits.TcpResources)
                throw new IOException("TCP helper observation registry is full or resource identity is invalid");
            var h = new Handle(this, id, generation, purpose, local.ToString(), reflector.ToString());
            active.Add(id, h); created++; peak = Math.Max(peak, active.Count); return h;
        }
    }
    // Four helper transactions/s, burst two. Defer *new* connects/queries when
    // observed kernel sends consume the 60pps envelope. Never intercept ACKs
    // or mark an untouched query stream unusable merely for waiting here.
    internal async Task Admit(CancellationToken token)
    {
        LinkedListNode<object>? queued = null;
        try {
            while (true) {
                token.ThrowIfCancellationRequested();
                double delay;
                lock (gate) {
                    long now = time.GetTimestamp();
                    tokens = Math.Min(2, tokens + time.GetElapsedTime(admissionAt, now).TotalSeconds * 4); admissionAt = now;
                    bool turn = queued == null ? pending.Count == 0 : ReferenceEquals(pending.First, queued);
                    if (turn && tokens >= 1 && Recent() < TraversalLimits.ControlPps) { tokens--; return; }
                    if (queued == null) {
                        if (pending.Count >= 32) throw new IOException("BudgetExhausted: TCP helper transaction queue is full");
                        queued = pending.AddLast(new object()); waits++;
                    }
                    delay = !turn || Recent() >= TraversalLimits.ControlPps ? 100 : Math.Clamp((1 - tokens) * 250, 10, 250);
                }
                await Task.Delay(TimeSpan.FromMilliseconds(delay), time, token);
            }
        } finally { if (queued != null) lock (gate) pending.Remove(queued); }
    }
    public TcpHelperUsage Snapshot()
    {
        lock (gate) return new(active.Count, peak, created, queries, queryFailures, sent, sentBytes,
            received, receivedBytes, Recent(), waits, active.Values.Select(h => h.Snapshot()).Concat(retired.TakeLast(4)).ToArray()) { PendingTransactions = pending.Count };
    }
    internal sealed class Handle(TcpHelperLedger owner, Guid id, Guid generation, TcpHelperPurpose purpose, string local, string reflector) : IDisposable
    {
        string state = "Bound", observation = "Unavailable:observer-not-started";
        long queries, failures, sent, sentBytes, received, receivedBytes, syn, resets, fin, pureAck;
        bool closed;
        internal void State(string value) { lock (owner.gate) if (!closed) state = value; }
        internal void Observation(string value) { lock (owner.gate) if (!closed) observation = value; }
        internal void Query(bool failed) { lock (owner.gate) {
            if (closed) return;
            if (failed) { failures++; owner.queryFailures++; state = "QueryUnusable"; }
            else { queries++; owner.queries++; }
        } }
        internal void Packet(bool outbound, int bytes, byte flags, int payload)
        {
            if (bytes is < 40 or > 65535 || payload < 0 || payload > bytes) return;
            lock (owner.gate) {
                if (closed) return;
                if (outbound) {
                    sent++; sentBytes += bytes; owner.sent++; owner.sentBytes += bytes;
                    long at = owner.Bin(); int i = (int)(at % owner.recent.Length);
                    var b = owner.recent[i]; owner.recent[i] = (at, b.At == at ? b.Packets + 1 : 1);
                } else { received++; receivedBytes += bytes; owner.received++; owner.receivedBytes += bytes; }
                if ((flags & 2) != 0) syn++;
                if ((flags & 4) != 0) resets++;
                if ((flags & 1) != 0) fin++;
                if ((flags & 0x3f) == 0x10 && payload == 0) pureAck++;
            }
        }
        internal TcpHelperResource Snapshot() => new(id, generation, purpose, local, reflector, state, closed, observation,
            queries, failures, sent, sentBytes, received, receivedBytes, syn, resets, fin, pureAck);
        public void Dispose() { lock (owner.gate) {
            if (closed) return; closed = true; state = "Closed";
            owner.active.Remove(id); owner.retired.Enqueue(Snapshot());
            while (owner.retired.Count > 64) owner.retired.Dequeue();
        } }
    }
}
