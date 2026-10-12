namespace StreamLink.Core;

public readonly record struct DatagramAmount(long Packets, long Bytes)
{
    public static DatagramAmount operator +(DatagramAmount a, DatagramAmount b) => new(a.Packets + b.Packets, a.Bytes + b.Bytes);
    public static DatagramAmount operator -(DatagramAmount a, DatagramAmount b) => new(a.Packets - b.Packets, a.Bytes - b.Bytes);
}

// These are local enqueue/send outcomes, not peer receipt or packets observed
// on a physical NIC. Byte units are specified by each queue owner.
public sealed record DatagramSendSnapshot(DatagramAmount Offered, DatagramAmount Accepted, DatagramAmount Sent,
    DatagramAmount CapacityRejected, DatagramAmount UnavailableRejected, DatagramAmount Evicted,
    DatagramAmount Cancelled, DatagramAmount Failed, DatagramAmount Queued, DatagramAmount InFlight)
{
    public bool Conserved => Offered == Accepted + CapacityRejected + UnavailableRejected &&
        Accepted == Sent + Evicted + Cancelled + Failed + Queued + InFlight;
}

public sealed record DatagramQueueStats(string Owner, string ByteUnit, int ByteLimit, double OldestQueuedMs, DatagramSendSnapshot Accounting);

public interface IMeshSendDiagnostics
{
    DatagramQueueStats SendQueue { get; }
}

// The owning queue's lock protects every transition, including snapshots and
// in-flight callbacks. Each accepted datagram has exactly one terminal outcome.
internal sealed class DatagramSendAccounting
{
    DatagramAmount offered, accepted, sent, capacity, unavailable, evicted, cancelled, failed, queued, inFlight;
    static DatagramAmount Amount(int bytes) => new(1, bytes);
    public void Offer(int bytes) => offered += Amount(bytes);
    public void Reject(int bytes, bool full) { if (full) capacity += Amount(bytes); else unavailable += Amount(bytes); }
    public void Accept(int bytes) { accepted += Amount(bytes); queued += Amount(bytes); }
    public void Drop(int bytes, bool overflow) { queued -= Amount(bytes); if (overflow) evicted += Amount(bytes); else cancelled += Amount(bytes); }
    public void Begin(int bytes) { queued -= Amount(bytes); inFlight += Amount(bytes); }
    public void Complete(int bytes, bool success, bool abandoned = false)
    {
        inFlight -= Amount(bytes);
        if (success) sent += Amount(bytes); else if (abandoned) cancelled += Amount(bytes); else failed += Amount(bytes);
    }
    public DatagramSendSnapshot Snapshot() => new(offered, accepted, sent, capacity, unavailable, evicted, cancelled, failed, queued, inFlight);
    public long PendingBytes => queued.Bytes + inFlight.Bytes;
    public long PendingPackets => queued.Packets + inFlight.Packets;
}
