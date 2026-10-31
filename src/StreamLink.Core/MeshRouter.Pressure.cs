namespace StreamLink.Core;

// Local rejection stages only. These counts do not measure physical-network
// loss or application delivery, and do not include native/OS socket drops.
public sealed record RouterPeerDrops(long NoHealthyPath, long SendRejected, long AuthenticationRejected,
    long ReceivePolicyRejected, long AdapterWriteRejected)
{
    public long Total => NoHealthyPath + SendRejected + AuthenticationRejected + ReceivePolicyRejected + AdapterWriteRejected;
}

public sealed record RouterPressureSnapshot(long MaintenanceTicks, long? MaintenanceAgeMs,
    long MaximumMaintenanceDelayMs, long MaximumMaintenanceLockWaitMs, long MaximumMaintenanceWorkMs, long ReceiveYields, long LegacySendRejected);

// Ordinary keepalives on one owned path only, excluding nomination, recovery
// and diagnostic probes. LocalAccepted means local enqueue/socket acceptance,
// not wire injection or remote delivery. RouterBudgetRejected is a subset of
// LocalRejected; null means this layer cannot separate budget from send refusal.
public sealed record PathKeepaliveSnapshot(Guid PathId, long Attempts, long SessionUnavailable,
    long LocalAccepted, long LocalRejected, long? RouterBudgetRejected, long FreshReplies,
    long LateReplies, long PendingEvicted, int Pending, long? LastAttemptAgeMs,
    long? LastAcceptedAgeMs, long? LastFreshReplyAgeMs);

public sealed partial class MeshRouter
{
    // All accesses are under gate. No packet history, nonce or endpoint is
    // exported, and observing a counter never changes the health decision.
    sealed class KeepaliveObservation
    {
        public long Attempts, SessionUnavailable, LocalAccepted, LocalRejected, RouterBudgetRejected;
        public long FreshReplies, LateReplies, PendingEvicted;
        long lastAttempt, lastAccepted, lastFreshReply;
        public void Attempt() { Attempts++; lastAttempt = System.Diagnostics.Stopwatch.GetTimestamp(); }
        public long Accept() { LocalAccepted++; return lastAccepted = System.Diagnostics.Stopwatch.GetTimestamp(); }
        public void Reply(bool fresh)
        {
            if (fresh) { FreshReplies++; lastFreshReply = System.Diagnostics.Stopwatch.GetTimestamp(); }
            else LateReplies++;
        }
        public PathKeepaliveSnapshot Snapshot(Guid pathId, int pending, bool budgetMeasured) => new(pathId,
            Attempts, SessionUnavailable, LocalAccepted, LocalRejected, budgetMeasured ? RouterBudgetRejected : null,
            FreshReplies, LateReplies, PendingEvicted, pending, Age(lastAttempt), Age(lastAccepted), Age(lastFreshReply));
    }
    static PathKeepaliveSnapshot KeepaliveStatus(ManagedPath path) => path.Keepalive.Snapshot(path.Identity.PathId,
        path.PendingRoundTrips.Values.Count(probe => probe.Keepalive), budgetMeasured: true);

    const int ReceiveBatch = 64;
    long maintenanceTicks, lastMaintenance, maximumMaintenanceDelayMs, maximumMaintenanceLockWaitMs, maximumMaintenanceWorkMs;
    long receiveYields, legacySendRejected;

    public RouterPressureSnapshot Pressure()
    {
        lock (gate) return new(maintenanceTicks, lastMaintenance == 0 ? null : Environment.TickCount64 - lastMaintenance,
            maximumMaintenanceDelayMs, maximumMaintenanceLockWaitMs, maximumMaintenanceWorkMs, Interlocked.Read(ref receiveYields), Interlocked.Read(ref legacySendRejected));
    }

    // Called under gate, after AEAD verification and path/source authorization.
    bool Deliver(Peer peer, byte[] packet, bool allowed)
    {
        if (!allowed) { peer.Dropped++; peer.ReceivePolicyDrops++; return false; }
        if (!adapter.Write(packet)) { peer.Dropped++; peer.AdapterWriteDrops++; return false; }
        return true;
    }
}
