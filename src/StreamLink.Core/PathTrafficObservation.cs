namespace StreamLink.Core;

public sealed record PathRttObservation(int Samples, double? P50Ms, double? P95Ms, int DiscardedSamples);
public sealed record PathTrafficWindow(long StartedMs, long EndedMs, bool Complete, long AcceptedSendPackets,
    long AcceptedSendBytes, long DeliveredReceivePackets, long DeliveredReceiveBytes, long SendRejectedPackets,
    PathRttObservation IdleRtt, PathRttObservation ActivityRtt)
{
    public double Seconds => Math.Max(0, EndedMs - StartedMs) / 1000d;
    public double AcceptedSendMbps => Seconds == 0 ? 0 : AcceptedSendBytes * 8d / Seconds / 1e6;
    public double DeliveredReceiveMbps => Seconds == 0 ? 0 : DeliveredReceiveBytes * 8d / Seconds / 1e6;
}
public sealed record PathTrafficSnapshot(Guid PathId, Guid ResourceId, Guid NetworkGeneration, string State,
    Guid? SendEpoch, Guid? ReceiveEpoch, PathTrafficWindow[] Windows, PathTrafficWindow? Current)
{
    // Local enqueue and inbound authenticated delivery do not establish remote
    // receipt, one-way delay, or loss. Keep absent evidence absent in the IPC.
    public string Qualification => "QualityUnknown";
    public long? PeerDeliveredSendBytes => null;
    public double? SendLossPercent => null;
    public double? OneWayDelayMs => null;
}

// Router-owned and serialized under its existing gate. No new packets, timers,
// receiver, or data ordering. Samples are tied to one actual retained path.
internal sealed class PathTrafficObservation(ValidatedPathIdentity identity)
{
    const int WindowMs = 5000, RetainedWindows = 3, MaximumRttSamples = 32;
    readonly Queue<PathTrafficWindow> windows = new();
    readonly List<double> idle = new(MaximumRttSamples), activity = new(MaximumRttSamples);
    long began, sentPackets, sentBytes, receivedPackets, receivedBytes, rejected, lastActivity;
    int idleDiscarded, activityDiscarded;
    bool running;
    Guid? sendEpoch, receiveEpoch;
    string state = "NotSelected";
    public void Start(long now)
    {
        running = true; state = "Observing"; began = now; windows.Clear(); Clear();
    }
    public void Epoch(bool outbound, Guid epoch, long now)
    {
        ref Guid? previous = ref (outbound ? ref sendEpoch : ref receiveEpoch);
        bool changed = previous != null && previous != epoch;
        previous = epoch;
        if (changed && running) Start(now);
    }
    void Clear(bool clearActivity = true)
    {
        sentPackets = sentBytes = receivedPackets = receivedBytes = rejected = 0;
        if (clearActivity) lastActivity = 0;
        idle.Clear(); activity.Clear(); idleDiscarded = activityDiscarded = 0;
    }
    static PathRttObservation Rtt(List<double> values, int discarded)
    {
        if (values.Count == 0) return new(0, null, null, discarded);
        double[] sorted = values.Order().ToArray();
        return new(sorted.Length, sorted[(int)Math.Ceiling(sorted.Length * .5) - 1], sorted[(int)Math.Ceiling(sorted.Length * .95) - 1], discarded);
    }
    PathTrafficWindow Window(long ended, bool complete) => new(began, ended, complete,
        sentPackets, sentBytes, receivedPackets, receivedBytes, rejected, Rtt(idle, idleDiscarded), Rtt(activity, activityDiscarded));
    void Store(PathTrafficWindow window) { windows.Enqueue(window); while (windows.Count > RetainedWindows) windows.Dequeue(); }
    public void Tick(long now)
    {
        if (!running || now < began + WindowMs) return;
        // A suspension or scheduling gap cannot attribute all old data to the
        // last five seconds. Keep the actual observation interval and flag it
        // incomplete; never fabricate a run of three successful windows.
        bool continuous = now - began <= WindowMs + 500;
        Store(Window(now, continuous)); began = now; Clear(false);
    }
    public void Send(int bytes, bool accepted, long now)
    {
        if (bytes is < 1 or > MeshLink.Mtu) throw new ArgumentOutOfRangeException(nameof(bytes));
        if (!running) return; Tick(now);
        if (accepted) { sentPackets++; sentBytes += bytes; lastActivity = now; } else rejected++;
    }
    public void Receive(int bytes, long now)
    {
        if (bytes is < 1 or > MeshLink.Mtu) throw new ArgumentOutOfRangeException(nameof(bytes));
        if (!running) return; Tick(now); receivedPackets++; receivedBytes += bytes; lastActivity = now;
    }
    public bool RecentlyBusy(long now) => running && lastActivity != 0 && now - lastActivity is >= 0 and <= 1000;
    public void RoundTrip(double milliseconds, long now, bool? activityAtSend = null)
    {
        if (!running || !double.IsFinite(milliseconds) || milliseconds < 0 || milliseconds > 12000) return;
        Tick(now);
        bool busy = activityAtSend ?? RecentlyBusy(now);
        var samples = busy ? activity : idle;
        if (samples.Count < MaximumRttSamples) samples.Add(milliseconds);
        else if (busy) activityDiscarded++; else idleDiscarded++;
    }
    public void Suspend(string reason, long now)
    {
        if (!running) return;
        Tick(now); if (now > began) Store(Window(now, false)); running = false; state = reason; Clear();
    }
    public PathTrafficSnapshot Snapshot(long now) => new(identity.PathId, identity.LeaseId, identity.NetworkGeneration,
        state, sendEpoch, receiveEpoch, windows.ToArray(), running ? Window(now, false) : null);
}
