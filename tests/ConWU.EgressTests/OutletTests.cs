using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using StreamLink.Core;

static class OutletTests
{
    public static async Task<object[]> Run(Action<bool, string> check, CancellationToken token)
    {
        return [await Hierarchy(check, token), await RoutedLifetime(check, token), await RetiringOutlet(check, token), RouteEvidence(check)];
    }
    static async Task<object> Hierarchy(Action<bool, string> check, CancellationToken token)
    {
        using var pacer = new EgressPacer(10);
        using var begin = new ManualResetEventSlim();
        var events = new ConcurrentQueue<(long At, int Outlet, int Size)>();
        var flows = new EgressPacer.Flow[7]; bool done = false;
        var sizes = new[] { 1466, 300, 1466, 300, 1466, 300, 700 };
        for (int i = 0; i < flows.Length; i++) {
            int slot = i, outlet = i == 6 ? 1 : 0; var packet = new byte[sizes[i]];
            flows[i] = pacer.Register("peer-" + i, "fixture-interface-" + outlet, (_, _) => {
                begin.Wait(token); events.Enqueue((Stopwatch.GetTimestamp(), outlet, packet.Length));
                if (!Volatile.Read(ref done)) flows[slot].TrySend(packet, packet.Length);
                return true;
            });
            for (int n = 0; n < 20; n++) flows[i].TrySend(packet, packet.Length);
        }
        var clock = Stopwatch.StartNew(); begin.Set(); await Task.Delay(2000, token); Volatile.Write(ref done, true);
        foreach (var flow in flows) flow.Dispose(); pacer.Dispose();
        var snapshot = pacer.Snapshot();
        var outlets = snapshot.Outlets.OrderBy(o => o.Outlet).ToArray();
        check(outlets.Length == 2 && outlets.All(o => o.SentBytes > 0) &&
            outlets.Max(o => o.SentBytes) / (double)outlets.Min(o => o.SentBytes) < 1.15,
            "two outlets get comparable byte shares although one has six peers and the other one");
        var shares = outlets[0].Peers.Select(p => p.SentBytes).ToArray();
        check(shares.Min() > 0 && shares.Max() / (double)shares.Min() < 1.25,
            "different packet lengths remain byte-fair within the six-peer outlet");
        var observed = events.ToArray(); bool bounded = true; int first = 0; long bytes = 0;
        for (int last = 0; last < observed.Length; last++) {
            bytes += observed[last].Size;
            while (Stopwatch.GetElapsedTime(observed[first].At, observed[last].At).TotalMilliseconds > 10) bytes -= observed[first++].Size;
            if (bytes - Stopwatch.GetElapsedTime(observed[first].At, observed[last].At).TotalSeconds * 1250000 > snapshot.BurstBytes + 1466) bounded = false;
        }
        check(bounded && snapshot.SentBytes <= clock.Elapsed.TotalSeconds * 1250000 + snapshot.BurstBytes + 1466 &&
            snapshot.RateScope == "WholeDevice", "multiple outlets cannot multiply the device rate or burst envelope");
        check(snapshot.Accounting!.Conserved && snapshot.QueuedBytes == 0 && snapshot.Failure == "" &&
            outlets.Sum(o => o.SentBytes) == snapshot.SentBytes && outlets.All(o => o.PeakQueuedBytes <= o.QueueLimitBytes),
            "outlet, peer and device accounting converge with bounded queues");
        return new { elapsedMs = clock.Elapsed.TotalMilliseconds, snapshot,
            scope = "real Windows pacing timer, controlled callback sinks; two outlet identities are fixtures, not two physical uplinks" };
    }
    static async Task<object> RoutedLifetime(Action<bool, string> check, CancellationToken token)
    {
        using var pacer = new EgressPacer(10);
        using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        var flow = pacer.RegisterRouted("same-member", c => (string)c!, (_, _) => { entered.Set(); release.Wait(token); return true; });
        try {
            var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            check(flow.TrySend(new byte[400], 400, "route-before", completion: completed), "routed resource queues on its first outlet");
            entered.Wait(token);
            check(flow.TrySend(new byte[600], 600, "route-after"), "route change uses a second outlet without a second socket or flow registration");
            var busy = pacer.Snapshot();
            check(busy.Outlets.Single(o => o.Outlet == "route-after").QueuedBytes == 600 && flow.SendQueue.Accounting.Conserved,
                "queued data retains its enqueue outlet and shared resource accounting");
            var close = Task.Run(flow.Dispose); await Task.Delay(30, token);
            check(!close.IsCompleted && flow.SendQueue.Accounting.Cancelled.Packets == 1,
                "closing routed flow cancels every outlet queue but waits for its actual in-flight send");
            release.Set(); await close.WaitAsync(token); await completed.Task.WaitAsync(token); pacer.Dispose();
            var final = pacer.Snapshot();
            check(final.Accounting!.Conserved && final.QueuedBytes == 0 && final.SentBytes == 400 && final.Cancelled == 1 &&
                final.Peers.Single(p => p.Peer == "same-member").SentBytes == 400 && flow.SendQueue.Accounting.Conserved,
                "one routed resource is not double-counted across outlet changes and closes without a queued reference");
            return new { busy, final, resource = flow.SendQueue, scope = "controlled route transition with a blocked actual callback; no physical interface change" };
        } finally { release.Set(); flow.Dispose(); }
    }
    static object RouteEvidence(Action<bool, string> check)
    {
        string v4 = EgressRouteSnapshot.PacingKey(IPAddress.Loopback, IPAddress.Loopback);
        string v6 = EgressRouteSnapshot.PacingKey(IPAddress.IPv6Loopback, IPAddress.IPv6Loopback);
        check(v4.StartsWith("WindowsInterface:") && v6 == v4,
            "actual Windows loopback IPv4/IPv6 route evidence shares one interface outlet");
        check(EgressRouteSnapshot.PacingKey(IPAddress.Loopback, IPAddress.IPv6Loopback) == "Unresolved",
            "incompatible source and destination families share the conservative unresolved outlet");
        int lookups = 0; var cache = new EgressRouteCache((_, _) => "fixture-" + ++lookups);
        bool reused = Enumerable.Range(0, 100).All(_ => cache.Get(IPAddress.Loopback, IPAddress.Loopback) == "fixture-1");
        check(reused && lookups == 1, "repeated sends to one destination IP reuse one OS route lookup");
        for (int i = 1; i <= 40; i++) cache.Get(IPAddress.Any, IPAddress.Parse("192.0.2." + i));
        check(cache.Get(IPAddress.Loopback, IPAddress.Loopback) != "fixture-1" && lookups == 42,
            "per-resource route cache evicts old evidence after its 32-address bound");
        return new { v4, v6, lookups, scope = "read-only GetBestRoute2 for real loopback plus bounded-cache fixture" };
    }
    static async Task<object> RetiringOutlet(Action<bool, string> check, CancellationToken token)
    {
        using var pacer = new EgressPacer(10); using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        var flow = pacer.Register("retiring", "retiring-interface", (_, _) => { entered.Set(); release.Wait(token); return true; });
        try {
            flow.TrySend(new byte[500], 500); entered.Wait(token);
            var close = Task.Run(flow.Dispose);
            while (flow.Alive) await Task.Delay(1, token);
            for (int i = 0; i < 70; i++) { using var other = pacer.Register("churn-" + i, "churn-interface", (_, _) => true); }
            check(pacer.Snapshot().Outlets.Any(o => o.Outlet == "retiring-interface") && !close.IsCompleted,
                "record reclamation cannot retire the outlet of a closed but still in-flight resource");
            release.Set(); await close.WaitAsync(token); pacer.Dispose(); var snapshot = pacer.Snapshot();
            check(snapshot.SentBytes == 500 && snapshot.Outlets.Sum(o => o.SentBytes) + snapshot.RetiredOutletSentBytes == 500 && snapshot.Accounting!.Conserved,
                "late actual send completion survives concurrent flow closure and outlet record churn");
            return snapshot;
        } finally { release.Set(); flow.Dispose(); }
    }
}
