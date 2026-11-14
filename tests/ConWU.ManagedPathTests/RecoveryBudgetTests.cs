using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using StreamLink.Core;

static class RecoveryBudgetTests
{
    public static async Task<object> ControlFlood(Action<bool, string> check, Func<string, string, byte[]> packet)
    {
        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var guest = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner))); guest.Directory = owner.Directory;
        var adapter = new Adapter(); await using var router = new MeshRouter(owner, adapter);
        await using var remote = new Echo(guest, owner, router.LocalEndpoint, new(), packet(guest.LocalIp, owner.LocalIp));
        router.SetCandidate(2, remote.Local, "fixture", "");
        var clock = Stopwatch.StartNew();
        while (!router.Status().Single().Connected) {
            if (clock.ElapsedMilliseconds > 8000) throw new Exception("control flood fixture could not authenticate");
            await Task.Delay(20);
        }
        await Task.Delay(250);
        int baseline = Volatile.Read(ref remote.HelloReplies);
        var before = TraversalResources.Shared.Usage(); clock.Restart();
        await remote.HelloBurst(300); await Task.Delay(250);
        var after = TraversalResources.Shared.Usage(); int replies = Volatile.Read(ref remote.HelloReplies) - baseline;
        check(replies > 0 && replies < 100 && after.SearchDeferred > before.SearchDeferred &&
            after.SearchAdmitted - before.SearchAdmitted <= 8 + 48 * clock.Elapsed.TotalSeconds + 2,
            "authenticated legacy hello flood produces bounded real replies and visible search deferral");
        check(replies <= after.SearchAdmitted - before.SearchAdmitted + 2 && router.Status().Single().Connected,
            "legacy handshake replies have admission evidence without replacing the active path");
        int received = adapter.Incoming.Count; await remote.BusinessBurst(24);
        clock.Restart();
        while (adapter.Incoming.Count < received + 24 && clock.ElapsedMilliseconds < 2000) await Task.Delay(10);
        check(adapter.Incoming.Count == received + 24,
            "ordinary authenticated IP datagrams continue while the control burst has exhausted its search tokens");
        return new { authenticatedHelloRequests = 300, observedReplies = replies,
            admittedSearchDelta = after.SearchAdmitted - before.SearchAdmitted,
            deferredSearchDelta = after.SearchDeferred - before.SearchDeferred,
            deliveredBusinessPackets = adapter.Incoming.Count - received };
    }
    public static async Task<object> Run(Action<bool, string> check, Func<string, string, byte[]> packet)
    {
        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var guests = Enumerable.Range(0, 7).Select(_ => MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)))).ToArray();
        foreach (var guest in guests) guest.Directory = owner.Directory;
        var adapter = new Adapter();
        await using var router = new MeshRouter(owner, adapter);
        var wire = new ConcurrentQueue<long>();
        var nodes = guests.Select(guest => new Echo(guest, owner, router.LocalEndpoint, wire, packet(guest.LocalIp, owner.LocalIp))).ToArray();
        try {
            foreach (var node in nodes) router.SetCandidate(node.Slot, node.Local, "fixture", "");
            var clock = Stopwatch.StartNew();
            while (router.Status().Any(p => !p.Connected)) {
                if (clock.ElapsedMilliseconds > 10000) throw new Exception("seven-neighbor fixture could not authenticate");
                await Task.Delay(25);
            }
            // Initial candidate challenges are not the selected-path
            // maintenance phase measured below. This is not a full wire audit.
            wire.Clear();
            var admissionStart = TraversalResources.Shared.Usage();
            foreach (var node in nodes) node.Load = true;
            clock.Restart();
            while (router.Status().Any(p => p.Recovery?.StableBusinessConfirmedMs == null)) {
                if (clock.ElapsedMilliseconds > 35000) throw new Exception("seven-neighbor recovery starved: " +
                    System.Text.Json.JsonSerializer.Serialize(router.Status().Select(p => new { p.Slot, p.Recovery })));
                await Task.Delay(25);
            }
            foreach (var node in nodes) node.Load = false;
            var status = router.Status(); var times = wire.ToArray().Order().ToArray();
            double seconds = Stopwatch.GetElapsedTime(times[0], times[^1]).TotalSeconds;
            int peak = 0, head = 0;
            for (int tail = 0; tail < times.Length; tail++) {
                while (Stopwatch.GetElapsedTime(times[head], times[tail]).TotalSeconds > 1) head++;
                peak = Math.Max(peak, tail - head + 1);
            }
            Console.WriteLine($"Maintenance observation: frames={times.Length} span={seconds:F3}s peak1s={peak} elapsedMs={clock.ElapsedMilliseconds}");
            check(status.Length == 7 && status.All(p => p.Connected && p.Recovery!.ConsecutiveProbes >= 10),
                "one real Router fairly completes business recovery for all seven authenticated neighbors");
            check(status.Sum(p => p.Recovery!.BudgetDeferred) > 0,
                "seven-neighbor workload actually exhausts shared maintenance tokens and reports deferral");
            check(times.Length <= 8 + 24 * seconds + 3 && peak <= 34,
                $"observed outbound MeshLink maintenance remains within 24 pps plus burst and loopback receive-time tolerance (frames={times.Length}, seconds={seconds:F3}, peak={peak})");
            check(status.All(p => p.Recovery!.StableBusinessConfirmedMs >= p.Recovery.StableBusinessStartMs + 3000),
                "budget contention never bypasses the business observation duration");
            return new { status = "Pass", neighbors = 7, elapsedMs = clock.ElapsedMilliseconds, maintenanceFrames = times.Length,
                receiveIntervalSeconds = seconds, peakOneSecondFrames = peak, peers = status,
                admissionStart, admissionEnd = TraversalResources.Shared.Usage(),
                scope = "one production legacy MeshRouter, seven authenticated loopback echo fixtures representing separate remote devices; real MeshLink UDP I/O, memory IP adapter; not eight real Windows or native wire overhead" };
        } finally { foreach (var node in nodes) await node.DisposeAsync(); }
    }

    sealed class Echo : IAsyncDisposable
    {
        readonly Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        readonly MeshLink link;
        readonly IPEndPoint target;
        readonly byte[] business;
        readonly ConcurrentQueue<long> wire;
        readonly CancellationTokenSource stop = new();
        readonly Task receive, send;
        public readonly int Slot;
        public int HelloReplies;
        public volatile bool Load;
        public IPEndPoint Local => (IPEndPoint)socket.LocalEndPoint!;
        public Echo(MeshProfile profile, MeshProfile owner, IPEndPoint target, ConcurrentQueue<long> wire, byte[] business)
        {
            Slot = profile.Self.Slot; this.target = target; this.wire = wire; this.business = business;
            var key = MeshIdentity.SharedKey(profile, owner.Self);
            try { link = new(Slot, owner.Self.Slot, key); } finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(key); }
            socket.ExclusiveAddressUse = true; socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            receive = Receive(); send = Send();
        }
        async Task Receive()
        {
            var buffer = new byte[2048];
            while (!stop.IsCancellationRequested) {
                var got = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), stop.Token);
                if (!got.RemoteEndPoint.Equals(target)) continue;
                var value = link.Receive(buffer.AsSpan(0, got.ReceivedBytes));
                if (!value.Authenticated) continue;
                if (buffer[4] == 2) Interlocked.Increment(ref HelloReplies);
                if (buffer[4] is 5 or 6) wire.Enqueue(Stopwatch.GetTimestamp());
                if (value.Reply != null) await socket.SendToAsync(value.Reply, SocketFlags.None, target, stop.Token);
            }
        }
        public async Task HelloBurst(int count)
        {
            for (int i = 0; i < count; i++) await socket.SendToAsync(link.Hello(), SocketFlags.None, target, stop.Token);
        }
        public async Task BusinessBurst(int count)
        {
            for (int i = 0; i < count; i++) await socket.SendToAsync(link.Data(business)!, SocketFlags.None, target, stop.Token);
        }
        async Task Send()
        {
            int tick = 0;
            while (!stop.IsCancellationRequested) {
                if (Load && link.Connected) {
                    var data = link.Data(business);
                    if (data != null) await socket.SendToAsync(data, SocketFlags.None, target, stop.Token);
                    // These are seven separate remote-device clocks, not seven
                    // additional copies of this node's shared limiter.
                    if (tick++ % 4 == 0 && link.Ping() is {} ping) await socket.SendToAsync(ping, SocketFlags.None, target, stop.Token);
                }
                await Task.Delay(100, stop.Token);
            }
        }
        public async ValueTask DisposeAsync()
        {
            stop.Cancel();
            try { await Task.WhenAll(receive, send); } catch (OperationCanceledException) { }
            finally { socket.Dispose(); link.Dispose(); stop.Dispose(); }
        }
    }
}
