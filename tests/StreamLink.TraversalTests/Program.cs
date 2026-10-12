using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

static partial class Program
{
    static int checks;
    static readonly CancellationToken None = CancellationToken.None;
    static void Check(bool pass, string description) { if (!pass) throw new Exception(description); checks++; Console.WriteLine("PASS " + description); }
    static byte[] Key() => RandomNumberGenerator.GetBytes(32);
    static UdpTraversal Session(ITraversalSocket socket, Guid attempt, int slot, byte[] key, TraversalResources? resources = null)
        => new(socket, Guid.NewGuid(), attempt, slot, 3 - slot, key, resources ?? new());
    static async Task ObserveOnly(string[] servers)
    {
        // Explicit developer diagnostic; never called by the application.
        var observations = new List<NatObservation>();
        var errors = new List<object>(); UdpTraversal? probe = null;
        using var total = new CancellationTokenSource(20000);
        try {
            foreach (string server in servers.Take(4)) {
                try {
                    using var resolve = CancellationTokenSource.CreateLinkedTokenSource(total.Token); resolve.CancelAfter(1500);
                    var target = await Stun.Resolve(server, resolve.Token);
                    probe ??= Session(new TraversalSocket(new(Stun.LocalAddress(target), 0)), Guid.NewGuid(), 1, Key());
                    observations.Add(await probe.Observe(target, total.Token));
                } catch (Exception ex) when (ex is System.Net.Sockets.SocketException or IOException or OperationCanceledException or ArgumentException) {
                    errors.Add(new { server, reason = ex is OperationCanceledException ? "timeout-or-budget" : ex.GetType().Name });
                    if (total.IsCancellationRequested) break;
                }
            }
        } finally { if (probe != null) await probe.DisposeAsync(); }
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { observations = observations.Select(o => new { o.SocketId, o.NetworkGeneration, o.Protocol, local = o.Local.ToString(), target = o.Target.ToString(), mapped = o.Mapped.ToString(), o.ObservedAt }), errors, assessment = NatObservations.Assess(observations, DateTimeOffset.UtcNow) }));
    }
    static async Task Data(UdpTraversal a, UdpTraversal b, byte[] key)
    {
        using var left = new MeshLink(1, 2, key); using var right = new MeshLink(2, 1, key);
        using var timeout = new CancellationTokenSource(3000);
        await a.SendPayload(left.Hello(), timeout.Token);
        var ack = right.Receive((await b.ReceivePayload(timeout.Token)).Data);
        await b.SendPayload(ack.Reply!, timeout.Token);
        var confirm = left.Receive((await a.ReceivePayload(timeout.Token)).Data);
        await a.SendPayload(confirm.Reply!, timeout.Token);
        right.Receive((await b.ReceivePayload(timeout.Token)).Data);
        byte[] payload = RandomNumberGenerator.GetBytes(1280);
        await a.SendPayload(left.Data(payload)!, timeout.Token);
        Check(right.Receive((await b.ReceivePayload(timeout.Token)).Data).Packet!.SequenceEqual(payload), "same winning socket carries a real 1344-byte encrypted MeshLink datagram A to B");
        await b.SendPayload(right.Data(payload)!, timeout.Token);
        Check(left.Receive((await a.ReceivePayload(timeout.Token)).Data).Packet!.SequenceEqual(payload), "verified socket carries authenticated application data B to A");
    }
    static async Task RealLoopback()
    {
        await using var s1 = new Reflector(IPAddress.Loopback);
        await using var s2 = new Reflector(IPAddress.Parse("127.0.0.2"));
        await using var s3 = new Reflector(IPAddress.Parse("127.0.0.2"));
        var socketA = new TraversalSocket(new(IPAddress.Loopback, 0)); var socketB = new TraversalSocket(new(IPAddress.Loopback, 0));
        var endpointA = socketA.Local; var id = socketA.Id; var attempt = Guid.NewGuid(); byte[] key = Key();
        await using (var a = Session(socketA, attempt, 1, key))
        await using (var b = Session(socketB, attempt, 2, key)) {
            var observations = new[] { await a.Observe(s1.Endpoint, None), await a.Observe(s2.Endpoint, None), await a.Observe(s3.Endpoint, None) };
            Check(observations.All(o => o.SocketId == id && o.Local.Equals(endpointA) && o.Mapped.Equals(endpointA)), "real STUN ignores wrong transactions and wrong source; same socket is retained");
            Check(NatObservations.Assess(observations, DateTimeOffset.UtcNow).Mapping == "observed-eim", "loopback evidence is scoped to observed mapping only");
            Check(NatObservations.Assess(observations, DateTimeOffset.UtcNow).Filtering == "unknown", "ordinary STUN does not claim filtering classification");
            var result = await Task.WhenAll(a.Punch([b.Local], new(2000), None), b.Punch([a.Local], new(2000), None));
            Check(result.All(r => r.Success) && a.SocketId == id && a.Local.Equals(endpointA), "real bilateral checks preserve the STUN binding");
            await Data(a, b, key);
        }
        using var rebound = new TraversalSocket(endpointA);
        Check(rebound.Local.Equals(endpointA), "disposal releases the winning socket for rebinding");
    }
    static async Task Model(string leftMapping, string leftFilter, string rightMapping, string rightFilter, bool success, bool learn = false, bool stunOnly = false, int maximumPayload = 1472)
    {
        var lab = new NatLab();
        var left = lab.Add("192.0.2.1", leftMapping, leftFilter, 40111, maximumPayload: maximumPayload);
        var right = lab.Add("192.0.2.2", rightMapping, rightFilter, 50919, stunOnly);
        var attempt = Guid.NewGuid(); byte[] key = Key();
        await using (var a = Session(left, attempt, 1, key))
        await using (var b = Session(right, attempt, 2, key)) {
            var observedA = await a.Observe(NatLab.Reflectors[0], None); var observedB = await b.Observe(NatLab.Reflectors[0], None);
            var result = await Task.WhenAll(a.Punch([observedB.Mapped], new(1000, 24), None), b.Punch([observedA.Mapped], new(1000, 24), None));
            Check(result.All(r => r.Success == success), $"model {leftMapping}/{leftFilter} vs {rightMapping}/{rightFilter}; stunOnly={stunOnly}, maxPayload={maximumPayload}, expected={success}");
            Check(result.All(r => r.SentPackets <= 24), "each attempt respects packet budget");
            if (success) {
                if (learn) Check(result[0].LearnedCandidates > 0 && a.Selected != null && !a.Selected.Equals(observedB.Mapped), "authenticated prflx learns the actual destination-dependent source");
                await Data(a, b, key);
            } else Check(result.All(r => r.Failure.Length > 0), "failure is explicit and never reported as established");
            if (maximumPayload is >= 96 and < 1344 && !stunOnly) Check(result.All(r => r.Failure == "mtu-unverified"), "small packets succeed but PMTU failure is reported separately");
        }
        Check(left.Disposed && right.Disposed, "unsuccessful and successful paths both release socket resources");
    }
    static async Task Classification()
    {
        foreach (string behavior in new[] { "eim", "adm", "apdm" }) {
            var lab = new NatLab(); var socket = lab.Add("192.0.2.1", behavior, "apdf", 53711);
            await using var node = Session(socket, Guid.NewGuid(), 1, Key());
            var observations = new List<NatObservation>(); foreach (var reflector in NatLab.Reflectors) observations.Add(await node.Observe(reflector, None));
            Check(NatObservations.Assess(observations, DateTimeOffset.UtcNow).Mapping == "observed-" + behavior, "mapping matrix identifies observed " + behavior + " without assuming port preservation");
            var modified = observations.ToArray(); modified[1] = modified[1] with { SocketId = Guid.NewGuid() };
            Check(NatObservations.Assess(modified, DateTimeOffset.UtcNow).Mapping == "unknown", "different sockets cannot be combined for classification");
            modified = observations.ToArray(); modified[1] = modified[1] with { Protocol = "tcp" };
            Check(NatObservations.Assess(modified, DateTimeOffset.UtcNow).Mapping == "unknown", "UDP evidence does not classify TCP");
            Check(NatObservations.Assess(observations, DateTimeOffset.UtcNow.AddMinutes(2)).Mapping == "unknown", "expired observations cannot determine strategy");
            Check(NatObservations.Assess(observations.Take(2).ToArray(), DateTimeOffset.UtcNow).Mapping == "unknown", "two ordinary STUN endpoints are not a full behavior test");
            modified = observations.ToArray(); modified[1] = modified[1] with { NetworkGeneration = Guid.NewGuid() };
            Check(NatObservations.Assess(modified, DateTimeOffset.UtcNow).Mapping == "unknown", "network-generation change invalidates comparison");
        }
    }
    static async Task AuthenticationAndLimits()
    {
        var counter = new TraversalResources(2, 0, 2);
        using (var firstLease = counter.Acquire()) {
            using (counter.Acquire()) Check(counter.Usage().OpenUdpResources == 2 && counter.Usage().PeakUdpResources == 2,
                "resource snapshots include concurrent ownership without a per-attempt reset");
            Check(counter.Usage().OpenUdpResources == 1 && counter.Usage().PeakUdpResources == 2, "quota release preserves historical peak");
            Check(counter.TrySend(32) && counter.TrySend(48, maintenance: true) && !counter.TrySend(32) && !counter.TrySend(48, maintenance: true),
                "one non-refilling ledger admits exactly its burst across search and maintenance");
            var observed = counter.Usage();
            Check(observed.SearchAdmitted == 1 && observed.MaintenanceAdmitted == 1 && observed.AdmittedBytes == 80 &&
                observed.SearchDeferred == 1 && observed.MaintenanceDeferred == 1,
                "control snapshots distinguish admission, deferral and bytes without claiming actual wire sends");
        }
        Check(counter.Usage().OpenUdpResources == 0, "last release is visible in the same resource ledger");
        var lab = new NatLab(); var left = lab.Add("192.0.2.1", "eim", "eif", 40111); var right = lab.Add("192.0.2.2", "eim", "eif", 50919);
        var attempt = Guid.NewGuid();
        byte[] rememberedKey = Key();
        await using (var a = Session(left, attempt, 1, Key()))
        await using (var b = Session(right, attempt, 2, rememberedKey)) {
            var ea = await a.Observe(NatLab.Reflectors[0], None); var eb = await b.Observe(NatLab.Reflectors[0], None);
            var result = await Task.WhenAll(a.Punch([eb.Mapped], new(600, 6), None), b.Punch([ea.Mapped], new(600, 6), None));
            Check(result.All(r => !r.Success && r.AuthenticatedPackets == 0 && r.LearnedCandidates == 0), "wrong credentials cannot select or teach an endpoint");
            bool rejected = false; try { await a.SendPayload(new byte[40], None); } catch (IOException) { rejected = true; }
            Check(rejected, "application data is refused before verification");
        }
        var captured = lab.Wire.First(w => w.Source.Address.Equals(right.External) && w.Packet.Length == 96);
        var replayLab = new NatLab(); var replayPort = replayLab.Add("192.0.2.1", "eim", "eif", 41111);
        await using (var target = Session(replayPort, Guid.NewGuid(), 1, rememberedKey)) {
            var check = target.Punch([captured.Source], new(400, 4), None);
            replayPort.Incoming.Writer.TryWrite(new(captured.Packet, captured.Source));
            var result = await check;
            Check(!result.Success && result.AuthenticatedPackets == 0 && result.LearnedCandidates == 0, "captured check from an old attempt cannot create a candidate in a new attempt");
        }
        var resources = new TraversalResources(1, 1, 1); using (resources.Acquire()) {
            bool rejected = false; try { using var overflow = resources.Acquire(); } catch (IOException) { rejected = true; }
            Check(rejected, "socket ceiling is shared across attempts");
            Check(resources.TrySend() && !resources.TrySend(), "shared token bucket bounds bursts across peers");
        }
        using (resources.Acquire()) Check(true, "disposing a lease returns the global socket slot");
        using (var occupied = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp) { ExclusiveAddressUse = true }) {
            occupied.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            using (resources.Acquire()) {
                bool quotaFirst = false;
                try { await using var rejected = UdpTraversal.Create((IPEndPoint)occupied.LocalEndPoint!, Guid.NewGuid(), Guid.NewGuid(), 1, 2, Key(), resources); }
                catch (IOException) { quotaFirst = true; }
                Check(quotaFirst, "factory rejects quota before attempting to bind an occupied candidate port");
            }
            bool bindFailed = false;
            try { await using var rejected = UdpTraversal.Create((IPEndPoint)occupied.LocalEndPoint!, Guid.NewGuid(), Guid.NewGuid(), 1, 2, Key(), resources); }
            catch (System.Net.Sockets.SocketException) { bindFailed = true; }
            using (resources.Acquire()) Check(bindFailed, "failed factory bind returns the reserved resource quota");
        }
        var completion = new TraversalControlRound(new TraversalResources(8, 10000, 256));
        for (int i = 0; i < 96; i++) if (!completion.TrySend(96, false)) throw new Exception("search budget ended early");
        Check(!completion.TrySend(96, false), "search cannot consume the 24 completion reservations");
        for (int i = 0; i < 24; i++) if (!completion.TrySend(96, true)) throw new Exception("completion reserve unavailable");
        Check(completion.Packets == 120 && !completion.TrySend(96, true), "checks and completion share one 120-packet limit");
        var bytes = new TraversalControlRound(new TraversalResources());
        for (int i = 0; i < 4; i++) if (!bytes.TrySend(16384, true)) throw new Exception("byte budget ended early");
        Check(bytes.Bytes == 65536 && !bytes.TrySend(1, true), "round byte cap remains bounded independently of packet count");
        using (resources.Acquire()) {
            var rejectedPort = replayLab.Add("192.0.2.3", "eim", "eif", 42111);
            try { await using var overflow = Session(rejectedPort, Guid.NewGuid(), 1, Key(), resources); } catch (IOException) { }
            Check(rejectedPort.Disposed, "resource admission failure closes the unaccepted socket");
        }
        var silentLab = new NatLab(); var silentPort = silentLab.Add("192.0.2.1", "eim", "eif", 40111);
        await using var silent = Session(silentPort, Guid.NewGuid(), 1, Key());
        using var cancel = new CancellationTokenSource(100);
        bool canceled = false;
        try { await silent.Punch([IPEndPoint.Parse("192.0.2.2:50123")], new(), cancel.Token); } catch (OperationCanceledException) { canceled = true; }
        Check(canceled, "cancellation interrupts the bounded attempt");
    }
    static async Task Main(string[] args)
    {
        if (args.Length > 1 && args[0] == "--observe") { await ObserveOnly(args[1..]); return; }
        if (args.Length == 2 && args[0] == "--managed") { await ManagedUdp(args[1]); return; }
        if (args.Length == 2 && args[0] == "--managed-smoke") { await ManagedUdp(args[1], 1); return; }
        await RealLoopback(); await Classification();
        await Model("eim", "apdf", "eim", "apdf", true);
        await Model("eim", "eif", "apdm", "apdf", true, true);
        await Model("eim", "adf", "apdm", "apdf", true, true);
        await Model("eim", "apdf", "apdm", "apdf", false);
        await Model("apdm", "apdf", "apdm", "apdf", false);
        await Model("eim", "eif", "eim", "eif", false, stunOnly: true);
        await Model("eim", "eif", "eim", "eif", false, maximumPayload: 1200);
        await Model("eim", "eif", "eim", "eif", false, maximumPayload: 1343);
        await Model("eim", "eif", "eim", "eif", true, maximumPayload: 1344);
        await AuthenticationAndLimits();
        Console.WriteLine($"{checks} traversal checks passed. Loopback/model only; no public probes, drivers, mapping rules or live configuration changes.");
    }
}
