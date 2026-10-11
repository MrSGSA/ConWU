using System.Diagnostics;
using System.Net;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.EndpointPoc;

static class FreshObservationTests
{
    public static async Task<object> Run(TcpSynObserver observer, string url, string pin, TcpObserverPoint[] points,
        Action<bool, string> check, CancellationToken token, bool raw)
    {
        await using var helper = new Reflector();
        using var lease = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), helper.Endpoint, Guid.NewGuid(), token);
        var io = new ProbeIo(observer, raw);
        await using var owner = new TcpCaptureOwner(lease, lease.NetworkGeneration, (_, _) => io); await owner.Ready;
        var budget = new TraversalResources(); var rounds = new List<object>();
        // Thirty repetitions exercise final-window attribution/resource cleanup.
        // They reuse the source; they are NOT independent allocation windows.
        for (int i = 0; i < 30; i++) {
            var profile = MeshIdentity.Create(url, pin, "faketcp"); using var control = new MeshDiscoveryClient(profile);
            await control.SaveDirectory(profile.Directory!, token);
            int charged = 0, before = io.Sent; long start = Stopwatch.GetTimestamp();
            var observations = await TcpShapeProbe.RunFresh(owner, control, () => { charged++; return true; }, _ => { }, token, budget, destinations: 2);
            double maxAgeMs = observations.Max(o => Stopwatch.GetElapsedTime(o.LocalProbeStartedAt).TotalMilliseconds);
            check(charged == 3 && io.Sent - before == 4 && observations.Length == 2 && observations.All(o => o.State == "SynObserved" &&
                o.Mapped == lease.Local.ToString() && o.ResourceId == lease.Id && o.LocalProbeStartedAt > 0 && o.TcpHandshakeVerified == "NotTested") && maxAgeMs < 2000,
                $"fresh round {i + 1}: final two-target observations arrive within local freshness limit using the retained source");
            check(owner.Status.Sessions == 0 && helper.Accepted == 1, "short observation releases tuple reservations without rebinding the helper");
            rounds.Add(new { round = i + 1, elapsedMs = Stopwatch.GetElapsedTime(start).TotalMilliseconds, maxAgeMs, charged, sent = io.Sent - before });
        }
        foreach (string fault in new[] { "legacy-catalog", "wrong-window", "nonfinal-read", "slow-register", "slow-read" }) {
            var profile = MeshIdentity.Create(url, pin, "faketcp"); using var client = new MeshDiscoveryClient(profile);
            await client.SaveDirectory(profile.Directory!, token);
            int packets = io.Sent, refs = lease.ReferenceCount; bool rejected = false;
            try { await TcpShapeProbe.RunFresh(owner, new FaultControl(client, fault), () => true, _ => { }, token, budget); }
            catch (Exception ex) when (ex is IOException or OperationCanceledException) { rejected = true; }
            check(rejected && owner.Status.Sessions == 0 && lease.ReferenceCount == refs,
                "short observation rejects " + fault + " and returns no usable anchor or leaked reference");
            if (fault is "legacy-catalog" or "wrong-window" or "slow-register")
                check(io.Sent == packets, "invalid or stale short-window registration emits no SYN");
        }
        // Direct observer injection covers a conflicting source and late arrivals
        // deterministically; no raw loopback behavior is claimed for this portion.
        var local = MeshIdentity.Create(url, pin, "faketcp"); Guid boot = Guid.NewGuid();
        var spec = new TcpProbeSpec(Guid.NewGuid(), points[0].Id, 333333333);
        var request = TcpObserverProtocol.Create(local, boot, "register-fresh", Guid.NewGuid(), [spec]);
        var opened = observer.Request(local.Pair.Network, request).Reply!;
        byte[] Packet(int port) => TcpShapeSyn.Create(new(IPAddress.Parse("192.0.2.20"), port), TcpObserverProtocol.Endpoint(points[0].Endpoint), spec.Iss, 1);
        observer.Observe(Packet(40000)); observer.Observe(Packet(40001));
        var early = observer.Request(local.Pair.Network, request).Reply!;
        check(!early.Final && early.Evidence[0].State == "Ambiguous", "conflicting sources inside the short window are ambiguous before finalization");
        await Task.Delay(TcpObserverProtocol.FreshWindowMs + 100, token);
        var final = observer.Request(local.Pair.Network, request).Reply!;
        observer.Observe(Packet(40002));
        var late = observer.Request(local.Pair.Network, request).Reply!;
        check(final.Final && final.Expires == opened.Expires && final.Evidence[0].State == "Ambiguous" &&
            late.Evidence.SequenceEqual(final.Evidence), "final short-window retry does not renew capture and late SYN cannot mutate finalized evidence");
        var collision = TcpObserverProtocol.Create(local, boot, "register-fresh", Guid.NewGuid(), [spec with { ProbeId = Guid.NewGuid() }]);
        check(observer.Request(local.Pair.Network, collision).Status == 409, "short capture retains ISS/target collision protection beyond finalization");
        using (var reference = lease.AcquireAttempt(lease.NetworkGeneration))
            check((await reference.Observe(token)).Public.Equals(lease.Local), "kernel helper still works after repeated short windows and negative cases");
        return new { rounds, windowMs = TcpObserverProtocol.FreshWindowMs, io.Sent,
            scope = raw ? "real HTTPS/helper and Linux loopback raw I/O, plus marked direct-injection negatives" : "real pinned HTTPS and TCP helper, memory raw I/O",
            independentAllocationWindows = false, portPredictionCandidate = false, nativeSo = false, publicNat = false };
    }
    sealed class FaultControl(ITcpObservationControl inner, string fault) : ITcpObservationControl
    {
        public async Task<TcpObserverReply> TcpObservation(string operation, Guid ticket, TcpProbeSpec[]? probes, CancellationToken token)
        {
            var reply = await inner.TcpObservation(operation, ticket, probes, token);
            if (operation == "catalog" && fault == "legacy-catalog") return reply with { FreshWindowMs = 0 };
            if (operation == "register-fresh" && fault == "wrong-window") return reply with { CaptureWindowMs = 8000 };
            if (operation == "read" && fault == "nonfinal-read") return reply with { Final = false };
            if (operation == "register-fresh" && fault == "slow-register") await Task.Delay(900, token);
            if (operation == "read" && fault == "slow-read") await Task.Delay(2000, token);
            return reply;
        }
    }
}
