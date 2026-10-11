using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

// Abort actual loopback HTTPS connections, including pending long polls.
// This is not a public-WAN, NIC or operating-system firewall failure fixture.
sealed class ControlFailureGate
{
    readonly object gate = new();
    readonly HashSet<HttpContext> active = [];
    bool offline;
    public long Blocked;
    public async Task Handle(HttpContext context, Func<Task> next)
    {
        lock (gate) {
            if (offline) { Interlocked.Increment(ref Blocked); context.Abort(); return; }
            active.Add(context);
        }
        try { await next(); } finally { lock (gate) active.Remove(context); }
    }
    public void SetOffline(bool value)
    {
        HttpContext[] interrupted;
        lock (gate) { offline = value; interrupted = value ? active.ToArray() : []; }
        // Abort may run cancellation continuations; never do that while
        // enumerating the mutable set or holding its lock.
        foreach (var context in interrupted) context.Abort();
    }
}

static class LifecycleTests
{
    public static async Task<object> Run(string binary, string root, string url, string pin,
        ControlFailureGate control, Action<bool, string> check, CancellationToken token)
    {
        var a = MeshIdentity.Create(url, pin, "faketcp");
        var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        // Administration must not change the Runner profile through aliasing.
        var admin = JsonSerializer.Deserialize<MeshProfile>(JsonSerializer.Serialize(a))!;
        var profiles = new[] { a, b }.Select(m => new DeviceProfile {
            Mesh = m, TraversalMode = "tcp", PathSelection = "faketcp-only", TcpStun = ["fixture.invalid:3478"]
        }).ToArray();
        await using var reflector = new Reflector();
        var wire = new NativeIpv6RunnerTests.Wire(false);
        var logs = new ConcurrentQueue<string>();
        var factories = profiles.Select(p => new NativeIpv6RunnerTests.Inspect(new MeshCandidateFactory(p, binary, root,
            [TraversalProfile.FakeTcpHttpSo], captureBroker: true, diagnostic: logs.Enqueue) {
            ResolveTarget = (_, _, _) => Task.FromResult(reflector.Endpoint),
            OpenCaptureForTest = (local, _) => wire.Open(local),
            RouteCheckForTest = (remote, expected, _) => {
                if (!IPAddress.IsLoopback(remote.Address) || expected != null && !IPAddress.IsLoopback(expected)) throw new IOException("Loopback fixture only");
            }
        })).ToArray();
        var adapters = new[] { new NativeIpv6RunnerTests.Adapter(), new NativeIpv6RunnerTests.Adapter() };
        var states = new SessionStatus?[2]; var remembered = new long[2];
        using var running = CancellationTokenSource.CreateLinkedTokenSource(token);
        MeshRuntimeServices Services(int i) => new(m => new MeshDiscoveryClient(m), _ => Task.FromResult<IPacketAdapter>(adapters[i]),
            async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new IOException(); },
            _ => throw new IOException("No legacy transport or relay in lifecycle fixture"),
            (_, _, ct) => Task.Delay(Timeout.Infinite, ct), (_, _, _) => { }, (_, _) => { }, Path.Combine(root, "lifecycle")) {
                Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(factories[i])
            };
        var tasks = profiles.Select((p, i) => new MeshRunner(p, logs.Enqueue, s => states[i] = s,
            d => Interlocked.Exchange(ref remembered[i], d.Revision), _ => { }, Services(i)).Run(running.Token)).ToArray();
        var clock = Stopwatch.StartNew(); var phases = new List<object>(); int sequence = 0;
        async Task Until(Func<bool> condition, string label, int milliseconds)
        {
            long start = Stopwatch.GetTimestamp();
            while (!condition()) {
                foreach (var task in tasks) if (task.IsFaulted) await task;
                if (Stopwatch.GetElapsedTime(start).TotalMilliseconds > milliseconds) throw new TimeoutException(label + "\n" + string.Join('\n', logs));
                await Task.Delay(20, token);
            }
        }
        async Task Traffic(TimeSpan duration, string phase)
        {
            var timer = Stopwatch.StartNew(); double maximumDeliveryMs = 0, nextProgress = 60; int sent = 0;
            do {
                int current = ++sequence;
                var expected = new[] { NativeIpv6RunnerTests.Packet(b.LocalIp, a.LocalIp), NativeIpv6RunnerTests.Packet(a.LocalIp, b.LocalIp) };
                foreach (var packet in expected) BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(28), current);
                var delivery = Stopwatch.StartNew();
                adapters[0].Outgoing.Add(expected[1]); adapters[1].Outgoing.Add(expected[0]);
                await Until(() => adapters.All(x => !x.Incoming.IsEmpty), phase + ": bidirectional business missing", 2000);
                for (int i = 0; i < 2; i++)
                    if (!adapters[i].Incoming.TryDequeue(out var packet) || !packet.SequenceEqual(expected[i]) || !adapters[i].Incoming.IsEmpty)
                        throw new IOException(phase + ": missing, duplicated or corrupted inner IP packet");
                maximumDeliveryMs = Math.Max(maximumDeliveryMs, delivery.Elapsed.TotalMilliseconds); sent += 2;
                if (!states.All(s => s?.Connected == true)) throw new IOException(phase + ": healthy path became disconnected");
                await Task.Delay(1000, token);
                if (timer.Elapsed.TotalSeconds >= nextProgress) { Console.WriteLine($"PROGRESS {phase}: {timer.Elapsed.TotalSeconds:F1}s, {sent} verified packets"); nextProgress += 60; }
            } while (timer.Elapsed < duration);
            check(factories.All(f => f.Gathers == 1 && f.Paths.Count == 1), phase + ": same nominated path, no replacement handshake or relay");
            phases.Add(new { phase, elapsedSeconds = timer.Elapsed.TotalSeconds, sent, delivered = sent, maximumDeliveryMs });
            Console.WriteLine($"PHASE {phase}: {timer.Elapsed.TotalSeconds:F1}s, {sent} exact bidirectional packets");
        }
        bool guestRevoked = false;
        try {
            await Until(() => states.All(s => s?.Connected == true), "production lifecycle pair connected", 45000);
            check(factories.All(f => f.Paths.Count == 1) && reflector.Active == 2, "formal native factory owns two real helper connections before outage");
            await Traffic(TimeSpan.FromSeconds(2), "baseline");
            int helperRequests = reflector.Requests;
            control.SetOffline(true);
            try { await Traffic(TimeSpan.FromSeconds(360), "both-control-connections-aborted"); }
            finally { control.SetOffline(false); }
            check(control.Blocked > 0 && reflector.Requests > helperRequests && reflector.Active == 2,
                "six-minute HTTPS outage crosses announcement expiry; TCP reflection remains separately available");
            await Traffic(TimeSpan.FromSeconds(3), "control-restored");
            helperRequests = reflector.Requests; reflector.Silent = true;
            await Traffic(TimeSpan.FromSeconds(24), "reflection-query-timeout");
            check(reflector.Requests > helperRequests && reflector.Active == 2,
                "failed reflection query retains the source sockets of healthy native paths");
            reflector.Silent = false;
            MeshIdentity.Revoke(admin, b.Self.Slot);
            using (var administration = new MeshDiscoveryClient(admin)) await administration.SaveDirectory(admin.Directory!, token);
            var revokeTimer = Stopwatch.StartNew();
            while (!tasks[1].IsCompleted) {
                if (revokeTimer.Elapsed.TotalSeconds > 45) throw new TimeoutException("revoked Runner continued despite recovered signed directory");
                await Task.Delay(50, token);
            }
            try { await tasks[1]; } catch (MeshRevokedException) { guestRevoked = true; }
            check(guestRevoked && adapters[1].Disposed, "signed removal exits the revoked member's actual native Runner");
            await Until(() => remembered[0] == admin.Directory!.Revision, "remaining member learned revocation via HTTPS", 45000);
            check(a.Directory!.Revision == admin.Directory!.Revision, "owner-signed directory is applied before further traversal after recovery");
            phases.Add(new { phase = "revocation", elapsedSeconds = revokeTimer.Elapsed.TotalSeconds, guestRevoked });
        } finally {
            control.SetOffline(false); running.Cancel();
            foreach (var task in tasks) try { await task.WaitAsync(TimeSpan.FromSeconds(10)); }
                catch (OperationCanceledException) { } catch (MeshRevokedException) when (guestRevoked) { }
        }
        check(adapters.All(x => x.Disposed) && wire.Endpoints.Values.All(x => x.Closed) && reflector.Active == 0,
            "shutdown releases capture, source sockets and adapters after revocation");
        return new { phases, elapsedSeconds = clock.Elapsed.TotalSeconds, control.Blocked, reflector.Requests,
            paths = factories.Select(f => f.Paths.Select(p => new { p.PathId, p.AttemptId, p.LeaseId, p.AttachId, p.NetworkGeneration,
                local = p.ActualLocal.ToString(), remote = p.ActualRemote.ToString(), p.Profile, p.Qualification }).ToArray()).ToArray(), actualNativeWorkers = true, realTcpHelpers = true,
            realHttps = true, rawAndIpAdaptersSimulated = true, publicNat = false, realWintun = false,
            gatewayLease = "NotUsed", membershipLifetime = "existing signed membership; no expiry extended" };
    }
}
