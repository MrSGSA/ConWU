using System.Collections.Concurrent;
using System.Diagnostics;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

static class TcpRetryTests
{
    public static async Task<object> Run(string binary, string root, string url, string pin, Action<bool, string> check, CancellationToken token)
    {
        var a = MeshIdentity.Create(url, pin, "faketcp");
        var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var mesh = new[] { a, b }; var adapters = new[] { new Adapter(), new Adapter() };
        var states = new SessionStatus?[2]; var logs = new ConcurrentQueue<string>();
        await using var reflector = new Reflector(); await using var proxy = new RawProtocolProxy(0, 0); proxy.Begin();
        var factories = mesh.Select(m => new RetryFactory(new(m, TraversalProfile.FakeTcpHttpSo, binary, root, reflector, proxy), m.Self.Slot == 1)).ToArray();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        var watch = Stopwatch.StartNew();
        var tasks = Enumerable.Range(0, 2).Select(i => {
            var services = new MeshRuntimeServices(m => new MeshDiscoveryClient(m), _ => Task.FromResult<IPacketAdapter>(adapters[i]),
                async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new InvalidOperationException(); },
                _ => throw new IOException("no explicit path in TCP retry fixture"), (_, _, ct) => Task.Delay(Timeout.Infinite, ct),
                (_, _, _) => { }, (_, _) => { }, Path.Combine(root, "tcp-retry")) {
                    Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(factories[i])
                };
            return new MeshRunner(new() { Mesh = mesh[i], TraversalMode = "tcp", PathSelection = "faketcp-only" },
                s => logs.Enqueue(i + " " + s), s => states[i] = s, _ => { }, _ => { }, services).Run(stop.Token);
        }).ToArray();
        long connectedAt;
        try {
            while (!states.All(s => s?.Connected == true)) {
                foreach (var task in tasks) if (task.IsCompleted) await task;
                if (watch.ElapsedMilliseconds >= 15000) throw new TimeoutException("TCP retry exceeded controlled cold-start target\n" + string.Join('\n', logs));
                await Task.Delay(20, token);
            }
            connectedAt = watch.ElapsedMilliseconds;
            check(factories[0].Calls == 2 && factories[1].Calls == 1 && states.All(s => !s!.Degraded),
                "FakeTcpOnly recovers from the first gather failure using its second native round, without UDP or background sleep");
            for (int i = 0; i < 2; i++) adapters[i].Outgoing.Add(UpgradeTests.Packet(mesh[i].LocalIp, mesh[1 - i].LocalIp, 123));
            var traffic = Stopwatch.StartNew();
            while (adapters.Any(d => d.Incoming.Count != 1) && traffic.ElapsedMilliseconds < 2500) await Task.Delay(10, token);
            check(adapters.All(d => d.Incoming.Count == 1), "second native round carries real MeshLink full-MTU data in both directions");
            check(logs.Count(s => s.Contains("开始直连机会窗")) == 2, "two peers each retain one foreground opportunity across the retry");
        } finally {
            stop.Cancel(); foreach (var task in tasks) try { await task.WaitAsync(TimeSpan.FromSeconds(10)); } catch (OperationCanceledException) { }
        }
        check(factories.All(f => f.Inner.Closed) && adapters.All(d => d.Disposed), "TCP retry runner teardown releases the successful raw protocol path and helper");
        return new { scenario = "faketcp-only-second-round", connectedAtMs = connectedAt, leaderGathers = factories[0].Calls, responderGathers = factories[1].Calls,
            realHttps = true, nativeTestBackend = true, realNat = false, wintun = false };
    }
    sealed class RetryFactory(Factory inner, bool failFirst) : IMeshCandidateFactory {
        public Factory Inner => inner;
        public int Calls;
        public TraversalProfile[] Profiles => [TraversalProfile.FakeTcpHttpSo];
        public Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile profile, Guid attempt, CancellationToken token) =>
            ++Calls == 1 && failFirst ? Task.FromException<IMeshCandidateResource>(new IOException("fixture first TCP gather failure")) : inner.Gather(peer, profile, attempt, token);
    }
}
