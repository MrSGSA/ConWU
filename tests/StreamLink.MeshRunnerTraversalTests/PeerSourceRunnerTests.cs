using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

static class PeerSourceRunnerTests
{
    public static async Task<object> Run(string binary, string root, string url, string pin, string mode, Action<bool, string> check, CancellationToken token, string? journal=null)
    {
        int count = mode == "same-public-ip" ? 3 : 2, stable = mode == "server-role" ? 1 : 0;
        var creator = MeshIdentity.Create(url, pin, "faketcp"); var members = new List<MeshProfile> { creator };
        for (int i = 1; i < count; i++) members.Add(MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(creator))));
        foreach (var m in members) m.Directory = creator.Directory;
        var wire = new PeerSourceNatWire(stable); await using var helper = new Reflector { MapForTest = wire.Reflect };
        var profiles = members.Select((m, i) => new DeviceProfile { Mesh = m, TraversalMode = "tcp", PathSelection = "faketcp-only",
            TcpPeerReflexive = !(mode == "old-peer" && i == 1), TcpStun = ["fixture.invalid:3478"] }).ToArray();
        var adapters = members.Select(_ => new NativeIpv6RunnerTests.Adapter()).ToArray(); var statuses = new SessionStatus?[count];
        var logs = new ConcurrentQueue<string>();
        var factories = profiles.Select((p, i) => new NativeIpv6RunnerTests.Inspect(new MeshCandidateFactory(p, binary, root, [TraversalProfile.FakeTcpHttpSo],
            captureBroker: true, wireControl: true, peerSourceNative: !(mode == "old-native" && i == 1)) {
            ResolveTarget = (_, _, _) => Task.FromResult(helper.Endpoint), RouteCheckForTest = (_, _, _) => { }, OpenCaptureForTest = (local, _) => wire.Open(i, local)
        })).ToArray();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token); var watch = Stopwatch.StartNew();
        MeshRuntimeServices Services(int i) => new(m => mode == "old-server" ? new OldSource(new MeshDiscoveryClient(m)) : new MeshDiscoveryClient(m),
            _ => Task.FromResult<IPacketAdapter>(adapters[i]), async (_, _, t) => { await Task.Delay(Timeout.Infinite, t); throw new IOException(); },
            _ => throw new IOException("No explicit test entry"), (_, _, t) => Task.Delay(Timeout.Infinite, t), (_, _, _) => { }, (_, _) => { }, Path.Combine(root, mode)) {
                Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(factories[i])
            };
        var runners=Enumerable.Range(0,count).Select(i=>new MeshRunner(profiles[i], s=>logs.Enqueue(i+" "+s), s=>statuses[i]=s,_=>{},_=>{},Services(i))).ToArray();
        var runs = runners.Select(r=>r.Run(stop.Token)).ToArray();
        bool negative = mode is "old-peer" or "old-server" or "old-native";
        bool Connected(int node, int peer) => statuses[node]?.Peers?.Any(p => p.Slot == peer + 1 && p.Connected) == true;
        try {
            while (negative ? !logs.Any(s => s.Contains("候选失败")) : !Enumerable.Range(0, count).Where(i => i != stable).All(i => Connected(stable, i) && Connected(i, stable))) {
                foreach (var run in runs) if (run.IsCompleted) await run;
                if (watch.ElapsedMilliseconds > 50000) throw new TimeoutException(string.Join('\n', logs)); await Task.Delay(20, token);
            }
            if (negative) {
                check(factories.All(f => f.Candidates.All(c => !c.PeerReflexive)) && factories.All(f => f.Paths.IsEmpty),
                    mode + ": missing peer/server/native capability never publishes source-learning authorization or selects a path");
                return new { mode, negative = true, wire.Syns, scope = "real HTTPS and native controlled failure; missing capability modeled explicitly" };
            }
            long connectedMs = watch.ElapsedMilliseconds;
            check(factories.All(f => f.Candidates.Any(c => c.PeerReflexive)) && statuses.All(s => s?.Degraded != true), mode + ": formal factory and signed control enable source learning without UDP or relay");
            check(factories[stable].Transports.Where(p => !p.Failed).Count(p => p.Diagnostics.PeerSource is { Learned: true, Frozen: true }) == count - 1,
                mode + ": selected real native paths retain authenticated learned source endpoints");
            if (count == 3) {
                check(factories[stable].Paths.Select(p => p.LeaseId).Distinct().Count() == 2 && factories[stable].Paths.Select(p => p.ActualLocal.Port).Distinct().Count() == 2,
                    "two members sharing a public IP have distinct actual retained TCP sources at the stable node");
                check(!Connected(1, 2) && !Connected(2, 1), "two hard members remain disconnected instead of forwarding via the stable member");
            }
            for (int i = 0; i < count; i++) if (i != stable) {
                adapters[stable].Outgoing.Add(NativeIpv6RunnerTests.Packet(members[stable].LocalIp, members[i].LocalIp));
                adapters[i].Outgoing.Add(NativeIpv6RunnerTests.Packet(members[i].LocalIp, members[stable].LocalIp));
            }
            var data = Stopwatch.StartNew();
            while (adapters[stable].Incoming.Count < count - 1 || Enumerable.Range(0, count).Where(i => i != stable).Any(i => adapters[i].Incoming.Count < 1)) {
                if (data.ElapsedMilliseconds > 3000) throw new TimeoutException("Source-aware Runner business missing"); await Task.Delay(10, token);
            }
            check(adapters[stable].Incoming.Count == count - 1, mode + ": full-size authenticated bidirectional business reaches every direct member");
            return new { mode, connectedMs, members = count, helper.Accepted, rawSources = wire.Ios.Length, wire.Packets,
                learned = factories[stable].Transports.Select(p => p.Diagnostics.PeerSource).ToArray(), realNat = false, wintun = false };
        } finally {
            journal??=Path.Combine(root,mode+"-shutdown.jsonl");Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(journal))!);
            using var sampling=new CancellationTokenSource();var closingWatch=Stopwatch.StartNew();
            void Snapshot(string phase) {
                File.AppendAllText(journal,JsonSerializer.Serialize(new {mode,phase,elapsedMs=closingWatch.ElapsedMilliseconds,pid=Environment.ProcessId,
                    taskStates=runs.Select(t=>t.Status.ToString()).ToArray(),runnerStages=runners.Select(r=>r.ExitDiagnostics).ToArray(),
                    resources=factories.Select(f=>new {f.Gathers,paths=f.Paths.Select(p=>new {p.PathId,p.LeaseId,p.AttachId,local=p.ActualLocal.ToString(),remote=p.ActualRemote.ToString()}).ToArray(),native=f.Transports.Select(p=>new {pid=p.ProcessId,p.Closed,diagnostics=p.Diagnostics}).ToArray()}).ToArray(),
                    captures=wire.Ios.Select(io=>new {io.Node,local=io.Local.ToString(),io.Closed}).ToArray(),adapters=adapters.Select(a=>a.Disposed).ToArray(),logs=logs.ToArray(),
                    scope="Memory adapters and modeled mapping/filter; actual native workers. Not Wintun or physical NAT."})+Environment.NewLine);
            }
            Snapshot("before-cancel");
            // A separate sampler records the blocked stage even if Cancel itself
            // is synchronous. The external process supervisor remains final containment.
            Task observer=Task.Run(async()=>{while(!sampling.IsCancellationRequested){Snapshot("waiting");await Task.Delay(500,sampling.Token);}});
            try {
                stop.Cancel(); foreach (var run in runs) try { await run.WaitAsync(TimeSpan.FromSeconds(10), token); } catch (OperationCanceledException) { }
                Snapshot("joined");
            }catch(Exception ex){Snapshot("failed:"+ex.GetType().Name);throw;}
            finally{sampling.Cancel();try{await observer;}catch(OperationCanceledException){} }
            check(wire.Ios.All(io => io.Closed) && adapters.All(a => a.Disposed), mode + ": Runner cleanup joins all isolated captures and adapters");
        }
    }
    sealed class OldSource(MeshDiscoveryClient inner) : IMeshDiscovery, IMeshChangeDiscovery, IMeshTraversalDiscovery {
        public Guid BootId => inner.BootId; public bool SupportsTraversal => inner.SupportsTraversal; public bool SupportsLongPolling => inner.SupportsLongPolling;
        public bool SupportsTcpPeerReflexive => false;
        public Task SaveDirectory(MeshDirectory d, CancellationToken t) => inner.SaveDirectory(d, t);
        public Task Publish(MeshAnnouncement a, CancellationToken t) => inner.Publish(a, t);
        public Task<MeshSnapshot?> Read(CancellationToken t) => inner.Read(t);
        public Task<MeshSnapshot?> WaitForChanges(CancellationToken t) => inner.WaitForChanges(t);
        public Task PublishTraversal(MeshTraversalMessage[] m, CancellationToken t) => inner.PublishTraversal(m, t);
        public void Dispose() => inner.Dispose();
    }
}
