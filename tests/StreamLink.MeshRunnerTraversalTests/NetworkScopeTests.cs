using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using StreamLink.Core;
using StreamLink.Service;
using TcpReflector = StreamLink.EndpointPoc.Reflector;

static class NetworkScopeTests
{
    public static async Task<object> Run(string binary, string root, string url, string pin, int rounds, Action<bool,string> check, CancellationToken token)
    {
        foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback }) {
            string snapshot = EgressRouteSnapshot.Capture(new(address, 3478));
            check(!snapshot.StartsWith("Unavailable") && snapshot.Contains(address.ToString()), "actual read-only Windows route/source query for " + address);
            check(EgressRouteSnapshot.Capture(new(address, 40000)) == snapshot, "TCP/UDP port numbers do not change the IP route snapshot");
        }
        var external = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 3478);
        string physical = EgressRouteSnapshot.Capture(external);
        string boundSource=Stun.LocalAddress(external).ToString();
        string afterSource=EgressRouteSnapshot.Capture(external);
        Console.WriteLine($"ROUTE external-before={physical}; socket-source={boundSource}; external-after={afterSource}");
        check(!physical.StartsWith("Unavailable") && physical.Contains("/"+boundSource+"/") && physical==afterSource,
            "actual external IPv4 best route agrees with the bound source selection without sending a probe; before="+physical+"; socket="+boundSource+"; after="+afterSource);
        check(EgressRouteSnapshot.Capture(external) == physical,"repeated read-only external route snapshot stays stable without configuration changes");
        for (int round = 0; round < rounds; round++) {
            await Boundary(binary, root, TraversalProfile.FakeTcpHttpSo, check, token);
            await Boundary(binary, root, TraversalProfile.UdpDirect, check, token);
        }
        await Ownership(binary, root, TraversalProfile.FakeTcpHttpSo, check, token);
        await Ownership(binary, root, TraversalProfile.UdpDirect, check, token);
        var runner = await Runner(binary, root, url, pin, check, token);
        return new { rounds, runner, scope = "actual OS read-only routes; controlled route fingerprints, real TCP/UDP sockets, C++/IPC/HTTPS and production Runner; memory raw/IP adapters, no physical NIC change, WinDivert/Wintun or WAN" };
    }

    static async Task Ownership(string binary,string root,TraversalProfile kind,Action<bool,string> check,CancellationToken token)
    {
        var a=MeshIdentity.Create("https://localhost","","faketcp");var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;
        await using var tcp=new TcpReflector();await using var udp=new Ipv6Tests.Reflector(System.Net.Sockets.AddressFamily.InterNetwork);
        IPEndPoint reflector=kind==TraversalProfile.UdpDirect?udp.Endpoint:tcp.Endpoint;
        var wire=new NativeIpv6RunnerTests.Wire(false);
        string currentRoute="owned-route";long now=1000;
        MeshCandidateFactory Factory(MeshProfile mesh)=>new(new DeviceProfile{Mesh=mesh,TraversalMode="tcp-udp",AllowUdpFallback=true,TcpStun=["fixture.invalid:3478"],UdpStun=["fixture.invalid:3478"]},binary,root,[kind],captureBroker:true,wireControl:true){
            ResolveTarget=(_,_,_)=>Task.FromResult(reflector),OpenCaptureForTest=(local,_)=>wire.Open(local),RouteCheckForTest=(_,_,_)=>{},NetworkRouteForTest=_=>currentRoute,NetworkClock=()=>now
        };
        await using var fa=Factory(a);await using var fb=Factory(b);
        var adapters=new[]{new NativeIpv6RunnerTests.Adapter(),new NativeIpv6RunnerTests.Adapter()};
        await using var ra=new MeshRouter(a,adapters[0],selection:new(AllowUdpFallback:true));await using var rb=new MeshRouter(b,adapters[1],selection:new(AllowUdpFallback:true));
        Guid attempt=Guid.NewGuid(),nonce=Guid.NewGuid();
        await using var ac=await fa.Gather(b.Self,kind,attempt,token);await using var bc=await fb.Gather(a.Self,kind,attempt,token);
        var ca=new TraversalAttemptContext(a.Pair.Network,a.Self.Device,ra.BootId,b.Self.Device,rb.BootId,attempt,ac.Candidate.Id,1,bc.Candidate.Id,1,kind,true,true,nonce);
        var cb=new TraversalAttemptContext(a.Pair.Network,b.Self.Device,rb.BootId,a.Self.Device,ra.BootId,attempt,bc.Candidate.Id,1,ac.Candidate.Id,1,kind,false,false,nonce);
        check(PathNomination.ContextDigest(ca).SequenceEqual(PathNomination.ContextDigest(cb)),kind+": reciprocal path contexts bind the same authenticated nomination scope");
        await using var ap=await ac.Prepare(ca,IPEndPoint.Parse(bc.Candidate.Endpoint),token);await using var bp=await bc.Prepare(cb,IPEndPoint.Parse(ac.Candidate.Endpoint),token);
        var activated=await Task.WhenAll(ap.Activate(token),bp.Activate(token));
        bool[] transferred=[false,false];
        try {
            ra.RegisterPath(b.Self.Slot,activated[0],ca,1,ap.RemainingAttemptTime,1);transferred[0]=true;
            rb.RegisterPath(a.Self.Slot,activated[1],cb,1,bp.RemainingAttemptTime,1);transferred[1]=true;
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(10000);
            while(!ra.Status().Single().Connected||!rb.Status().Single().Connected)await Task.Delay(20,deadline.Token);
            await ap.DisposeAsync();await bp.DisposeAsync();await ac.DisposeAsync();await bc.DisposeAsync();
            currentRoute="owned-route-next-hop-two";fa.NotifyNetworkChanged();fb.NotifyNetworkChanged();now+=251;
            check(fa.PollNetworkChange()&&fb.PollNetworkChange(),kind+": Active retains route ownership after Attempt and preparation references end");
            now+=5001;check(!fa.PollNetworkChange()&&!fb.PollNetworkChange(),kind+": releasing old Attempt does not lose or repeatedly invalidate the retained Active route scope");
            adapters[0].Outgoing.Add(NativeIpv6RunnerTests.Packet(a.LocalIp,b.LocalIp));adapters[1].Outgoing.Add(NativeIpv6RunnerTests.Packet(b.LocalIp,a.LocalIp));
            while(adapters.Any(x=>x.Incoming.IsEmpty))await Task.Delay(20,deadline.Token);
            check(!activated.Any(p=>p.Failed)&&adapters[0].Incoming.Single().SequenceEqual(NativeIpv6RunnerTests.Packet(b.LocalIp,a.LocalIp))&&
                adapters[1].Incoming.Single().SequenceEqual(NativeIpv6RunnerTests.Packet(a.LocalIp,b.LocalIp)),
                kind+": disposing preparation and Attempt references preserves Router-owned bidirectional full-MTU IP on the same actual resource");
        }finally{for(int i=0;i<2;i++)if(!transferred[i])await activated[i].DisposeAsync();}
    }
    static async Task Boundary(string binary, string root, TraversalProfile kind, Action<bool,string> check, CancellationToken token)
    {
        var a = MeshIdentity.Create("https://localhost", "", "faketcp");
        var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var profile = new DeviceProfile { Mesh = a, TraversalMode = "tcp-udp", TcpStun = ["fixture.invalid:3478"], UdpStun = ["fixture.invalid:3478"] };
        await using var tcp = new TcpReflector(); await using var udp = new Ipv6Tests.Reflector(System.Net.Sockets.AddressFamily.InterNetwork);
        IPEndPoint reflector = kind == TraversalProfile.UdpDirect ? udp.Endpoint : tcp.Endpoint;
        var wire = new NativeIpv6RunnerTests.Wire(false);
        string route = "physical/source/next-hop-1"; long now = 1000;
        await using var factory = new MeshCandidateFactory(profile, binary, root, [kind], captureBroker: true, wireControl: true) {
            ResolveTarget = (_,_,_) => Task.FromResult(reflector), OpenCaptureForTest = (local,_) => wire.Open(local),
            RouteCheckForTest = (_,_,_) => { }, NetworkRouteForTest = _ => route, NetworkClock = () => now
        };
        Guid attempt = Guid.NewGuid();
        await using var resource = await factory.Gather(b.Self, kind, attempt, token);
        Guid resourceId = resource.Candidate.Id;
        Guid original = factory.GenerationForTest;
        TraversalAttemptContext Context(IMeshCandidateResource r, Guid round) => new(a.Pair.Network, a.Self.Device, Guid.NewGuid(), b.Self.Device, Guid.NewGuid(),
            round, r.Candidate.Id, r.Candidate.Version, Guid.NewGuid(), 1, kind, true, true, Guid.NewGuid());
        await using var prepared = await resource.Prepare(Context(resource, attempt), new(IPAddress.Loopback, 43101), token);
        try {
            factory.NotifyNetworkChanged(); now += 249;
            check(!factory.PollNetworkChange(), kind + ": notifications are debounced before examining actual routes");
            now += 1;
            check(!factory.PollNetworkChange() && factory.GenerationForTest == original && prepared.Armed,
                kind + ": unrelated/VMware interface notification preserves the observed route and armed candidate");
            route = "physical/source/next-hop-2";
            bool beforeNotification = false; try { await using var late = await prepared.Activate(token); } catch (IOException) { beforeNotification = true; }
            check(beforeNotification && factory.GenerationForTest == original && wire.Packets == 0,
                kind + ": actual route recheck rejects changed output before OS notification or first SYN");
            factory.NotifyNetworkChanged(); now += 251;
            check(factory.PollNetworkChange() && factory.GenerationForTest != original, kind + ": same-source gateway change creates a new actual endpoint generation");
            bool stale = false; try { _ = resource.Candidate; } catch (IOException) { stale = true; }
            check(stale && !prepared.Armed && prepared.RemainingAttemptTime == TimeSpan.Zero, kind + ": old observation and Armed cannot authorize a new round");
            stale = false; try { await using var late = await prepared.Activate(token); } catch (IOException) { stale = true; }
            check(stale && wire.Packets == 0, kind + ": late Start fails before native SYN or candidate business injection");
            Guid freshAttempt = Guid.NewGuid();
            await using var fresh = await factory.Gather(b.Self, kind, freshAttempt, token);
            await using var freshPrepared = await fresh.Prepare(Context(fresh, freshAttempt), new(IPAddress.Loopback, 43102), token);
            check(freshPrepared.Armed && fresh.Candidate.Id != resourceId, kind + ": fresh resource can be prepared while old failed references are still held");
        } finally { await prepared.DisposeAsync(); await resource.DisposeAsync(); }

        // Late DNS/reflector results are also forbidden, including a provider
        // which ignores cancellation. The outer epoch scope owns final acceptance.
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
        string delayedRoute = "route-one"; long delayedClock = 1000; int calls = 0;
        await using var delayed = new MeshCandidateFactory(profile,binary,root,[kind],captureBroker:true,wireControl:true) {
            ResolveTarget = (_,_,_) => Interlocked.Increment(ref calls) == 1 ? Task.FromResult(reflector) : Delay(),
            OpenCaptureForTest = (local,_) => wire.Open(local), RouteCheckForTest = (_,_,_) => { },
            NetworkRouteForTest = _ => delayedRoute, NetworkClock = () => delayedClock
        };
        Task<IPEndPoint> Delay() { ready.TrySetResult(); return release.Task; }
        await using var initial = await delayed.Gather(b.Self,kind,Guid.NewGuid(),token);
        var pending = delayed.Gather(b.Self,kind,Guid.NewGuid(),token); await ready.Task.WaitAsync(token);
        delayedRoute = "route-two"; delayed.NotifyNetworkChanged(); delayedClock += 251;
        check(delayed.PollNetworkChange(), kind + ": route change is recognized during an asynchronous gather");
        release.TrySetResult(reflector);
        bool rejected = false;
        try { await using var late = await pending; } catch (Exception ex) when (ex is IOException or OperationCanceledException) { rejected = true; }
        check(rejected, kind + ": cancelled provider result never publishes a candidate in the new generation");
        now += 5001; check(!factory.PollNetworkChange(), kind + ": fallback polling coalesces one unchanged new scope");
    }

    static async Task<object> Runner(string binary,string root,string url,string pin,Action<bool,string> check,CancellationToken token)
    {
        var a=MeshIdentity.Create(url,pin,"faketcp"); var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory=a.Directory;
        var profiles=new[]{a,b}.Select(m=>new DeviceProfile{Mesh=m,TraversalMode="tcp",PathSelection="faketcp-only",TcpStun=["fixture.invalid:3478"]}).ToArray();
        await using var reflector=new TcpReflector(); var wire=new NativeIpv6RunnerTests.Wire(false); var logs=new ConcurrentQueue<string>();
        var routes=new[]{"ethernet/gateway-one","ethernet/gateway-one"};
        var inner=profiles.Select((p,i)=>new MeshCandidateFactory(p,binary,root,[TraversalProfile.FakeTcpHttpSo],captureBroker:true,diagnostic:logs.Enqueue,wireControl:true){
            ResolveTarget=(_,_,_)=>Task.FromResult(reflector.Endpoint),OpenCaptureForTest=(local,_)=>wire.Open(local),RouteCheckForTest=(_,_,_)=>{},NetworkRouteForTest=_=>routes[i]
        }).ToArray();
        var factories=inner.Select(f=>new NativeIpv6RunnerTests.Inspect(f)).ToArray();
        var adapters=new[]{new NativeIpv6RunnerTests.Adapter(),new NativeIpv6RunnerTests.Adapter()}; var states=new SessionStatus?[2]; int adapterOpens=0;
        using var running=CancellationTokenSource.CreateLinkedTokenSource(token);
        MeshRuntimeServices Services(int i)=>new(m=>new MeshDiscoveryClient(m),_=>{Interlocked.Increment(ref adapterOpens);return Task.FromResult<IPacketAdapter>(adapters[i]);},
            async(_,_,ct)=>{await Task.Delay(Timeout.Infinite,ct);throw new IOException();},_=>throw new IOException("No legacy or relay in route fixture"),
            (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(root,"network-scope")) {Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(factories[i])};
        var tasks=profiles.Select((p,i)=>new MeshRunner(p,logs.Enqueue,s=>states[i]=s,_=>{},_=>{},Services(i)).Run(running.Token)).ToArray();
        async Task Until(Func<bool> condition,string label,int duration=45000) {
            var clock=Stopwatch.StartNew(); while(!condition()){foreach(var task in tasks)if(task.IsCompleted)await task;
                if(clock.ElapsedMilliseconds>duration)throw new TimeoutException(label+"\n"+string.Join('\n',logs));await Task.Delay(20,token);}
        }
        async Task Send(string label) {
            int[] counts=adapters.Select(x=>x.Incoming.Count).ToArray();
            adapters[0].Outgoing.Add(NativeIpv6RunnerTests.Packet(a.LocalIp,b.LocalIp)); adapters[1].Outgoing.Add(NativeIpv6RunnerTests.Packet(b.LocalIp,a.LocalIp));
            await Until(()=>adapters.Select((x,i)=>x.Incoming.Count==counts[i]+1).All(x=>x),label,4000);
        }
        long recoveredMs=0;
        try {
            await Until(()=>states.All(s=>s?.Connected==true),"initial SO path"); await Send("initial actual IP");
            Guid[] epochs=inner.Select(f=>f.GenerationForTest).ToArray();
            foreach(var f in inner)f.NotifyNetworkChanged(); await Task.Delay(600,token); await Send("unrelated event path");
            check(inner.Select((f,i)=>f.GenerationForTest==epochs[i]).All(x=>x)&&factories.All(f=>f.Paths.Count==1),"formal Runner ignores unrelated NIC notification without a replacement handshake");
            routes[0]=routes[1]="ethernet/gateway-two";foreach(var f in inner)f.NotifyNetworkChanged();
            await Until(()=>inner.Select((f,i)=>f.GenerationForTest!=epochs[i]).All(x=>x),"new network generation");await Send("route changed healthy old path");
            check(factories.All(f=>f.Paths.Count==1&&f.Transports.Single().WireControl is{Selected:true})&&adapterOpens==2,
                "formal Runner preserves active socket/capture, native session and Wintun adapter after changed route while actual bidirectional business continues");
            var timer=Stopwatch.StartNew();foreach(var f in factories){using var worker=Process.GetProcessById(f.Transports.Single().ProcessId);worker.Kill();}
            await Until(()=>factories.All(f=>f.Paths.Count==2)&&states.All(s=>s?.Connected==true),"fresh native path recovery",60000);
            await Send("recovered actual IP"); recoveredMs=timer.ElapsedMilliseconds;
            check(factories.Select((f,i)=>f.Paths.Last().NetworkGeneration==inner[i].GenerationForTest&&f.Paths.Last().NetworkGeneration!=epochs[i]&&f.Paths.First().LeaseId!=f.Paths.Last().LeaseId).All(x=>x),
                "worker fault recovers with new epoch, new held source and new capture; old source is never rebound into an overlapping handshake");
            check(adapterOpens==2&&states.All(s=>s?.Connected==true),"recovery reuses the existing virtual adapter and authenticated member session");
        }finally{
            running.Cancel();foreach(var task in tasks)try{await task;}catch(OperationCanceledException){}
        }
        check(wire.Endpoints.Values.All(io=>io.Closed)&&reflector.Active==0,"formal route/worker lifecycle joins native capture and real helper shutdown");
        return new{recoveredMs,adapterOpens,oldAndNewPaths=factories.Select(f=>f.Paths.Select(p=>new{p.NetworkGeneration,p.LeaseId,p.AttachId})).ToArray(),scope="controlled route fingerprints and native worker exit; no physical NIC or WAN transition"};
    }
}
