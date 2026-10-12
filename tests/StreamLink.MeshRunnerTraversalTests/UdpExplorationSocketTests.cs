using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using StreamLink.Core;
using StreamLink.Service;

static class UdpExplorationSocketTests
{
    public static async Task<object> Run(string root,string url,string pin,Action<bool,string> check,CancellationToken token)
    {
        await using var reflector=new UdpExplorationAdmissionTests.UdpReflector();
        var a=MeshIdentity.Create(url,pin,"faketcp");var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;var mesh=new[]{a,b};
        var machines=new[]{new TraversalResources(),new TraversalResources()};var opened=new ConcurrentBag<Tracked>();
        var adapters=new[]{new NativeIpv6RunnerTests.Adapter(),new NativeIpv6RunnerTests.Adapter()};var states=new SessionStatus?[2];var logs=new ConcurrentQueue<string>();
        var factories=mesh.Select((m,i)=>new NativeIpv6RunnerTests.Inspect(new MeshCandidateFactory(new DeviceProfile{Mesh=m,TraversalMode="tcp-udp",AllowUdpFallback=true,UdpExploration=true},"unused","unused",[TraversalProfile.UdpDirect]){
            ExplorationBudgetForTest=machines[i],ResolveTarget=(_,_,_)=>Task.FromResult(reflector.Endpoint),RouteCheckForTest=(_,_,_)=>{},
            OpenExplorationSocketForTest=local=>{var source=new Tracked(new TraversalSocket(local),i);opened.Add(source);return source;},
            ExplorationTargetsForTest=hint=>[hint.Port],
            ExplorationEvidenceForTest=(owner,g,observed,remote)=>i!=1?null:UdpStableSourceEvidence.PeerPorts(owner,g,IPEndPoint.Parse(remote!.Endpoint).Address,
                MeshUdpExploration.Ports(remote.Exploration!.Targets),[new(owner.SocketId,g,"udp",owner.Local,IPEndPoint.Parse(remote.Endpoint),observed[0].Mapped,observed[0].ObservedAt,observed[0].ProbeStartedAt)])
        })).ToArray();
        var wrappers=factories.Select(f=>new UdpExplorationRunnerTests.FirstBlocked(f)).ToArray();using var stop=CancellationTokenSource.CreateLinkedTokenSource(token);var watch=Stopwatch.StartNew();
        MeshRuntimeServices Services(int i)=>new(m=>new MeshDiscoveryClient(m),_=>Task.FromResult<IPacketAdapter>(adapters[i]),async(_,_,t)=>{await Task.Delay(Timeout.Infinite,t);throw new IOException();},
            _=>throw new IOException("no explicit fixture"),(_,_,t)=>Task.Delay(Timeout.Infinite,t),(_,_,_)=>{},(_,_)=>{},Path.Combine(root,"real-exploration")){
            Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(wrappers[i])};
        var runs=Enumerable.Range(0,2).Select(i=>new MeshRunner(new DeviceProfile{Mesh=mesh[i],TraversalMode="tcp-udp",AllowUdpFallback=true,UdpExploration=true},s=>logs.Enqueue(i+" "+s),s=>states[i]=s,_=>{},_=>{},Services(i)).Run(stop.Token)).ToArray();
        try{
            while(!states.All(s=>s?.Connected==true)){foreach(var run in runs)if(run.IsCompleted)await run;if(watch.ElapsedMilliseconds>45000)throw new TimeoutException(string.Join('\n',logs));await Task.Delay(20,token);}
            long connected=watch.ElapsedMilliseconds;
            check(opened.Count==33&&opened.Count(s=>!s.Closed)==2,"real Windows exploration retains only two actual winning UDP sockets from 33 sources");
            check(factories[1].Paths.Single().LeaseId==opened.Single(s=>s.Node==1).Id&&factories[0].Paths.Single().ActualRemote.Equals(opened.Single(s=>s.Node==1).Local),
                "same-source promotion preserves actual Winsock resource IDs and both selected endpoints");
            for(int i=0;i<2;i++)adapters[i].Outgoing.Add(NativeIpv6RunnerTests.Packet(mesh[i].LocalIp,mesh[1-i].LocalIp));
            var data=Stopwatch.StartNew();while(adapters.Any(a=>a.Incoming.IsEmpty)){if(data.ElapsedMilliseconds>2000)throw new TimeoutException("Real UDP business missing");await Task.Delay(10,token);}
            check(adapters.All(a=>a.Incoming.Count==1),"real UDP same-socket exploratory path carries complete bidirectional MeshLink frames");
            return new{environment="real Windows loopback UDP sockets and HTTPS; peer-port proof and blocked ordinary branch are injected, IP adapter is memory",connectedMs=connected,actualSockets=opened.Count};
        }finally{stop.Cancel();foreach(var run in runs)try{await run.WaitAsync(TimeSpan.FromSeconds(10),token);}catch(OperationCanceledException){}
            check(opened.All(s=>s.Closed)&&machines.All(m=>m.Usage().OpenUdpResources==0),"real socket shutdown returns every shared UDP quota without closing the retained winner early");}
    }
    sealed class Tracked(ITraversalSocket inner,int node):ITraversalSocket{
        public int Node=>node;public Guid Id=>inner.Id;public IPEndPoint Local=>inner.Local;public bool DontFragment=>inner.DontFragment;public bool Closed;
        public ValueTask Send(ReadOnlyMemory<byte> p,IPEndPoint e,CancellationToken t)=>inner.Send(p,e,t);
        public ValueTask<TraversalDatagram> Receive(CancellationToken t)=>inner.Receive(t);
        public void Dispose(){Closed=true;inner.Dispose();}
    }
}
