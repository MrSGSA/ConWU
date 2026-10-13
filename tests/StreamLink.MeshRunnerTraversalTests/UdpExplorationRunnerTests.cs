using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using StreamLink.Core;
using StreamLink.Service;

static class UdpExplorationRunnerTests
{
    public static async Task<object> Run(string root, string url, string pin, int stable, Action<bool,string> check, CancellationToken token)
    {
        var a=MeshIdentity.Create(url,pin,"faketcp"); var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;
        var members=new[]{a,b}; var wire=new UdpExplorationNatWire(stable); var machine=new[]{new TraversalResources(),new TraversalResources()};
        var configs=members.Select(m=>new DeviceProfile{Mesh=m,TraversalMode="tcp-udp",AllowUdpFallback=true,UdpExploration=true,UdpStun=["fixture.invalid:3478"]}).ToArray();
        int[] ports=Enumerable.Range(0,32).Select(i=>45000+7*i).ToArray();
        var adapters=new[]{new NativeIpv6RunnerTests.Adapter(),new NativeIpv6RunnerTests.Adapter()}; var states=new SessionStatus?[2]; var logs=new ConcurrentQueue<string>();
        var factories=configs.Select((c,i)=>new NativeIpv6RunnerTests.Inspect(new MeshCandidateFactory(c,"unused","unused",[TraversalProfile.UdpDirect]){
            ExplorationBudgetForTest=machine[i],ResolveTarget=(_,_,_)=>Task.FromResult(UdpExplorationNatWire.Reflector), RouteCheckForTest=(_,_,_)=>{},
            OpenExplorationSocketForTest=_=>wire.Open(i),ExplorationTargetsForTest=_=>ports,
            ExplorationEvidenceForTest=(owner,g,observed,remote)=> i!=stable ? null : UdpStableSourceEvidence.PeerPorts(owner,g,wire.Public(1-i),ports,
                ports.Select(p=>new NatObservation(owner.SocketId,g,"udp",owner.Local,new(wire.Public(1-i),p),observed[0].Mapped,observed[0].ObservedAt,observed[0].ProbeStartedAt)).ToArray())
        })).ToArray();
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(token);var watch=Stopwatch.StartNew();
        var inspected=factories.Select(f=>new FirstBlocked(f)).ToArray();
        MeshRuntimeServices Services(int i)=>new(m=>new MeshDiscoveryClient(m),_=>Task.FromResult<IPacketAdapter>(adapters[i]),
            async(_,_,t)=>{await Task.Delay(Timeout.Infinite,t);throw new IOException();},_=>throw new IOException("No explicit entry"),(_,_,t)=>Task.Delay(Timeout.Infinite,t),(_,_,_)=>{},(_,_)=>{},Path.Combine(root,"exploration-"+stable)){
                Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(inspected[i])
            };
        var runs=Enumerable.Range(0,2).Select(i=>new MeshRunner(configs[i],s=>logs.Enqueue(i+" "+s),s=>states[i]=s,_=>{},_=>{},Services(i)).Run(stop.Token)).ToArray();
        try {
            while(!states.All(s=>s?.Connected==true)) {
                foreach(var run in runs) if(run.IsCompleted) await run;
                if(watch.ElapsedMilliseconds>50000)throw new TimeoutException(string.Join('\n',logs));await Task.Delay(20,token);
            }
            long connected=watch.ElapsedMilliseconds;
            check(factories.All(f=>f.Candidates.Any(c=>c.Exploration!=null)) && factories[stable].Candidates.Any(c=>c.Exploration?.Stable==true),"formal Runner exchanges signed stable/hard UDP exploration candidates");
            check(factories.All(f=>f.Paths.Any()) && states.All(s=>s?.Degraded==true),"exploration selects an authenticated UDP path and preserves explicit quality-degraded status");
            check(wire.Sources.Count(p=>p.Node==1-stable)==32 && wire.Sources.Count(p=>p.Node==stable)==1,"formal preparation includes the observed seed within one stable and 32 total hard sources");
            check(factories[stable].Paths.Single().LeaseId==wire.Sources.Single(p=>p.Node==stable).Id && machine[1-stable].Usage().OpenUdpResources==1,
                "the same observed stable resource wins; unused hard resources close before Router ownership");
            for(int i=0;i<2;i++)adapters[i].Outgoing.Add(NativeIpv6RunnerTests.Packet(members[i].LocalIp,members[1-i].LocalIp));
            var data=Stopwatch.StartNew();while(adapters.Any(a=>a.Incoming.IsEmpty)){if(data.ElapsedMilliseconds>2500)throw new TimeoutException("Exploration business missing");await Task.Delay(10,token);}
            check(adapters.All(a=>a.Incoming.Count==1),"formal exploratory UDP path delivers full-size bidirectional MeshLink business");
            return new{stable,connectedMs=connected,sources=wire.Sources.Length,wire.Packets,wire.Reflects,
                scope="real HTTPS/formal Runner/actor/router; ordinary branch is deliberately failed, NAT/filter and peer-port stability proof are injected fixtures, no physical NAT/Wintun or measured coverage"};
        } finally {
            stop.Cancel();foreach(var run in runs)try{await run.WaitAsync(TimeSpan.FromSeconds(10),token);}catch(OperationCanceledException){}
            check(wire.Sources.All(p=>p.Closed)&&machine.All(m=>m.Usage().OpenUdpResources==0)&&adapters.All(a=>a.Disposed),"formal exploratory shutdown closes every seed, extra source and adapter");
        }
    }
    internal sealed class FirstBlocked(NativeIpv6RunnerTests.Inspect inner):IMeshCandidateFactory,IAsyncDisposable {
        public TraversalProfile[] Profiles=>inner.Profiles;public bool SupportsUdpExploration=>true;
        public bool SupportsUdpEmpiricalStability=>inner.SupportsUdpEmpiricalStability;
        public Task<IMeshCandidateResource> Gather(MeshMember peer,TraversalProfile p,Guid a,CancellationToken t)=>throw new IOException("fixture ordinary opportunity not reachable");
        public Task<IMeshCandidateResource> GatherEnhanced(MeshMember peer,TraversalProfile p,Guid a,bool v6,MeshTraversalCandidate? r,int round,bool prediction,bool source,bool exploration,Func<bool> eligible,CancellationToken t,bool empiricalAllowed=false)=>
            round==1 && r?.Exploration==null ? throw new IOException("fixture ordinary opportunity not reachable") : inner.GatherEnhanced(peer,p,a,v6,r,round,prediction,source,exploration,eligible,t,empiricalAllowed);
        public ValueTask DisposeAsync()=>inner.DisposeAsync();
    }
}
