using StreamLink.Core;
using StreamLink.Service;
using System.Net;

static class ShutdownFailureTests
{
    public static async Task<object> Run(string root,string url,string pin,Action<bool,string> check,CancellationToken token){
        var mesh=MeshIdentity.Create(url,pin,"faketcp");var profile=new DeviceProfile{Mesh=mesh,TraversalMode="tcp-udp",PathSelection="prefer-faketcp",AllowUdpFallback=true};
        var adapter=new NativeIpv6RunnerTests.Adapter();var factory=new FaultFactory();var logs=new List<string>();
        var services=new MeshRuntimeServices(m=>new MeshDiscoveryClient(m),_=>Task.FromResult<IPacketAdapter>(adapter),
            async(_,_,t)=>{await Task.Delay(Timeout.Infinite,t);throw new IOException();},_=>throw new IOException("No entry in isolated cleanup fixture"),
            (_,_,t)=>Task.Delay(Timeout.Infinite,t),(_,_,_)=>{},(_,_)=>{},Path.Combine(root,"cleanup-failure")){
                Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(factory)};
        var runner=new MeshRunner(profile,s=>{lock(logs)logs.Add(s);},_=>{},_=>{},_=>{},services);
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(token);var run=runner.Run(stop.Token);
        // Wait for the real Runner to publish adapter state, not a wall-clock
        // guess. No capture, driver or installed service is used in this fixture.
        while(!factory.Obtained){if(run.IsCompleted)await run;await Task.Delay(10,token);}
        stop.Cancel();bool refused=false;try{await run.WaitAsync(TimeSpan.FromSeconds(10),token);}catch(MeshShutdownException){refused=true;}
        check(refused&&!runner.CleanupComplete&&factory.Disposed,"an owned factory close failure cannot be reported as completed cleanup");
        check(adapter.Disposed,"cleanup still releases the independent adapter after another owner failure");
        check(runner.UnprovenOwnerCount==1,"failed owner remains strongly retained instead of relying on finalization");
        return new{scope="Real Runner cleanup with injected owner-close failure; memory adapter, no kernel",refused,runner.CleanupComplete,runner.ExitDiagnostics,logs=logs.ToArray()};
    }
    sealed class FaultFactory:IMeshCandidateFactory,IAsyncDisposable {
        public bool Obtained,Disposed;
        public TraversalProfile[] Profiles {get{Obtained=true;return [TraversalProfile.UdpDirect];}}
        public Task<IMeshCandidateResource> Gather(MeshMember p,TraversalProfile k,Guid a,CancellationToken t)=>throw new IOException("No peer candidates in cleanup fixture");
        public ValueTask DisposeAsync(){Disposed=true;return ValueTask.FromException(new IOException("Owned capture close not proven (injected)"));}
    }
}
