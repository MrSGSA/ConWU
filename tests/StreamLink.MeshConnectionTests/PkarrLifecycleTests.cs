using System.Collections.Concurrent;
using System.Net;
using System.Security.Principal;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    sealed class HeldPkarrGateway:HttpMessageHandler
    {
        public readonly ConcurrentDictionary<string,byte[]> Packets=new();
        public readonly ConcurrentQueue<long> FailedPuts=new();
        public volatile bool Offline;
        public TaskCompletionSource? Hold,Entered;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            string key=request.RequestUri!.AbsolutePath[1..];
            if(request.Method==HttpMethod.Put){
                if(Offline){FailedPuts.Enqueue(Environment.TickCount64);return new(HttpStatusCode.ServiceUnavailable);}
                byte[] bytes=await request.Content!.ReadAsByteArrayAsync(token);
                if(Hold is {} hold){Entered?.TrySetResult();await hold.Task.WaitAsync(token);}
                Packets[key]=bytes;return new(HttpStatusCode.NoContent);
            }
            return Packets.TryGetValue(key,out var packet)?new(HttpStatusCode.OK){Content=new ByteArrayContent(packet)}:new(HttpStatusCode.NotFound);
        }
    }
    static async Task PkarrLifecycle()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var store=new ProfileStore(Path.Combine(ProfileStore.Root,"pkarr-lifecycle"));
        var mesh=MeshIdentity.Create("","","faketcp",direct:true);
        var profile=new DeviceProfile{Device=mesh.Self.Device,Mesh=mesh,Enabled=true};
        ConnectionSettings.Apply(profile,new(){ConnectionSource="custom",DirectMode=true,DiscoveryMode="pkarr",PkarrPublish=true});
        store.Save(profile);
        string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        using var gateway=new HeldPkarrGateway();using var http=new HttpClient(gateway);
        int identityAttempts=0,listeners=0;var mappings=new ConcurrentBag<Mapping>();
        store.ValidateNetworkProfile=p=>{if(p.PkarrSeed.Length>0&&Interlocked.Increment(ref identityAttempts)==1)throw new IOException("fixture transient identity write failure");};
        var services=new MeshRuntimeServices(m=>new DirectMeshDiscovery(m),_=>Task.FromResult<IPacketAdapter>(new MemoryAdapter()),
            (_,_,_)=>{var mapping=new Mapping();mapping.Change(new(IPAddress.Parse("203.0.113.77"),44680));mappings.Add(mapping);return Task.FromResult<IMapping>(mapping);},
            request=>{if(request.Server)Interlocked.Increment(ref listeners);return new StubTransport(null);},
            (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(store.DirectoryPath,"sessions")){
                PkarrClientFactory=()=>new(http,["https://fixture.invalid"]),
                Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null),NetworkWake=()=>new MeshNetworkWake(false)
            };
        using var worker=new ControlWorker(store,services,isolatedNetwork:true);
        worker.StartLocal();
        try{
            await Until(()=>gateway.Packets.Count==1,"transient identity persistence failure is retried by the same running PKARR worker",18000);
            Check(identityAttempts>=2&&worker.SingleUiSnapshot().Pkarr is {Error:"",PublishedAt:>0},"recovery clears the identity-write error after a committed signed publication");
            var before=store.LoadForMaintenance();string source=PkarrPacket.Source(before.PkarrSeed);int servers=listeners;
            gateway.Hold=new(TaskCreationOptions.RunContinuationsAsynchronously);gateway.Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);
            var refresh=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("refresh-pkarr",ExpectedNetwork:mesh.Pair.Network)),sid,default);
            Check(refresh.Ok,"manual discovery refresh is accepted before a deliberately stalled PUT");
            await gateway.Entered.Task.WaitAsync(TimeSpan.FromSeconds(12));
            var status=worker.SingleUiSnapshot();
            var off=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:status.Settings! with{DiscoveryMode="direct",PkarrPublish=false},ExpectedRevision:status.SettingsRevision)),sid,default);
            Check(off.Ok,"saving another discovery policy completes while an older publication is in flight: "+off.Error);
            gateway.Hold.TrySetResult();gateway.Hold=null;
            await Until(()=>worker.SingleUiSnapshot().Pkarr?.Enabled==false,"a late publication cannot re-enable discovery after settings disable it",5000);
            var disabled=store.LoadForMaintenance();
            Check(disabled.PkarrSeed==before.PkarrSeed&&disabled.PkarrSequence>before.PkarrSequence&&disabled.SavedNetworkSettings?.DiscoveryMode=="direct"&&listeners==servers,"policy saves preserve discovery identity and advanced sequence without restarting the receiver");
            status=worker.SingleUiSnapshot();
            var on=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:status.Settings! with{DiscoveryMode="pkarr",PkarrPublish=true},ExpectedRevision:status.SettingsRevision)),sid,default);
            Check(on.Ok,"PKARR can be re-enabled on the same network: "+on.Error);
            await Until(()=>worker.SingleUiSnapshot().Pkarr is {Enabled:true,Error:"",PublishedAt:>0} p&&p.Source==source&&store.LoadForMaintenance().PkarrSequence>disabled.PkarrSequence,"re-enabled publisher updates its original record and never reuses an old sequence",12000);
            gateway.Offline=true;
            foreach(var mapping in mappings)mapping.Change(new(IPAddress.Parse("203.0.113.78"),44681));
            await Until(()=>gateway.FailedPuts.Count>=3,"a changed entry encounters three deliberate publication failures",20000);
            var attempts=gateway.FailedPuts.ToArray();
            Check(attempts[1]-attempts[0]>=2000&&attempts[2]-attempts[1]>=4000,"a changed but unpublished payload does not reset the exponential retry backoff every tick");
            gateway.Offline=false;
            var recovery=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("refresh-pkarr",ExpectedNetwork:mesh.Pair.Network)),sid,default);
            Check(recovery.Ok,"manual refresh can wake a backed-off publisher after gateway recovery");
            await Until(()=>worker.SingleUiSnapshot().Pkarr is {Error:"",Endpoints:var addresses}&&addresses.Contains("203.0.113.78:44681"),"gateway recovery publishes the pending new entry and clears the old failure",12000);
            Check(listeners==servers,"publication backoff and recovery never allocate another receiver");
        }finally{gateway.Hold?.TrySetResult();store.ValidateNetworkProfile=null;await worker.StopLocal();}
        Check(!worker.HasOutstandingOwnership,"shutdown joins PKARR and network resources after failure and policy changes");
        Console.WriteLine($"PASS {checks} PKARR lifecycle checks; isolated store, injected gateway and loopback adapter only");
    }
}
