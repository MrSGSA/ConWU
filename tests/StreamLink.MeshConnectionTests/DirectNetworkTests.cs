using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task DirectNetworks()
    {
        await DirectShortPairing();
        static void Reject(Action action){try{action();}catch(Exception ex)when(ex is FormatException or CryptographicException or System.IO.IOException){return;}throw new Exception("unexpected direct credential acceptance");}
        var owner=MeshIdentity.Create("","","faketcp","10.171.139.1",direct:true);
        var code=DirectInvitation.Issue(owner,[new(0,"txt://stun.example.com#streamlink")]);var first=DirectInvitation.Import(code);
        Check(first.Mesh.Pair.Direct&&first.Mesh.Pair.Service==""&&!first.Mesh.IsOwner&&first.Mesh.LocalIp=="10.171.139.2","serverless invitation carries a per-device credential, signed IP and no coordinator/owner private key");
        Check(first.Entries.Single()==new ExistingEntry(1,"txt://stun.example.com#streamlink"),"invitation preserves dynamically refreshed owner ingress and strict application selector");
        var original=JsonSerializer.Deserialize<DirectInvitation>(Convert.FromBase64String(code[4..]))!;
        string Encode(DirectInvitation value)=>"SL5."+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(value));
        Reject(()=>DirectInvitation.Import(Encode(original with{Entries=[new(1,"203.0.113.99:42")]})));
        Reject(()=>DirectInvitation.Import(Encode(original with{Enrollment=original.Enrollment with{Expires=1}})));
        Reject(()=>DirectInvitation.Import(Encode(original with{Directory=original.Directory with{Revision=99}})));
        Check(true,"endpoint substitution, expiry alteration and directory tampering are rejected before connection");
        Check(!SensitiveText.Redact(code,new()).Contains("SL5."),"long direct credential is redacted from diagnostics");
        Check(ExistingEntry.ForJoinedNetwork([new(-1,"203.0.113.1:4"),new(0,"203.0.113.2:4")]).SequenceEqual(new ExistingEntry[]{new(1,"203.0.113.1:4"),new(0,"203.0.113.2:4")}),"pre-enrollment host entry binds to owner while preserving own ingress");
        ExistingEntryResolver.Validate([new(-1,"203.0.113.1:4")]);
        using(var cleanTxt=new ExistingEntryResolver((_,_)=>Task.FromResult(new[]{IPAddress.Parse("203.0.113.2")}),(_,_)=>Task.FromResult(new[]{"203.0.113.1:44680"})))
            Check((await cleanTxt.Resolve([new(-1,"txt://clean.example.com")],"faketcp",default)).Single().Endpoints.Single()=="203.0.113.1:44680","plain TXT IP:port needs no streamlink prefix");

        var firstAdapter=new MemoryAdapter();var ownerAdapter=new MemoryAdapter();
        await using var ownerRouter=new MeshRouter(ProfileChanges.Copy(new DeviceProfile{Mesh=owner}).Mesh!,ownerAdapter);
        await using var firstRouter=new MeshRouter(ProfileChanges.Copy(new DeviceProfile{Mesh=first.Mesh}).Mesh!,firstAdapter);
        using var ownerDiscovery=new DirectMeshDiscovery(owner);using var firstDiscovery=new DirectMeshDiscovery(first.Mesh);
        ownerDiscovery.Attach(ownerRouter);firstDiscovery.Attach(firstRouter);
        ownerRouter.SetCandidate(first.Mesh.Self.Slot,firstRouter.LocalEndpoint,"first","");firstRouter.SetCandidate(1,ownerRouter.LocalEndpoint,"owner","");
        await Until(()=>ownerRouter.HasHealthyPath(2)&&firstRouter.HasHealthyPath(1),"invited devices authenticate an actual encrypted loopback link without any HTTP service");
        long revision=DateTime.UtcNow.Ticks,expiry=DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds();
        await ownerDiscovery.Publish(new(1,owner.Self.Device,revision,expiry,"203.0.113.1:44680","host"),default);
        await firstDiscovery.Publish(new(2,first.Mesh.Self.Device,revision,expiry,"203.0.113.2:44680","first"),default);
        async Task PumpUntil(Func<Task<bool>> done,string label,int timeout=15000){var until=Environment.TickCount64+timeout;while(Environment.TickCount64<until){ownerDiscovery.Tick(Environment.TickCount64);firstDiscovery.Tick(Environment.TickCount64);if(await done()){Check(true,label);return;}await Task.Delay(110);}throw new Exception("Timeout "+label);}
        await PumpUntil(async()=> (await firstDiscovery.Read(default))!.Nodes.Any(n=>n.Slot==1)&& (await ownerDiscovery.Read(default))!.Nodes.Any(n=>n.Slot==2),"fragmented signed endpoint announcements cross encrypted data paths");
        Check(ownerRouter.Status().Single().ReceivedBytes==0&&firstRouter.Status().Single().ReceivedBytes==0,"metadata does not inflate application byte counters");
        var second=DirectInvitation.Import(DirectInvitation.Issue(owner,[new(0,"203.0.113.1:44680")]));
        ownerRouter.ApplyDirectory(owner.Directory!);await ownerDiscovery.SaveDirectory(owner.Directory!,default);
        await PumpUntil(async()=> (await firstDiscovery.Read(default))!.Directory.Revision==owner.Directory!.Revision,"previous member receives new signed multi-device directory without a server");
        var sync=(await firstDiscovery.Read(default))!;firstRouter.ApplyDirectory(sync.Directory);
        await using var secondRouter=new MeshRouter(second.Mesh,new MemoryAdapter());
        firstRouter.SetCandidate(3,secondRouter.LocalEndpoint,"second","");secondRouter.SetCandidate(2,firstRouter.LocalEndpoint,"first","");
        await Until(()=>firstRouter.HasHealthyPath(3)&&secondRouter.HasHealthyPath(2),"two non-owner members authenticate each other after directory synchronization");
        firstAdapter.Outgoing.Add(Packet(first.Mesh.LocalIp,second.Mesh.LocalIp));
        await Until(()=>secondRouter.Status().Single(p=>p.Slot==2).ReceivedBytes==1280,"real full-MTU payload goes peer to peer without owner traffic forwarding");
        MeshIdentity.Revoke(owner,3);ownerRouter.ApplyDirectory(owner.Directory!);await ownerDiscovery.SaveDirectory(owner.Directory!,default);
        await PumpUntil(async()=> (await firstDiscovery.Read(default))!.Directory.Revision==owner.Directory!.Revision,"revocation propagates to another member over a direct link");
        firstRouter.ApplyDirectory((await firstDiscovery.Read(default))!.Directory);
        Check(firstRouter.Status().All(p=>p.Slot!=3),"revocation closes the previously authenticated peer route");
        Reject(()=>firstRouter.ApplyDirectory(second.Mesh.Directory!));
        Check(true,"old signed directory cannot resurrect a revoked route");
        var liveProfile=new DeviceProfile{Mesh=owner};var staleDraft=ProfileChanges.Copy(liveProfile);
        MeshIdentity.Issue(owner);ProfileChanges.PreserveLatestDirectory(liveProfile,staleDraft);
        Check(staleDraft.Mesh!.Directory!.Revision==owner.Directory!.Revision&&staleDraft.Mesh.Directory.Members.Length==owner.Directory.Members.Length,"settings saved after async validation cannot erase a newly approved member");
        await DirectRunner();
        Console.WriteLine($"PASS {checks} direct invitation and encrypted multi-device checks; loopback, not public NAT validation");
    }
    static async Task DirectRunner()
    {
        var owner=MeshIdentity.Create("","","faketcp",direct:true);
        var guest=DirectInvitation.Import(DirectInvitation.Issue(owner,[new(0,"203.0.113.1:44680")]));
        IPEndPoint? listening=null;int probes=0,candidates=0;var adapters=new[]{new MemoryAdapter(),new MemoryAdapter()};var statuses=new SessionStatus?[2];
        var folder=Path.Combine(Path.GetTempPath(),"streamlink-direct-runner-"+Guid.NewGuid().ToString("N"));
        StreamLink.Service.MeshRuntimeServices Services(int node)=>new(mesh=>new DirectMeshDiscovery(mesh),_=>Task.FromResult<IPacketAdapter>(adapters[node]),(_,_,_)=>{probes++;throw new Exception("serverless run cannot probe a gateway");},request=>{
            if(request.Server){listening=request.Target;return new StubTransport(null);}
            return new ForwardingTransport(request.Target);
        },(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},folder){
            NetworkWake=()=>new StreamLink.Service.MeshNetworkWake(false),Candidates=(_,_,_,_)=>{candidates++;return Task.FromResult<IMeshCandidateFactory?>(null);},
            ResolveEntries=async (_,_,ct)=>{while(node==1&&listening==null)await Task.Delay(20,ct);return new EntryResolution[]{new(node==0?0:1,0,"地址",[node==0?"203.0.113.1:44680":listening!.ToString()],"")};}
        };
        var ownerRunner=new StreamLink.Service.MeshRunner(new(){Mesh=owner,ConnectionSource="existing",DirectMode=true,ExistingEntries=[new(0,"203.0.113.1:44680")]},_=>{},s=>statuses[0]=s,_=>{},_=>{},Services(0));
        var guestRunner=new StreamLink.Service.MeshRunner(new(){Mesh=guest.Mesh,ConnectionSource="existing",DirectMode=true,ExistingEntries=guest.Entries},_=>{},s=>statuses[1]=s,_=>{},_=>{},Services(1));
        using var stop=new CancellationTokenSource();var runs=new[]{ownerRunner.Run(stop.Token),guestRunner.Run(stop.Token)};
        try{
            await Until(()=>statuses.All(s=>s?.Connected==true),"production Runner establishes both serverless directions through supplied ingress",15000);
            Check(probes==0&&candidates==0,"serverless Runner never invokes gateway or coordinator-dependent hole-punch factories");
            adapters[1].Outgoing.Add(Packet(guest.Mesh.LocalIp,owner.LocalIp));
            await Until(()=>statuses[0]?.Peers?.Single().ReceivedBytes>=1280,"production serverless Runner delivers a full-size authenticated packet");
            MeshIdentity.Revoke(owner,guest.Mesh.Self.Slot);
            await ownerRunner.NotifyDirectClosure(owner.Directory!,default);
            await Until(()=>runs[1].IsFaulted,"deleting a direct network notifies the connected member before owner routes close",10000);
            Check(runs[1].Exception!.GetBaseException() is MeshRevokedException,"peer stops on owner-signed closure rather than importing an old directory");
        }finally{
            stop.Cancel();foreach(var run in runs)try{await run.WaitAsync(TimeSpan.FromSeconds(5));}catch(OperationCanceledException){}catch(MeshRevokedException){}
            if(Directory.Exists(folder)){foreach(var d in Directory.EnumerateDirectories(folder))Directory.Delete(d);Directory.Delete(folder);}
        }
        Check(ownerRunner.CleanupComplete&&guestRunner.CleanupComplete&&adapters.All(a=>a.Disposed),"both serverless workers prove resource cleanup");
    }
}
