using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task EntryAdmissions()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        foreach(bool direct in new[]{true,false})await EntryAdmissionOwner(direct);
        await EntryAdmissionGuest();
    }
    static async Task EntryAdmissionOwner(bool direct)
    {
        string root=ProfileStore.Root,sid=WindowsIdentity.GetCurrent().User!.Value;
        Directory.CreateDirectory(root);
        using var signing=RSA.Create(2048);
        var request=new CertificateRequest("CN=localhost",signing,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var generated=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        using var cert=X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx),null);
        var builder=WebApplication.CreateSlimBuilder();builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(o=>o.Listen(IPAddress.Loopback,0,l=>l.UseHttps(cert)));
        await using var coordinator=builder.Build();
        Directory.CreateDirectory(Path.Combine(root,"registry"));
        var registry=new MeshRegistry(Path.Combine(root,"registry"));
        coordinator.MapGet("/v3/mesh/{network}",(HttpContext c,string network)=>registry.Read(c,network));
        coordinator.MapPut("/v4/mesh/{network}/membership",(HttpContext c,string network,MeshMembershipRequest m)=>registry.Membership(c,network,m));
        await coordinator.StartAsync();
        string url=coordinator.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single()+"/";
        string pin=Convert.ToHexString(SHA256.HashData(cert.RawData));
        var owner=MeshIdentity.Create(direct?"":url,direct?"":pin,"faketcp",direct:direct);
        if(!direct){MeshGovernance.Enable(owner);using var client=new MeshDiscoveryClient(owner);await client.CommitMembership(new("",owner.Directory!),default);}
        var store=new ProfileStore();string credential=owner.OwnerPrivate;
        store.Save(new DeviceProfile{Mesh=owner,Enabled=true,DirectMode=direct,ConnectionSource="existing"});store.AuthorizeUiUser(sid);
        IPEndPoint? listener=null;int gatewayCalls=0;
        var services=new MeshRuntimeServices(m=>direct?new DirectMeshDiscovery(m):new MeshDiscoveryClient(m),_=>Task.FromResult<IPacketAdapter>(new MemoryAdapter()),
            (_,_,_)=>{gatewayCalls++;throw new IOException("gateway must not run");},r=>{if(r.Server)listener=r.Target;return new PairTransport(r.Target);},
            (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(root,"sessions")){
            Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null),NetworkWake=()=>new MeshNetworkWake(false)
        };
        using var worker=new ControlWorker(services);worker.StartLocal();
        Task<UiControlReply> Status()=>worker.HandleUi(new("status"),sid,default);
        try{
            await Until(()=>listener!=null,"default receiver starts without publishing a local address: "+direct);
            using var guestKey=new PairKeyExchange();using var guest=new DirectPairClient(_=>new PairTransport(listener!),entryAdmission:true);
            var joined=await guest.Join(DirectPairWire.EntryLocator,guestKey,"entry guest",default);
            await Until(()=>Status().GetAwaiter().GetResult().Status!.Pairing is {Active:true,Owner:true,Method:"entry",Candidate.Length:>0},"unsolicited entry request becomes a visible pending approval without a generated code");
            var revealed=await guest.Poll(joined,false,default);Check(revealed.HostPublic.Length>0,"host reveals only its committed ephemeral key");
            await guest.Reveal(joined,false,guestKey,default);
            await Until(()=>Status().GetAwaiter().GetResult().Status!.Pairing!.Verification.Length==6,"host observes and verifies entry request without a browser polling it");
            var before=(await Status()).Status!;var pending=before.Pairing!;
            var shared=guestKey.Derive(revealed.HostPublic,joined.HostCommitment,joined.Room,joined.Candidate,false);
            Check(pending.Verification==PairKeyExchange.Verification(shared)&&store.Load().Mesh!.Directory!.Members.Length==1,"entry exchange has matching SAS and grants no membership before approval");
            var bad=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("approve",Candidate:pending.Candidate,Verification:pending.Verification=="000000"?"000001":"000000",ProposedIp:pending.ProposedIp)),sid,default);
            Check(!bad.Ok&&store.Load().Mesh!.Directory!.Members.Length==1,"invalid confirmation cannot authorize an entry applicant");
            var approved=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("approve",Candidate:pending.Candidate,Verification:pending.Verification,ProposedIp:pending.ProposedIp)),sid,default);
            Check(approved.Ok&&store.Load().Mesh!.Directory!.Members.Length==2,"entry approval commits exactly one signed member: "+direct);
            var delivered=await guest.Poll(joined,false,default);
            var enrolled=NetworkEntryEnrollment.Import(PairKeyExchange.DecryptInvitation(shared,delivered.Ciphertext,joined.Room,joined.Candidate,DirectPairWire.MaximumCipher));
            Check(enrolled.Mesh.Pair.Direct==direct&&enrolled.Mesh.LocalIp==pending.ProposedIp&&enrolled.Mesh.IsDecentralized==!direct,"entry delivers the approved network type, address and permissions");
            Check(JsonSerializer.Serialize(approved.Status!.Settings)==JsonSerializer.Serialize(before.Settings)&&gatewayCalls==0,"entry admission preserves settings and never starts autonomous punching in strict mode");
            Check(!JsonSerializer.Serialize(await Status()).Contains(credential),"host private key is absent from every ordinary UI snapshot");
            var hidden=await worker.HandleUi(new("ddns-token",OperationId:Guid.NewGuid()),"S-1-5-21-1-2-3-9999",default);
            var shown=await worker.HandleUi(new("ddns-token",OperationId:Guid.NewGuid()),sid,default);
            Check(!hidden.Ok&&hidden.Credential==null&&!shown.Ok&&shown.Credential==null,"retired DNS-token operation cannot reveal credentials even to an authorized UI");
            using var refusedKey=new PairKeyExchange();using var refusedClient=new DirectPairClient(_=>new PairTransport(listener!),entryAdmission:true);
            var refusedTicket=await refusedClient.Join(DirectPairWire.EntryLocator,refusedKey,"declined entry",default);
            await Until(()=>Status().GetAwaiter().GetResult().Status!.Pairing?.Candidate==refusedTicket.Candidate,"next entry request is accepted after the previous authorization delivery");
            var refused=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("reject",Candidate:refusedTicket.Candidate)),sid,default);
            Check(refused.Ok&&store.Load().Mesh!.Directory!.Members.Length==2,"rejecting an entry request grants no credential");
            using var nextKey=new PairKeyExchange();using var nextClient=new DirectPairClient(_=>new PairTransport(listener!),entryAdmission:true);
            var nextTicket=await nextClient.Join(DirectPairWire.EntryLocator,nextKey,"following entry",default);
            await Until(()=>Status().GetAwaiter().GetResult().Status!.Pairing?.Candidate==nextTicket.Candidate,"rejecting one request does not block the next applicant for five minutes");
            var receipt=await refusedClient.Poll(refusedTicket,false,default);
            Check(receipt.Outcome=="Rejected"&&(await Status()).Status!.Pairing!.Candidate==nextTicket.Candidate,"old applicant can read its rejection while the next applicant is pending");
            await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("reject",Candidate:nextTicket.Candidate)),sid,default);
            Check((await nextClient.Poll(nextTicket,false,default)).Outcome=="Rejected"&&store.Load().Mesh!.Directory!.Members.Length==2,"successive rejection receipts remain bounded and never enroll either applicant");
            CryptographicOperations.ZeroMemory(shared);
        }finally{await worker.StopLocal();}
    }
    static async Task EntryAdmissionGuest()
    {
        var owner=MeshIdentity.Create("","","faketcp",direct:true);
        using var host=new DirectPairHost(entryAdmission:true);using var key=new PairKeyExchange();
        var room=await host.Create(key,"entry host",default);
        await using var router=new MeshRouter(owner,new MemoryAdapter()){DirectPairing=host.Handle};
        var services=new MeshRuntimeServices(m=>new DirectMeshDiscovery(m),_=>Task.FromResult<IPacketAdapter>(new MemoryAdapter()),(_,_,_)=>throw new IOException("no gateway permitted"),
            r=>new PairTransport(r.Server?r.Target:router.LocalEndpoint),(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(ProfileStore.Root,"sessions")){
            Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null),NetworkWake=()=>new MeshNetworkWake(false)
        };
        var store=new ProfileStore();store.Save(new DeviceProfile{Enabled=false,ListenPort=45010,SourcePort=45011});
        string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        using var worker=new ControlWorker(services);worker.StartLocal();
        Task<UiControlReply> Ui(UiNetworkAction a)=>worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:a),sid,default);
        try{
            var before=(await worker.HandleUi(new("status"),sid,default)).Status!;string saved=JsonSerializer.Serialize(before.Settings);
            var pending=await Ui(new("join-entry"){Entry="203.0.113.42:44680"});
            Check(pending.Ok&&store.Load().Mesh==null&&pending.Status!.Pairing!.Method=="entry","real guest service can request entry admission without editing settings");
            await host.Reveal(room,true,key,default);await Ui(new("pair-poll"));
            var state=await host.Poll(room,true,default);
            var shared=key.Derive(state.GuestPublic,state.GuestCommitment,room.Room,state.Candidate,true);
            var issued=NetworkEntryEnrollment.Encode(DirectInvitation.Issue(owner,[]),[]);
            await host.Approve(room,state.Candidate,PairKeyExchange.EncryptInvitation(shared,issued,room.Room,state.Candidate),default);
            var joined=await Ui(new("pair-poll"));
            Check(joined.Ok&&store.Load().Mesh!.Pair.Network==owner.Pair.Network&&store.Load().UsesExistingEntriesOnly,"guest adopts only approved identity and retains strict entry behavior");
            Check(JsonSerializer.Serialize(joined.Status!.Settings)==saved,"entry joining cannot rewrite any saved settings");
            var change=await Ui(new("settings",Settings:joined.Status.Settings,ExpectedRevision:joined.Status.SettingsRevision){Patch=new(DeviceName:"renamed after join")});
            Check(change.Ok&&store.Load().UsesExistingEntriesOnly&&store.Load().ExistingEntries.Any(e=>e.Source=="203.0.113.42:44680"),"saving unrelated settings retains the authenticated runtime seed and never enables punching");
            Check(JsonSerializer.Serialize(change.Status!.Settings)==saved,"effective runtime entry choices do not leak into persisted UI preferences");
            var crowded=store.Load();crowded.SavedNetworkSettings=crowded.SavedNetworkSettings! with{ConnectionSource="existing",ExistingEntries=Enumerable.Range(1,12).Select(i=>new ExistingEntry(ExistingEntry.Network,$"203.0.113.{i}:45000")).ToArray()};
            Check(ControlWorker.RuntimeEntries(crowded).Length==12&&ControlWorker.RuntimeEntries(crowded).Any(e=>e.Source=="203.0.113.42:44680")&&crowded.SavedNetworkSettings.ExistingEntries.Length==12,"runtime source limit reserves the successfully used join seed without changing twelve saved sources");
            crowded.SavedNetworkSettings=crowded.SavedNetworkSettings with{ExistingEntries=[new(1,"203.0.113.42:44680"),new(ExistingEntry.Network,"203.0.113.42:44680")]};
            var duplicate=ControlWorker.RuntimeEntries(crowded);
            Check(duplicate.Length==1&&duplicate[0].PeerSlot==ExistingEntry.Network,"a saved source and its authenticated join seed use one worker and keep network-scoped discovery");
            var left=await Ui(new("leave",ExpectedNetwork:owner.Pair.Network,ConfirmReplace:true));
            Check(left.Ok&&store.Load().Mesh==null&&JsonSerializer.Serialize(left.Status!.Settings)==saved,"exit after entry joining still preserves the same saved settings");
            CryptographicOperations.ZeroMemory(shared);
        }finally{await worker.StopLocal();}
    }
}
