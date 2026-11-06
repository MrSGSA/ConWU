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
    static async Task GovernanceServiceRecovery()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        string root=ProfileStore.Root;Directory.CreateDirectory(root);
        string registryRoot=Path.Combine(root,"registry");Directory.CreateDirectory(registryRoot);
        var registry=new MeshRegistry(registryRoot);var rooms=new PairRooms();bool loseReply=false;
        using var key=RSA.Create(2048);
        var request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var generated=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        using var cert=X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx),null);
        var builder=WebApplication.CreateSlimBuilder();builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(o=>o.Listen(IPAddress.Loopback,0,l=>l.UseHttps(cert)));
        await using var app=builder.Build();
        app.MapGet("/health",()=>Results.Json(new{meshProtocol=4,pairingDecisions=1,meshAddressing=1,memberRejoin=1,meshGovernance=1}));
        app.MapGet("/v3/mesh/{network}",(HttpContext c,string network)=>registry.Read(c,network));
        app.MapPut("/v3/mesh/{network}/directory",(HttpContext c,string network,MeshDirectory d)=>registry.Directory(c,network,d));
        app.MapPut("/v4/mesh/{network}/membership",(HttpContext c,string network,MeshMembershipRequest change)=>{
            var result=registry.Membership(c,network,change);if(loseReply){loseReply=false;c.Abort();}return result;
        });
        app.MapPost("/v2/pair",(PairRoomCreate p)=>rooms.Create(p));
        app.MapPost("/v2/pair/join",(PairRoomJoin p)=>rooms.Join(p));
        app.MapGet("/v2/pair/{room}/owner",(HttpContext c,string room)=>rooms.Exchange(c,room,true));
        app.MapGet("/v2/pair/{room}/guest",(HttpContext c,string room)=>rooms.Exchange(c,room,false));
        app.MapPost("/v2/pair/{room}/owner/reveal",(HttpContext c,string room,PairRoomReveal p)=>rooms.Exchange(c,room,true,p));
        app.MapPost("/v2/pair/{room}/guest/reveal",(HttpContext c,string room,PairRoomReveal p)=>rooms.Exchange(c,room,false,p));
        app.MapPost("/v2/pair/{room}/approve",(HttpContext c,string room,PairRoomApproval p)=>rooms.Exchange(c,room,true,approve:p));
        app.MapDelete("/v2/pair/{room}",(HttpContext c,string room)=>rooms.Exchange(c,room,true,close:true));
        await app.StartAsync();
        string address=app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single()+"/";
        string pin=Convert.ToHexString(SHA256.HashData(cert.RawData));
        var creator=MeshIdentity.Create(address,pin,"faketcp");MeshGovernance.Enable(creator);
        using(var discovery=new MeshDiscoveryClient(creator))await discovery.CommitMembership(new("",creator.Directory!),default);
        var first=creator.Directory!;var b=Guest(creator);
        using(var discovery=new MeshDiscoveryClient(creator))await discovery.CommitMembership(new(MeshGovernance.Head(first),creator.Directory!),default);
        var store=new ProfileStore();string sid=WindowsIdentity.GetCurrent().User!.Value;
        store.Save(new DeviceProfile{Mesh=b,Enabled=false,DeviceName="Equal member B",ConnectionSource="existing",CoordinationService=address,CoordinationPin=pin,ExistingEntries=[new(-1,"https://entry.example/address")],EntryRefreshSeconds=180,RequestedVirtualIp="10.171.139.99"});
        store.AuthorizeUiUser(sid);
        var services=new MeshRuntimeServices(m=>new MeshDiscoveryClient(m),_=>Task.FromResult<IPacketAdapter>(new MemoryAdapter()),
            (_,_,_)=>Task.FromException<IMapping>(new IOException("isolated test")),_=>throw new IOException("isolated test"),
            (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(root,"sessions")){
            Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null),NetworkWake=()=>new MeshNetworkWake(false)
        };
        ControlWorker? worker=new(services);worker.StartLocal();
        Task<UiControlReply> Act(UiNetworkAction action)=>worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:action),sid,default);
        try{
            string saved=JsonSerializer.Serialize((await worker.HandleUi(new("status"),sid,default)).Status!.Settings);
            var invitation=await Act(new("invite",ExpectedNetwork:b.Pair.Network));
            Check(invitation.Ok&&invitation.Status!.CanManageNetwork&&!invitation.Status.IsOwner,"non-creator can open a six-digit invitation through production service");
            using var guestKey=new PairKeyExchange();using var guestClient=new ShortPairClient(address,pin);
            var ticket=await guestClient.Join(invitation.Status!.Pairing!.Code,guestKey,"Equal member C",default);
            await Act(new("pair-poll"));
            var revealed=await guestClient.Reveal(ticket,false,guestKey,default);
            var polled=await Act(new("pair-poll"));var p=polled.Status!.Pairing!;
            Check(polled.Ok&&p.Verification.Length==6&&p.ProposedIp.Length>0,"real encrypted pairing produces explicit IP and verification feedback");
            loseReply=true;
            var lost=await Act(new("approve",Candidate:p.Candidate,Verification:p.Verification,ProposedIp:p.ProposedIp));
            Check(!lost.Ok&&lost.Status!.PendingMembership&&store.Load().PendingMembership!=null,"lost commit acknowledgement preserves a recoverable transaction before reporting failure");
            int issuedNext=store.Load().PendingMembership!.Proposed.NextSlot;
            var duplicate=await Act(new("invite",ExpectedNetwork:b.Pair.Network));
            Check(!duplicate.Ok&&store.Load().PendingMembership!.Proposed.NextSlot==issuedNext,"pending transaction blocks a second invite without consuming another slot");
            await worker.StopLocal();worker.Dispose();worker=new(services);worker.StartLocal();
            var resumed=await Act(new("membership-resume"));
            Check(resumed.Ok&&!resumed.Status!.PendingMembership&&store.Load().Mesh!.Directory!.NextSlot==issuedNext,"restart resumes the same transaction and clears pending state after delivery");
            var approved=await guestClient.Poll(ticket,false,default);
            byte[] shared=guestKey.Derive(revealed.HostPublic,ticket.HostCommitment,ticket.Room,ticket.Candidate,false);
            var guest=MeshIdentity.Import(PairKeyExchange.DecryptInvitation(shared,approved.Ciphertext,ticket.Room,ticket.Candidate,MeshGovernance.MaximumCipher));
            Check(guest.CanManage&&guest.IntroducerSlot==b.Self.Slot&&guest.OwnerPrivate.Length==0,"recovered encrypted invitation grants independent equal management");
            Check(JsonSerializer.Serialize(resumed.Status!.Settings)==saved,"approval and restart preserve every saved network setting");
            var again=await Act(new("invite",ExpectedNetwork:b.Pair.Network));
            using var lostGuestKey=new PairKeyExchange();
            var lostTicket=await guestClient.Join(again.Status!.Pairing!.Code,lostGuestKey,"Undelivered member",default);
            await Act(new("pair-poll"));await guestClient.Reveal(lostTicket,false,lostGuestKey,default);
            var pendingPair=(await Act(new("pair-poll"))).Status!.Pairing!;
            loseReply=true;await Act(new("approve",Candidate:pendingPair.Candidate,Verification:pendingPair.Verification,ProposedIp:pendingPair.ProposedIp));
            var interrupted=store.Load().PendingMembership!;
            var roomContext=new DefaultHttpContext();roomContext.Request.Headers.Authorization="Bearer "+interrupted.Room!.Token;
            rooms.Exchange(roomContext,interrupted.Room.Room,true,close:true);
            var abandoned=await Act(new("membership-resume"));
            int abandonedSlot=interrupted.Proposed.NextSlot-1;
            Check(abandoned.Ok&&!abandoned.Status!.PendingMembership&&abandoned.Status.Peers.Any(peer=>peer.Slot==abandonedSlot),"lost pairing room clears recovery wait and exposes the committed member for explicit removal");
            var cleaned=await Act(new("revoke",ExpectedNetwork:b.Pair.Network,PeerSlot:abandonedSlot));
            Check(cleaned.Ok,"unconfirmed invitation can be removed explicitly without deleting other members");
            var removed=await Act(new("revoke",ExpectedNetwork:b.Pair.Network,PeerSlot:1));
            Check(removed.Ok&&store.Load().Mesh!.Directory!.Members.All(m=>m.Slot!=1),"production non-creator service removes the original creator");
            loseReply=true;
            var leave=await Act(new("leave",ExpectedNetwork:b.Pair.Network,ConfirmReplace:true));
            Check(!leave.Ok&&store.Load().PendingMembership?.Action=="leave","lost exit acknowledgement does not forget the network or transaction");
            var complete=await Act(new("membership-resume"));
            Check(complete.Ok&&store.Load().Mesh==null&&store.Load().PendingMembership==null,"confirmed self-exit clears only local membership");
            Check(JsonSerializer.Serialize(complete.Status!.Settings)==saved&&store.Load().ExistingEntries.Any(e=>e.Source=="https://entry.example/address"),"exit preserves target subscription and all user settings");
            using var guestDiscovery=new MeshDiscoveryClient(guest);var final=await guestDiscovery.Read(default);
            Check(final!.Directory.Members.Length==1&&final.Directory.Members[0]==guest.Self&&!final.Directory.Closed,"remaining member network survives creator removal and inviter exit");
        }finally{
            if(worker!=null){await worker.StopLocal();worker.Dispose();}
            await app.StopAsync();Directory.Delete(root,true);
        }
    }
}
