using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task ApprovalGuestService()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var owner=MeshIdentity.Create("","","faketcp",direct:true);
        using var host=new DirectPairHost();using var key=new PairKeyExchange();
        var offer=await host.CreateInvitation(key,"Guest-Service-Host",default);
        var invite=DirectPairInvitation.Issue(owner,[new(0,"203.0.113.42:44680")],offer.Ticket,offer.Capability);
        await using var router=new MeshRouter(owner,new MemoryAdapter()){DirectPairing=host.Handle};
        var services=new MeshRuntimeServices(m=>new DirectMeshDiscovery(m),_=>Task.FromResult<IPacketAdapter>(new MemoryAdapter()),(_,_,_)=>throw new Exception("no gateway permitted"),
            r=>new PairTransport(r.Server?r.Target:router.LocalEndpoint),(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(ProfileStore.Root,"sessions")){
            Candidates=(_,_,_,_)=>throw new Exception("no coordinator permitted")
        };
        var store=new ProfileStore();store.Save(new DeviceProfile{Enabled=false,DirectMode=true,ConnectionSource="existing",EntryRefreshSeconds=180,ListenPort=45010,SourcePort=45011,ExistingEntries=[new(ExistingEntry.NetworkOwner,"203.0.113.24:44680")]});
        string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        using var worker=new ControlWorker(services);worker.StartLocal();
        Task<UiControlReply> Ui(string action,string code="",string mode="faketcp")=>worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new(action,Code:code,Mode:mode)),sid,default);
        string savedSettings=JsonSerializer.Serialize((await worker.HandleUi(new("status"),sid,default)).Status!.Settings);
        try {
            var mismatch=await Ui("join-invitation",invite,"udp");Check(!mismatch.Ok&&store.Load().Mesh==null,"invitation cannot silently change the user's selected transport");
            Check(JsonSerializer.Serialize(mismatch.Status!.Settings)==savedSettings,"protocol mismatch leaves every saved connection setting unchanged");
            var pending=await Ui("join-invitation",invite);Check(pending.Ok&&pending.Status!.Pairing!.Active&&!pending.Status.Pairing.Owner&&store.Load().Mesh==null,"real guest control worker waits for approval without persisting membership");
            await host.Reveal(offer.Ticket,true,key,default);var polled=await Ui("pair-poll");
            var hostState=await host.Poll(offer.Ticket,true,default);
            var shared=key.Derive(hostState.GuestPublic,hostState.GuestCommitment,offer.Ticket.Room,hostState.Candidate,true);
            Check(polled.Ok&&polled.Status!.Pairing!.Verification==PairKeyExchange.Verification(shared)&&store.Load().Mesh==null,"guest worker exposes matching SAS while authorization is pending");
            var enrollment=DirectInvitation.Issue(owner,[new(0,"203.0.113.42:44680")]);
            await host.Approve(offer.Ticket,hostState.Candidate,PairKeyExchange.EncryptInvitation(shared,enrollment,offer.Ticket.Room,hostState.Candidate),default);
            var approved=await Ui("pair-poll");
            Check(approved.Ok&&approved.Status!.NetworkId==owner.Pair.Network&&!approved.Status.IsOwner&&store.Load().Mesh!.OwnerKey==owner.OwnerKey,"guest worker imports only the approved invitation identity and starts its memory adapter");
            Check(store.Load().ExistingEntries.Any(e=>e.PeerSlot==1)&&store.Load().DirectMode,"approved host entries persist for serverless reconnect");
            Check(JsonSerializer.Serialize(approved.Status!.Settings)==savedSettings&&!approved.Status.Settings!.ExistingEntries.Any(e=>e.Source=="203.0.113.42:44680"),"actual approved join keeps invitation endpoints out of independent user settings");
            CryptographicOperations.ZeroMemory(shared);
            var beforeLeave=store.Load().Mesh!;
            var left=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("leave",ExpectedNetwork:owner.Pair.Network,ConfirmReplace:true)),sid,default);
            Check(left.Ok&&store.Load().Mesh==null&&store.Load().RejoinCredential?.Member==beforeLeave.Self,"real guest departure removes network credentials and retains only a protected membership proof");
            Check(JsonSerializer.Serialize(left.Status!.Settings)==savedSettings&&store.Load().ExistingEntries.Any(e=>e.PeerSlot==-1),"actual guest exit preserves the complete saved settings and reusable target entry");
            var fresh=await host.CreateInvitation(key,"Guest-Service-Host",default);
            string freshCode=DirectPairInvitation.Issue(owner,[new(0,"203.0.113.42:44680")],fresh.Ticket,fresh.Capability);
            var reapplied=await Ui("join-invitation",freshCode);
            Check(reapplied.Ok&&store.Load().Mesh==null,"guest service still requires approval when rejoining the same host");
            Check(JsonSerializer.Serialize(reapplied.Status!.Settings)==savedSettings,"pending rejoin cannot rewrite settings before host approval");
            await host.Reveal(fresh.Ticket,true,key,default);await Ui("pair-poll");
            var rejoinState=await host.Poll(fresh.Ticket,true,default);
            var prior=MeshRejoin.Resolve(owner,rejoinState.Rejoin,fresh.Capability,rejoinState.GuestCommitment);
            Check(prior==beforeLeave.Self,"real guest service sends its old-key proof through the bounded direct-pair protocol");
            string replacement=DirectInvitation.Issue(owner,[new(0,"203.0.113.42:44680")],replacing:prior);
            var rejoinShared=key.Derive(rejoinState.GuestPublic,rejoinState.GuestCommitment,fresh.Ticket.Room,rejoinState.Candidate,true);
            await host.Approve(fresh.Ticket,rejoinState.Candidate,PairKeyExchange.EncryptInvitation(rejoinShared,replacement,fresh.Ticket.Room,rejoinState.Candidate),default);
            var rejoined=await Ui("pair-poll");CryptographicOperations.ZeroMemory(rejoinShared);
            Check(rejoined.Ok&&store.Load().Mesh!.LocalIp==beforeLeave.LocalIp&&store.Load().RejoinCredential==null,"approved guest rejoin restores its IP and discards the retired proof credential");
            Check(JsonSerializer.Serialize(rejoined.Status!.Settings)==savedSettings,"actual successful rejoin preserves saved settings exactly");
            var stopped=await worker.HandleUi(new("stop",OperationId:Guid.NewGuid()),sid,default);
            Check(stopped.Ok&&!stopped.Status!.NetworkEnabled&&JsonSerializer.Serialize(stopped.Status.Settings)==savedSettings,"stopping a joined network preserves independent settings");
            var resumed=await worker.HandleUi(new("start",OperationId:Guid.NewGuid()),sid,default);
            Check(resumed.Ok&&resumed.Status!.NetworkEnabled&&JsonSerializer.Serialize(resumed.Status.Settings)==savedSettings,"restarting a joined network preserves independent settings");
        }finally{await worker.StopLocal();}
    }
}
