using System.Security.Cryptography;
using System.Security.Principal;
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
        var store=new ProfileStore();store.Save(new DeviceProfile{Enabled=false,DirectMode=true,ConnectionSource="existing"});
        string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        using var worker=new ControlWorker(services);worker.StartLocal();
        Task<UiControlReply> Ui(string action,string code="",string mode="faketcp")=>worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new(action,Code:code,Mode:mode)),sid,default);
        try {
            var mismatch=await Ui("join-invitation",invite,"udp");Check(!mismatch.Ok&&store.Load().Mesh==null,"invitation cannot silently change the user's selected transport");
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
            CryptographicOperations.ZeroMemory(shared);
        }finally{await worker.StopLocal();}
    }
}
