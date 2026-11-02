using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task DirectPairingService()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var owner=MeshIdentity.Create("","","faketcp",direct:true);var store=new ProfileStore();
        store.Save(new DeviceProfile{Mesh=owner,Enabled=true,DirectMode=true,ConnectionSource="existing",ExistingEntries=[new(0,"203.0.113.42:44680")]});
        string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);IPEndPoint? listener=null;
        var services=new MeshRuntimeServices(m=>new DirectMeshDiscovery(m),_=>Task.FromResult<IPacketAdapter>(new MemoryAdapter()),(_,_,_)=>throw new Exception("no gateway permitted"),
            r=>{if(r.Server)listener=r.Target;return new PairTransport(r.Target);},(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(ProfileStore.Root,"sessions")){
            Candidates=(_,_,_,_)=>throw new Exception("no coordinator permitted")
        };
        using var worker=new ControlWorker(services);worker.StartLocal();
        async Task<UiControlReply> Action(string action,string candidate="",string verification="",string ip="")=>await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new(action,ExpectedNetwork:owner.Pair.Network,Candidate:candidate,Verification:verification,ProposedIp:ip)),sid,default);
        try{
            await Until(()=>listener!=null,"actual control worker owns a direct native-listener target with no coordination service");
            var invited=await Action("invite");Check(invited.Ok&&invited.Status!.Pairing!.Code.StartsWith("SL6."),"restricted UI generates approval invitation on running owner");
            using var guestKey=new PairKeyExchange();using var guest=new DirectPairClient(_=>new PairTransport(listener!));
            var joined=await guest.Join(DirectPairInvitation.Import(invited.Status!.Pairing!.Code).Capability,guestKey,"service guest",default);
            var polled=await Action("pair-poll");Check(polled.Ok&&polled.Status!.Pairing!.PeerName=="service guest","incoming invitation request reaches actual service UI snapshot");
            var remote=await guest.Poll(joined,false,default);await guest.Reveal(joined,false,guestKey,default);polled=await Action("pair-poll");
            var p=polled.Status!.Pairing!;var shared=guestKey.Derive(remote.HostPublic,joined.HostCommitment,joined.Room,joined.Candidate,false);
            Check(p.Verification==PairKeyExchange.Verification(shared)&&p.ProposedIp.Length>0,"service exposes matching SAS and preallocated address before granting membership");
            var wrong=await Action("approve",p.Candidate,p.Verification=="000000"?"000001":"000000",p.ProposedIp);Check(!wrong.Ok&&store.Load().Mesh!.Directory!.Members.Length==1,"wrong UI verification cannot issue a credential");
            var approved=await Action("approve",p.Candidate,p.Verification,p.ProposedIp);Check(approved.Ok&&store.Load().Mesh!.Directory!.Members.Length==2,"owner approval persists exactly one signed member through restricted UI");
            var delivered=await guest.Poll(joined,false,default);var enrolled=DirectInvitation.Import(PairKeyExchange.DecryptInvitation(shared,delivered.Ciphertext,joined.Room,joined.Candidate,DirectPairWire.MaximumCipher));
            Check(enrolled.Mesh.LocalIp==p.ProposedIp&&!enrolled.Mesh.IsOwner,"remote client receives its approved IP and never administrator credentials");CryptographicOperations.ZeroMemory(shared);
            var again=await Action("approve",p.Candidate,p.Verification,p.ProposedIp);Check(!again.Ok&&store.Load().Mesh!.Directory!.Members.Length==2,"duplicate approval after completion cannot allocate another member");
        }finally{await worker.StopLocal();}
    }
}
