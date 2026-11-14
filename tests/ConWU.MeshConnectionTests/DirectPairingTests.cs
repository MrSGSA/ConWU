using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    sealed class PairTransport(IPEndPoint endpoint):IMeshTransport {public IPEndPoint ClientEndpoint=>endpoint;public bool Exited{get;private set;}public void Dispose()=>Exited=true;}
    sealed class PairClock:TimeProvider {public DateTimeOffset Now=DateTimeOffset.UtcNow;public override DateTimeOffset GetUtcNow()=>Now;}
    static async Task DirectShortPairing()
    {
        var clock=new PairClock();using var host=new DirectPairHost(clock);using var ownerKey=new PairKeyExchange();using var guestKey=new PairKeyExchange();
        var owner=MeshIdentity.Create("","","faketcp",direct:true);
        await using var router=new MeshRouter(owner,new MemoryAdapter()){DirectPairing=host.Handle};
        using var guest=new DirectPairClient(_=>new PairTransport(router.LocalEndpoint));
        var ticket=await host.Create(ownerKey,new string('主',64),default);
        Check(ticket.Code.Length==6&&ticket.Code.All(char.IsAsciiDigit),"direct host generates a random six-digit expiring code without a coordinator");
        var joined=await guest.Join(ticket.Code,guestKey,new string('客',64),default);
        var initial=await host.Poll(ticket,true,default);
        Check(initial.Candidate==joined.Candidate&&!initial.Approved&&owner.Directory!.Members.Length==1,"short request cannot issue membership before local owner approval");
        var revealed=await host.Reveal(ticket,true,ownerKey,default);
        var guestState=await guest.Poll(joined,false,default);PairKeyExchange.ValidateState(joined,null,guestState,guestKey,false);
        guestState=await guest.Reveal(joined,false,guestKey,default);
        var ownerState=await host.Poll(ticket,true,default);PairKeyExchange.ValidateState(ticket,initial,ownerState,ownerKey,true);
        var hostShared=ownerKey.Derive(ownerState.GuestPublic,ownerState.GuestCommitment,ticket.Room,joined.Candidate,true);
        var guestShared=guestKey.Derive(guestState.HostPublic,joined.HostCommitment,joined.Room,joined.Candidate,false);
        Check(PairKeyExchange.Verification(hostShared)==PairKeyExchange.Verification(guestShared),"committed ECDH exchange yields matching human verification codes over actual router UDP I/O");
        var invitation=DirectInvitation.Issue(owner,[new(0,"203.0.113.42:44680")]);
        var encrypted=PairKeyExchange.EncryptInvitation(hostShared,invitation,ticket.Room,joined.Candidate);
        await host.Approve(ticket,joined.Candidate,encrypted,default);host.Dispose();
        try{await host.Create(ownerKey,"too soon",default);throw new Exception("lost pending authorization");}catch(IOException){Check(true,"new code cannot discard an approved credential before the guest receives it");}
        var approved=await guest.Poll(joined,false,default);PairKeyExchange.ValidateState(joined,guestState,approved,guestKey,false);
        var plain=PairKeyExchange.DecryptInvitation(guestShared,approved.Ciphertext,ticket.Room,joined.Candidate,DirectPairWire.MaximumCipher);
        Check(plain==invitation&&DirectInvitation.Import(plain).Mesh.Pair.DirectBootstrap,"bounded fragmented encrypted invitation survives local UI handle disposal and imports the signed direct network");
        Check(router.Status().Length==0,"pre-membership pairing frames never become business peers or virtual-IP traffic");
        CryptographicOperations.ZeroMemory(hostShared);CryptographicOperations.ZeroMemory(guestShared);
        await host.Create(ownerKey,"主机",default);
        try{await host.Poll(ticket,true,default);throw new Exception("accepted old room");}catch(IOException){Check(true,"generating another code invalidates the previous room and owner token");}
        var cancelledTicket=await host.Create(ownerKey,"主机",default);var cancelled=await guest.Join(cancelledTicket.Code,guestKey,"cancel",default);await guest.Finish(cancelled,false,default);
        Check((await host.Poll(cancelledTicket,true,default)).Outcome=="Cancelled","remote cancellation reaches the host without issuing membership");
        var rejectedTicket=await host.Create(ownerKey,"主机",default);var rejected=await guest.Join(rejectedTicket.Code,guestKey,"reject",default);await host.Finish(rejectedTicket,true,default);
        Check((await guest.Poll(rejected,false,default)).Outcome=="Rejected","local rejection reaches the requesting device");
        clock.Now=clock.Now.AddMinutes(6);Check(host.Handle(DirectPairWire.Encode(new DirectPairRequest(Guid.NewGuid().ToString("N"),"poll",rejected.Room,rejected.Token)))==null,"expired room responds to no remote request");
        var bounded=await host.Create(ownerKey,"host",default);int replies=0;
        for(int n=0;n<100;n++)if(host.Handle(DirectPairWire.Encode(new DirectPairRequest(Guid.NewGuid().ToString("N"),"join",Code:bounded.Code,Commitment:guestKey.Commitment,Name:"bounded")))!=null)replies++;
        Check(replies<=5,"unauthenticated requests have a global five-reply-per-second cap and one candidate");
        host.Clear();Check(host.Handle(DirectPairWire.Encode(new DirectPairRequest(Guid.NewGuid().ToString("N"),"join",Code:bounded.Code,Commitment:guestKey.Commitment,Name:"late")))==null,"closing host pairing removes the pre-membership surface");
        Console.WriteLine("PASS direct short pairing; real router sockets, no public NAT claim");
    }
}
