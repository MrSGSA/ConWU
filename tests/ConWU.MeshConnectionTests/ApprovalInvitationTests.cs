using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task ApprovalInvitations()
    {
        using var host=new DirectPairHost();using var hostKey=new PairKeyExchange();using var guestKey=new PairKeyExchange();
        var owner=MeshIdentity.Create("","","faketcp",direct:true);
        var before=JsonSerializer.Serialize(owner);
        var room=await host.CreateInvitation(hostKey,"Approval Host",default);
        var code=DirectPairInvitation.Issue(owner,[new(0,"https://entry.example.com/subscribe#streamlink")],room.Ticket,room.Capability);
        var offer=DirectPairInvitation.Import(code);
        Check(JsonSerializer.Serialize(owner)==before&&owner.Directory!.Members.Length==1,"generating an approval invitation never issues membership or changes the directory");
        var payload=System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(code[4..]));
        foreach(var secret in new[]{owner.OwnerPrivate,owner.SigningPrivate,owner.ExchangePrivate,owner.Pair.Secret})Check(!payload.Contains(secret),"approval invitation excludes existing private/business keys");
        Check(offer.Entries.Single().PeerSlot==1&&offer.HostCommitment==hostKey.Commitment,"invitation binds host commitment, network, protocol and host entry");
        void Reject(DirectPairInvitation changed){try{DirectPairInvitation.Import("SL6."+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(changed)));throw new Exception("tampered invitation accepted");}catch(Exception ex)when(ex is CryptographicException or FormatException or ArgumentException){Check(true,"altered invitation rejected");}}
        Reject(offer with{Mode="udp"});Reject(offer with{Expires=1});Reject(offer with{Entries=[new(1,"203.0.113.99:99")]});Reject(offer with{HostCommitment=guestKey.Commitment});Reject(offer with{Capability=new string('0',64)});
        await using var router=new MeshRouter(owner,new MemoryAdapter()){DirectPairing=host.Handle};
        using var client=new DirectPairClient(_=>new PairTransport(router.LocalEndpoint));
        // An invitation room accepts its random capability, never its legacy short code.
        var denied=host.Handle(DirectPairWire.Encode(new DirectPairRequest(Guid.NewGuid().ToString("N"),"join",Code:room.Ticket.Code,Commitment:guestKey.Commitment,Name:"wrong code")));
        Check(denied!=null&&DirectPairWire.Decode<DirectPairReply>(denied).Error.Length>0,"six digits cannot enter a capability-only invitation room");
        var joined=await client.Join(offer.Capability,guestKey,"Approval Guest",default);
        var state=await host.Poll(room.Ticket,true,default);
        Check(!state.Approved&&state.Ciphertext.Length==0&&owner.Directory!.Members.Length==1,"applicant remains pending without member keys before owner approval");
        await host.Reveal(room.Ticket,true,hostKey,default);await client.Reveal(joined,false,guestKey,default);
        state=await host.Poll(room.Ticket,true,default);
        var a=hostKey.Derive(state.GuestPublic,state.GuestCommitment,joined.Room,joined.Candidate,true);
        var b=guestKey.Derive(hostKey.PublicKey,joined.HostCommitment,joined.Room,joined.Candidate,false);
        Check(PairKeyExchange.Verification(a)==PairKeyExchange.Verification(b),"approval invitation authenticates the pending exchange over real local router sockets");
        var enrollment=DirectInvitation.Issue(owner,[new(0,"203.0.113.42:44680")]);
        await host.Approve(room.Ticket,joined.Candidate,PairKeyExchange.EncryptInvitation(a,enrollment,joined.Room,joined.Candidate),default);
        var approved=await client.Poll(joined,false,default);
        var imported=DirectInvitation.Import(PairKeyExchange.DecryptInvitation(b,approved.Ciphertext,joined.Room,joined.Candidate,DirectPairWire.MaximumCipher));
        Check(imported.Mesh.Pair.Network==offer.Network&&imported.Mesh.OwnerKey==offer.OwnerKey&&owner.Directory!.Members.Length==2,"member credentials are delivered only after explicit owner approval");
        CryptographicOperations.ZeroMemory(a);CryptographicOperations.ZeroMemory(b);
    }
}
