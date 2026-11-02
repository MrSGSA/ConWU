using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    static void RejoinIdentity()
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp","10.171.139.1");
        var original=Guest(owner);original.Directory=owner.Directory;
        var other=Guest(owner);other.Directory=owner.Directory;
        var credential=MeshRejoin.Retain(original)!;credential.Validate();
        using var key=new PairKeyExchange();
        var proof=MeshRejoin.Create(credential,"123456",key)!;
        Check(MeshRejoin.Resolve(owner,proof,"123456",key.Commitment)==original.Self,"rejoin associates the original signed identity, not a name or endpoint");
        void RejectProof(MeshRejoinProof p,string code,string commitment){bool rejected=false;try{MeshRejoin.Resolve(owner,p,code,commitment);}catch(CryptographicException){rejected=true;}Check(rejected,"rejoin tampering, expiry and transcript substitution rejected");}
        RejectProof(proof,"654321",key.Commitment);
        using(var replacementKey=new PairKeyExchange())RejectProof(proof,"123456",replacementKey.Commitment);
        RejectProof(proof with{Slot=other.Self.Slot,Device=other.Self.Device},"123456",key.Commitment);
        RejectProof(proof with{Expires=DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds()},"123456",key.Commitment);
        RejectProof(proof with{Signature=Convert.ToBase64String(new byte[64])},"123456",key.Commitment);
        string previousIp=original.LocalIp;var oldDirectory=owner.Directory!;
        var next=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Replace(owner,original.Self,previousIp)));
        Check(owner.Directory!.Members.Length==3&&!owner.Directory.Members.Contains(original.Self)&&owner.Directory.Members.Contains(other.Self),"approved rejoin replaces only the proven old member and preserves unrelated devices");
        Check(next.LocalIp==previousIp&&next.Self.Slot>original.Self.Slot&&next.Self.SigningKey!=original.Self.SigningKey,"rejoin preserves the virtual IP but rotates slot and authentication keys");
        Check(MeshRejoin.Resolve(owner,proof,"123456",key.Commitment)==null,"old proof cannot replace a newly approved identity");
        var history=MeshRejoin.Remember(owner,[],original.Self,next.Self);
        Check(MeshRejoin.Resolve(owner,proof,"123456",key.Commitment,history)==next.Self,"owner journal recovers a lost approval delivery without adding another member");
        MeshIdentity.ValidateDirectory(owner.Directory,owner.Pair.Network,owner.OwnerKey,oldDirectory.Revision);
        Check(owner.Directory.ReservedAddresses!.Contains(previousIp),"replacement keeps signed address history");
        for(int round=0;round<5;round++){
            var prior=next;using var joinKey=new PairKeyExchange();
            var claim=MeshRejoin.Create(MeshRejoin.Retain(prior),"654321",joinKey)!;
            var matched=MeshRejoin.Resolve(owner,claim,"654321",joinKey.Commitment)!;
            next=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Replace(owner,matched)));
            history=MeshRejoin.Remember(owner,history,prior.Self,next.Self);
            Check(owner.Directory.Members.Length==3&&next.LocalIp==previousIp,"repeated rejoin does not consume member capacity or another virtual IP");
        }
        while(owner.Directory.Members.Length<MeshIdentity.MaxMembers)Guest(owner);
        var replacedAtCapacity=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Replace(owner,next.Self)));
        history=MeshRejoin.Remember(owner,history,next.Self,replacedAtCapacity.Self);
        Check(owner.Directory.Members.Length==MeshIdentity.MaxMembers&&replacedAtCapacity.LocalIp==previousIp,"an approved replacement works at full member capacity");
        var savedOwner=new DeviceProfile{Mesh=owner,RejoinHistory=history};savedOwner.Validate();
        var restored=ProfileChanges.Copy(savedOwner);
        Check(MeshRejoin.Resolve(restored.Mesh!,proof,"123456",key.Commitment,restored.RejoinHistory)==replacedAtCapacity.Self,"protected profile roundtrip preserves old-proof recovery after owner restart");
        MeshIdentity.Revoke(owner,replacedAtCapacity.Self.Slot);
        Check(MeshRejoin.Resolve(owner,proof,"123456",key.Commitment,history)==null,"explicit revocation cannot be bypassed through the owner recovery journal");
        var profile=new DeviceProfile{RejoinCredential=credential};
        Check(!SensitiveText.Redact("old="+credential.SigningPrivate,profile).Contains(credential.SigningPrivate),"retained proof credential is redacted after departure");
        Check(MeshRejoin.Retain(owner)==null,"administrator key is never retained as a guest rejoin credential");
        var state=new PairRoomState(Guid.NewGuid().ToString("N"),key.Commitment,new string('机',64),key.PublicKey,key.PublicKey,"",false,DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()){Addressing=1,Rejoin=proof};
        foreach(string name in new[]{new string('机',64),new string('\uE000',64)}){
            var response=DirectPairWire.ForGuest(state with{GuestName=name,RequestedIp="192.168.255.254"});
            Check(response.Rejoin==null&&response.RejoinDigest==MeshRejoin.Fingerprint(proof)&&DirectPairWire.Encode(new DirectPairReply(Guid.NewGuid().ToString("N"),State:response)).Length<=DirectPairWire.MaximumDatagram,"rejoin acknowledgement and maximum UTF-8 or escaped device name fit the bounded direct-pair datagram");
        }
    }
}
