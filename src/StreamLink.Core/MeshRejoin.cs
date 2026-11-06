using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

// Kept only in the protected local profile after an explicit guest departure.
// This is proof of the former membership, never an automatic admission grant.
public sealed record MeshRejoinCredential(string Network, string OwnerKey, MeshMember Member, string SigningPrivate)
{
    public MeshDirectory? Directory {get;init;}
    public void Validate()
    {
        if (Member is null || Member.Slot == 1 && Directory?.Governance == null || SigningPrivate is not { Length: > 0 and <= 512 })
            throw new FormatException("重新加入凭据无效");
        MeshIdentity.ValidateMember(Network, OwnerKey, Member, Directory);
        if (MeshIdentity.PublicSigning(SigningPrivate) != Member.SigningKey)
            throw new CryptographicException("重新加入凭据不匹配");
    }
}

public sealed record MeshRejoinProof(string Network, int Slot, string Device, long Expires, string Signature);
// Public former credentials only. This bounded owner-local journal lets an
// applicant recover after approval delivery was lost or the owner restarted.
// An explicit owner revocation removes every journal link to that member.
public sealed record MeshRejoinHistory(string Network,MeshMember Former,int CurrentSlot);

public static class MeshRejoin
{
    public static string Fingerprint(MeshRejoinProof proof)=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(proof)));
    static byte[] Data(MeshRejoinProof proof,string code,string commitment) => JsonSerializer.SerializeToUtf8Bytes(new {
        domain = "streamlink-member-rejoin-v1", proof.Network, proof.Slot, proof.Device,
        commitment, locator=Locator(code), proof.Expires
    });
    static string Locator(string code) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code)));

    public static MeshRejoinCredential? Retain(MeshProfile? profile) => profile != null && (!profile.IsOwner || profile.IsDecentralized)
        ? new(profile.Pair.Network, profile.OwnerKey, profile.Self, profile.SigningPrivate) {Directory=profile.IsDecentralized?profile.Directory:null} : null;

    public static MeshRejoinProof? Create(MeshRejoinCredential? credential, string code, PairKeyExchange key)
    {
        if (credential == null) return null;
        credential.Validate();
        var proof = new MeshRejoinProof(credential.Network, credential.Member.Slot, credential.Member.Device,
            DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(), "");
        return proof with { Signature = MeshIdentity.Sign(credential.SigningPrivate, Data(proof,code,key.Commitment)) };
    }

    public static bool WellFormed(MeshRejoinProof proof) =>
        Guid.TryParseExact(proof.Network, "N", out _) && proof.Slot is >= 1 and <= 254 &&
        Guid.TryParseExact(proof.Device, "N", out _) && proof.Signature is { Length: > 0 and <= 128 };

    public static MeshMember? Resolve(MeshProfile owner, MeshRejoinProof? proof, string code, string commitment,IEnumerable<MeshRejoinHistory>? history=null)
    {
        if (proof == null || proof.Network != owner.Pair.Network) return null;
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (!WellFormed(proof) || proof.Slot==owner.Self.Slot || proof.Slot==1&&!owner.IsDecentralized || !PairKeyExchange.ValidCommitment(commitment) ||
            proof.Expires <= now || proof.Expires > now + 360)
            throw new CryptographicException("重新加入证明无效，请重新申请");
        var member = owner.Directory?.Members.FirstOrDefault(m => m.Slot == proof.Slot && m.Device == proof.Device);
        var signingMember=member;
        if(member==null&&owner.Directory?.Governance!=null&&MeshGovernance.RejoinLineage(owner.Directory,proof.Slot,proof.Device) is {} lineage){
            member=lineage.Current;signingMember=lineage.Former;
        }
        if(member==null&&history!=null){
            var retained=history.LastOrDefault(h=>h.Network==proof.Network&&h.Former.Slot==proof.Slot&&h.Former.Device==proof.Device);
            if(retained!=null){
                MeshIdentity.ValidateMember(owner.Pair.Network,owner.OwnerKey,retained.Former,owner.Directory);
                member=owner.Directory?.Members.FirstOrDefault(m=>m.Slot==retained.CurrentSlot&&m.Slot!=owner.Self.Slot);
                signingMember=retained.Former;
            }
        }
        // An already removed membership cannot replace another member or reclaim
        // its address. The normal owner-approved admission remains available.
        if (member == null) return null;
        if (!MeshIdentity.Verify(signingMember!.SigningKey, Data(proof,code,commitment), proof.Signature))
            throw new CryptographicException("重新加入证明签名不符，请重新申请");
        return member;
    }

    public static MeshRejoinHistory[] Remember(MeshProfile owner,IEnumerable<MeshRejoinHistory> history,MeshMember former,MeshMember current)
        => history.Where(h=>h.Network==owner.Pair.Network)
            .Select(h=>h.CurrentSlot==former.Slot?h with{CurrentSlot=current.Slot}:h)
            .Append(new(owner.Pair.Network,former,current.Slot))
            .Where(h=>owner.Directory!.Members.Any(m=>m.Slot==h.CurrentSlot))
            .TakeLast(32).ToArray();
}
