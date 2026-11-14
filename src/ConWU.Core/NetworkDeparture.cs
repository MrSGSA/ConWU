using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace StreamLink.Core;

// A member can revoke only its own, owner-certified slot. Slots are never
// reused, so a delayed/replayed departure cannot remove a later enrollment.
public sealed record NetworkDeparture(
    [property:JsonPropertyName("n")] string Network,
    [property:JsonPropertyName("m")] MeshMember Member,
    [property:JsonPropertyName("r")] string Nonce,
    [property:JsonPropertyName("s")] string Signature)
{
    static byte[] Signed(string owner,NetworkDeparture value)=>JsonSerializer.SerializeToUtf8Bytes(new{domain="conwu-member-departure-v1",owner,value.Network,value.Member,value.Nonce});
    public static NetworkDeparture Create(MeshProfile guest)
    {
        guest.Validate();if(guest.IsOwner||guest.IsDecentralized)throw new IOException("仅从机可以发送本人退出通知");
        var value=new NetworkDeparture(guest.Pair.Network,guest.Self,Guid.NewGuid().ToString("N"),"");
        return value with{Signature=MeshIdentity.Sign(guest.SigningPrivate,Signed(guest.OwnerKey,value))};
    }
    public void Validate(string owner)
    {
        if(!Guid.TryParseExact(Network,"N",out _)||!Guid.TryParseExact(Nonce,"N",out _)||Member is not {Slot:>1}||Signature is not {Length:>=80 and <=104})throw new CryptographicException("退出通知无效");
        MeshIdentity.ValidateMember(Network,owner,Member);
        if(!MeshIdentity.Verify(Member.SigningKey,Signed(owner,this),Signature))throw new CryptographicException("退出通知签名无效");
    }
    public override string ToString()=>"NetworkDeparture (identity omitted)";
}

public sealed record NetworkDepartureReceipt(string Network,string Nonce,int Slot,long Revision,string Signature)
{
    static byte[] Signed(NetworkDepartureReceipt value)=>JsonSerializer.SerializeToUtf8Bytes(new{domain="conwu-member-departure-receipt-v1",value.Network,value.Nonce,value.Slot,value.Revision});
    public static NetworkDepartureReceipt Create(MeshProfile owner,NetworkDeparture notice)
    {
        if(!owner.IsOwner||owner.Pair.Network!=notice.Network||owner.Directory!.Members.Any(m=>m.Slot==notice.Member.Slot))throw new CryptographicException("主机尚未移除此成员");
        var value=new NetworkDepartureReceipt(notice.Network,notice.Nonce,notice.Member.Slot,owner.Directory.Revision,"");
        return value with{Signature=MeshIdentity.Sign(owner.OwnerPrivate,Signed(value))};
    }
    public void Validate(string owner,NetworkDeparture notice)
    {
        if(Network!=notice.Network||Nonce!=notice.Nonce||Slot!=notice.Member.Slot||Revision<1||!MeshIdentity.Verify(owner,Signed(this),Signature))throw new CryptographicException("主机退出回执无效");
    }
}
