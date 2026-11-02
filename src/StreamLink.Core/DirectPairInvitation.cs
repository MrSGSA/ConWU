using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

// An application capability, not a member enrollment. Approval must issue
// separate device credentials after the committed key exchange and SAS check.
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record DirectPairInvitation(string Network,string OwnerKey,string Mode,string Room,string HostCommitment,
    string Capability,long Expires,ExistingEntry[] Entries,string Signature)
{
    public const int MaximumCode=32768;
    static byte[] Signed(DirectPairInvitation v)=>JsonSerializer.SerializeToUtf8Bytes(new{domain="streamlink-approval-invitation-v1",v.Network,v.OwnerKey,v.Mode,v.Room,v.HostCommitment,v.Capability,v.Expires,v.Entries});
    public static string Issue(MeshProfile owner,ExistingEntry[] entries,PairRoomTicket room,string capability)
    {
        if(!owner.IsOwner||!owner.Pair.Direct)throw new IOException("只有无服务器网络的创建者可以生成直连邀请");
        var sources=entries.Where(e=>e.PeerSlot==0).Select(e=>e with{PeerSlot=1}).ToArray();
        var invitation=new DirectPairInvitation(owner.Pair.Network,owner.OwnerKey,owner.Pair.Mode,room.Room,room.HostCommitment,capability,room.Expires,sources,"");
        invitation=invitation with{Signature=MeshIdentity.Sign(owner.OwnerPrivate,Signed(invitation))};
        var code="SL6."+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(invitation));
        Import(code);return code;
    }
    public static DirectPairInvitation Import(string code)
    {
        if(code is null||!code.StartsWith("SL6.")||code.Length>MaximumCode)throw new FormatException("请使用新版主机生成的 SL6. 直连邀请；旧版预授权邀请需要重新生成");
        DirectPairInvitation v;
        try{v=JsonSerializer.Deserialize<DirectPairInvitation>(Convert.FromBase64String(code[4..]))??throw new FormatException("直连邀请为空");}
        catch(JsonException){throw new FormatException("直连邀请内容无效");}
        if(v.Network is not {Length:32}||v.OwnerKey is not {Length:>0 and <=512}||v.Signature is not {Length:>0 and <=512}||
            v.Mode is not ("faketcp" or "udp")||!Guid.TryParseExact(v.Room,"N",out _)||
            !PairKeyExchange.ValidCommitment(v.HostCommitment)||v.Capability is not {Length:64}||!v.Capability.All(char.IsAsciiHexDigit)||
            v.Expires<=DateTimeOffset.UtcNow.ToUnixTimeSeconds()||v.Expires>DateTimeOffset.UtcNow.AddMinutes(6).ToUnixTimeSeconds()||
            v.Entries is not {Length:>0 and <=12})throw new FormatException("直连邀请无效或已过期，请主机重新生成");
        if(MeshIdentity.NetworkId(v.OwnerKey)!=v.Network||!MeshIdentity.Verify(v.OwnerKey,Signed(v),v.Signature))throw new CryptographicException("直连邀请签名无效");
        ExistingEntryResolver.Validate(v.Entries);
        if(v.Entries.Any(e=>e.PeerSlot!=1))throw new FormatException("直连邀请入口必须属于主机");
        return v;
    }
}
