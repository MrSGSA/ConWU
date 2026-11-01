using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

// An invitation is an explicit per-device authorization. Treat the whole code
// as a credential. It carries no administrator key and is never logged.
public sealed record DirectInvitation(MeshEnrollment Enrollment, MeshDirectory Directory, ExistingEntry[] Entries, string Signature)
{
    public const int MaximumCode = 32768;
    static byte[] Signed(DirectInvitation value) => JsonSerializer.SerializeToUtf8Bytes(new {domain="streamlink-direct-invitation-v1",value.Enrollment,value.Directory,value.Entries});
    public static string Issue(MeshProfile owner, ExistingEntry[] entries)
    {
        if(!owner.Pair.Direct)throw new IOException("当前网络使用服务器配对，请使用六位配对码");
        entries=entries.Where(e=>e.PeerSlot==0).Select(e=>e with{PeerSlot=1}).ToArray();
        ExistingEntryResolver.Validate(entries);
        if(entries.Length==0)throw new IOException("请先在设置中填写本机可供其他设备连接的入口");
        var enrollment=MeshIdentity.Issue(owner);
        var invite=new DirectInvitation(enrollment,owner.Directory!,entries,"");
        var code="SL5."+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(invite with {Signature=MeshIdentity.Sign(owner.OwnerPrivate,Signed(invite))}));
        if(code.Length>MaximumCode)throw new FormatException("直连邀请过长，请减少入口来源");
        return code;
    }
    public static (MeshProfile Mesh,ExistingEntry[] Entries,long Expires) Import(string code)
    {
        if(code is null||!code.StartsWith("SL5.")||code.Length>MaximumCode)throw new FormatException("直连邀请格式无效");
        DirectInvitation ticket;
        try {ticket=JsonSerializer.Deserialize<DirectInvitation>(Convert.FromBase64String(code[4..]))??throw new FormatException("直连邀请为空");}
        catch(JsonException){throw new FormatException("直连邀请内容无效");}
        if(ticket.Enrollment?.Pair?.Direct!=true||ticket.Directory==null||ticket.Entries is not {Length:>0}||
            !MeshIdentity.Verify(ticket.Enrollment.OwnerKey,Signed(ticket),ticket.Signature))throw new CryptographicException("直连邀请签名无效");
        var mesh=MeshIdentity.Import(MeshIdentity.Export(ticket.Enrollment));
        MeshIdentity.ValidateDirectory(ticket.Directory,mesh.Pair.Network,mesh.OwnerKey);
        if(!ticket.Directory.Members.Contains(mesh.Self)||mesh.Self.Slot==1)throw new CryptographicException("邀请不包含有效成员授权");
        ExistingEntryResolver.Validate(ticket.Entries);
        if(ticket.Entries.Any(e=>e.PeerSlot!=1))throw new FormatException("直连邀请入口必须属于主机");
        mesh.Directory=ticket.Directory;return(mesh,ticket.Entries,ticket.Enrollment.Expires);
    }
}
