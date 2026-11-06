using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

// A network entry is only a hint until the responder proves current membership.
// The proof selects a member; it never authorizes forwarding another peer's data.
public static class MeshEntryHandshake
{
    public sealed record Message(string Network,int Slot,string Device,string Nonce,long Issued,string ReplyTo,string Signature);
    public static bool IsFrame(ReadOnlySpan<byte> bytes)=>bytes.Length is >=8 and <=1536&&bytes[..4].SequenceEqual("SLE1"u8);
    static byte[] Signed(Message m)=>JsonSerializer.SerializeToUtf8Bytes(new{domain="streamlink-network-entry-v1",m.Network,m.Slot,m.Device,m.Nonce,m.Issued,m.ReplyTo});
    static byte[] Encode(Message m)=>"SLE1"u8.ToArray().Concat(JsonSerializer.SerializeToUtf8Bytes(m)).ToArray();
    static Message Sign(MeshProfile mesh,string nonce,string replyTo) {
        var m=new Message(mesh.Pair.Network,mesh.Self.Slot,mesh.Self.Device,nonce,DateTimeOffset.UtcNow.ToUnixTimeSeconds(),replyTo,"");
        return m with{Signature=MeshIdentity.Sign(mesh.SigningPrivate,Signed(m))};
    }
    public static (string Nonce,byte[] Frame) Request(MeshProfile mesh) {
        string nonce=Convert.ToHexString(RandomNumberGenerator.GetBytes(24));return(nonce,Encode(Sign(mesh,nonce,"")));
    }
    static Message? Read(MeshProfile mesh,ReadOnlySpan<byte> bytes) {
        if(!IsFrame(bytes))return null;
        try {
            var m=JsonSerializer.Deserialize<Message>(bytes[4..]);
            if(m==null||m.Network!=mesh.Pair.Network||m.Nonce is not {Length:48}||!m.Nonce.All(char.IsAsciiHexDigit)||
                m.Signature is not {Length:>0 and <=256}||m.ReplyTo is not {Length:0 or 32}||Math.Abs((decimal)m.Issued-DateTimeOffset.UtcNow.ToUnixTimeSeconds())>30)return null;
            var member=mesh.Directory?.Members.FirstOrDefault(x=>x.Slot==m.Slot&&x.Device==m.Device);
            return member!=null&&MeshIdentity.Verify(member.SigningKey,Signed(m),m.Signature)?m:null;
        }catch(Exception ex)when(ex is JsonException or FormatException or CryptographicException){return null;}
    }
    public static byte[]? Reply(MeshProfile mesh,ReadOnlySpan<byte> bytes) {
        var request=Read(mesh,bytes);return request is {ReplyTo.Length:0}&&request.Device!=mesh.Self.Device?Encode(Sign(mesh,request.Nonce,request.Device)):null;
    }
    public static int VerifyReply(MeshProfile mesh,string nonce,ReadOnlySpan<byte> bytes) {
        var reply=Read(mesh,bytes);return reply!=null&&reply.Nonce==nonce&&reply.ReplyTo==mesh.Self.Device&&reply.Device!=mesh.Self.Device?reply.Slot:0;
    }
}
