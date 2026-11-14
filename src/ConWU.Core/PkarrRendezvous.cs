using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record PkarrPeerBinding(string Network,int Slot,string Device,string SigningKey,string Source);
public sealed record PkarrPeerState(Guid Boot,Guid AcknowledgedBoot,long ObservedAt,long Expires,string Name)
{
    public Guid Entry {get;init;}
    public Guid AcknowledgedEntry {get;init;}
}
public sealed record PkarrPeerObservation(string Source,PkarrPeerState State,long ReceivedAt);

// An optional backwards-compatible extension to an address record. It is small,
// pair-specific and encrypted; it carries no enrollment or business traffic.
public static class PkarrRendezvous
{
    static readonly UTF8Encoding Utf8=new(false,true);
    public static string MemberSeed(MeshProfile member)
    {
        byte[] input=Convert.FromBase64String(member.SigningPrivate),output=new byte[32];
        try{HKDF.DeriveKey(HashAlgorithmName.SHA256,input,output,Encoding.ASCII.GetBytes(member.Pair.Network),"conwu-pkarr-member-source-v1"u8);return Convert.ToBase64String(output);}
        finally{CryptographicOperations.ZeroMemory(input);CryptographicOperations.ZeroMemory(output);}
    }
    static byte[] Key(MeshProfile local,MeshMember peer,int sender)
    {
        byte[] shared=MeshIdentity.SharedKey(local,peer),key=new byte[32];
        try{HKDF.DeriveKey(HashAlgorithmName.SHA256,shared,key,Encoding.ASCII.GetBytes(local.Pair.Network),Encoding.ASCII.GetBytes("conwu-pkarr-state-v1/"+sender));return key;}
        finally{CryptographicOperations.ZeroMemory(shared);}
    }
    static byte[] Aad(string network,int sender,string source,PkarrAnnouncement record)=>JsonSerializer.SerializeToUtf8Bytes(new{domain="conwu-pkarr-state-v1",network,sender,source,record.Mode,record.Expires,record.Endpoints});
    public static Guid EntryId(string source,PkarrAnnouncement record,Guid boot)=>new(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new{domain="conwu-pkarr-entry-v1",source,boot,record.Mode,record.Endpoints})).AsSpan(0,16));
    public static string Seal(MeshProfile local,MeshMember peer,string source,PkarrAnnouncement record,PkarrPeerState state)
    {
        state=state with{Entry=EntryId(source,record,state.Boot)};
        Validate(state,DateTimeOffset.UtcNow.ToUnixTimeSeconds());PkarrPacket.KeyFromSource(source);
        using var stream=new MemoryStream();using(var writer=new BinaryWriter(stream,Utf8,true)){
            writer.Write((byte)1);writer.Write(state.Boot.ToByteArray());writer.Write(state.AcknowledgedBoot.ToByteArray());writer.Write(state.Entry.ToByteArray());writer.Write(state.AcknowledgedEntry.ToByteArray());writer.Write(state.ObservedAt);writer.Write(state.Expires);
            byte[] name=Utf8.GetBytes(state.Name);writer.Write((ushort)name.Length);writer.Write(name);
        }
        byte[] plain=stream.ToArray(),wire=new byte[28+plain.Length],key=Key(local,peer,local.Self.Slot);RandomNumberGenerator.Fill(wire.AsSpan(0,12));
        try{using var aes=new AesGcm(key,16);aes.Encrypt(wire.AsSpan(0,12),plain,wire.AsSpan(28),wire.AsSpan(12,16),Aad(local.Pair.Network,local.Self.Slot,source,record));return Convert.ToBase64String(wire);}
        finally{CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(plain);}
    }
    public static PkarrPeerState Open(MeshProfile local,MeshMember peer,string source,PkarrAnnouncement record)
    {
        if(record.State is not {Length:>0 and <=512})throw new FormatException("PKARR 对端状态缺失或过大");
        byte[] wire=Convert.FromBase64String(record.State);if(wire.Length is <111 or >367)throw new FormatException("PKARR 对端状态长度无效");
        byte[] plain=new byte[wire.Length-28],key=Key(local,peer,peer.Slot);
        try{
            using var aes=new AesGcm(key,16);aes.Decrypt(wire.AsSpan(0,12),wire.AsSpan(28),wire.AsSpan(12,16),plain,Aad(local.Pair.Network,peer.Slot,source,record));
            using var stream=new MemoryStream(plain,false);using var reader=new BinaryReader(stream,Utf8);
            if(reader.ReadByte()!=1)throw new FormatException("PKARR 对端状态版本不支持");
            var boot=new Guid(reader.ReadBytes(16));var acknowledged=new Guid(reader.ReadBytes(16));var entry=new Guid(reader.ReadBytes(16));var acknowledgedEntry=new Guid(reader.ReadBytes(16));long observed=reader.ReadInt64(),expires=reader.ReadInt64();int length=reader.ReadUInt16();
            if(length>256||stream.Length-stream.Position!=length)throw new FormatException("PKARR 对端名称长度无效");
            var state=new PkarrPeerState(boot,acknowledged,observed,expires,Utf8.GetString(reader.ReadBytes(length))){Entry=entry,AcknowledgedEntry=acknowledgedEntry};Validate(state,DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            if(entry!=EntryId(source,record,boot))throw new CryptographicException("PKARR 状态与入口版本不符");return state;
        }finally{CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(plain);}
    }
    static void Validate(PkarrPeerState value,long now)
    {
        if(value.Boot==Guid.Empty||value.Entry==Guid.Empty||value.ObservedAt<=0||value.ObservedAt>now+5||value.Expires<=now||value.Expires>value.ObservedAt+180||value.Name is not {Length:>0 and <=64}||value.Name.Any(char.IsControl))throw new FormatException("PKARR 对端状态已过期或无效");
    }
    public static bool Uses(DeviceProfile profile)=>!profile.UsesExistingEntriesOnly&&profile.Mesh is {Pair.Direct:true}&&profile.SavedNetworkSettings?.DiscoveryMode=="pkarr";
    public static bool Matches(PkarrPeerBinding binding,MeshProfile mesh)=>binding.Network==mesh.Pair.Network&&mesh.Directory?.Members.Any(m=>m.Slot!=mesh.Self.Slot&&m.Slot==binding.Slot&&m.Device==binding.Device&&m.SigningKey==binding.SigningKey)==true;
}
