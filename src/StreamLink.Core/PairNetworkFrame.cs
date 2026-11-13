using System.Security.Cryptography;
using System.Text;

namespace StreamLink.Core;

// Public routing hint for the shared legacy receiver. This does not authenticate
// a sender; the destination router still verifies its own MeshLink AEAD/proofs.
public static class PairNetworkFrame
{
    public const int HeaderSize=20;
    public static bool IsFrame(ReadOnlySpan<byte> bytes)=>bytes.Length>=HeaderSize&&bytes[..4].SequenceEqual("CNW1"u8);
    public static byte[] Wrap(string network,ReadOnlySpan<byte> payload)
    {
        if(!Guid.TryParseExact(network,"N",out _))throw new ArgumentException("网络身份无效");
        var result=new byte[HeaderSize+payload.Length];"CNW1"u8.CopyTo(result);Convert.FromHexString(network).CopyTo(result,4);payload.CopyTo(result.AsSpan(HeaderSize));return result;
    }
    public static string Network(ReadOnlySpan<byte> bytes)=>IsFrame(bytes)?Convert.ToHexString(bytes.Slice(4,16)).ToLowerInvariant():"";
    public static bool Authenticated(MeshProfile mesh,ReadOnlySpan<byte> bytes)
    {
        if(!IsFrame(bytes)||Network(bytes)!=mesh.Pair.Network)return false;
        var frame=bytes[HeaderSize..];if(MeshEntryHandshake.IsFrame(frame))return MeshEntryHandshake.Authenticated(mesh,frame);
        if(frame.Length is <MeshLink.Overhead or >MeshLink.Overhead+MeshLink.Mtu||!frame[..4].SequenceEqual("SLM4"u8)||frame[6]!=mesh.Self.Slot||frame[4] is <1 or >9)return false;
        if(frame[7]!=0&&(!TransportModes.Stream(mesh.Pair.Mode)||frame[7]>3||frame[4]!=4))return false;
        int sourceSlot=frame[5];var member=mesh.Directory?.Members.FirstOrDefault(m=>m.Slot==sourceSlot);if(member==null||member.Slot==mesh.Self.Slot)return false;
        byte[]? secret=null,session=null;
        try{
            secret=MeshIdentity.SharedKey(mesh,member);session=HKDF.DeriveKey(HashAlgorithmName.SHA256,secret,32,frame.Slice(8,16).ToArray(),Encoding.ASCII.GetBytes(MeshLink.KeyContext(frame[5],frame[6],frame[7])));
            Span<byte> nonce=stackalloc byte[12];nonce.Clear();frame.Slice(40,8).CopyTo(nonce[4..]);
            int count=frame.Length-MeshLink.Overhead;Span<byte> plain=stackalloc byte[count];
            using var cipher=new AesGcm(session,16);cipher.Decrypt(nonce,frame.Slice(MeshLink.HeaderSize,count),frame.Slice(MeshLink.HeaderSize+count,16),plain,frame[..MeshLink.HeaderSize]);return true;
        }catch(Exception ex)when(ex is CryptographicException or FormatException or ArgumentException){return false;}
        finally{if(secret!=null)CryptographicOperations.ZeroMemory(secret);if(session!=null)CryptographicOperations.ZeroMemory(session);}
    }
}
