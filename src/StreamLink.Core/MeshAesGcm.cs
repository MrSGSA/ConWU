using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace StreamLink.Core;

// Android's native .NET cipher aborts on an empty input pointer. SLM4's
// authenticated Hello/Ack records intentionally have no payload. Their GCM tag
// is exactly GMAC over the header; keep the wire format and native bulk cipher.
internal sealed class MeshAesGcm : IDisposable
{
    readonly AesGcm native;
    readonly byte[]? emptyKey;
    public MeshAesGcm(byte[] key,bool? managedEmpty=null)
    {native=new(key,16);if(managedEmpty??OperatingSystem.IsAndroid())emptyKey=key.ToArray();}
    void EmptyTag(ReadOnlySpan<byte> nonce,ReadOnlySpan<byte> aad,Span<byte> tag)
    {
        if(nonce.Length!=12||tag.Length!=16)throw new ArgumentException("Invalid mesh AEAD nonce or tag length");
        var mac=new GMac(new GcmBlockCipher(new AesEngine()),128);
        mac.Init(new ParametersWithIV(new KeyParameter(emptyKey!),nonce.ToArray()));
        byte[] header=aad.ToArray(),output=new byte[16];
        mac.BlockUpdate(header,0,header.Length);mac.DoFinal(output,0);output.CopyTo(tag);
    }
    public void Encrypt(ReadOnlySpan<byte> nonce,ReadOnlySpan<byte> plain,Span<byte> cipher,Span<byte> tag,ReadOnlySpan<byte> aad)
    {
        if(emptyKey!=null&&plain.Length==0){if(cipher.Length!=0)throw new ArgumentException("AEAD length mismatch");EmptyTag(nonce,aad,tag);}
        else native.Encrypt(nonce,plain,cipher,tag,aad);
    }
    public void Decrypt(ReadOnlySpan<byte> nonce,ReadOnlySpan<byte> cipher,ReadOnlySpan<byte> tag,Span<byte> plain,ReadOnlySpan<byte> aad)
    {
        if(emptyKey!=null&&cipher.Length==0){
            if(plain.Length!=0)throw new ArgumentException("AEAD length mismatch");
            Span<byte> expected=stackalloc byte[16];EmptyTag(nonce,aad,expected);
            if(!CryptographicOperations.FixedTimeEquals(expected,tag))throw new AuthenticationTagMismatchException();
        }else native.Decrypt(nonce,cipher,tag,plain,aad);
    }
    public void Dispose(){native.Dispose();if(emptyKey!=null)CryptographicOperations.ZeroMemory(emptyKey);}
}
