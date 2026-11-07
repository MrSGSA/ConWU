using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace StreamLink.Core;

// Binds the persistent device identity to the committed ephemeral pairing key.
// The proof is public. Its signing key remains in the device's protected store.
public sealed record NodeIdentityProof(string PublicKey,string Signature)
{
    [JsonIgnore] public string DeviceId=>MeshIdentity.NetworkId(PublicKey);
    static byte[] Data(string publicKey,string commitment)=>JsonSerializer.SerializeToUtf8Bytes(new{domain="conwu-node-pairing-v1",publicKey,commitment});
    public static NodeIdentityProof Create(string signingPrivate,string commitment)
    {
        string key=MeshIdentity.PublicSigning(signingPrivate);return new(key,MeshIdentity.Sign(signingPrivate,Data(key,commitment)));
    }
    public static bool Valid(NodeIdentityProof? proof,string commitment)=>proof is {PublicKey.Length:>0 and <=180,Signature.Length:>0 and <=128}&&PairKeyExchange.ValidCommitment(commitment)&&MeshIdentity.Verify(proof.PublicKey,Data(proof.PublicKey,commitment),proof.Signature);
    public static string Fingerprint(NodeIdentityProof proof)=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(proof)));
    public static string GeneratePrivate(){using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);return Convert.ToBase64String(key.ExportPkcs8PrivateKey());}
}
