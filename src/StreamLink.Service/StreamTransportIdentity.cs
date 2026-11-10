using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StreamLink.Core;

namespace StreamLink.Service;

// Stable per-device key; DPAPI on Windows and private files on Linux. Certificate
// renewal keeps the SPKI pin, so it cannot silently change the paired identity.
internal static class StreamTransportIdentity
{
    static readonly ConcurrentDictionary<string,Lazy<X509Certificate2>> values=new(StringComparer.Ordinal);
    internal static X509Certificate2 Get()=>values.GetOrAdd(ProfileStore.Root,path=>new(()=>Load(new ProfileStore(path)))).Value;
    internal static X509Certificate2 Load(ProfileStore store)
    {
        var saved=store.ReadPrivate<byte[]>("stream-tls.protected");
        X509Certificate2? prior=null;
        try{
            prior=saved==null?null:StreamCertificates.LoadPrivate(saved);
            using var existing=prior?.GetECDsaPrivateKey();
            if(prior!=null&&(existing==null||!prior.HasPrivateKey))throw new CryptographicException("HTTPS 身份私钥无效，请从备份恢复；不会自动替换已配对身份");
            if(prior!=null&&prior.NotAfter.ToUniversalTime()>DateTime.UtcNow.AddDays(30)&&prior.NotBefore.ToUniversalTime()<=DateTime.UtcNow){var result=prior;prior=null;return result;}
            using var fresh=existing==null?ECDsa.Create(ECCurve.NamedCurves.nistP256):null;
            using var issued=StreamCertificates.CreateServer(existing??fresh!,DateTimeOffset.UtcNow.AddYears(5));
            byte[] encoded=issued.Export(X509ContentType.Pkcs12);
            try{store.WritePrivate("stream-tls.protected",encoded);return StreamCertificates.LoadPrivate(encoded);}
            finally{CryptographicOperations.ZeroMemory(encoded);}
        }finally{prior?.Dispose();if(saved!=null)CryptographicOperations.ZeroMemory(saved);}
    }
}
