using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace StreamLink.Core;

public static class StreamCertificates
{
    // Schannel requires a named private key. Omitting PersistKeySet keeps its
    // lifetime bound to the certificate; EphemeralKeySet causes SEC_E_NO_CREDENTIALS.
    public static X509Certificate2 LoadPrivate(byte[] pfx)=>X509CertificateLoader.LoadPkcs12(pfx,null,
        X509KeyStorageFlags.Exportable|(OperatingSystem.IsWindows()?X509KeyStorageFlags.MachineKeySet:X509KeyStorageFlags.EphemeralKeySet));

    public static X509Certificate2 CreateServer(ECDsa key,DateTimeOffset expires)
    {
        var request=new CertificateRequest("CN=ConWU stream",key,HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature,true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new("1.3.6.1.5.5.7.3.1")},true));
        using var issued=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),expires);
        byte[] pfx=issued.Export(X509ContentType.Pkcs12);
        try{return LoadPrivate(pfx);}finally{CryptographicOperations.ZeroMemory(pfx);}
    }
}
