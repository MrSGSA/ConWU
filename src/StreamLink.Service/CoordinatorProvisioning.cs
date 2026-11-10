using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using StreamLink.Core;

namespace StreamLink.Service;

// This identity belongs to the device listener, never to any network, pairing
// room, or PKARR identity. Existing operator-managed listeners are preserved.
internal static class CoordinatorProvisioning
{
    internal static CoordinatorSettings Enable(ProfileStore store,CoordinatorSettings settings)
    {
        if(settings.Enabled){settings.Validate();return settings;}
        if(settings!=new CoordinatorSettings()){
            var selected=settings with{Enabled=true};selected.Validate();return selected;
        }
        string folder=Path.Combine(store.DirectoryPath,"coordinator-tls");
        if(Directory.Exists(folder)&&(File.GetAttributes(folder)&FileAttributes.ReparsePoint)!=0)throw new IOException("协调证书目录不能是链接");
        if(OperatingSystem.IsLinux())LinuxPlatform.PrivateDirectory(folder);else Directory.CreateDirectory(folder);
        string certificate=Path.Combine(folder,"device.pem"),privateKey=Path.Combine(folder,"device-key.pem");
        foreach(string path in new[]{certificate,privateKey})if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("协调证书文件不能是链接");
        if(!File.Exists(certificate)||!File.Exists(privateKey)){
            using var key=RSA.Create(2048);
            var request=new CertificateRequest("CN=ConWU device coordinator",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature|X509KeyUsageFlags.KeyEncipherment,true));
            var purposes=new OidCollection{new("1.3.6.1.5.5.7.3.1")};
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(purposes,true));
            var names=new SubjectAlternativeNameBuilder();names.AddDnsName("localhost");names.AddIpAddress(IPAddress.Loopback);request.CertificateExtensions.Add(names.Build());
            using var issued=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddYears(5));
            Write(privateKey,key.ExportPkcs8PrivateKeyPem());Write(certificate,issued.ExportCertificatePem());
        }
        using var loaded=X509Certificate2.CreateFromPemFile(certificate,privateKey);
        if(!loaded.HasPrivateKey||DateTime.UtcNow>loaded.NotAfter.ToUniversalTime())throw new IOException("本机协调证书不可用，请在高级服务设置中更新证书");
        var automatic=new CoordinatorSettings(true,"https://0.0.0.0:47822",certificate,privateKey,PublicCertificatePin:Convert.ToHexString(SHA256.HashData(loaded.RawData)));
        automatic.Validate();return automatic;
    }
    static void Write(string path,string text)
    {
        byte[] bytes=Encoding.UTF8.GetBytes(text);
        try{
            if(OperatingSystem.IsLinux()){LinuxPlatform.PrivateWrite(path,bytes);return;}
            string temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
            try{
                using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){stream.Write(bytes);stream.Flush(true);}
                File.Move(temporary,path,true);
            }finally{if(File.Exists(temporary))File.Delete(temporary);}
        }finally{CryptographicOperations.ZeroMemory(bytes);}
    }
}
