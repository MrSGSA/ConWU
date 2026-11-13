using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StreamLink.Core;
using StreamLink.Service;

static class StreamIdentityChecks
{
    public static void Run(Action<bool,string> check)
    {
        string folder=Path.Combine(Path.GetTempPath(),"conwu-stream-identity-"+Guid.NewGuid().ToString("N"));
        try{
            var store=new ProfileStore(folder);
            using(var first=StreamTransportIdentity.Load(store))using(var second=StreamTransportIdentity.Load(store))
                check(first.HasPrivateKey&&StreamMeshTransport.CertificatePin(first)==StreamMeshTransport.CertificatePin(second),"protected HTTPS device identity survives an independent reload");
            using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var nearExpiry=StreamCertificates.CreateServer(key,DateTimeOffset.UtcNow.AddDays(1));
            byte[] pfx=nearExpiry.Export(X509ContentType.Pkcs12);
            try{store.WritePrivate("stream-tls.protected",pfx);}finally{CryptographicOperations.ZeroMemory(pfx);}
            using(var renewed=StreamTransportIdentity.Load(store))
                check(renewed.NotAfter.ToUniversalTime()>DateTime.UtcNow.AddYears(4)&&StreamMeshTransport.CertificatePin(renewed)==StreamMeshTransport.CertificatePin(nearExpiry),"HTTPS certificate renewal preserves the approved public-key pin");
            store.WritePrivate("stream-tls.protected",new byte[]{1,2,3});bool refused=false;
            try{using var invalid=StreamTransportIdentity.Load(store);}catch(CryptographicException){refused=true;}
            check(refused&&store.ReadPrivate<byte[]>("stream-tls.protected")!.SequenceEqual(new byte[]{1,2,3}),"a damaged HTTPS identity is rejected without silently replacing its paired key");
            if(OperatingSystem.IsWindows()){
                string journal=Path.Combine(folder,"sessions");
                using(var access=WindowsHost.AllowStreamListener(48445,journal)){
                    Recovery.Recover(_=>{},journal);
                    check(Directory.GetFiles(journal,"owner.json",SearchOption.AllDirectories).Length==1,"Windows stream listener records its exact firewall owner and recovery preserves a live lease");
                }
                check(!Directory.EnumerateDirectories(journal).Any(),"Windows stream listener releases its firewall ownership journal on normal shutdown");
                using(var access=WindowsHost.AllowStreamListener(48446,journal,Environment.ProcessPath!.Replace('\\','/')))
                    check(Directory.GetFiles(journal,"owner.json",SearchOption.AllDirectories).Length==1,"Windows firewall accepts a forward-slash executable path after exact application normalization");
                check(!Directory.EnumerateDirectories(journal).Any(),"normalized executable rule and ownership journal are released together");
            }
        }finally{if(Directory.Exists(folder))Directory.Delete(folder,true);}
    }
}
