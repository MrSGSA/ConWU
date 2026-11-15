using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using StreamLink.Discovery;

static class AssistHelperNode
{
    public static async Task Run(string listen="https://0.0.0.0:49350",int lifetime=0)
    {
        string root=Path.Combine(Path.GetTempPath(),"conwu-assist-helper-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        try{
            using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var cert=new CertificateRequest("CN=isolated-helper",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
            string certificate=Path.Combine(root,"cert.pem"),privateKey=Path.Combine(root,"key.pem");
            File.WriteAllText(certificate,cert.ExportCertificatePem());File.WriteAllText(privateKey,key.ExportPkcs8PrivateKeyPem());
            await using var host=CoordinationHost.Create(new(Path.Combine(root,"state"),listen,certificate,privateKey));await host.Start();
            Console.WriteLine(JsonSerializer.Serialize(new{eventName="ready",pin=Convert.ToHexString(SHA256.HashData(cert.RawData))}));
            if(lifetime is >0 and <=3600)await Task.Delay(TimeSpan.FromSeconds(lifetime));
            else await Console.In.ReadLineAsync().WaitAsync(TimeSpan.FromMinutes(30));
        }finally{Directory.Delete(root,true);}
    }
}
