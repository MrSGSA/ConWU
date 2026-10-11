using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Discovery;

static class ControlServer
{
    public static async Task Run(string[] args)
    {
        if (args.Length != 5) throw new ArgumentException("--serve bind-ip port root seconds");
        var ip = IPAddress.Parse(args[1]); int port = int.Parse(args[2]), seconds = int.Parse(args[4]);
        if (ip.Equals(IPAddress.Any) || seconds is < 30 or > 1800) throw new ArgumentException("Explicit interface and bounded duration required");
        string root = Path.GetFullPath(args[3]); Directory.CreateDirectory(root);
        using var rsa = RSA.Create(2048); var request = new CertificateRequest("CN=StreamLink isolated control", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(ip); request.CertificateExtensions.Add(san.Build());
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(ip, port, l => l.UseHttps(certificate)));
        await using var app = builder.Build(); var registry = new MeshRegistry(root);
        app.MapPost("/v3/mesh/{network}/watch", (HttpContext c, string network, MeshWatchRequest r) => registry.Watch(c, network, r));
        app.MapPost("/v3/mesh/{network}/traversal", (HttpContext c, string network, MeshTraversalBatch r) => registry.Traversal(c, network, r));
        app.MapGet("/v3/mesh/{network}", (HttpContext c, string network) => registry.Read(c, network));
        app.MapPut("/v3/mesh/{network}/directory", (HttpContext c, string network, MeshDirectory d) => registry.Directory(c, network, d));
        app.MapPut("/v3/mesh/{network}/nodes/{slot:int}", (HttpContext c, string network, int slot, MeshEnvelope e) => registry.Publish(c, network, slot, e));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        await app.StartAsync(deadline.Token);
        await File.WriteAllTextAsync(Path.Combine(root, "coordination.json"), JsonSerializer.Serialize(new { url = app.Urls.Single(), pin = Convert.ToHexString(SHA256.HashData(certificate.RawData)) }));
        Console.WriteLine("Isolated authenticated control ready; no business forwarding endpoints.");
        try { while (!File.Exists(Path.Combine(root, "stop"))) await Task.Delay(250, deadline.Token); }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
        finally { await app.StopAsync(); }
    }
}
