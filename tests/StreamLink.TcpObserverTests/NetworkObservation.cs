using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Discovery;

static class NetworkObservation
{
    sealed record Config(string Service, string Pin);
    public static async Task Serve(string[] args)
    {
        if (args.Length is not (3 or 5)) throw new ArgumentException("--serve-syn local-public-ip config-output [port-a port-b]");
        var address = IPAddress.Parse(args[1]);
        if (!NetworkInterface.GetAllNetworkInterfaces().Any(n => n.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(address)))) throw new ArgumentException("Observer address must belong to a local interface");
        int firstPort = args.Length == 5 ? int.Parse(args[3]) : 47221;
        int secondPort = args.Length == 5 ? int.Parse(args[4]) : 47222;
        if (firstPort is < 1024 or > 65535 || secondPort is < 1024 or > 65535 || firstPort == secondPort) throw new ArgumentException("Two distinct observation ports in 1024..65535 required");
        // Passive header observation only: this does not bind either TCP port or
        // change the listener/firewall. A known reachable port is a useful
        // control when an unused high port produces no public observations.
        TcpObserverPoint[] points = [new("wan-a", new IPEndPoint(address, firstPort).ToString()), new("wan-b", new IPEndPoint(address, secondPort).ToString())];
        var observer = new TcpSynObserver(points); await using var capture = new LinuxSynCapture(observer, points);
        using var rsa = RSA.Create(2048); var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); req.CertificateExtensions.Add(san.Build());
        using var generated = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var cert = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => { k.Listen(IPAddress.Loopback, 43983, l => l.UseHttps(cert)); k.Limits.MaxRequestBodySize = 16384; k.Limits.MaxConcurrentConnections = 16; });
        await using var app = builder.Build(); string root = Path.Combine(Path.GetTempPath(), "streamlink-syn-network-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        var registry = new MeshRegistry(root);
        app.MapPut("/v3/mesh/{network}/directory", (HttpContext c, string network, MeshDirectory d) => registry.Directory(c, network, d));
        app.MapPost("/v3/mesh/{network}/tcp-observer", (HttpContext c, string network, TcpObserverRequest r) => registry.TcpObservation(c, network, r, observer));
        app.MapGet("/capture-count", () => capture.ReceivedPackets); // Loopback-only isolated harness, no tuples or payload.
        await app.StartAsync();
        await File.WriteAllTextAsync(args[2], JsonSerializer.Serialize(new Config("https://127.0.0.1:43983/", Convert.ToHexString(SHA256.HashData(cert.RawData)))));
        Console.WriteLine("Ready: isolated loopback HTTPS and two public SYN observation points; 150-second maximum lifetime");
        await Task.Delay(TimeSpan.FromSeconds(150)); await app.StopAsync();
        Console.WriteLine("Kernel SYN captures: " + capture.ReceivedPackets);
    }
    public static async Task Probe(string[] args)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows WinDivert observation required");
        if (args.Length < 5) throw new ArgumentException("--native-observe config WinDivert.dll result.json stun-host:port...");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(80));
        var config = JsonSerializer.Deserialize<Config>(await File.ReadAllTextAsync(args[1]))!;
        var profile = MeshIdentity.Create(config.Service, config.Pin, "faketcp");
        using var control = new MeshDiscoveryClient(profile); await control.SaveDirectory(profile.Directory!, stop.Token);
        using var diagnosticHandler = new HttpClientHandler { UseProxy = false, ServerCertificateCustomValidationCallback = (_, c, _, _) => c != null && Convert.ToHexString(SHA256.HashData(c.RawData)) == config.Pin };
        using var diagnostic = new HttpClient(diagnosticHandler) { Timeout = TimeSpan.FromSeconds(5) };
        async Task<long> Count() => long.Parse(await diagnostic.GetStringAsync(config.Service + "capture-count", stop.Token));
        TcpEndpointLease? lease = null; var failures = new List<object>();
        foreach (string server in args.Skip(4)) {
            try {
                using var shortWait = CancellationTokenSource.CreateLinkedTokenSource(stop.Token); shortWait.CancelAfter(4000);
                var target = await Stun.Resolve(server, shortWait.Token);
                var local = Stun.LocalAddress(target); Physical(local);
                lease = await TcpEndpointLease.Open(new(local, 0), target, Guid.NewGuid(), shortWait.Token);
                using var reference = lease.AcquireAttempt(lease.NetworkGeneration); await reference.Observe(shortWait.Token); break;
            } catch (Exception ex) { failures.Add(new { server, failure = ex.GetType().Name }); lease?.Dispose(); lease = null; }
        }
        if (lease == null) { await File.WriteAllTextAsync(args[3], JsonSerializer.Serialize(new { status = "NoHelper", failures })); return; }
        using (lease) {
            try {
                await using var owner = new TcpCaptureOwner(lease, lease.NetworkGeneration, (local, helper) => {
                    if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
                    return new WinDivertEndpointIo(Path.GetFullPath(args[2]), local, helper);
                }); await owner.Ready;
                using var held = lease.AcquireAttempt(lease.NetworkGeneration); var before = await held.Observe(stop.Token);
                long captureBefore = await Count();
                var clock = Stopwatch.StartNew();
                Action<IPEndPoint> checkRoute = ep => {
                    var local = Stun.LocalAddress(ep); Physical(local);
                    if (!local.Equals(lease.Local.Address)) throw new IOException("Observation route differs from held helper source");
                };
                bool fresh = args[0] == "--native-observe-fresh";
                var observations = fresh ? await TcpShapeProbe.RunFresh(owner, control, () => true, checkRoute, stop.Token, destinations: 2) :
                    await TcpShapeProbe.Run(owner, control, () => true, checkRoute, stop.Token);
                var agesAtReturnMs = observations.Select(o => Stopwatch.GetElapsedTime(o.LocalProbeStartedAt).TotalMilliseconds).ToArray();
                double probeElapsedMs = clock.Elapsed.TotalMilliseconds;
                var after = await held.Observe(stop.Token);
                long captureAfterNative = await Count();
                // Independent ordinary TCP reachability control, with unrelated
                // ephemeral sockets. It does not prove same-port/native continuity.
                foreach (var observation in observations) {
                    using var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
                    using var shortWait = CancellationTokenSource.CreateLinkedTokenSource(stop.Token); shortWait.CancelAfter(800);
                    try { await socket.ConnectAsync(IPEndPoint.Parse(observation.Target), shortWait.Token); }
                    catch (Exception ex) when (ex is System.Net.Sockets.SocketException or OperationCanceledException) { }
                }
                await Task.Delay(200, stop.Token); long captureAfterKernelControl = await Count();
                await File.WriteAllTextAsync(args[3], JsonSerializer.Serialize(new {
                    status = observations.All(o => o.State == "SynObserved") ? "SynObserved" : "PartialOrNotObserved",
                    elapsedMs = clock.Elapsed.TotalMilliseconds, scope = "Windows physical source and real WinDivert capture owner, remote Linux public SYN observer; no business/handshake/NAT classification proof",
                    helperBefore = before.Public.ToString(), helperAfter = after.Public.ToString(), owner = owner.Status, observations, failures,
                    mode = fresh ? "fresh-final-window" : "legacy-eight-second", probeElapsedMs, agesAtReturnMs,
                    captureBefore, captureAfterNative, captureAfterKernelControl
                }, new JsonSerializerOptions { WriteIndented = true }));
                Console.WriteLine($"Observed {observations.Count(o => o.State == "SynObserved")}/{observations.Length}; helper remains queryable; no handshake/business claim");
            } catch (Exception ex) { await File.WriteAllTextAsync(args[3], JsonSerializer.Serialize(new { status = "Fail", failure = ex.ToString(), failures }, new JsonSerializerOptions { WriteIndented = true })); throw; }
        }
    }
    static void Physical(IPAddress local)
    {
        var nic = NetworkInterface.GetAllNetworkInterfaces().Single(n => n.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(local)));
        if (nic.NetworkInterfaceType is not (NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211) ||
            nic.Description.Contains("Wintun", StringComparison.OrdinalIgnoreCase) || nic.Description.Contains("EasyTier", StringComparison.OrdinalIgnoreCase))
            throw new IOException("Physical egress required");
    }
}
