using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.EndpointPoc;
using StreamLink.Service;

if (args.Length > 0 && args[0] == "--serve") { await ControlServer.Run(args); return; }
bool upgradeOnly = args.Length == 7 && args[6] == "--upgrade-only";
bool baselineOnly = args.Length == 7 && args[6] == "--baseline-only";
bool opportunityOnly = args.Length == 7 && args[6] == "--opportunity-only";
bool tcpRetryOnly = args.Length == 7 && args[6] == "--tcp-retry-only";
bool gatewayOnly = args.Length == 7 && args[6] == "--gateway-only";
bool ipv6Only = args.Length == 7 && args[6] == "--ipv6-only";
bool egressOnly = args.Length == 7 && args[6] == "--egress-only";
bool nativeIpv6Only = args.Length == 7 && args[6] == "--native-ipv6-only";
bool lifecycleOnly = args.Length == 7 && args[6] == "--lifecycle-only";
bool wireOnly = args.Length == 7 && args[6] == "--wire-only";
bool predictionOnly = args.Length == 7 && args[6] == "--prediction-only";
bool predictionRunnerOnly = args.Length == 7 && args[6] == "--prediction-runner-only";
bool sourceOnly = args.Length == 7 && args[6] == "--source-only";
bool explorationOnly = args.Length == 7 && args[6] == "--exploration-only";
bool feedbackOnly = args.Length == 7 && args[6] == "--feedback-only";
bool standbyOnly = args.Length == 7 && args[6] == "--standby-only";
bool udpStandbyOnly = args.Length == 7 && args[6] == "--udp-standby-only";
bool diagnosticOnly=args.Length==7&&args[6]=="--diagnostic-only";
bool diagnosticLoadOnly=args.Length==7&&args[6]=="--diagnostic-load-only";
bool diagnosticRunnerOnly=args.Length==7&&args[6]=="--diagnostic-runner-only";
bool nativeDiagnosticRunnerOnly=args.Length==7&&args[6]=="--native-diagnostic-runner-only";
bool diagnosticBusyOnly=args.Length==7&&args[6]=="--diagnostic-busy-only";
bool poolOnly = args.Length == 7 && args[6] == "--pool-only";
if ((!upgradeOnly && !baselineOnly && !opportunityOnly && !tcpRetryOnly && !gatewayOnly && !ipv6Only && !nativeIpv6Only && !egressOnly && !lifecycleOnly && !wireOnly && !predictionOnly && !predictionRunnerOnly && !poolOnly && !sourceOnly && !explorationOnly && !feedbackOnly && !standbyOnly && !udpStandbyOnly && !diagnosticOnly && !diagnosticLoadOnly && !diagnosticRunnerOnly && !nativeDiagnosticRunnerOnly && !diagnosticBusyOnly && args.Length != 6) || args[0] != "--native" || args[2] != "--rounds" || args[4] != "--output") throw new ArgumentException("--native exe --rounds 30 --output result.json [--pool-only or another existing mode]");
string binary = Path.GetFullPath(args[1]), output = Path.GetFullPath(args[5]); int rounds = int.Parse(args[3]);
string root = Path.Combine(Path.GetTempPath(), "streamlink-runner-traversal-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(predictionRunnerOnly ? Math.Max(1200, rounds * 75 + 60) : 1200)); var token = deadline.Token;
var rows = new List<object>(); int checks = 0;
void Check(bool b, string why) { if (!b) throw new Exception(why); checks++; Console.WriteLine("PASS " + why); }
using var rsa = RSA.Create(2048); var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build());
using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, l => l.UseHttps(certificate)));
await using var app = builder.Build(); Directory.CreateDirectory(Path.Combine(root, "registry")); var online = new MeshRegistry(Path.Combine(root, "registry"));
bool controlOffline = false;
var controlFailure = new ControlFailureGate();
app.Use(controlFailure.Handle);
app.Use(async (context, next) => { if (controlOffline) { context.Response.StatusCode = 503; return; } await next(); });
app.MapPost("/v3/mesh/{network}/watch", (HttpContext c, string network, MeshWatchRequest r) => online.Watch(c, network, r));
app.MapPost("/v3/mesh/{network}/traversal", (HttpContext c, string network, MeshTraversalBatch r) => online.Traversal(c, network, r));
app.MapGet("/v3/mesh/{network}", (HttpContext c, string network) => online.Read(c, network));
app.MapPut("/v3/mesh/{network}/directory", (HttpContext c, string network, MeshDirectory d) => online.Directory(c, network, d));
app.MapPut("/v3/mesh/{network}/nodes/{slot:int}", (HttpContext c, string network, int slot, MeshEnvelope e) => online.Publish(c, network, slot, e));
var predictionObserver = new TcpSynObserver(PredictionRunnerTests.Points); predictionObserver.SetAvailable(true);
app.MapPost("/v3/mesh/{network}/tcp-observer", (HttpContext c, string network, TcpObserverRequest r) => online.TcpObservation(c, network, r, predictionObserver));
await app.StartAsync(token);
string url = app.Urls.Single(), pin = Convert.ToHexString(SHA256.HashData(certificate.RawData));
try {
    if(diagnosticBusyOnly)rows.Add(await Ipv6Tests.RunDiagnostics(root,url,pin,Check,token,interruptBusy:true));
    else if(nativeDiagnosticRunnerOnly)rows.Add(await NativeIpv6RunnerTests.RunDiagnostics(binary,root,url,pin,Check,token));
    else if(diagnosticRunnerOnly)rows.Add(await Ipv6Tests.RunDiagnostics(root,url,pin,Check,token));
    else if(diagnosticLoadOnly)rows.Add(await NativeDiagnosticTests.Run(binary,root,Check,token,load:true));
    else if(diagnosticOnly)rows.Add(await NativeDiagnosticTests.Run(binary,root,Check,token));
    else if (udpStandbyOnly) rows.Add(await Ipv6Tests.RunStandby(root,url,pin,Check,token));
    else if (standbyOnly) rows.Add(await NativeIpv6RunnerTests.RunStandby(binary,root,url,pin,Check,token));
    else if (feedbackOnly) {
        rows.Add(await NativeIpv6RunnerTests.Run(binary, root, url, pin, Check, token, feedback: true));
        rows.Add(await Ipv6Tests.Run(root, url, pin, rounds, Check, token, feedback: true));
    }
    else if (explorationOnly) {
        await UdpExplorationAdmissionTests.Run(Check, token);
        for (int round = 0; round < rounds; round++) {
            for (int stable = 0; stable < 2; stable++) rows.Add(await UdpExplorationRunnerTests.Run(Path.Combine(root, "exploration-round-" + round), url, pin, stable, Check, token));
            rows.Add(await UdpExplorationSocketTests.Run(Path.Combine(root, "exploration-socket-round-" + round), url, pin, Check, token));
        }
    }
    else if (sourceOnly) { await PeerSourceAdmissionTests.Run(binary, root, Check, token); foreach (string mode in new[] { "client-role", "server-role", "same-public-ip", "old-peer", "old-server", "old-native" }) rows.Add(await PeerSourceRunnerTests.Run(binary, root, url, pin, mode, Check, token)); }
    else if (poolOnly) { await PeerSourceBoundaryTests.Run(Check, token); for (int round = 0; round < rounds; round++) await EndpointPoolTests.Run(Check, token); }
    else if (predictionRunnerOnly) {
        await PredictionRunnerTests.Admission(binary, root, Check, token);
        for (int round = 0; round < rounds; round++) rows.Add(await PredictionRunnerTests.Run(binary, Path.Combine(root, "prediction-round-" + round), url, pin, predictionObserver, Check, token, round % 2, helperFallback: round % 2 == 1));
        rows.Add(await PredictionRunnerTests.Run(binary, Path.Combine(root, "prediction-mismatch"), url, pin, predictionObserver, Check, token, changedStableMapping: true));
    }
    else if (predictionOnly) rows.Add(await PredictionQualificationTests.Run(binary, root, Check, token));
    else if (wireOnly) {
        rows.Add(await WireBudgetTests.Run(Check, token));
        await SharedBrokerRunner.Run(binary, root, url, pin, Check, token);
        rows.Add(await NativeIpv6RunnerTests.Run(binary, root, url, pin, Check, token));
    }
    else if (lifecycleOnly) rows.Add(await LifecycleTests.Run(binary, root, url, pin, controlFailure, Check, token));
    else {
    if (nativeIpv6Only || egressOnly || args.Length == 6) rows.Add(await NativeIpv6RunnerTests.Run(binary, root, url, pin, Check, token, egressOnly));
    if (egressOnly) rows.Add(await Ipv6Tests.Run(root, url, pin, rounds, Check, token, true));
    if (!nativeIpv6Only && !egressOnly) {
    if (ipv6Only || args.Length == 6) rows.Add(await Ipv6Tests.Run(root, url, pin, rounds, Check, token));
    if (!ipv6Only) {
    if (gatewayOnly || !baselineOnly && !upgradeOnly && !opportunityOnly && !tcpRetryOnly) rows.Add(await UdpGatewayTests.Run(root, url, pin, Check, token));
    if (!gatewayOnly) {
    if (!baselineOnly && !upgradeOnly && !tcpRetryOnly) rows.Add(await OpportunityTests.Run(Check, token));
    if (!baselineOnly && !opportunityOnly && !tcpRetryOnly) rows.Add(await UpgradeTests.Run(binary, root, url, pin, Check, token));
    if (tcpRetryOnly || !baselineOnly && !upgradeOnly && !opportunityOnly) rows.Add(await TcpRetryTests.Run(binary, root, url, pin, Check, token));
    if (!upgradeOnly && !opportunityOnly && !tcpRetryOnly) {
    await AdmissionTests.Run(binary, root, Check, token);
    CaptureFilterTests.Run(Path.Combine(Path.GetDirectoryName(binary)!, "..", "downloads", "WinDivert-2.2.2-A", "x64", "WinDivert.dll"), Check);
    await EndpointPoolTests.Run(Check, token);
    await SharedBrokerRunner.Run(binary, root, url, pin, Check, token);
    foreach (var kind in new[] { TraversalProfile.UdpDirect, TraversalProfile.FakeTcpHttpSo }) for (int round = 1; round <= rounds; round++) {
        var a = MeshIdentity.Create(url, pin, "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        await using var reflector = new Reflector { Silent = false }; await using var proxy = new RawProtocolProxy(0, 0); proxy.Begin();
        var adapters = new[] { new Adapter(), new Adapter() }; var states = new SessionStatus?[2];
        var factories = new[] { new Factory(a, kind, binary, root, reflector, proxy), new Factory(b, kind, binary, root, reflector, proxy) };
        using var runningStop = CancellationTokenSource.CreateLinkedTokenSource(token);
        var logs = new ConcurrentQueue<string>(); int legacyCalls = 0;
        MeshRuntimeServices Services(int i) => new(
            mesh => new MeshDiscoveryClient(mesh), _ => Task.FromResult<IPacketAdapter>(adapters[i]),
            async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new InvalidOperationException(); },
            _ => { Interlocked.Increment(ref legacyCalls); throw new IOException("no explicit entry in this fixture"); },
            (_, _, ct) => Task.Delay(Timeout.Infinite, ct), (_, _, _) => { }, (_, _) => { }, Path.Combine(root, "sessions")) {
                Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(factories[i])
            };
        string policy = kind == TraversalProfile.FakeTcpHttpSo ? "faketcp-only" : "prefer-faketcp";
        var runners = new[] { new MeshRunner(new() { Mesh = a, TraversalMode = "tcp-udp", PathSelection = policy, AllowUdpFallback = true }, s => logs.Enqueue("A " + s), s => states[0] = s, _ => { }, _ => { }, Services(0)),
            new MeshRunner(new() { Mesh = b, TraversalMode = "tcp-udp", PathSelection = policy, AllowUdpFallback = true }, s => logs.Enqueue("B " + s), s => states[1] = s, _ => { }, _ => { }, Services(1)) };
        var clock = Stopwatch.StartNew(); var tasks = runners.Select(r => r.Run(runningStop.Token)).ToArray();
        try {
            while (!states.All(s => s?.Connected == true)) {
                foreach (var task in tasks) if (task.IsCompleted) await task;
                if (clock.ElapsedMilliseconds > 25000) throw new TimeoutException(string.Join('\n', logs));
                await Task.Delay(25, token);
            }
            long selectedMs = clock.ElapsedMilliseconds;
            Check(states.All(s => s!.Degraded == (kind == TraversalProfile.UdpDirect) && s.Peers!.Single().Degraded == s.Degraded), "Runner distinguishes authenticated UDP fallback from target quality, without mislabeling FakeTCP");
            Check(legacyCalls == 0 && factories.All(f => f.Gathers == 1 && f.Prepared == 1), $"{kind} round {round}: production MeshRunner automatically negotiates and owns one actual endpoint per peer");
            if (round == 1) { controlOffline = true; await Task.Delay(9000, token); }
            adapters[0].Outgoing.Add(Packet(a.LocalIp, b.LocalIp)); adapters[1].Outgoing.Add(Packet(b.LocalIp, a.LocalIp));
            var data = Stopwatch.StartNew();
            while (adapters.Any(x => x.Incoming.Count != 1)) { if (data.ElapsedMilliseconds > 1800) throw new TimeoutException("actual Runner business data missing"); await Task.Delay(10, token); }
            Check(states.All(s => s?.Connected == true), "full-MTU encrypted bidirectional business survives the original Attempt deadline and control outage");
            rows.Add(new { kind, round, selectedMs, automaticRunner = true, realHttps = true, realSocket = true, nativeTestBackend = kind == TraversalProfile.FakeTcpHttpSo, realNat = false, wintun = false });
        } finally {
            controlOffline = false; runningStop.Cancel();
            foreach (var task in tasks) try { await task.WaitAsync(TimeSpan.FromSeconds(8)); } catch (OperationCanceledException) { }
            Check(factories.All(f => f.Closed) && adapters.All(a => a.Disposed), "Runner shutdown closes the final endpoint references and adapter");
        }
    }
    }
    }
    }
    }
    }
    await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows, scope = explorationOnly ? "formal UDP exploration factory/Runner/actor, real HTTPS and Windows loopback sockets plus controlled mapping/filter and injected source qualifications; no physical NAT/Wintun or public success claim" : sourceOnly ? "formal source-aware factory/Runner/actor over real HTTPS, helpers and C++; raw/mapping/filter/IP adapters and absent-capability cases are controlled fixtures, no physical Windows driver or public NAT" : poolOnly ? "formal endpoint pool and seven-peer candidate factory; real Windows TCP helpers; clock injection for cache age, memory capture; no native worker, MeshRunner, physical WinDivert/Wintun or NAT" : predictionRunnerOnly ? "formal Runner/factory/actor, signed HTTPS observer/coordination, real TCP helpers and C++ protocol; controlled NAT/raw/IP and synthetic qualified training fixtures, no WinDivert/Wintun/public NAT" : predictionOnly ? "formal candidate factory and TcpShapeProbe, real loopback TCP helper; controlled observer API and raw I/O; no MeshRunner/native worker, Wintun, public NAT or real multiple devices" : lifecycleOnly ? "production TCP factory/Runner/native; real HTTPS connection abort for 360 seconds, TCP helper query outage, signed revocation; memory raw/IP adapters, no physical driver, WAN, Wintun or gateway lease" : egressOnly ? "production paced native and UDP factories/Runner; real timer, native, TCP helpers, UDP, HTTPS; memory raw/IP adapters, no physical driver or WAN" : nativeIpv6Only
        ? "production FakeTCP IPv6 factory/Runner, actual native workers/helpers/HTTPS; pure WinDivert filter evaluation; memory raw and IP adapters, not physical WinDivert/Wintun or WAN"
        : ipv6Only
        ? "production UDP gathering/Runner over real IPv6/IPv4 loopback sockets and HTTPS; memory IP adapters; not Internet IPv6, native FakeTCP IPv6, wire fragmentation capture or Wintun"
        : gatewayOnly
        ? "production UDP gathering/Runner with real loopback PCP, STUN, HTTPS, UDP and memory IP adapters; no real NAT, router or Wintun"
        : opportunityOnly
        ? "production pair scheduler and legacy admission with controlled failing/held resource factories; real timers, no native I/O, WAN, Wintun or real 8 devices"
        : "real production MeshRunner, HTTPS, socket/native protocol; injected loopback endpoint gathering and memory IP adapter, not WinDivert/WAN/Wintun or real 8 devices" }, new JsonSerializerOptions { WriteIndented = true }));
} catch (Exception ex) { await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() }, new JsonSerializerOptions { WriteIndented = true })); throw; }
finally { await app.StopAsync(); }

static byte[] Packet(string from, string to) {
    byte[] p = new byte[1280]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), 1280);
    IPAddress.Parse(from).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(p, 16);
    uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
}
sealed class Adapter : IPacketAdapter {
    public readonly BlockingCollection<byte[]> Outgoing = new(); public readonly ConcurrentQueue<byte[]> Incoming = new(); public bool Disposed;
    public int Read(byte[] buffer) { if (!Outgoing.TryTake(out var packet, 30)) return 0; packet.CopyTo(buffer, 0); return packet.Length; }
    public bool Write(byte[] p) { Incoming.Enqueue(p); return true; }
    public void Dispose() { Disposed = true; Outgoing.Dispose(); }
}
sealed class Factory(MeshProfile mesh, TraversalProfile kind, string binary, string folder, Reflector reflector, RawProtocolProxy proxy) : IMeshCandidateFactory {
    readonly Guid generation = Guid.NewGuid(); readonly TraversalResources budget = new();
    readonly MeshProfile local = mesh; readonly string exe = binary, root = folder; readonly RawProtocolProxy wire = proxy;
    public int Gathers, Prepared; public TcpEndpointLease? Tcp; public UdpTraversal? Udp;
    public bool Closed => (Tcp?.Closed ?? true) && (Udp?.Closed ?? true);
    public TraversalProfile[] Profiles => [kind];
    public async Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile profile, Guid attempt, CancellationToken token) {
        Gathers++; IPEndPoint endpoint;
        if (kind == TraversalProfile.UdpDirect) {
            byte[] shared = MeshIdentity.SharedKey(local, peer);
            try { Udp = UdpTraversal.Create(new(IPAddress.Loopback, 0), generation, attempt, local.Self.Slot, peer.Slot, shared, budget); } finally { CryptographicOperations.ZeroMemory(shared); }
            endpoint = Udp.Local;
        } else {
            Tcp = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, token);
            using var query = Tcp.AcquireAttempt(generation); endpoint = (await query.Observe(token)).Public;
        }
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return new Resource(this, peer, new(Guid.NewGuid(), 1, endpoint.ToString(), null, now, now + 120, CandidatePurpose.Host));
    }
    sealed class Resource(Factory owner, MeshMember peer, MeshTraversalCandidate candidate) : IMeshCandidateResource {
        bool transferred;
        public MeshTraversalCandidate Candidate => candidate;
        public async Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context, IPEndPoint remote, CancellationToken token) {
            owner.Prepared++;
            if (owner.Udp != null) { var result = owner.Udp.PreparePath(context, owner.generation, remote); transferred = true; return result; }
            byte[] shared = MeshIdentity.SharedKey(owner.local, peer);
            try {
                return await NativeDatagramPath.Prepare(owner.exe, owner.root, owner.Tcp!, owner.generation, context, remote, shared, token, owner.budget,
                    new Dictionary<string,string> { ["STREAMLINK_TEST_BIND"] = "0", ["STREAMLINK_TEST_PEER"] = (context.ProtocolClient ? owner.wire.ClientPort : owner.wire.ServerPort).ToString(), ["STREAMLINK_TEST_HELLO"] = owner.wire.RegistrationToken });
            } finally { CryptographicOperations.ZeroMemory(shared); }
        }
        public async ValueTask DisposeAsync() { owner.Tcp?.Dispose(); if (!transferred && owner.Udp != null) await owner.Udp.DisposeAsync(); }
    }
}
