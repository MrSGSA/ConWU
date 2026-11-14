using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Channels;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.EndpointPoc;

if (args.FirstOrDefault() == "--serve-syn") { await NetworkObservation.Serve(args); return; }
if (args.FirstOrDefault() is "--native-observe" or "--native-observe-fresh") { await NetworkObservation.Probe(args); return; }
if (args.Length is < 2 or > 3 || args[0] != "--output") throw new ArgumentException("--output file [--linux-raw]");
bool raw = args.Length == 3 && args[2] == "--linux-raw";
string output = Path.GetFullPath(args[1]), root = Path.Combine(Path.GetTempPath(), "streamlink-syn-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root); Directory.CreateDirectory(Path.GetDirectoryName(output)!);
using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(3)); var ct = stop.Token;
int checks = 0; var rows = new List<object>();
void Check(bool value, string why) { if (!value) throw new Exception(why); checks++; Console.WriteLine("PASS " + why); }
TcpProbeSpec Spec(string id, uint iss) => new(Guid.NewGuid(), id, iss);
TcpObserverPoint[] points = [new("one-a", "127.0.0.1:47221"), new("one-b", "127.0.0.1:47222"), new("two-a", "127.0.0.2:47221"), new("two-b", "127.0.0.2:47222")];
var observer = new TcpSynObserver(points);
await using var capture = raw ? new LinuxSynCapture(observer, points) : null;
if (!raw) observer.SetAvailable(true);
using var rsa = RSA.Create(2048); var certRequest = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); certRequest.CertificateExtensions.Add(san.Build());
using var generated = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, l => l.UseHttps(certificate)));
await using var app = builder.Build(); var registry = new MeshRegistry(root);
app.MapPut("/v3/mesh/{network}/directory", (HttpContext c, string network, MeshDirectory d) => registry.Directory(c, network, d));
app.MapPost("/v3/mesh/{network}/tcp-observer", (HttpContext c, string network, TcpObserverRequest r) => registry.TcpObservation(c, network, r, observer));
await app.StartAsync(ct);
string url = app.Urls.Single(), pin = Convert.ToHexString(SHA256.HashData(certificate.RawData));
try {
    // These 30 rounds exercise deterministic attribution states, not NAT coverage.
    for (int round = 0; round < 30; round++) {
        var local = MeshIdentity.Create(url, pin, "faketcp"); var boot = Guid.NewGuid();
        var specs = points.Select((p, i) => Spec(p.Id, (uint)(10000 + round * 4 + i))).ToArray();
        var request = TcpObserverProtocol.Create(local, boot, "register", Guid.NewGuid(), specs);
        var initial = observer.Request(local.Pair.Network, request);
        Check(initial.Status == 200 && initial.Reply!.Evidence.All(e => e.State == "Pending"), $"round {round + 1}: bounded pending ticket");
        var packets = points.Select((p, i) => TcpShapeSyn.Create(new(IPAddress.Parse("192.0.2.20"), 40000 + i), TcpObserverProtocol.Endpoint(p.Endpoint), specs[i].Iss, 100)).ToArray();
        foreach (var p in packets) { observer.Observe(p); observer.Observe(p); }
        var repeat = observer.Request(local.Pair.Network, request);
        Check(repeat.Reply!.Expires == initial.Reply!.Expires && repeat.Reply.Evidence.All(e => e.State == "SynObserved" && e.Retransmissions == 1 && e.TcpHandshakeVerified == "NotTested" && e.LegacyPayloadVerified == "NotTested"), "retransmits deduplicate, retries do not renew, SYN never proves handshake");
        observer.Observe(TcpShapeSyn.Create(new(IPAddress.Parse("192.0.2.20"), 50001), TcpObserverProtocol.Endpoint(points[0].Endpoint), specs[0].Iss, 100));
        Check(observer.Request(local.Pair.Network, request).Reply!.Evidence[0] is { State: "Ambiguous", Source: null }, "conflicting actual sources are ambiguous, not authenticated");
        var wrong = TcpObserverProtocol.Create(local, boot, "register", Guid.NewGuid(), [specs[0] with { ProbeId = Guid.NewGuid() }]);
        Check(observer.Request(local.Pair.Network, wrong).Status == 409, "cross-ticket ISS/target collision rejected");
        var corrupted = packets[1].ToArray(); corrupted[33] = 0x12;
        Check(!TcpShapeSyn.Read(corrupted, out _, out _, out _), "SYN+ACK cannot masquerade as outgoing SYN observation");
        Array.Resize(ref corrupted, 61); corrupted[3] = 61; corrupted[33] = 2;
        Check(!TcpShapeSyn.Read(corrupted, out _, out _, out _), "payload-bearing packet cannot enter SYN metadata observer");
    }
    rows.Add(new { scope = "deterministic ticket attribution", rounds = 30, native = false, nat = false });
    var a = MeshIdentity.Create(url, pin, "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
    using var client = new MeshDiscoveryClient(a); using var other = new MeshDiscoveryClient(b);
    await client.SaveDirectory(a.Directory!, ct);
    var catalog = await client.TcpObservation("catalog", Guid.Empty, null, ct);
    Check(catalog.Points.Length == 4 && catalog.Epoch != Guid.Empty, "real pinned HTTPS returns only configured observation points");
    var ticket = Guid.NewGuid(); var spec = Spec("one-a", uint.MaxValue);
    var registered = await client.TcpObservation("register", ticket, [spec], ct);
    try { await other.TcpObservation("read", ticket, null, ct); Check(false, "foreign read"); }
    catch (HttpRequestException ex) { Check(ex.StatusCode == HttpStatusCode.Forbidden, "network bearer cannot read another member's ticket"); }
    // Correct bearer with an invalid member signature must fail at the real API.
    using var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, c, _, _) => c != null && Convert.ToHexString(SHA256.HashData(c.RawData)) == pin };
    using var http = new HttpClient(handler); http.DefaultRequestHeaders.Authorization = new("Bearer", a.Pair.Auth);
    var forged = TcpObserverProtocol.Create(a, Guid.NewGuid(), "catalog", Guid.Empty) with { Device = b.Self.Device, Slot = b.Self.Slot };
    using var denied = await http.PostAsJsonAsync(url + $"/v3/mesh/{a.Pair.Network}/tcp-observer", forged, ct);
    Check(denied.StatusCode == HttpStatusCode.Forbidden, "forged member identity is rejected over HTTPS");
    var arbitrary = TcpObserverProtocol.Create(a, Guid.NewGuid(), "register", Guid.NewGuid(), [Spec("unconfigured", 5)]);
    using var unknown = await http.PostAsJsonAsync(url + $"/v3/mesh/{a.Pair.Network}/tcp-observer", arbitrary, ct);
    Check(unknown.StatusCode == HttpStatusCode.BadRequest, "authenticated client cannot select arbitrary probe destinations");
    await using var helper = new Reflector { Silent = false }; var generation = Guid.NewGuid();
    using var lease = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), helper.Endpoint, generation, ct);
    var io = new ProbeIo(observer, raw);
    await using var owner = new TcpCaptureOwner(lease, generation, (_, _) => io); await owner.Ready;
    // Use another network/member for the actual sequence to stay inside normal
    // per-member HTTP limits rather than weakening them for test convenience.
    var c = MeshIdentity.Create(url, pin, "faketcp"); using var control = new MeshDiscoveryClient(c); await control.SaveDirectory(c.Directory!, ct);
    int charged = 0; long start = Stopwatch.GetTimestamp();
    var results = await TcpShapeProbe.Run(owner, control, () => { charged++; return true; }, _ => { }, ct, new());
    Check(charged == 3 && results.Length == 4 && results.All(o => o.State == "SynObserved" && o.Mapped == lease.Local.ToString()), "same held source through four destinations and authenticated register/read");
    Check(results.All(o => o.ResourceId == lease.Id && o.NetworkGeneration == generation && o.Protocol == "TCP" && o.Filtering == "Unknown" && o.TcpHandshakeVerified == "NotTested" && o.LegacyPayloadVerified == "NotTested"), "resource, generation and independent evidence levels survive product adapter");
    Check(results.All(o => o.LocalProbeStartedAt > 0 && Stopwatch.GetElapsedTime(o.LocalProbeStartedAt).TotalSeconds >= 6), "legacy final observations retain local probe age and cannot serve as two-second prediction anchors");
    Check(io.Sent == 12 && io.Sources.All(ep => ep.Equals(lease.Local)) && helper.Accepted == 1, "one exclusive helper, no rebind, bounded twelve SYN packets");
    using (var reference = lease.AcquireAttempt(generation)) Check((await reference.Observe(ct)).Public.Equals(lease.Local), "same kernel helper still works after native endpoint observations");
    Check(owner.Status.Sessions == 0, "finished diagnostic leaves no session or tuple reservation");
    int referencesBeforeCancel = lease.ReferenceCount, packetsBeforeCancel = io.Sent;
    using (var cancel = new CancellationTokenSource(80)) {
        try { await TcpShapeProbe.Run(owner, control, () => false, _ => { }, cancel.Token, new()); Check(false, "cancel expected"); }
        catch (OperationCanceledException) { }
    }
    Check(io.Sent == packetsBeforeCancel && lease.ReferenceCount == referencesBeforeCancel && owner.Status.Sessions == 0, "cancellation while queued releases only its reference and emits no packets");
    using (var existing = owner.Register(generation, TcpObserverProtocol.Endpoint(points[0].Endpoint))) {
        existing.Start(); bool refused = false;
        try { await TcpShapeProbe.Run(owner, control, () => true, _ => { }, ct, new()); }
        catch (IOException) { refused = true; }
        Check(refused && io.Sent == packetsBeforeCancel && owner.Status.Sessions == 1 && !existing.Failed, "diagnostic cannot steal an existing TCP tuple or start a second sequence state");
    }
    var expired = await client.TcpObservation("read", ticket, null, ct);
    Check(expired.Evidence.Single().State == "NotObserved", "expired unused ticket reports no observation, not NAT blocked");
    observer.Observe(TcpShapeSyn.Create(new(IPAddress.Loopback, 50000), TcpObserverProtocol.Endpoint(points[0].Endpoint), uint.MaxValue, 100));
    Check((await client.TcpObservation("read", ticket, null, ct)).Evidence.Single().State == "NotObserved", "late SYN cannot revive expired observation");
    rows.Add(new { scope = raw ? "Linux real loopback IPv4 raw I/O and locked kernel BPF; not Windows WinDivert or WAN NAT" : "real HTTPS and exclusive TCP helper with in-memory broker I/O; no raw I/O or NAT",
        elapsedMs = Stopwatch.GetElapsedTime(start).TotalMilliseconds, io.Sent, charged, results });
    rows.Add(await FreshObservationTests.Run(observer, url, pin, points, Check, ct, raw));
    if (raw) {
        long before = capture!.ReceivedPackets;
        // Same target with invalid flags/port/size cannot reach user-space capture.
        byte[] packet = TcpShapeSyn.Create(lease.Local, TcpObserverProtocol.Endpoint(points[0].Endpoint), 99, 100);
        packet[33] = 0x10; io.Inject(packet); packet[33] = 2; packet[23] ^= 1; io.Inject(packet);
        packet[23] ^= 1; packet[32] = 0x90; io.Inject(packet);
        await Task.Delay(200, ct);
        Check(capture.ReceivedPackets == before, "real Linux locked BPF rejects ACK, unconfigured port and data-bearing shape before user space");
        byte[] minimal = packet[..40]; minimal[3] = 40; minimal[32] = 0x50; io.Inject(minimal);
        await Task.Delay(200, ct);
        Check(capture.ReceivedPackets > before, "real Linux BPF accepts a header-only SYN after TCP options are removed");
        rows.Add(new { scope = "Linux kernel filter", before, after = capture.ReceivedPackets });
    }
    await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows }, new JsonSerializerOptions { WriteIndented = true }));
} catch (Exception ex) { await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() }, new JsonSerializerOptions { WriteIndented = true })); throw; }
finally { await app.StopAsync(); }

sealed class ProbeIo : IEndpointPacketIo
{
    readonly TcpSynObserver observer;
    readonly Socket? raw;
    readonly Channel<EndpointPacket> input = Channel.CreateBounded<EndpointPacket>(8);
    public readonly List<IPEndPoint> Sources = [];
    public int Sent;
    public ProbeIo(TcpSynObserver observer, bool kernel) {
        this.observer = observer;
        if (kernel) { raw = new(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Raw); raw.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true); }
    }
    public bool Inject(ReadOnlySpan<byte> p) {
        Sent++;
        var source = new IPEndPoint(new IPAddress(p.Slice(12, 4)), BinaryPrimitives.ReadUInt16BigEndian(p[20..])); Sources.Add(source);
        if (raw == null) observer.Observe(p);
        else raw.SendTo(p, SocketFlags.None, new IPEndPoint(new IPAddress(p.Slice(16, 4)), 0));
        return true;
    }
    public ValueTask<EndpointPacket> Receive(CancellationToken token) => input.Reader.ReadAsync(token);
    public bool Reinject(EndpointPacket packet) => true;
    public void Shutdown() => input.Writer.TryComplete();
    public void Dispose() { raw?.Dispose(); Shutdown(); }
}
