using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using StreamLink.Core;


namespace StreamLink.Discovery;

// The standalone launcher and integrated device host share exactly the same routes,
// persistence and request limits. No second membership implementation.
public sealed record CoordinationHostOptions(string DataDirectory, string? ListenUrl = null,
    string CertificateFile = "", string CertificateKeyFile = "", bool TrustCloudflare = false, string? TcpObserverPoints = null)
{
    public void Validate() {
        if (string.IsNullOrWhiteSpace(DataDirectory)) throw new ArgumentException("协调数据目录不能为空");
        if (ListenUrl == null) return; // Standalone compatibility: ASP.NET hosting configuration.
        if (!Uri.TryCreate(ListenUrl, UriKind.Absolute, out var url) || url.Scheme is not ("http" or "https") ||
            !System.Net.IPAddress.TryParse(url.Host, out var ip) || url.AbsolutePath != "/" || url.Query.Length != 0 || url.Fragment.Length != 0 || url.UserInfo.Length != 0)
            throw new ArgumentException("协调监听地址需为 http(s)://监听IP:端口");
        if (url.Scheme == "http" && !System.Net.IPAddress.IsLoopback(ip)) throw new ArgumentException("未加密协调监听仅允许本机；公网监听需要 HTTPS 证书");
        if (url.Scheme == "https" && (!File.Exists(CertificateFile) || !File.Exists(CertificateKeyFile))) throw new ArgumentException("HTTPS 监听需要 PEM 证书和私钥文件");
    }
}

public sealed class CoordinationHost : IAsyncDisposable
{
    readonly WebApplication app;
    readonly LinuxSynCapture? capture;
    readonly FileStream lease;
    CoordinationHost(WebApplication app, LinuxSynCapture? capture, FileStream lease) { this.app = app; this.capture = capture; this.lease = lease; }
    public Task Start(CancellationToken token = default) => app.StartAsync(token);
    public Task Run(CancellationToken token = default) => app.RunAsync(token);
    public string[] Addresses => app.Urls.ToArray();
    public static CoordinationHost Create(CoordinationHostOptions options, string[]? args = null)
    {
        options.Validate();
        if(OperatingSystem.IsLinux())LinuxPlatform.PrivateDirectory(options.DataDirectory);
        else Directory.CreateDirectory(options.DataDirectory);
        if ((File.GetAttributes(options.DataDirectory) & FileAttributes.ReparsePoint) != 0) throw new IOException("协调数据目录不能是链接");
        var lease = new FileStream(Path.Combine(options.DataDirectory, "coordinator.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try {
var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args ?? [], ContentRootPath = AppContext.BaseDirectory });
builder.Logging.ClearProviders(); // Do not log pairing IDs, authorization headers or payloads.
builder.WebHost.ConfigureKestrel(k => { k.Limits.MaxRequestBodySize = 16384; k.Limits.MaxConcurrentConnections = 128; k.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10); });
builder.Services.AddRateLimiter(o => {
    o.RejectionStatusCode = 429;
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetFixedWindowLimiter("all", _ => new() { PermitLimit = 600, Window = TimeSpan.FromSeconds(1), QueueLimit = 0 }));
    o.AddPolicy("mesh", c => RateLimitPartition.GetFixedWindowLimiter(c.Request.RouteValues["network"]?.ToString() ?? "unknown", _ => new() { PermitLimit = 512, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    o.AddPolicy("metadata", c => RateLimitPartition.GetFixedWindowLimiter(c.Request.RouteValues["network"]?.ToString() ?? "unknown", _ => new() { PermitLimit = 120, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    o.AddPolicy("pair-create", c => RateLimitPartition.GetFixedWindowLimiter(ClientAddress(c), _ => new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    o.AddPolicy("pair-join", c => RateLimitPartition.GetFixedWindowLimiter(ClientAddress(c), _ => new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    o.AddPolicy("pair-room", c => RateLimitPartition.GetFixedWindowLimiter(c.Request.RouteValues["room"]?.ToString() ?? "unknown", _ => new() { PermitLimit = 120, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});
string ClientAddress(HttpContext c) => options.TrustCloudflare && c.Connection.RemoteIpAddress is { } address && System.Net.IPAddress.IsLoopback(address) && System.Net.IPAddress.TryParse(c.Request.Headers["CF-Connecting-IP"].ToString(), out var forwarded) ? forwarded.ToString() : c.Connection.RemoteIpAddress?.ToString() ?? "unknown";
options.Validate();
if (options.ListenUrl != null) {
    var listen = new Uri(options.ListenUrl);
    builder.WebHost.ConfigureKestrel(k => k.Listen(System.Net.IPAddress.Parse(listen.Host), listen.Port, endpoint => {
        if (listen.Scheme == "https") endpoint.UseHttps(System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(options.CertificateFile, options.CertificateKeyFile));
    }));
}
var app = builder.Build(); app.UseRateLimiter();
app.Use(async (context, next) => { context.Response.Headers.CacheControl = "no-store"; await next(context); });
app.Use(async (context,next) => {
    string path=context.Request.Path.Value??"";
    long limit=Regex.IsMatch(path,@"^/v[34]/mesh/[a-f0-9]{32}/(membership|directory)$")?MeshGovernance.MaximumDirectoryBytes+4096:
        Regex.IsMatch(path,@"^/v2/pair/[a-f0-9]{32}/approve$")?MeshGovernance.MaximumCipher+4096:16384;
    var size=context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>();
    if(size is {IsReadOnly:false})size.MaxRequestBodySize=limit;
    await next(context);
});
string root = Path.GetFullPath(options.DataDirectory); Directory.CreateDirectory(root);
string file = Path.Combine(root, "networks.json");
var networks = File.Exists(file) ? JsonSerializer.Deserialize<Dictionary<string, Registration>>(File.ReadAllText(file))! : new();
var messages = new Dictionary<string, (Envelope Message, DateTimeOffset Expires)>(); object sync = new();
void Save() { File.WriteAllText(file + ".tmp", JsonSerializer.Serialize(networks)); File.Move(file + ".tmp", file, true); }
IResult Exchange(HttpContext ctx, string network, int slot, Envelope? envelope)
{
    string auth = ctx.Request.Headers.Authorization.ToString();
    if (!Guid.TryParseExact(network, "N", out _) || slot is < 1 or > 2 || !Regex.IsMatch(auth, "^Bearer [A-F0-9]{64}$")) return Results.BadRequest();
    string hash = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(auth)));
    if (envelope != null && (!Guid.TryParseExact(envelope.Device, "N", out _) || envelope.Revision <= 0 || envelope.Data is null || envelope.Data.Length is < 40 or > 5500)) return Results.BadRequest();
    lock (sync)
    {
        if (!networks.TryGetValue(network, out var registration))
        {
            if (envelope == null) return Results.NotFound();
            if (networks.Count >= 2048) return Results.StatusCode(503);
            registration = new(hash, "", ""); networks.Add(network, registration); Save();
        }
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(hash), Convert.FromHexString(registration.AuthHash))) return Results.Unauthorized();
        string key = network + "/" + slot;
        if (envelope == null) return messages.TryGetValue(key, out var found) && found.Expires > DateTimeOffset.UtcNow ? Results.Json(found.Message) : Results.NoContent();
        string device = slot == 1 ? registration.One : registration.Two;
        if (device.Length != 0 && device != envelope.Device) return Results.Conflict(new { error = "slot-already-paired" });
        if (messages.TryGetValue(key, out var old) && envelope.Revision <= old.Message.Revision) return Results.Conflict(new { error = "stale-revision" });
        if (device.Length == 0) { networks[network] = slot == 1 ? registration with { One = envelope.Device } : registration with { Two = envelope.Device }; Save(); }
        messages[key] = (envelope, DateTimeOffset.UtcNow.AddSeconds(120)); return Results.NoContent();
    }
}
var pairRooms = new PairRooms();
var meshRegistry = new MeshRegistry(root);
TcpSynObserver? synObserver = null;
LinuxSynCapture? synCapture = null;
// Explicit deployment configuration only. Every IP must be assigned to this
// host, not a CDN hostname, destination selected by a client, or translated VIP.
string? observerConfig = options.TcpObserverPoints;
if (!string.IsNullOrWhiteSpace(observerConfig)) {
    try {
        var points = JsonSerializer.Deserialize<TcpObserverPoint[]>(observerConfig) ?? throw new FormatException();
        TcpObserverProtocol.ValidatePoints(points);
        var localAddresses = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(a => a.Address).ToHashSet();
        if (points.Any(p => !localAddresses.Contains(TcpObserverProtocol.Endpoint(p.Endpoint).Address))) throw new FormatException("观察地址不在本机接口上");
        synObserver = new(points); synCapture = new(synObserver, points);
    } catch (Exception ex) when (ex is FormatException or JsonException or ArgumentException or System.Net.Sockets.SocketException or PlatformNotSupportedException) {
        synObserver = null; // A missing raw capability must not take down discovery.
        Console.Error.WriteLine("TCP observer disabled: " + ex.GetType().Name);
    }
}
app.MapPost("/v3/mesh/{network}/tcp-observer", (HttpContext c, string network, TcpObserverRequest request) => meshRegistry.TcpObservation(c, network, request, synObserver)).RequireRateLimiting("mesh");
app.MapGet("/v3/mesh/{network}", (HttpContext c, string network) => meshRegistry.Read(c, network)).RequireRateLimiting("mesh");
app.MapPost("/v3/mesh/{network}/watch", (HttpContext c, string network, MeshWatchRequest request) => meshRegistry.Watch(c, network, request)).RequireRateLimiting("mesh");
app.MapPost("/v3/mesh/{network}/traversal", (HttpContext c, string network, MeshTraversalBatch input) => meshRegistry.Traversal(c, network, input)).RequireRateLimiting("mesh");
app.MapPut("/v3/mesh/{network}/directory", (HttpContext c, string network, MeshDirectory directory) => meshRegistry.Directory(c, network, directory)).RequireRateLimiting("mesh");
app.MapPut("/v3/mesh/{network}/nodes/{slot:int}", (HttpContext c, string network, int slot, MeshEnvelope envelope) => meshRegistry.Publish(c, network, slot, envelope)).RequireRateLimiting("mesh");
app.MapPut("/v4/mesh/{network}/membership", (HttpContext c,string network,MeshMembershipRequest request)=>meshRegistry.Membership(c,network,request)).RequireRateLimiting("mesh");
app.MapGet("/health", () => Results.Json(new { service = "StreamLink coordination", protocol = 3, metadataProtocol = 2, shortPairing = true, pairingDecisions = 1, memberRejoin = 1, meshAddressing = 1, meshProtocol = 4, meshGovernance = 1, integratedCoordinator = 1, meshWatch = 1, meshTraversal = 1, tcpSynObserver = synObserver?.Available == true ? 1 : 0, maxMembers = MeshIdentity.MaxMembers, relay = false }));
app.MapPost("/v2/pair", (PairRoomCreate input) => pairRooms.Create(input)).RequireRateLimiting("pair-create");
app.MapPost("/v2/pair/join", (PairRoomJoin input) => pairRooms.Join(input)).RequireRateLimiting("pair-join");
app.MapGet("/v2/pair/{room}/owner", (HttpContext c, string room) => pairRooms.Exchange(c, room, true)).RequireRateLimiting("pair-room");
app.MapGet("/v2/pair/{room}/guest", (HttpContext c, string room) => pairRooms.Exchange(c, room, false)).RequireRateLimiting("pair-room");
app.MapPost("/v2/pair/{room}/owner/reveal", (HttpContext c, string room, PairRoomReveal input) => pairRooms.Exchange(c, room, true, input)).RequireRateLimiting("pair-room");
app.MapPost("/v2/pair/{room}/guest/reveal", (HttpContext c, string room, PairRoomReveal input) => pairRooms.Exchange(c, room, false, input)).RequireRateLimiting("pair-room");
app.MapPost("/v2/pair/{room}/approve", (HttpContext c, string room, PairRoomApproval input) => pairRooms.Exchange(c, room, true, approve: input)).RequireRateLimiting("pair-room");
app.MapDelete("/v2/pair/{room}", (HttpContext c, string room) => pairRooms.Exchange(c, room, true, close: true)).RequireRateLimiting("pair-room");
app.MapPost("/v2/pair/{room}/reject", (HttpContext c,string room) => pairRooms.Exchange(c,room,true,finish:true)).RequireRateLimiting("pair-room");
app.MapPost("/v2/pair/{room}/guest/cancel", (HttpContext c,string room) => pairRooms.Exchange(c,room,false,finish:true)).RequireRateLimiting("pair-room");
app.MapGet("/v1/{network}/{slot:int}", (HttpContext c, string network, int slot) => Exchange(c, network, slot, null)).RequireRateLimiting("metadata");
app.MapPut("/v1/{network}/{slot:int}", (HttpContext c, string network, int slot, Envelope envelope) => Exchange(c, network, slot, envelope)).RequireRateLimiting("metadata");
return new(app, synCapture, lease);
        } catch { lease.Dispose(); throw; }
    }
    public async ValueTask DisposeAsync() {
        try { await app.StopAsync(TimeSpan.FromSeconds(10)); }
        finally { try { if (capture != null) await capture.DisposeAsync(); await app.DisposeAsync(); } finally { lease.Dispose(); } }
    }
    sealed record Registration(string AuthHash, string One, string Two);
}
