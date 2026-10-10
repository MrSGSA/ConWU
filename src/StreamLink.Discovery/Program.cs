using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using StreamLink.Core;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders(); // Do not log pairing IDs, authorization headers or payloads.
builder.WebHost.ConfigureKestrel(k => { k.Limits.MaxRequestBodySize = 8192; k.Limits.MaxConcurrentConnections = 128; k.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10); });
builder.Services.AddRateLimiter(o => {
    o.RejectionStatusCode = 429;
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetFixedWindowLimiter("all", _ => new() { PermitLimit = 600, Window = TimeSpan.FromSeconds(1), QueueLimit = 0 }));
    o.AddPolicy("metadata", c => RateLimitPartition.GetFixedWindowLimiter(c.Request.RouteValues["network"]?.ToString() ?? "unknown", _ => new() { PermitLimit = 120, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});
var app = builder.Build(); app.UseRateLimiter();
app.Use(async (context, next) => { context.Response.Headers.CacheControl = "no-store"; await next(context); });
string root = Environment.GetEnvironmentVariable("STREAMLINK_DISCOVERY_DATA") ?? Path.Combine(AppContext.BaseDirectory, "data"); Directory.CreateDirectory(root);
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
app.MapGet("/health", () => Results.Json(new { service = "StreamLink discovery", protocol = 2, relay = false }));
app.MapGet("/v1/{network}/{slot:int}", (HttpContext c, string network, int slot) => Exchange(c, network, slot, null)).RequireRateLimiting("metadata");
app.MapPut("/v1/{network}/{slot:int}", (HttpContext c, string network, int slot, Envelope envelope) => Exchange(c, network, slot, envelope)).RequireRateLimiting("metadata");
app.Run();
sealed record Registration(string AuthHash, string One, string Two);
