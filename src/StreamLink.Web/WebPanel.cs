using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using StreamLink.Core;

namespace StreamLink.Web;

public sealed class WebPanel : IAsyncDisposable
{
    sealed class Session(string csrf, long expires) {
        public string Csrf {get;} = csrf;
        public long Expires {get;} = expires;
        public HashSet<Guid> Requests {get;} = [];
    }
    readonly WebApplication app;
    readonly Func<UiControlRequest,CancellationToken,Task<UiControlReply>> call;
    readonly string assets;
    readonly object gate = new();
    readonly Dictionary<string,long> tickets = [];
    readonly Dictionary<string,Session> sessions = [];
    readonly SemaphoreSlim slots = new(8,8);
    long rateStart = Environment.TickCount64;
    int rateCount;
    string origin = "";
    string cookieName="";
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { MaxDepth = 16 };
    static string Secret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public string Origin => origin;

    WebPanel(WebApplication application, Func<UiControlRequest,CancellationToken,Task<UiControlReply>> backend, string root) { app = application; call = backend; assets = root; }
    public static async Task<WebPanel> Start(Func<UiControlRequest,CancellationToken,Task<UiControlReply>> backend, string assets)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], ContentRootPath = AppContext.BaseDirectory });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(o => {
            o.Listen(IPAddress.Loopback, 0);
            o.Limits.MaxRequestBodySize = 65536;
            o.Limits.MaxConcurrentConnections = 32;
            o.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(5);
            o.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
        });
        var app = builder.Build(); var panel = new WebPanel(app,backend,assets);
        app.Run(panel.Handle);
        await app.StartAsync();
        panel.origin = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        panel.cookieName="StreamLinkSession-"+new Uri(panel.origin).Port;
        return panel;
    }
    public string OpenLink()
    {
        lock (gate) {
            Prune();
            if (tickets.Count >= 4) tickets.Remove(tickets.Keys.First());
            string ticket = Secret(); tickets[ticket] = Environment.TickCount64 + 60000;
            return origin + "/#" + ticket;
        }
    }
    void Prune()
    {
        long now = Environment.TickCount64;
        foreach (var key in tickets.Where(x => x.Value <= now).Select(x => x.Key).ToArray()) tickets.Remove(key);
        foreach (var key in sessions.Where(x => x.Value.Expires <= now).Select(x => x.Key).ToArray()) sessions.Remove(key);
    }
    static bool Equal(string a, string b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(System.Text.Encoding.UTF8.GetBytes(a),System.Text.Encoding.UTF8.GetBytes(b));
    async Task Handle(HttpContext context)
    {
        var request = context.Request; var response = context.Response;
        response.Headers.CacheControl = "no-store";
        response.Headers["X-Content-Type-Options"] = "nosniff";
        response.Headers["X-Frame-Options"] = "DENY";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
        if (origin.Length == 0 || context.Connection.RemoteIpAddress is not {} ip || !IPAddress.IsLoopback(ip) || request.Host.Value != new Uri(origin).Authority) { response.StatusCode = 403; return; }
        if (request.QueryString.HasValue || request.Headers.Origin.Count > 1 || request.Headers.Origin.Count == 1 && request.Headers.Origin.ToString() != origin || request.Headers["Sec-Fetch-Site"] is var site && site.Count > 0 && site.ToString() is not ("same-origin" or "none")) { response.StatusCode = 403; return; }
        lock (gate) {
            long now = Environment.TickCount64;
            if (now - rateStart >= 10000) { rateStart = now; rateCount = 0; }
            if (++rateCount > 100) { response.StatusCode = 429; return; }
        }
        if (!await slots.WaitAsync(0)) { response.StatusCode = 429; return; }
        try {
            string path = request.Path.Value ?? "/";
            if (request.Method == "GET" && path is "/" or "/app.js" or "/style.css" or "/icon.svg") {
                response.ContentType = path switch { "/app.js" => "text/javascript; charset=utf-8", "/style.css" => "text/css; charset=utf-8", "/icon.svg"=>"image/svg+xml", _ => "text/html; charset=utf-8" };
                await response.SendFileAsync(Path.Combine(assets,path == "/" ? "index.html" : path[1..]),context.RequestAborted); return;
            }
            bool post = request.Method == "POST";
            if (post && (request.Headers.Origin.ToString() != origin || request.ContentType?.Split(';')[0].Trim() != "application/json" || request.ContentLength is > 65536)) { response.StatusCode = 403; return; }
            if (post && path == "/api/session") {
                var boot = await JsonSerializer.DeserializeAsync<Bootstrap>(request.Body,Json,context.RequestAborted);
                Session session; string id;
                lock (gate) {
                    Prune();
                    if (boot?.Ticket is not {Length:64} ticket || !tickets.Remove(ticket)) { response.StatusCode = 401; return; }
                    if (sessions.Count >= 8) sessions.Remove(sessions.Keys.First());
                    id = Secret(); session = new(Secret(),Environment.TickCount64 + 30 * 60 * 1000); sessions[id] = session;
                }
                response.Cookies.Append(cookieName,id,new CookieOptions { HttpOnly=true, SameSite=SameSiteMode.Strict, IsEssential=true, Path="/", MaxAge=TimeSpan.FromMinutes(30) });
                await response.WriteAsJsonAsync(new {csrf=session.Csrf},context.RequestAborted); return;
            }
            Session? current;
            lock (gate) { Prune(); current = request.Cookies.TryGetValue(cookieName,out var id) ? sessions.GetValueOrDefault(id) : null; }
            if (current == null) { response.StatusCode = 401; return; }
            if (request.Method == "GET" && path == "/api/session") { await response.WriteAsJsonAsync(new {csrf=current.Csrf},context.RequestAborted); return; }
            UiControlRequest command;
            if (request.Method == "GET" && path == "/api/status") command = new("status");
            else if (post && path == "/api/command") {
                if (!Equal(request.Headers["X-StreamLink-CSRF"].ToString(),current.Csrf)) { response.StatusCode = 403; return; }
                command = await JsonSerializer.DeserializeAsync<UiControlRequest>(request.Body,Json,context.RequestAborted) ?? throw new JsonException();
                lock (gate) {
                    if (command.OperationId == Guid.Empty || current.Requests.Count >= 512 || !current.Requests.Add(command.OperationId)) { response.StatusCode = 409; return; }
                }
            } else { response.StatusCode = 404; return; }
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted); deadline.CancelAfter(22000);
            try { await response.WriteAsJsonAsync(await call(command,deadline.Token),context.RequestAborted); }
            catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException) {
                response.StatusCode = 503;
                var known=ex as UiBackendException;
                await response.WriteAsJsonAsync(new {ok=false,code=known?.Code??"Unavailable",error=known?.Message??"本地后台连接暂未完成，请从托盘检查个人服务状态。"},context.RequestAborted);
            }
        } catch (Exception ex) when (ex is JsonException or BadHttpRequestException) { response.StatusCode = 400; }
        finally { slots.Release(); }
    }
    public async ValueTask DisposeAsync() { await app.StopAsync(); await app.DisposeAsync(); slots.Dispose(); }
    [System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
    sealed record Bootstrap(string Ticket);
}
