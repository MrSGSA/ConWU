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
    public const int DefaultPort=47821;
    const long IdleMs=30*60*1000, MaximumSessionMs=8*60*60*1000;
    sealed class Session(string csrf, long now) {
        public string Csrf {get;} = csrf;
        public long Expires = now+IdleMs;
        public long CookieIssued = now;
        public readonly long AbsoluteExpires = now+MaximumSessionMs;
        public HashSet<Guid> Requests {get;} = [];
    }
    readonly WebApplication app;
    readonly Func<UiControlRequest,CancellationToken,Task<UiControlReply>> call;
    readonly string assets;
    readonly object gate = new();
    readonly Dictionary<string,long> tickets = [];
    readonly Dictionary<string,Session> sessions = [];
    readonly SemaphoreSlim slots = new(8,8);
    readonly TimeProvider clock;
    readonly long clockStart;
    long Now => (long)clock.GetElapsedTime(clockStart).TotalMilliseconds;
    long rateStart;
    int rateCount;
    string origin = "";
    string cookieName="";
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { MaxDepth = 16 };
    static string Secret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public string Origin => origin;

    WebPanel(WebApplication application, Func<UiControlRequest,CancellationToken,Task<UiControlReply>> backend, string root, TimeProvider time) { app = application; call = backend; assets = root; clock=time;clockStart=clock.GetTimestamp(); }
    public static async Task<WebPanel> Start(Func<UiControlRequest,CancellationToken,Task<UiControlReply>> backend, string assets, TimeProvider? timeProvider=null, int port=0)
    {
        if(port!=0 && (port is <1024 or >65535)) throw new ArgumentOutOfRangeException(nameof(port));
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], ContentRootPath = AppContext.BaseDirectory });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(o => {
            o.Listen(IPAddress.Loopback, port);
            o.Limits.MaxRequestBodySize = 65536;
            o.Limits.MaxConcurrentConnections = 32;
            o.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(5);
            o.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
        });
        var app = builder.Build(); var panel = new WebPanel(app,backend,assets,timeProvider??TimeProvider.System);
        app.Run(panel.Handle);
        try { await app.StartAsync(); }
        catch { await app.DisposeAsync(); throw; }
        panel.origin = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        panel.cookieName="StreamLinkSession-"+new Uri(panel.origin).Port;
        return panel;
    }
    public string OpenLink()
    {
        lock (gate) {
            Prune();
            if (tickets.Count >= 4) tickets.Remove(tickets.Keys.First());
            string ticket = Secret(); tickets[ticket] = Now + 60000;
            return origin + "/#" + ticket;
        }
    }
    void Prune()
    {
        long now = Now;
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
        if (request.Headers.Origin.Count > 1 || request.Headers.Origin.Count == 1 && request.Headers.Origin.ToString() != origin || request.Headers["Sec-Fetch-Site"] is var site && site.Count > 0 && site.ToString() is not ("same-origin" or "none")) { response.StatusCode = 403; return; }
        // Progress is the only route that accepts a query. An operation ID is
        // just a selector; the session/Origin/CSRF boundaries below still apply.
        Guid operation = Guid.Empty;
        if (request.QueryString.HasValue) {
            if (request.Method != "GET" || request.Path != "/api/status" || request.Query.Count != 1 ||
                request.Query.Single().Key != "operation" || request.Query["operation"].Count != 1) { response.StatusCode = 403; return; }
            string selector = request.Query["operation"].ToString();
            if (selector.Length != 36 || !Guid.TryParseExact(selector, "D", out operation) || operation == Guid.Empty) { response.StatusCode = 400; return; }
        }
        lock (gate) {
            long now = Now;
            if (now - rateStart >= 10000) { rateStart = now; rateCount = 0; }
            if (++rateCount > 100) { response.StatusCode = 429; return; }
        }
        if (!await slots.WaitAsync(0)) { response.StatusCode = 429; return; }
        try {
            string path = request.Path.Value ?? "/";
            if (request.Method == "GET" && path is "/" or "/app.js" or "/style.css" or "/icon.svg" or "/streamlink-tokyo-45.svg") {
                response.ContentType = path switch { "/app.js" => "text/javascript; charset=utf-8", "/style.css" => "text/css; charset=utf-8", "/icon.svg" or "/streamlink-tokyo-45.svg"=>"image/svg+xml", _ => "text/html; charset=utf-8" };
                string file = path switch { "/" => "index.html", "/streamlink-tokyo-45.svg" => "icon.svg", _ => path[1..] };
                await response.SendFileAsync(Path.Combine(assets,file),context.RequestAborted); return;
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
                    id = Secret(); session = new(Secret(),Now); sessions[id] = session;
                }
                response.Cookies.Append(cookieName,id,new CookieOptions { HttpOnly=true, SameSite=SameSiteMode.Strict, IsEssential=true, Path="/", MaxAge=TimeSpan.FromMinutes(30) });
                await response.WriteAsJsonAsync(new {csrf=session.Csrf},context.RequestAborted); return;
            }
            Session? current;
            string? sessionId;
            lock (gate) { Prune(); current = request.Cookies.TryGetValue(cookieName,out sessionId) ? sessions.GetValueOrDefault(sessionId) : null; }
            if (current == null) { response.StatusCode = 401; return; }
            void Touch() {
                lock(gate) {
                    long now=Now;current.Expires=Math.Min(current.AbsoluteExpires,now+IdleMs);
                    if(now-current.CookieIssued>=60000) {
                        response.Cookies.Append(cookieName,sessionId!,new CookieOptions {HttpOnly=true,SameSite=SameSiteMode.Strict,IsEssential=true,Path="/",MaxAge=TimeSpan.FromMilliseconds(Math.Max(0,current.Expires-now))});
                        current.CookieIssued=now;
                    }
                }
            }
            if (request.Method == "GET" && path == "/api/session") { Touch();await response.WriteAsJsonAsync(new {csrf=current.Csrf},context.RequestAborted); return; }
            UiControlRequest command;
            if (request.Method == "GET" && path == "/api/status") {
                command = new("status",OperationId:operation);
            }
            else if (post && path == "/api/command") {
                if (!Equal(request.Headers["X-StreamLink-CSRF"].ToString(),current.Csrf)) {
                    response.StatusCode = 403;
                    await response.WriteAsJsonAsync(new {ok=false,code="SessionChanged",error="面板会话已更新，需要重新读取当前会话。"},context.RequestAborted);
                    return;
                }
                command = await JsonSerializer.DeserializeAsync<UiControlRequest>(request.Body,Json,context.RequestAborted) ?? throw new JsonException();
                lock (gate) {
                    if (command.OperationId == Guid.Empty || current.Requests.Count >= 512 || !current.Requests.Add(command.OperationId)) { response.StatusCode = 409; return; }
                }
            } else { response.StatusCode = 404; return; }
            Touch(); // Only an authenticated, valid route may renew idle time.
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
