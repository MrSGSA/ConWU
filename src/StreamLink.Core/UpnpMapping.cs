using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// A direct, owned IGD grant does not depend on a STUN server being online.
// Private/CGN WAN addresses are deliberately not promoted to public entries.
public sealed class UpnpMapping : IMapping, IMappingRefresh
{
    readonly Upnp router;
    RouterMapping rule;
    readonly Action<string> log;
    readonly CancellationTokenSource stop = new();
    readonly SemaphoreSlim refresh = new(0, 1);
    readonly object lifecycle = new();
    readonly TimeSpan renewal;
    Task maintenance = Task.CompletedTask;
    long expires;
    bool disposed, started;
    public IPAddress LocalAddress => router.Service.LocalAddress;
    public IPEndPoint PublicEndpoint { get; private set; }
    public bool IsValid => !Volatile.Read(ref disposed) && Environment.TickCount64 < Volatile.Read(ref expires);
    public event Action<IPEndPoint>? Changed;
    UpnpMapping(Upnp router, RouterMapping rule, IPAddress external, Action<string> log, TimeSpan renewal)
    {
        this.router = router; this.rule = rule; this.log = log; this.renewal = renewal;
        PublicEndpoint = new(external, rule.ExternalPort); expires = Environment.TickCount64 + 180000;
    }
    public static Task<IMapping> CreateTcp(int port, Action<string> log, CancellationToken token) =>
        Create(port, PortControlRoute.LocalSources, Upnp.DiscoverServices, log, token);
    internal static async Task<IMapping> Create(int port, Func<IPAddress[]> sources,
        Func<IPAddress, CancellationToken, IAsyncEnumerable<RouterService>> discover, Action<string> log, CancellationToken token,
        TimeSpan? renewal = null)
    {
        if (port is < 1024 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        Exception? last = null;
        foreach (var local in sources().Distinct().Take(4)) {
            try {
                await foreach (var service in discover(local, token)) {
                    var router = new Upnp(service); RouterMapping? rule = null;
                    try {
                        if (!IPAddress.TryParse(await router.ExternalAddress(token), out var external) || !PortControlRoute.GlobalV4(external)) {
                            router.Dispose(); continue;
                        }
                        var requested = new RouterMapping(port, port, local.ToString(), "TCP", "ConWU-" + Guid.NewGuid().ToString("N"));
                        rule = requested;
                        rule = await router.Reserve(requested, token);
                        token.ThrowIfCancellationRequested();
                        var mapping = new UpnpMapping(router, rule, external, log, renewal ?? TimeSpan.FromSeconds(60));
                        log($"UPnP 已授予本机 TCP 端口 {local}:{port} → {mapping.PublicEndpoint}（180 秒租约）；等待对端认证验证");
                        return mapping;
                    } catch (Exception ex) when (ex is IOException or HttpRequestException or SocketException or OperationCanceledException) {
                        if (rule != null) try { await router.RemoveOwned(rule, CancellationToken.None); } catch { }
                        router.Dispose(); token.ThrowIfCancellationRequested(); last = ex;
                    }
                }
            } catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or SocketException or HttpRequestException) { last = ex; }
        }
        token.ThrowIfCancellationRequested(); throw new IOException("未取得有效的公网 UPnP 租约，继续尝试其他自主入口", last);
    }
    public Task Maintain(CancellationToken token)
    {
        lock (lifecycle) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (started) throw new InvalidOperationException("UPnP 租约只能维护一次");
            started = true; return maintenance = Run(token);
        }
    }
    public void RequestRefresh() { lock (lifecycle) if (!disposed && refresh.CurrentCount == 0) refresh.Release(); }
    async Task Run(CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token); token = linked.Token;
        int failures = 0; var delay = renewal;
        while (true) {
            await refresh.WaitAsync(delay, token);
            try {
                if (!TcpMapping.LocalSourcePresent(LocalAddress)) throw new IOException("UPnP 源地址已变化，需要重新发现网关");
                // A router reboot may lose the rule; a foreign replacement must
                // survive. Reserve returns the actual new port in that case.
                rule = await router.Reserve(rule, token);
                if (!IPAddress.TryParse(await router.ExternalAddress(token), out var external) || !PortControlRoute.GlobalV4(external)) {
                    Volatile.Write(ref expires, 0);
                    throw new IOException("网关 WAN 地址已变为内层地址，重新准备外层候选");
                }
                var endpoint = new IPEndPoint(external, rule.ExternalPort);
                bool changed = !endpoint.Equals(PublicEndpoint); PublicEndpoint = endpoint;
                Volatile.Write(ref expires, Environment.TickCount64 + 180000);
                if (changed) Changed?.Invoke(endpoint);
                if (failures > 0) log("UPnP 租约维护已恢复，继续使用本机接收端口");
                failures = 0; delay = renewal;
            } catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or HttpRequestException or SocketException or OperationCanceledException) {
                if (!TcpMapping.LocalSourcePresent(LocalAddress) || !IsValid) throw new IOException("UPnP 租约已失效，需要重新发现入口", ex);
                delay = TimeSpan.FromSeconds(Math.Min(20, 5 << Math.Min(failures++, 2)));
                log($"UPnP 续租暂未确认，保留尚未到期的租约及已有直连；{delay.TotalSeconds:0} 秒后重试：{ex.GetType().Name}");
            }
        }
    }
    public async ValueTask DisposeAsync()
    {
        lock (lifecycle) { if (disposed) return; disposed = true; }
        stop.Cancel(); try { await maintenance; } catch { }
        try { await router.RemoveOwned(rule, CancellationToken.None); }
        catch (Exception ex) when (ex is IOException or HttpRequestException or OperationCanceledException) { log("UPnP 删除未确认，租约将自然到期：" + ex.GetType().Name); }
        finally { router.Dispose(); stop.Dispose(); refresh.Dispose(); }
    }
}
