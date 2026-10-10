using System.Net;

namespace StreamLink.Core;

public sealed class TcpMapping : IMapping
{
    readonly Upnp router;
    readonly RouterMapping rule;
    readonly Action<string> log;
    readonly int sourcePort;
    TcpBinding binding;
    string[] servers = Stun.TcpServers;
    public string StunServer { get; private set; } = "";
    public IPAddress LocalAddress { get; }
    public IPEndPoint PublicEndpoint { get; private set; }
    public string RouterAddress => router.Service.ControlUrl.Host;
    public event Action<IPEndPoint>? Changed;
    TcpMapping(Upnp router, RouterMapping rule, TcpBinding binding, StunResult result, Action<string> log)
    {
        this.router = router; this.rule = rule; this.binding = binding; this.log = log;
        LocalAddress = result.Local.Address; sourcePort = result.Local.Port; PublicEndpoint = result.Public;
    }

    public static async Task<TcpMapping> Create(int sourcePort, int targetPort, Action<string> log, CancellationToken token, string[]? servers = null, string? owner = null)
    {
        if (sourcePort == targetPort || sourcePort is < 1024 or > 65535 || targetPort is < 1024 or > 65535) throw new ArgumentException("探测源端口和传输端口必须是不同的非特权端口");
        if (owner != null && !Guid.TryParseExact(owner, "N", out _)) throw new ArgumentException("映射所有者无效");
        var timeline = new ConnectionTimeline(log);
        var (binding, result) = await TcpBinding.Connect(sourcePort, null, log, token, servers);
        timeline.Mark("TCP STUN 建连与查询完成");
        try
        {
            log($"TCP STUN 返回 {result.Public}，正在发现路由器；尚未确认入站可达");
            Exception? last = null;
            await foreach (var service in Upnp.DiscoverServices(result.Local.Address, token))
            {
                timeline.Mark("发现路由器候选，立即尝试租约");
                var router = new Upnp(service);
                var rule = new RouterMapping(sourcePort, targetPort, result.Local.Address.ToString(), "TCP", "StreamLink-" + (owner ?? Guid.NewGuid().ToString("N")));
                bool added = false;
                try
                {
                    await router.Add(rule, token); added = true;
                    result = await binding.Pulse(token);
                    timeline.Mark("路由器租约与映射复核完成");
                    log($"已申请 180 秒路由器租约 {sourcePort} → {targetPort}，保活使用同一 STUN 连接；等待对端验证");
                    return new TcpMapping(router, rule, binding, result, log) { servers = servers ?? Stun.TcpServers, StunServer = result.Server };
                }
                catch (Exception ex)
                {
                    last = ex;
                    if (added) { try { await router.RemoveOwned(rule, CancellationToken.None); } catch { } }
                    router.Dispose(); if (token.IsCancellationRequested) throw;
                }
            }
            if (last == null) throw new IOException("未发现可用 UPnP 网关。自动映射不可用；可使用已有 Lucky 端点或手动转发。");
            throw new IOException("自动映射失败：" + last?.Message, last);
        }
        catch { binding.Dispose(); throw; }
    }

    public async Task Maintain(CancellationToken token)
    {
        int tick = 0;
        while (true)
        {
            await Task.Delay(TimeSpan.FromSeconds(10), token);
            StunResult result;
            try { result = await binding.Pulse(token); }
            catch (Exception) when (!token.IsCancellationRequested)
            {
                binding.Dispose();
                log("STUN 保活连接断开，正在重建并复核映射");
                (binding, result) = await TcpBinding.Connect(sourcePort, LocalAddress, log, token, servers.OrderByDescending(s => s == StunServer));
                StunServer = result.Server;
            }
            if (!result.Public.Equals(PublicEndpoint))
            {
                PublicEndpoint = result.Public;
                log("公网映射已变化，发布更新后的端点");
                Changed?.Invoke(PublicEndpoint);
            }
            if (++tick % 6 == 0) await router.Add(rule, token);
        }
    }
    public async ValueTask DisposeAsync()
    {
        binding.Dispose();
        try { await router.RemoveOwned(rule, CancellationToken.None); log("已移除本软件的路由器租约"); }
        catch (Exception ex) { log("租约删除未确认，将按租期到期：" + ex.Message); }
        router.Dispose();
    }
}
