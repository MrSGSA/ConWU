using System.Net;

namespace StreamLink.Core;

public sealed class TcpMapping : IMapping, IMappingRefresh
{
    readonly Upnp? router;
    readonly RouterMapping? rule;
    readonly PortControlLease? gateway;
    readonly Action<string> log;
    readonly int sourcePort;
    readonly object lifecycle = new();
    readonly CancellationTokenSource stopping = new();
    readonly SemaphoreSlim refresh = new(0, 1);
    readonly TcpHelperRecovery helperRecovery = new();
    Task maintenance = Task.CompletedTask;
    bool disposed, maintaining;
    TcpBinding binding;
    string[] servers = Stun.TcpServers;
    public string StunServer { get; private set; } = "";
    public IPAddress LocalAddress { get; }
    public IPEndPoint PublicEndpoint { get; private set; }
    public string RouterAddress => gateway?.Snapshot.Gateway ?? router!.Service.ControlUrl.Host;
    public bool IsValid => !Volatile.Read(ref disposed) && (gateway?.Valid ?? HelperObservation != null);
    public PortControlSnapshot? GatewayLease => gateway?.Snapshot;
    public StunResult? HelperObservation { get; private set; }
    public TcpBindingSnapshot HelperResource => binding.Snapshot;
    public event Action<IPEndPoint>? Changed;
    internal TcpMapping(Upnp router, RouterMapping rule, TcpBinding binding, StunResult result, Action<string> log, string[]? servers = null)
    {
        this.servers = servers ?? Stun.TcpServers; StunServer = result.Server;
        this.router = router; this.rule = rule; this.binding = binding; this.log = log;
        LocalAddress = result.Local.Address; sourcePort = result.Local.Port; PublicEndpoint = result.Public;
        HelperObservation = result;
        LogHelper();
    }
    internal TcpMapping(PortControlLease gateway, TcpBinding binding, StunResult result, Action<string> log, string[]? servers = null)
    {
        this.servers = servers ?? Stun.TcpServers; StunServer = result.Server;
        this.gateway = gateway; this.binding = binding; this.log = log; LocalAddress = result.Local.Address; sourcePort = result.Local.Port;
        HelperObservation = result; PublicEndpoint = GatewayCandidate(gateway);
        LogHelper();
        log($"网关通知模式 {gateway.Snapshot.NotificationMode}，降级原因 {gateway.Snapshot.NotificationReason}");
        gateway.Changed += _ => {
            if (!gateway.Valid) return;
            var endpoint = GatewayCandidate(gateway);
            if (!endpoint.Equals(PublicEndpoint)) { PublicEndpoint = endpoint; Changed?.Invoke(endpoint); }
        };
    }
    internal static IPEndPoint GatewayCandidate(PortControlLease lease)
    {
        var endpoint = lease.External;
        if (!lease.Valid || !PortControlRoute.GlobalV4(endpoint.Address))
            throw new IOException("网关只返回内层或无效地址；未把 STUN 的外层端点拼接到该映射，需独立验证外层映射链");
        return endpoint;
    }
    void LogHelper()
    {
        var owner = binding.Snapshot;
        log($"TCP helper 独占资源 lease={owner.LeaseId:N} generation={owner.Generation:N} local={owner.Local} reflector={owner.Reflector}");
    }

    public static async Task<TcpMapping> Create(int sourcePort, int targetPort, Action<string> log, CancellationToken token, string[]? servers = null, string? owner = null, bool portControl = false)
    {
        if (sourcePort == targetPort || sourcePort is < 1024 or > 65535 || targetPort is < 1024 or > 65535) throw new ArgumentException("探测源端口和传输端口必须是不同的非特权端口");
        if (owner != null && !Guid.TryParseExact(owner, "N", out _)) throw new ArgumentException("映射所有者无效");
        var timeline = new ConnectionTimeline(log);
        var (binding, result) = await TcpBinding.ConnectAvailable(sourcePort,targetPort,null,log,token,servers);
        sourcePort=result.Local.Port;
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
            if (portControl) {
                log("原有 UPnP 入口不可用，后台尝试本地网关 PCP；仅在明确版本响应后尝试 NAT-PMP");
                using var mappedStop = CancellationTokenSource.CreateLinkedTokenSource(token);
                var creating = PortControlLease.Create(result.Local.Address, targetPort, sourcePort, PortMappingProtocol.Tcp, mappedStop.Token);
                PortControlLease? lease = null;
                try {
                    // Keep the exact helper alive during protocol retransmission;
                    // candidate selection elsewhere never waits for this task.
                    while (!creating.IsCompleted) {
                        await Task.WhenAny(creating, Task.Delay(10000, token));
                        token.ThrowIfCancellationRequested();
                        if (!creating.IsCompleted) result = await binding.Pulse(token);
                    }
                    lease = await creating;
                    var mapping = new TcpMapping(lease, binding, result, log) { servers = servers ?? Stun.TcpServers, StunServer = result.Server };
                    log($"{lease.Snapshot.Provider} 返回实际候选 {mapping.PublicEndpoint} → {targetPort}；仍需对端认证检查");
                    return mapping;
                } catch {
                    mappedStop.Cancel();
                    try { lease ??= await creating; } catch { }
                    if (lease != null) await lease.DisposeAsync();
                    throw;
                }
            }
            if (last == null) throw new IOException("未发现可用 UPnP 网关。自动映射不可用；可使用已有 Lucky 端点或手动转发。");
            throw new IOException("自动映射失败：" + last?.Message, last);
        }
        catch { binding.Dispose(); throw; }
    }

    public Task Maintain(CancellationToken token)
    {
        lock (lifecycle) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (maintaining) throw new InvalidOperationException("映射只能维护一次");
            maintaining = true; return maintenance = MaintainCore(token);
        }
    }
    public void RequestRefresh()
    {
        lock (lifecycle) { if (!disposed && refresh.CurrentCount == 0) refresh.Release(); }
    }
    async Task MaintainCore(CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, stopping.Token); token = linked.Token;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        // Gateway renewal and helper recovery have separate lifetimes. A failed
        // STUN selection must not remove a valid mapping or close its listener.
        var leaseTask = gateway?.Maintain(stop.Token) ?? MaintainRouter(stop.Token);
        var helperTask = MaintainHelper(stop.Token);
        try { await await Task.WhenAny(leaseTask, helperTask); }
        finally { stop.Cancel(); try { await Task.WhenAll(leaseTask, helperTask); } catch { } }
    }
    async Task MaintainRouter(CancellationToken token)
    {
        while (true) {
            // Refresh hints affect observation only, not the 180-second grant.
            await Task.Delay(60000, token);
            await router!.Add(rule!, token);
        }
    }
    async Task MaintainHelper(CancellationToken token)
    {
        bool connected = true; int failures = 0; long retryAt = 0;
        while (true) {
            await refresh.WaitAsync(TimeSpan.FromSeconds(10), token);
            if (!connected && Environment.TickCount64 < retryAt) continue;
            try {
                StunResult observation;
                if (connected) observation = await binding.Pulse(token);
                else {
                    (binding, var result) = await TcpBinding.Connect(sourcePort, LocalAddress, log, token, helperRecovery.Candidates(servers, StunServer));
                    observation = result; StunServer = result.Server; connected = true; failures = 0;
                    LogHelper();
                }
                if (gateway == null && !observation.Public.Equals(PublicEndpoint)) {
                    PublicEndpoint = observation.Public;
                    log("公网映射观察已变化，发布新候选；已有直连仍由双向保活判断");
                    Changed?.Invoke(PublicEndpoint);
                }
                HelperObservation = observation;
            } catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or System.Net.Sockets.SocketException or OperationCanceledException) {
                if (connected) helperRecovery.Failed(StunServer);
                binding.Dispose(); HelperObservation = null; connected = false;
                // A disappeared local address needs a new mapping owner/source,
                // unlike an unavailable reflector. Do not retry a dead NIC forever.
                if (!LocalSourcePresent(LocalAddress)) throw new IOException("本机入口源地址已失效，需要重新发现网络入口", ex);
                retryAt = Environment.TickCount64 + Math.Min(45000, 5000L << Math.Min(failures++, 4));
                log($"STUN 辅助观察暂不可用 reason={HelperFailure(ex)}；保留网关租约和已有业务路径，退避后优先尝试其他已配置服务");
            }
            // A helper's outer mapping is a different observation. It cannot
            // overwrite the actual external port returned for the listening Q.
        }
    }
    internal static bool LocalSourcePresent(IPAddress address)
    {
        try { return System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Any(n => n.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(address))); }
        catch (System.Net.NetworkInformation.NetworkInformationException) { return true; } // unknown is not removal proof
    }
    internal static string HelperFailure(Exception error) => error switch {
        EndOfStreamException => "RemoteClosed",
        OperationCanceledException => "QueryTimeoutOrCancellation",
        System.Net.Sockets.SocketException socket => "Socket:" + socket.SocketErrorCode,
        IOException { InnerException: System.Net.Sockets.SocketException socket } => "Socket:" + socket.SocketErrorCode,
        _ => error.GetType().Name
    };
    public async ValueTask DisposeAsync()
    {
        lock (lifecycle) { if (disposed) return; disposed = true; }
        stopping.Cancel(); try { await maintenance; } catch { }
        binding.Dispose();
        if (gateway != null) { try { await gateway.DisposeAsync(); log("端口控制资源已回收；网关清理状态：" + gateway.Snapshot.Cleanup); } finally { stopping.Dispose(); refresh.Dispose(); } return; }
        try { await router!.RemoveOwned(rule!, CancellationToken.None); log("已移除本软件的路由器租约"); }
        catch (Exception ex) { log("租约删除未确认，将按租期到期：" + ex.Message); }
        router!.Dispose(); stopping.Dispose(); refresh.Dispose();
    }
}
