using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// Explicit Q -> externally assigned endpoint only. There is no inferred CGN
// chain and no helper socket P: native retains its own listener Q as before.
public sealed class GatewayMapping : IMapping
{
    readonly PortControlLease lease;
    readonly Action<string> log;
    int disposed;
    public IPAddress LocalAddress { get; }
    public IPEndPoint PublicEndpoint { get; private set; }
    public bool IsValid => Volatile.Read(ref disposed) == 0 && lease.Valid;
    public PortControlSnapshot Snapshot => lease.Snapshot;
    public event Action<IPEndPoint>? Changed;
    internal GatewayMapping(PortControlLease lease, IPAddress local, Action<string> log)
    {
        var snapshot = lease.Snapshot;
        if (snapshot.Protocol != PortMappingProtocol.Tcp || !IPEndPoint.Parse(snapshot.Local).Address.Equals(local)) throw new IOException("独立 TCP 入口租约与本地资源不匹配");
        this.lease = lease; this.log = log; LocalAddress = local; PublicEndpoint = TcpMapping.GatewayCandidate(lease);
        lease.Changed += _ => {
            if (!IsValid) return;
            var endpoint = TcpMapping.GatewayCandidate(lease);
            if (!endpoint.Equals(PublicEndpoint)) { PublicEndpoint = endpoint; Changed?.Invoke(endpoint); }
        };
        log($"独立 {lease.Snapshot.Provider} 入口 {PublicEndpoint}，无需 STUN 观察；仍待对端认证检查");
        log($"网关通知模式 {lease.Snapshot.NotificationMode}，降级原因 {lease.Snapshot.NotificationReason}");
    }
    public Task Maintain(CancellationToken token) { ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this); return lease.Maintain(token); }
    public async ValueTask DisposeAsync() { if (Interlocked.Exchange(ref disposed, 1) != 0) return; await lease.DisposeAsync(); log("独立网关入口清理：" + lease.Snapshot.Cleanup); }

    public static Task<IMapping> CreateTcp(int sourcePort, int targetPort, Action<string> log, CancellationToken token,
        string[]? servers = null, string? owner = null, bool portControl = false)
    {
        if (sourcePort == targetPort || sourcePort is < 1024 or > 65535 || targetPort is < 1024 or > 65535) throw new ArgumentException("探测源端口和传输端口必须是不同的非特权端口");
        if (owner != null && !Guid.TryParseExact(owner, "N", out _)) throw new ArgumentException("映射所有者无效");
        return SelectTcp(ct => TcpMapping.Create(sourcePort, targetPort, log, ct, servers, owner), PortControlRoute.LocalSources,
            (ip, ct) => PortControlLease.Create(ip, targetPort, 0, PortMappingProtocol.Tcp, ct), portControl, log, token);
    }
    internal static async Task<IMapping> SelectTcp(Func<CancellationToken, Task<TcpMapping>> legacy, Func<IPAddress[]> sources,
        Func<IPAddress, CancellationToken, Task<PortControlLease>> open, bool enabled, Action<string> log, CancellationToken token)
    {
        try { return await legacy(token); }
        catch (Exception ex) when (enabled && !token.IsCancellationRequested && ex is IOException or SocketException or TimeoutException or OperationCanceledException) {
            // The legacy attempt has joined and disposed its helper/rules before
            // this fallback. Do not race two mapping protocols for the same Q.
            log("原入口本轮未就绪，尝试独立网关入口：" + ex.GetType().Name);
        }
        return await Create(sources, open, log, token);
    }
    internal static async Task<GatewayMapping> Create(Func<IPAddress[]> sources,
        Func<IPAddress, CancellationToken, Task<PortControlLease>> open, Action<string> log, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        Exception? last = null;
        foreach (var local in sources().Distinct().Take(4)) {
            token.ThrowIfCancellationRequested(); PortControlLease? lease = null; bool transferred = false;
            try { lease = await open(local, token); token.ThrowIfCancellationRequested(); var mapping = new GatewayMapping(lease, local, log); transferred = true; return mapping; }
            catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or SocketException or TimeoutException) { last = ex; }
            finally { if (lease != null && !transferred) await lease.DisposeAsync(); }
        }
        token.ThrowIfCancellationRequested(); throw new IOException("独立网关入口不可用；未发现有效公网候选", last);
    }
}
