using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace StreamLink.Core;

public sealed record PortControlSnapshot(Guid Id, PortControlKind Provider, string Gateway, string Local,
    string? External, PortMappingProtocol Protocol, uint Lifetime, uint Epoch, string Ownership, string State,
    string RouteGeneration, double RemainingSeconds, string Cleanup)
{
    public long Notifications { get; init; }
    public long Revalidations { get; init; }
    public string NotificationMode { get; init; } = "";
    public string NotificationReason { get; init; } = "";
}

// One shared connected UDP control socket per source/gateway/generation. Data
// ownership remains with its existing owner. Only an exact PCP nonce grants an
// explicit deletion capability; NAT-PMP mappings always expire naturally.
public sealed partial class PortControlLease : IAsyncDisposable
{
    readonly PortControlRoute route;
    readonly ushort internalPort, requestedPort;
    readonly PortMappingProtocol protocol;
    readonly byte[] nonce = RandomNumberGenerator.GetBytes(12);
    readonly TraversalResources budget;
    readonly Func<bool> currentRoute;
    readonly GatewayAccount account;
    readonly string claim;
    readonly string accountKey;
    readonly object sync = new();
    readonly SemaphoreSlim operation = new(1);
    readonly CancellationTokenSource stop = new();
    readonly Guid id = Guid.NewGuid();
    PortControlKind kind = PortControlKind.Pcp;
    IPEndPoint? external;
    uint lifetime, epoch;
    long grantedAt, epochAt;
    string state = "Creating";
    string cleanupState = "NotStarted";
    bool confirmed, sawPcpRequest, mayDelete, cleanupForbidden, disposed;
    int maintaining;
    Task maintenance = Task.CompletedTask;
    const uint RequestedLifetime = 180;
    public event Action<PortControlSnapshot>? Changed;
    public PortControlSnapshot Snapshot { get { lock (sync) {
        string notificationReason = account.Multicast.Reason;
        return new(id, kind, route.Gateway.ToString(), new IPEndPoint(route.Local, internalPort).ToString(),
        external?.ToString(), protocol, lifetime, epoch, !confirmed ? "Unconfirmed" : kind == PortControlKind.Pcp ? "PcpNonce" : "LocalGrantNoDelete", state,
        route.Generation, confirmed ? Math.Max(0, lifetime - Stopwatch.GetElapsedTime(grantedAt).TotalSeconds) : 0, cleanupState)
        { Notifications = notifications, Revalidations = revalidations, NotificationMode = notificationReason.Length == 0 ? "UnicastAndMulticast" : "UnicastOnly", NotificationReason = notificationReason }; } } }
    public IPEndPoint External { get { lock (sync) return external == null ? throw new IOException("网关未返回映射") : new(external.Address, external.Port); } }
    public bool Valid { get { lock (sync) return confirmed && state == "Granted" && Stopwatch.GetElapsedTime(grantedAt).TotalSeconds < lifetime; } }

    sealed class GatewayAccount : IDisposable
    {
        public int References;
        public readonly SemaphoreSlim Serial = new(1);
        public readonly Socket Socket;
        public readonly PortControlChannel Channel;
        public readonly PortControlMulticast.Subscription Multicast;
        public readonly TraversalResources Budget;
        readonly IDisposable quota;
        public GatewayAccount(PortControlRoute route, TraversalResources resources)
        {
            Budget = resources; quota = resources.Acquire(); Socket? opened = null;
            PortControlChannel? channel = null;
            try {
                opened = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); opened.Bind(new IPEndPoint(route.Local, 0)); opened.Connect(route.Gateway);
                Socket = opened; Channel = channel = new(Socket);
                Multicast = PortControlMulticast.Subscribe(route, resources, Channel.MulticastNotification);
            } catch { channel?.Dispose(); opened?.Dispose(); quota.Dispose(); Serial.Dispose(); throw; }
        }
        public void Dispose() { Multicast.Dispose(); Channel.Dispose(); Socket.Dispose(); quota.Dispose(); Serial.Dispose(); }
    }
    static readonly object accountsGate = new();
    static readonly Dictionary<string, GatewayAccount> accounts = [];
    static readonly HashSet<string> claims = [];
    static readonly Dictionary<string, long> unavailableUntil = [];
    static PortControlLease() { NetworkChange.NetworkAddressChanged += (_, _) => { lock (accountsGate) unavailableUntil.Clear(); }; }

    PortControlLease(PortControlRoute route, ushort port, ushort desired, PortMappingProtocol protocol, Func<bool> current, TraversalResources resources)
    {
        this.route = route; internalPort = port; requestedPort = desired; this.protocol = protocol; currentRoute = current; budget = resources;
        claim = route.Local + "/" + protocol + "/" + port;
        accountKey = route.Local + "/" + route.Gateway + "/" + route.Generation;
        lock (accountsGate) {
            if (!claims.Add(claim)) throw new IOException("本机端口已有受管网关租约");
            try {
                if (!accounts.TryGetValue(accountKey, out account!)) accounts.Add(accountKey, account = new(route, resources));
                if (!ReferenceEquals(account.Budget, resources)) throw new IOException("共享网关控制资源必须使用同一全机账本");
                account.Channel.Subscribe(id, ObserveNotification);
                account.References++;
            } catch {
                claims.Remove(claim);
                if (accounts.TryGetValue(accountKey, out var unused) && unused.References == 0) { accounts.Remove(accountKey); unused.Dispose(); }
                throw;
            }
        }
    }
    void ReleaseAccount()
    {
        lock (accountsGate) {
            claims.Remove(claim);
            account.Channel.Unsubscribe(id);
            if (--account.References == 0) { accounts.Remove(accountKey); account.Dispose(); }
        }
    }
    public static async Task<PortControlLease> Create(IPAddress local, int internalPort, int suggestedPort,
        PortMappingProtocol protocol, CancellationToken token)
    {
        var routes = PortControlRoute.Discover(local);
        if (routes.Length == 0) throw new IOException("未发现该出口的本地默认网关；未向公网尝试端口控制");
        Exception? last = null;
        foreach (var route in routes) {
            try { return await Open(route, internalPort, suggestedPort, protocol, route.StillCurrent, token); }
            catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or SocketException or TimeoutException) { last = ex; }
        }
        throw new IOException("PCP/NAT-PMP 候选不可用：" + last?.Message, last);
    }
    internal static async Task<PortControlLease> Open(PortControlRoute route, int port, int desired,
        PortMappingProtocol protocol, Func<bool> current, CancellationToken token, TraversalResources? resources = null)
    {
        if (port is < 1024 or > 65535 || desired is < 0 or > 65535 || !Enum.IsDefined(protocol)) throw new ArgumentException("端口控制参数无效");
        lock (accountsGate) {
            if (unavailableUntil.TryGetValue(route.Generation, out long until) && until > Environment.TickCount64) throw new IOException("网关处于协议退避期，网络变化后重新发现");
            if (unavailableUntil.Count >= 128) foreach (var key in unavailableUntil.Where(p => p.Value <= Environment.TickCount64).Select(p => p.Key).ToArray()) unavailableUntil.Remove(key);
        }
        var lease = new PortControlLease(route, (ushort)port, (ushort)desired, protocol, current, resources ?? TraversalResources.Shared);
        try {
            byte[] request = PortControlProtocol.Pcp(route.Local, (ushort)port, protocol, lease.nonce, RequestedLifetime, new(IPAddress.Any, desired));
            var reply = await lease.Exchange(request, PortControlKind.Pcp, 4, null, token);
            if (reply.NatPmpFallback) {
                // An explicit version response is required. A timeout, malformed
                // response or authorization error cannot trigger downgrade.
                if (!PortControlRoute.Private(route.Local) && !IPAddress.IsLoopback(route.Local)) throw new IOException("NAT-PMP 只用于私网默认网关");
                lease.kind = PortControlKind.NatPmp; lease.sawPcpRequest = false;
                var address = await lease.Exchange([0, 0], lease.kind, 9, null, token); lease.CheckError(address);
                lease.TrackEpoch(address.Epoch);
                reply = await lease.Exchange(PortControlProtocol.Pmp((ushort)port, protocol, RequestedLifetime, (ushort)desired), lease.kind, 9, address.External!.Address, token);
            }
            lease.Accept(reply); return lease;
        } catch (Exception ex) {
            lock (accountsGate) if (!token.IsCancellationRequested && unavailableUntil.Count < 128)
                unavailableUntil[route.Generation] = Environment.TickCount64 + (ex is PortControlException error ? Math.Max(4L, error.RetrySeconds) * 1000 : 900000);
            await lease.DisposeAsync(); throw;
        }
    }
    void CheckError(PortControlReply r)
    {
        if (r.Error != 0) {
            cleanupForbidden = true; // Respect the error hold-down, including deletion; let the grant expire.
            throw new PortControlException($"{kind} 返回错误 {r.Error}", r.Lifetime);
        }
    }
    void TrackEpoch(uint value)
    {
        long now = Stopwatch.GetTimestamp();
        if (epochAt != 0 && PortControlTiming.EpochChanged(kind, epoch, value, Stopwatch.GetElapsedTime(epochAt, now).TotalSeconds)) {
            epoch = value; epochAt = now; state = "GatewayEpochChanged";
            throw new IOException("网关 epoch 变化，旧候选失效并等待重新建链");
        }
        epoch = value; epochAt = now;
    }
    void Accept(PortControlReply reply, bool revalidated = false)
    {
        if (!currentRoute()) throw new IOException("网关或接口代次已变化，丢弃迟到租约");
        CheckError(reply);
        if (reply.External == null || reply.Lifetime < 8) throw new IOException("网关租期不足以可靠维护，未发布候选");
        lock (sync) {
            mayDelete = kind == PortControlKind.Pcp;
            // Store a successful grant before checking epoch, so cancellation or
            // a reboot response can still clean up this exact nonce safely.
            external = reply.External; lifetime = reply.Lifetime; grantedAt = Stopwatch.GetTimestamp(); confirmed = true;
            // PCP MAP replies and updates have identical wire form: this proves
            // the matching resource, not a cryptographically fresh transaction.
            if (revalidated) epochAt = 0;
            TrackEpoch(reply.Epoch); state = noticePending ? "GatewayRevalidating" : "Granted";
        }
        Changed?.Invoke(Snapshot);
    }
    async Task<PortControlReply> Exchange(byte[] request, PortControlKind protocolKind, int attempts, IPAddress? externalIp, CancellationToken token,
        TimeSpan? oneWait = null)
    {
        await account.Serial.WaitAsync(token);
        try {
            double interval = PortControlTiming.InitialRetry(protocolKind, Random.Shared.NextDouble());
            for (int retry = 0; retry < attempts; retry++) {
                token.ThrowIfCancellationRequested();
                if (!currentRoute()) throw new IOException("默认网关或源接口已变化，原租约失效");
                while (!budget.TrySend(request.Length, maintenance: true)) await Task.Delay(25, token);
                if (protocolKind == PortControlKind.Pcp && request.Length == 60 && request[4..8].Any(b => b != 0)) sawPcpRequest = true;
                using var pending = account.Channel.Expect(request, protocolKind, externalIp);
                await account.Socket.SendAsync(request, SocketFlags.None, token);
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(token);
                wait.CancelAfter(oneWait ?? TimeSpan.FromSeconds(interval));
                try { return await pending.Result.WaitAsync(wait.Token); }
                catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
                interval = PortControlTiming.NextRetry(protocolKind, interval, Random.Shared.NextDouble());
            }
            throw new TimeoutException(protocolKind + " 本轮没有匹配响应");
        } finally { account.Serial.Release(); }
    }
    public Task Maintain(CancellationToken token)
    {
        lock (sync) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (Interlocked.Exchange(ref maintaining, 1) != 0) throw new InvalidOperationException("映射维护只能启动一次");
            return maintenance = Run(token);
        }
    }
    async Task Run(CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token); token = linked.Token;
        async Task WatchRoute()
        {
            try {
                while (true) {
                    await Task.Delay(1000, token);
                    if (currentRoute() && account.Channel.Failure == null) continue;
                    lock (sync) state = account.Channel.Failure == null ? "RouteChanged" : "GatewayReceiverFailed";
                    Changed?.Invoke(Snapshot); linked.Cancel(); return;
                }
            } catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            catch (NetworkInformationException) { lock (sync) state = "RouteChanged"; linked.Cancel(); }
        }
        Task routeWatch = WatchRoute();
        try {
            while (true) {
                int retry = 1;
                while (true) {
                    if (await RevalidateNotification(token)) break;
                    double fraction = kind == PortControlKind.Pcp ? PortControlTiming.PcpRenewFraction(retry, Random.Shared.NextDouble()) : .5;
                    double due = lifetime * fraction, elapsed = Stopwatch.GetElapsedTime(grantedAt).TotalSeconds;
                    if (due > elapsed && await noticeWake.WaitAsync(TimeSpan.FromSeconds(Math.Min(due - elapsed, 86400)), token)) continue;
                    elapsed = Stopwatch.GetElapsedTime(grantedAt).TotalSeconds;
                    if (elapsed < due) continue; // Long granted lifetimes use cancellable daily slices.
                    if (elapsed >= lifetime) throw new IOException("网关租约已到期");
                    using var remaining = CancellationTokenSource.CreateLinkedTokenSource(token);
                    remaining.CancelAfter(TimeSpan.FromSeconds(lifetime - elapsed));
                    await operation.WaitAsync(remaining.Token);
                    try {
                        if (kind == PortControlKind.NatPmp) {
                            var address = await Exchange([0, 0], kind, 9, null, remaining.Token); CheckError(address); lock (sync) TrackEpoch(address.Epoch);
                            var response = await Exchange(PortControlProtocol.Pmp(internalPort, protocol, RequestedLifetime, (ushort)external!.Port), kind, 9, address.External!.Address, remaining.Token);
                            Accept(response); break;
                        }
                        double nextDue = lifetime * PortControlTiming.PcpRenewFraction(retry + 1, Random.Shared.NextDouble());
                        double wait = Math.Min(lifetime - elapsed, Math.Max(4, nextDue - elapsed));
                        try {
                            var response = await Exchange(PortControlProtocol.Pcp(route.Local, internalPort, protocol, nonce, RequestedLifetime, external!), kind, 1, null, remaining.Token, TimeSpan.FromSeconds(wait));
                            Accept(response); break;
                        } catch (TimeoutException) { retry++; }
                    } catch (OperationCanceledException) when (!token.IsCancellationRequested && remaining.IsCancellationRequested) {
                        throw new IOException("网关续租排队或响应超过实际租期");
                    } finally { operation.Release(); }
                }
            }
        } catch (Exception ex) {
            if (ex is PortControlException error) lock (accountsGate) if (unavailableUntil.Count < 128)
                unavailableUntil[route.Generation] = Environment.TickCount64 + Math.Max(4L, error.RetrySeconds) * 1000;
            lock (sync) if (state == "Granted") state = currentRoute() ? "ExpiredOrRenewalFailed" : "RouteChanged";
            lock (sync) if (state == "GatewayRevalidating") state = currentRoute() ? "GatewayRevalidationFailed" : "RouteChanged";
            Changed?.Invoke(Snapshot); throw;
        } finally { linked.Cancel(); await routeWatch; }
    }
    public async ValueTask DisposeAsync()
    {
        lock (sync) { if (disposed) return; disposed = true; }
        stop.Cancel(); try { await maintenance; } catch { }
        await operation.WaitAsync();
        try {
            lock (sync) cleanupState = kind == PortControlKind.NatPmp ? "NaturalExpiry" : "NoDeleteCapabilityOrRouteChanged";
            // NAT-PMP cannot establish nonce ownership. No deletion request is
            // ever sent, especially after timeout, epoch change or cancellation.
            if (kind == PortControlKind.Pcp && !cleanupForbidden && (mayDelete || !confirmed && sawPcpRequest) && currentRoute()) {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(4));
                try {
                    var response = await Exchange(PortControlProtocol.Pcp(route.Local, internalPort, protocol, nonce, 0, external ?? new(IPAddress.Any, requestedPort)), kind, 1, null, cleanup.Token);
                    lock (sync) cleanupState = !response.NatPmpFallback && response.Error == 0 && response.Lifetime == 0 ? "DeleteConfirmed" : "DeleteNotConfirmed";
                } catch (Exception ex) when (ex is IOException or SocketException or TimeoutException or OperationCanceledException) { lock (sync) cleanupState = "DeleteNotConfirmed"; }
            }
        } finally {
            lock (sync) state = "Closed";
            ReleaseAccount(); operation.Release(); stop.Dispose(); noticeWake.Dispose();
        }
    }
}
