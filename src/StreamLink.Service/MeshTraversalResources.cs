using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

internal interface IMeshCandidateResource : IAsyncDisposable
{
    MeshTraversalCandidate Candidate { get; }
    bool PredictionReady => false;
    TimeSpan ExplorationRemaining => TimeSpan.Zero;
    object? ExplorationStats => null;
    bool PredictionControlReady(int requests) => false;
    Task<MeshTraversalCandidate> MeasurePrediction(long started, CancellationToken token) => throw new NotSupportedException();
    void FinishPrediction(PredictionOutcome outcome) { }
    Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context, IPEndPoint remote, CancellationToken token);
    Task<IPreparedMeshPath> PrepareCandidate(TraversalAttemptContext context, MeshTraversalCandidate remote, CancellationToken token) => Prepare(context, IPEndPoint.Parse(remote.Endpoint), token);
}
internal interface IMeshCandidateFactory
{
    TraversalProfile[] Profiles { get; }
    bool SupportsUdpIpv6 => false;
    bool SupportsFakeTcpIpv6 => false;
    bool SupportsTcpPrediction => false;
    bool SupportsTcpPeerReflexive => false;
    bool SupportsUdpExploration => false;
    EgressStats? Egress => null;
    Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile profile, Guid attempt, CancellationToken token);
    Task<IMeshCandidateResource> GatherForPeer(MeshMember peer, TraversalProfile profile, Guid attempt,
        bool allowIpv6, IPEndPoint? remote, int round, CancellationToken token) => Gather(peer, profile, attempt, token);
    Task<IMeshCandidateResource> GatherCoordinated(MeshMember peer, TraversalProfile profile, Guid attempt, bool allowIpv6,
        MeshTraversalCandidate? remote, int round, bool predictionAllowed, CancellationToken token) =>
        GatherForPeer(peer, profile, attempt, allowIpv6, remote == null ? null : IPEndPoint.Parse(remote.Endpoint), round, token);
    Task<IMeshCandidateResource> GatherSourceAware(MeshMember peer, TraversalProfile profile, Guid attempt, bool allowIpv6,
        MeshTraversalCandidate? remote, int round, bool predictionAllowed, bool peerSourceAllowed, CancellationToken token) =>
        GatherCoordinated(peer, profile, attempt, allowIpv6, remote, round, predictionAllowed, token);
    Task<IMeshCandidateResource> GatherEnhanced(MeshMember peer, TraversalProfile profile, Guid attempt, bool allowIpv6,
        MeshTraversalCandidate? remote, int round, bool predictionAllowed, bool peerSourceAllowed, bool explorationAllowed, Func<bool> stillEligible, CancellationToken token) =>
        GatherSourceAware(peer, profile, attempt, allowIpv6, remote, round, predictionAllowed, peerSourceAllowed, token);
}

// One request budget for all discovery operations of this running device.
// Below the service's 48/minute, burst 8; eight devices stay under 512/minute.
internal sealed class MeshRequestBudget(int burst = 6)
{
    readonly object gate = new();
    readonly int capacity = burst is >= 6 and <= 8 ? burst : throw new ArgumentOutOfRangeException(nameof(burst));
    double tokens = burst;
    long last = Stopwatch.GetTimestamp();
    int backgroundHolds;
    void Refill() { long now = Stopwatch.GetTimestamp(); tokens = Math.Min(capacity, tokens + Stopwatch.GetElapsedTime(last, now).TotalSeconds * (40d / 60)); last = now; }
    public bool Available(int requests) { lock (gate) { Refill(); return requests <= capacity && tokens >= requests; } }
    public IDisposable HoldBackground() { lock (gate) { backgroundHolds++; return new BackgroundHold(this); } }
    sealed class BackgroundHold(MeshRequestBudget owner) : IDisposable {
        MeshRequestBudget? held = owner;
        public void Dispose() { var budget = Interlocked.Exchange(ref held, null); if (budget != null) lock (budget.gate) budget.backgroundHolds--; }
    }
    public bool Take(bool priority = false)
    {
        lock (gate) {
        Refill();
        if (!priority && backgroundHolds > 0) return false;
        if (tokens < (priority ? 1 : 3)) return false;
        tokens--; return true;
        }
    }
}

internal sealed partial class MeshCandidateFactory(DeviceProfile profile, string executable, string folder,
    TraversalProfile[] profiles, bool captureBroker = false, Action<string>? diagnostic = null, bool ipv6Native = false, bool wireControl = false, bool peerSourceNative = false) : IMeshCandidateFactory, IAsyncDisposable
{
    readonly Guid generation = Guid.NewGuid();
    readonly DeviceProfile options = profile;
    readonly bool countWireControl = wireControl && captureBroker;
    readonly string binary = executable, root = folder;
    readonly EgressPacer? pacer = profile.ManagedEgressMbps > 0 ? new(profile.ManagedEgressMbps) : null;
    public EgressStats? Egress => pacer?.Snapshot();
    MeshTcpEndpointPool? pool;
    readonly object poolGate = new();
    readonly Dictionary<int, (string Device, bool GatewayNext)> udpMethods = [];
    internal Action<IPEndPoint, IPAddress?, bool>? RouteCheckForTest { get; init; }
    internal Func<bool>? Ipv6AvailableForTest { get; init; }
    internal Func<IPEndPoint, IPEndPoint, IEndpointPacketIo>? OpenCaptureForTest { get; init; }
    internal TimeProvider? EndpointTimeForTest { get; init; }
    internal Func<string, AddressFamily, CancellationToken, Task<IPEndPoint>> ResolveTarget { get; init; } = Stun.Resolve;
    internal Func<IPAddress, int, CancellationToken, Task<PortControlLease>> OpenUdpGateway { get; init; } =
        (local, port, ct) => PortControlLease.Create(local, port, port, PortMappingProtocol.Udp, ct);
    internal Func<IPAddress[]> GatewaySources { get; init; } = PortControlRoute.LocalSources;
    MeshTcpEndpointPool Pool { get { lock (poolGate) return pool ??= new(generation,
        (local, helper) => OpenCaptureForTest?.Invoke(local, helper) ?? new WinDivertEndpointIo(Path.Combine(Path.GetDirectoryName(binary)!, "WinDivert.dll"), local, helper), pacer: pacer, time: EndpointTimeForTest); } }
    public TraversalProfile[] Profiles => profiles;
    public bool SupportsUdpIpv6 => options.UdpIpv6 && profiles.Contains(TraversalProfile.UdpDirect);
    public bool SupportsFakeTcpIpv6 => options.FakeTcpIpv6 && captureBroker && ipv6Native && profiles.Contains(TraversalProfile.FakeTcpHttpSo);
    public bool SupportsTcpPrediction => options.TcpPortPrediction && options.TcpPortCalibration && options.TcpSynObservation && countWireControl && profiles.Contains(TraversalProfile.FakeTcpHttpSo);
    public bool SupportsTcpPeerReflexive => options.TcpPeerReflexive && peerSourceNative && countWireControl && profiles.Contains(TraversalProfile.FakeTcpHttpSo);
    public static async Task<IMeshCandidateFactory?> Create(DeviceProfile profile, string executable, string folder, Action<string> log, CancellationToken token)
    {
        profile.Selection().Validate();
        if (profile.TraversalMode == "legacy") return null;
        var supported = new List<TraversalProfile>();
        bool broker = false, ipv6 = false, wireControl = false, peerSource = false;
        try {
            var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            info.ArgumentList.Add("--native-info");
            using var process = Process.Start(info) ?? throw new IOException("无法查询原生能力");
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(token); limit.CancelAfter(3000);
            try {
                var output = process.StandardOutput.ReadToEndAsync(limit.Token); var error = process.StandardError.ReadToEndAsync(limit.Token);
                await process.WaitForExitAsync(limit.Token); string json = await output; await error;
                if (process.ExitCode != 0 || json.Length > 8192) throw new IOException("原生能力响应无效");
                using var document = JsonDocument.Parse(json); var r = document.RootElement;
                broker = r.TryGetProperty("captureBroker", out var capture) && capture.GetInt32() == 1;
                wireControl = broker && r.TryGetProperty("wireControl", out var wire) && wire.GetInt32() == 1;
                peerSource = wireControl && r.TryGetProperty("tcpPeerReflexive", out var reflexive) && reflexive.GetInt32() == 1;
                ipv6 = broker && r.TryGetProperty("ipv6", out var v6) && v6.GetBoolean() && r.TryGetProperty("ipv6Abi", out var abi6) && abi6.GetInt32() == 2 &&
                    r.TryGetProperty("ipv6Attach", out var attach6) && attach6.GetString() == "broker-only";
                if (r.GetProperty("nativeAbi").GetInt32() == 1 && r.GetProperty("backend").GetString() == "windivert" &&
                    r.TryGetProperty("preparedStart", out var prepared) && prepared.GetBoolean() &&
                    r.TryGetProperty("simultaneousOpen", out var so) && so.GetBoolean() && r.GetProperty("wireProtocol").GetString() == "udp2raw-http-c4995ea")
                    supported.Add(TraversalProfile.FakeTcpHttpSo);
            } finally { if (!process.HasExited) { process.Kill(); await process.WaitForExitAsync(); } }
        } catch (Exception ex) when (!token.IsCancellationRequested) { log("原生双主动暂未启用：" + ex.GetType().Name); }
        if (profile.TraversalMode == "tcp-udp" && profile.Selection().Allows(TraversalProfile.UdpDirect)) supported.Add(TraversalProfile.UdpDirect);
        if (profile.FakeTcpIpv6 && !ipv6) log("FakeTCP IPv6 暂未启用：原生组件需提供 ABI 2 与统一捕获能力，继续 IPv4");
        if (profile.ManagedEgressMbps > 0 && supported.Contains(TraversalProfile.FakeTcpHttpSo) && !broker)
            throw new IOException("实验出口调度要求受管捕获后端，请升级原生组件或关闭出口上限");
        if (profile.ManagedEgressMbps > 0) log($"实验链路共享 {profile.ManagedEgressMbps} Mbps 外层 IP 出口预算；兼容入口、内核反射与 HTTPS 控制流不在此范围");
        if (supported.Contains(TraversalProfile.FakeTcpHttpSo) && !wireControl) log("原生组件未提供线上控制报文计账，当前仅统计上层检查消息");
        if (profile.TcpPeerReflexive && !peerSource) log("TCP 来源学习暂未启用：原生组件需独立声明 IPv4 来源学习及线上计账能力");
        return supported.Count == 0 ? null : new MeshCandidateFactory(profile, executable, folder, supported.ToArray(), broker, log, ipv6, wireControl, peerSource);
    }
    void CheckRoute(IPEndPoint endpoint, IPAddress? expected = null, bool gatewayCandidate = false)
    {
        if (RouteCheckForTest != null) { RouteCheckForTest(endpoint, expected, gatewayCandidate); return; }
        if (endpoint.AddressFamily == AddressFamily.InterNetworkV6) {
            if (gatewayCandidate || !Ipv6Direct.Global(endpoint.Address) || endpoint.Port == 0) throw new IOException("候选不是原生全局 IPv6 单播地址");
            var source = Stun.LocalAddress(endpoint);
            if (expected != null && !source.Equals(expected) || !Ipv6Direct.SourceReady(source)) throw new IOException("IPv6 物理出口或保留的源地址已失效");
            return;
        }
        if (gatewayCandidate && !PortControlRoute.GlobalV4(endpoint.Address)) throw new IOException("UDP 网关只返回内层地址，未推断外层 CGN 可达");
        byte[] ip = endpoint.Address.GetAddressBytes();
        if (ip.Length != 4 || ip[0] is 0 or 127 or >= 224 || ip[0] == 169 && ip[1] == 254 || endpoint.Port == 0)
            throw new IOException("候选地址不能用于公网打洞");
        var local = Stun.LocalAddress(endpoint);
        if (expected != null && !local.Equals(expected)) throw new IOException("候选出口与保留的源地址不一致");
        var own = IPAddress.Parse(options.Mesh!.LocalIp).GetAddressBytes();
        if (ip.AsSpan(0, 3).SequenceEqual(own.AsSpan(0, 3))) throw new IOException("不能通过本网络虚拟网卡递归打洞");
        var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(local)));
        if (nic == null || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel ||
            (nic.Name + " " + nic.Description).Contains("StreamLink", StringComparison.OrdinalIgnoreCase) ||
            nic.Description.Contains("Wintun", StringComparison.OrdinalIgnoreCase) || nic.Description.Contains("EasyTier", StringComparison.OrdinalIgnoreCase))
            throw new IOException("未找到可用的直接出口，避免依赖其他组网承载");
    }
    public Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile kind, Guid attempt, CancellationToken token)
        => GatherForPeer(peer, kind, attempt, false, null, 1, token);
    public Task<IMeshCandidateResource> GatherForPeer(MeshMember peer, TraversalProfile kind, Guid attempt,
        bool allowIpv6, IPEndPoint? remote, int round, CancellationToken token) => GatherScoped(peer, kind, attempt, allowIpv6, remote, round, false, token);
    async Task<IMeshCandidateResource> GatherScoped(MeshMember peer, TraversalProfile kind, Guid attempt,
        bool allowIpv6, IPEndPoint? remote, int round, bool peerSource, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(12000);
        bool supported6 = kind == TraversalProfile.UdpDirect ? SupportsUdpIpv6 : SupportsFakeTcpIpv6;
        if (remote?.AddressFamily == AddressFamily.InterNetworkV6) {
            if (!allowIpv6 || !supported6) throw new IOException("本轮未协商该承载的 IPv6 能力");
            return await GatherFamily(peer, kind, attempt, AddressFamily.InterNetworkV6, deadline.Token);
        }
        // The Offer selects one family; the responder must follow it. A failed
        // first IPv6 check leaves the second existing profile round for IPv4.
        bool try6 = remote == null && round == 1 && allowIpv6 && supported6;
        bool available6 = try6 && (Ipv6AvailableForTest?.Invoke() ?? Ipv6Direct.Available());
        if (try6 && !available6) diagnostic?.Invoke("IPv6Unavailable：未找到可用的原生物理 IPv6 源地址，继续 IPv4");
        if (available6) {
            using var fast = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token); fast.CancelAfter(3500);
            try { return await GatherFamily(peer, kind, attempt, AddressFamily.InterNetworkV6, fast.Token); }
            catch (Exception ex) when (!deadline.IsCancellationRequested && ex is IOException or SocketException or OperationCanceledException or ArgumentException) {
                diagnostic?.Invoke("本轮未获得 IPv6 候选，继续 IPv4 同端点观察");
            }
        }
        return await GatherFamily(peer, kind, attempt, AddressFamily.InterNetwork, deadline.Token, peerSource);
    }
    async Task<IMeshCandidateResource> GatherFamily(MeshMember peer, TraversalProfile kind, Guid attempt, AddressFamily family, CancellationToken token, bool peerSource = false)
    {
        if (!Profiles.Contains(kind)) throw new NotSupportedException();
        bool useGateway = false;
        if (family == AddressFamily.InterNetwork && kind == TraversalProfile.UdpDirect && options.PortControlMapping) lock (poolGate) {
            var prior = udpMethods.GetValueOrDefault(peer.Slot);
            useGateway = prior.Device == peer.Device && prior.GatewayNext;
            udpMethods[peer.Slot] = (peer.Device, !useGateway);
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(12000);
        if (useGateway) return await GatherUdpGateway(peer, attempt, deadline.Token);
        bool independentFallback = family == AddressFamily.InterNetwork && kind == TraversalProfile.UdpDirect && options.PortControlMapping;
        using var observing = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        if (independentFallback) observing.CancelAfter(4500); // reserve time inside this same twelve-second gather
        var servers = kind == TraversalProfile.UdpDirect ? options.UdpStun : options.OrderedTcp();
        Exception? last = null;
        foreach (string name in servers.Take(3)) {
            TcpEndpointLease? tcp = null; UdpTraversal? udp = null;
            MeshTcpEndpointPool.Use? pooled = null;
            bool transferred = false;
            try {
                var target = await ResolveTarget(name, family, observing.Token); CheckRoute(target);
                var local = new IPEndPoint(Stun.LocalAddress(target), 0);
                IPEndPoint mapped; string observation = target.ToString(); double lifetime = 120;
                if (kind == TraversalProfile.UdpDirect) {
                    byte[] shared = MeshIdentity.SharedKey(options.Mesh!, peer);
                    try { udp = UdpTraversal.Create(local, generation, attempt, options.Mesh!.Self.Slot, peer.Slot, shared, pacer: pacer, fairnessKey: peer.Device); }
                    finally { CryptographicOperations.ZeroMemory(shared); }
                    mapped = (await udp.Observe(target, observing.Token)).Mapped;
                } else if (captureBroker) {
                    pooled = await Pool.Acquire(local.Address, target, deadline.Token, peerSource ? peer.Device : null); tcp = pooled.Lease; mapped = pooled.Observed;
                    if (family == AddressFamily.InterNetwork) ObserveInBackground(pooled.Owner, peer); // observer wire protocol is still IPv4-only
                } else {
                    using var connect = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token); connect.CancelAfter(3500);
                    tcp = await TcpEndpointLease.Open(local, target, generation, connect.Token);
                    using var reference = tcp.AcquireAttempt(generation); mapped = (await reference.Observe(deadline.Token)).Public;
                }
                CheckRoute(mapped, gatewayCandidate: useGateway);
                long now = (pooled?.ObservedAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
                var candidate = new MeshTraversalCandidate(Guid.NewGuid(), 1, mapped.ToString(), observation, now, now + (long)lifetime,
                    kind == TraversalProfile.UdpDirect ? CandidatePurpose.UdpDirect : CandidatePurpose.SimultaneousOpen, PeerReflexive: peerSource);
                var resource = new Resource(this, peer, candidate, tcp, udp, pooled); transferred = true; return resource;
            } catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or SocketException or OperationCanceledException or ArgumentException) { last = ex; }
            finally { // Success transfers both resources into Resource.
                if (!transferred) { if (pooled != null) pooled.Dispose(); else tcp?.Dispose(); if (udp != null) await udp.DisposeAsync(); }
            }
            if (observing.IsCancellationRequested) break;
            last ??= new IOException("候选观察失败");
        }
        if (independentFallback && !deadline.IsCancellationRequested) {
            diagnostic?.Invoke("STUN 本轮未产生 UDP 候选，在剩余准备时间内尝试独立网关入口");
            return await GatherUdpGateway(peer, attempt, deadline.Token);
        }
        throw new IOException("同端点候选观察未成功", last);
    }
    async Task<IMeshCandidateResource> GatherUdpGateway(MeshMember peer, Guid attempt, CancellationToken token)
    {
        Exception? last = null;
        foreach (var local in GatewaySources().Distinct().Take(4)) {
            token.ThrowIfCancellationRequested(); UdpTraversal? udp = null; bool transferred = false;
            try {
                byte[] shared = MeshIdentity.SharedKey(options.Mesh!, peer);
                try { udp = UdpTraversal.Create(new(local, 0), generation, attempt, options.Mesh!.Self.Slot, peer.Slot, shared, pacer: pacer, fairnessKey: peer.Device); }
                finally { CryptographicOperations.ZeroMemory(shared); }
                var mapping = await OpenUdpGateway(local, udp.Local.Port, token);
                try { udp.AttachGateway(mapping); } catch { await mapping.DisposeAsync(); throw; }
                var mapped = mapping.External; CheckRoute(mapped, gatewayCandidate: true);
                var snapshot = mapping.Snapshot; double lifetime = Math.Min(120, Math.Floor(snapshot.RemainingSeconds));
                if (lifetime <= TraversalLimits.UdpRoundMs / 1000 + 2) throw new IOException("UDP 网关租期不足以准备和检查候选");
                diagnostic?.Invoke($"UDP 独立显式候选 {mapped}，socket={udp.SocketId:N}；仍需同 socket 双向认证与 MTU 检查");
                diagnostic?.Invoke($"网关通知模式 {snapshot.NotificationMode}，降级原因 {snapshot.NotificationReason}");
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var candidate = new MeshTraversalCandidate(Guid.NewGuid(), 1, mapped.ToString(), snapshot.Gateway, now, now + (long)lifetime, CandidatePurpose.UdpDirect);
                var resource = new Resource(this, peer, candidate, null, udp, null); transferred = true; return resource;
            } catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or SocketException or TimeoutException or ArgumentException) { last = ex; }
            finally { if (!transferred && udp != null) await udp.DisposeAsync(); }
        }
        token.ThrowIfCancellationRequested(); throw new IOException("独立 UDP 网关候选不可用", last);
    }
    sealed class Resource(MeshCandidateFactory owner, MeshMember peer, MeshTraversalCandidate candidate,
        TcpEndpointLease? tcp, UdpTraversal? udp, MeshTcpEndpointPool.Use? pooled) : IMeshCandidateResource
    {
        bool prepared;
        public MeshTraversalCandidate Candidate {
            get {
                if (udp?.GatewaySnapshot != null && !udp.GatewayCandidateCurrent(IPEndPoint.Parse(candidate.Endpoint)))
                    throw new IOException("UDP 网关候选已变化或失效，拒绝发布旧轮次");
                return candidate;
            }
        }
        public async Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context, IPEndPoint remote, CancellationToken token)
        {
            if (prepared) throw new IOException("候选资源已被接入");
            _ = Candidate;
            owner.CheckRoute(remote, tcp?.Local.Address ?? udp!.Local.Address);
            if (udp != null) { var result = udp.PreparePath(context, owner.generation, remote); prepared = true; return result; }
            byte[] shared = MeshIdentity.SharedKey(owner.options.Mesh!, peer);
            try {
                var result = await NativeDatagramPath.Prepare(owner.binary, owner.root, tcp!, owner.generation, context, remote, shared, token,
                    captureOwner: pooled?.Owner, countWireControl: owner.countWireControl, peerReflexive: candidate.PeerReflexive);
                prepared = true; return result;
            } finally { CryptographicOperations.ZeroMemory(shared); }
        }
        public async ValueTask DisposeAsync()
        {
            if (pooled != null) pooled.Dispose(); else tcp?.Dispose();
            if (udp != null && !prepared) await udp.DisposeAsync(); // Prepared owns original UDP reference after transfer.
        }
    }
    public async ValueTask DisposeAsync() { try { await StopObservation(); } finally { try { if (pool != null) await pool.DisposeAsync(); } finally { pacer?.Dispose(); } } }
}
