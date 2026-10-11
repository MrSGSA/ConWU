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
    Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context, IPEndPoint remote, CancellationToken token);
}
internal interface IMeshCandidateFactory
{
    TraversalProfile[] Profiles { get; }
    bool SupportsUdpIpv6 => false;
    bool SupportsFakeTcpIpv6 => false;
    EgressStats? Egress => null;
    Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile profile, Guid attempt, CancellationToken token);
    Task<IMeshCandidateResource> GatherForPeer(MeshMember peer, TraversalProfile profile, Guid attempt,
        bool allowIpv6, IPEndPoint? remote, int round, CancellationToken token) => Gather(peer, profile, attempt, token);
}

// One request budget for all discovery operations of this running device.
// Below the service's 48/minute, burst 8; eight devices stay under 512/minute.
internal sealed class MeshRequestBudget
{
    readonly object gate = new();
    double tokens = 6;
    long last = Stopwatch.GetTimestamp();
    public bool Take(bool priority = false)
    {
        lock (gate) {
        long now = Stopwatch.GetTimestamp(); tokens = Math.Min(6, tokens + Stopwatch.GetElapsedTime(last, now).TotalSeconds * (40d / 60)); last = now;
        if (tokens < (priority ? 1 : 3)) return false;
        tokens--; return true;
        }
    }
}

internal sealed partial class MeshCandidateFactory(DeviceProfile profile, string executable, string folder,
    TraversalProfile[] profiles, bool captureBroker = false, Action<string>? diagnostic = null, bool ipv6Native = false, bool wireControl = false) : IMeshCandidateFactory, IAsyncDisposable
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
    internal Func<string, AddressFamily, CancellationToken, Task<IPEndPoint>> ResolveTarget { get; init; } = Stun.Resolve;
    internal Func<IPAddress, int, CancellationToken, Task<PortControlLease>> OpenUdpGateway { get; init; } =
        (local, port, ct) => PortControlLease.Create(local, port, port, PortMappingProtocol.Udp, ct);
    MeshTcpEndpointPool Pool { get { lock (poolGate) return pool ??= new(generation,
        (local, helper) => OpenCaptureForTest?.Invoke(local, helper) ?? new WinDivertEndpointIo(Path.Combine(Path.GetDirectoryName(binary)!, "WinDivert.dll"), local, helper), pacer: pacer); } }
    public TraversalProfile[] Profiles => profiles;
    public bool SupportsUdpIpv6 => options.UdpIpv6 && profiles.Contains(TraversalProfile.UdpDirect);
    public bool SupportsFakeTcpIpv6 => options.FakeTcpIpv6 && captureBroker && ipv6Native && profiles.Contains(TraversalProfile.FakeTcpHttpSo);
    public static async Task<IMeshCandidateFactory?> Create(DeviceProfile profile, string executable, string folder, Action<string> log, CancellationToken token)
    {
        profile.Selection().Validate();
        if (profile.TraversalMode == "legacy") return null;
        var supported = new List<TraversalProfile>();
        bool broker = false, ipv6 = false, wireControl = false;
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
        return supported.Count == 0 ? null : new MeshCandidateFactory(profile, executable, folder, supported.ToArray(), broker, log, ipv6, wireControl);
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
    public async Task<IMeshCandidateResource> GatherForPeer(MeshMember peer, TraversalProfile kind, Guid attempt,
        bool allowIpv6, IPEndPoint? remote, int round, CancellationToken token)
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
        return await GatherFamily(peer, kind, attempt, AddressFamily.InterNetwork, deadline.Token);
    }
    async Task<IMeshCandidateResource> GatherFamily(MeshMember peer, TraversalProfile kind, Guid attempt, AddressFamily family, CancellationToken token)
    {
        if (!Profiles.Contains(kind)) throw new NotSupportedException();
        bool useGateway = false;
        if (family == AddressFamily.InterNetwork && kind == TraversalProfile.UdpDirect && options.PortControlMapping) lock (poolGate) {
            var prior = udpMethods.GetValueOrDefault(peer.Slot);
            useGateway = prior.Device == peer.Device && prior.GatewayNext;
            udpMethods[peer.Slot] = (peer.Device, !useGateway);
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(12000);
        var servers = kind == TraversalProfile.UdpDirect ? options.UdpStun : options.OrderedTcp();
        Exception? last = null;
        foreach (string name in servers.Take(3)) {
            TcpEndpointLease? tcp = null; UdpTraversal? udp = null;
            MeshTcpEndpointPool.Use? pooled = null;
            bool transferred = false, gatewayTried = false;
            try {
                var target = await ResolveTarget(name, family, deadline.Token); CheckRoute(target);
                var local = new IPEndPoint(Stun.LocalAddress(target), 0);
                IPEndPoint mapped; string observation = target.ToString(); double lifetime = 120;
                if (kind == TraversalProfile.UdpDirect) {
                    byte[] shared = MeshIdentity.SharedKey(options.Mesh!, peer);
                    try { udp = UdpTraversal.Create(local, generation, attempt, options.Mesh!.Self.Slot, peer.Slot, shared, pacer: pacer, fairnessKey: peer.Device); }
                    finally { CryptographicOperations.ZeroMemory(shared); }
                    if (useGateway) {
                        gatewayTried = true;
                        var mapping = await OpenUdpGateway(udp.Local.Address, udp.Local.Port, deadline.Token);
                        try { udp.AttachGateway(mapping); } catch { await mapping.DisposeAsync(); throw; }
                        mapped = mapping.External; var snapshot = mapping.Snapshot;
                        lifetime = Math.Min(120, Math.Floor(snapshot.RemainingSeconds)); observation = snapshot.Gateway;
                        if (lifetime <= TraversalLimits.UdpRoundMs / 1000 + 2) throw new IOException("UDP 网关租期不足以准备和检查候选");
                        diagnostic?.Invoke($"UDP 显式候选 {mapped}，socket={udp.SocketId:N}；仍需同 socket 双向认证与 MTU 检查");
                    } else mapped = (await udp.Observe(target, deadline.Token)).Mapped;
                } else if (captureBroker) {
                    pooled = await Pool.Acquire(local.Address, target, deadline.Token); tcp = pooled.Lease; mapped = pooled.Observed;
                    if (family == AddressFamily.InterNetwork) ObserveInBackground(pooled.Owner, peer); // observer wire protocol is still IPv4-only
                } else {
                    using var connect = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token); connect.CancelAfter(3500);
                    tcp = await TcpEndpointLease.Open(local, target, generation, connect.Token);
                    using var reference = tcp.AcquireAttempt(generation); mapped = (await reference.Observe(deadline.Token)).Public;
                }
                CheckRoute(mapped, gatewayCandidate: useGateway);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var candidate = new MeshTraversalCandidate(Guid.NewGuid(), 1, mapped.ToString(), observation, now, now + (long)lifetime,
                    kind == TraversalProfile.UdpDirect ? CandidatePurpose.UdpDirect : CandidatePurpose.SimultaneousOpen);
                var resource = new Resource(this, peer, candidate, tcp, udp, pooled); transferred = true; return resource;
            } catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or SocketException or OperationCanceledException or ArgumentException) { last = ex; }
            finally { // Success transfers both resources into Resource.
                if (!transferred) { if (pooled != null) pooled.Dispose(); else tcp?.Dispose(); if (udp != null) await udp.DisposeAsync(); }
            }
            if (deadline.IsCancellationRequested) break;
            if (gatewayTried) break; // Another STUN server cannot repair this gateway transaction.
            last ??= new IOException("候选观察失败");
        }
        throw new IOException("同端点候选观察未成功", last);
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
                    captureOwner: pooled?.Owner, countWireControl: owner.countWireControl);
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
