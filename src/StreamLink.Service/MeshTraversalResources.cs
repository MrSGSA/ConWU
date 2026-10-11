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
    Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile profile, Guid attempt, CancellationToken token);
}

// One request budget for all discovery operations of this running device.
// Below the service's 48/minute, burst 8; eight devices stay under 512/minute.
internal sealed class MeshRequestBudget
{
    double tokens = 6;
    long last = Stopwatch.GetTimestamp();
    public bool Take(bool priority = false)
    {
        long now = Stopwatch.GetTimestamp(); tokens = Math.Min(6, tokens + Stopwatch.GetElapsedTime(last, now).TotalSeconds * (40d / 60)); last = now;
        if (tokens < (priority ? 1 : 3)) return false;
        tokens--; return true;
    }
}

internal sealed class MeshCandidateFactory(DeviceProfile profile, string executable, string folder,
    TraversalProfile[] profiles, bool captureBroker = false) : IMeshCandidateFactory, IAsyncDisposable
{
    readonly Guid generation = Guid.NewGuid();
    readonly DeviceProfile options = profile;
    readonly string binary = executable, root = folder;
    MeshTcpEndpointPool? pool;
    readonly object poolGate = new();
    MeshTcpEndpointPool Pool { get { lock (poolGate) return pool ??= new(generation,
        (local, helper) => new WinDivertEndpointIo(Path.Combine(Path.GetDirectoryName(binary)!, "WinDivert.dll"), local, helper)); } }
    public TraversalProfile[] Profiles => profiles;
    public static async Task<IMeshCandidateFactory?> Create(DeviceProfile profile, string executable, string folder, Action<string> log, CancellationToken token)
    {
        profile.Selection().Validate();
        if (profile.TraversalMode == "legacy") return null;
        var supported = new List<TraversalProfile>();
        bool broker = false;
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
                if (r.GetProperty("nativeAbi").GetInt32() == 1 && r.GetProperty("backend").GetString() == "windivert" &&
                    r.TryGetProperty("preparedStart", out var prepared) && prepared.GetBoolean() &&
                    r.TryGetProperty("simultaneousOpen", out var so) && so.GetBoolean() && r.GetProperty("wireProtocol").GetString() == "udp2raw-http-c4995ea")
                    supported.Add(TraversalProfile.FakeTcpHttpSo);
            } finally { if (!process.HasExited) { process.Kill(); await process.WaitForExitAsync(); } }
        } catch (Exception ex) when (!token.IsCancellationRequested) { log("原生双主动暂未启用：" + ex.GetType().Name); }
        if (profile.TraversalMode == "tcp-udp" && profile.Selection().Allows(TraversalProfile.UdpDirect)) supported.Add(TraversalProfile.UdpDirect);
        return supported.Count == 0 ? null : new MeshCandidateFactory(profile, executable, folder, supported.ToArray(), broker);
    }
    void CheckRoute(IPEndPoint endpoint, IPAddress? expected = null)
    {
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
    public async Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile kind, Guid attempt, CancellationToken token)
    {
        if (!Profiles.Contains(kind)) throw new NotSupportedException();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(12000);
        var servers = kind == TraversalProfile.UdpDirect ? options.UdpStun : options.OrderedTcp();
        Exception? last = null;
        foreach (string name in servers.Take(3)) {
            TcpEndpointLease? tcp = null; UdpTraversal? udp = null;
            MeshTcpEndpointPool.Use? pooled = null;
            bool transferred = false;
            try {
                var target = await Stun.Resolve(name, deadline.Token); CheckRoute(target);
                var local = new IPEndPoint(Stun.LocalAddress(target), 0);
                IPEndPoint mapped;
                if (kind == TraversalProfile.UdpDirect) {
                    byte[] shared = MeshIdentity.SharedKey(options.Mesh!, peer);
                    try { udp = UdpTraversal.Create(local, generation, attempt, options.Mesh!.Self.Slot, peer.Slot, shared); }
                    finally { CryptographicOperations.ZeroMemory(shared); }
                    mapped = (await udp.Observe(target, deadline.Token)).Mapped;
                } else if (captureBroker) {
                    pooled = await Pool.Acquire(local.Address, target, deadline.Token); tcp = pooled.Lease; mapped = pooled.Observed;
                } else {
                    using var connect = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token); connect.CancelAfter(3500);
                    tcp = await TcpEndpointLease.Open(local, target, generation, connect.Token);
                    using var reference = tcp.AcquireAttempt(generation); mapped = (await reference.Observe(deadline.Token)).Public;
                }
                CheckRoute(mapped);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var candidate = new MeshTraversalCandidate(Guid.NewGuid(), 1, mapped.ToString(), target.ToString(), now, now + 120,
                    kind == TraversalProfile.UdpDirect ? CandidatePurpose.UdpDirect : CandidatePurpose.SimultaneousOpen);
                var resource = new Resource(this, peer, candidate, tcp, udp, pooled); transferred = true; return resource;
            } catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or SocketException or OperationCanceledException or ArgumentException) { last = ex; }
            finally { // Success transfers both resources into Resource.
                if (!transferred) { if (pooled != null) pooled.Dispose(); else tcp?.Dispose(); if (udp != null) await udp.DisposeAsync(); }
            }
            if (deadline.IsCancellationRequested) break;
            last ??= new IOException("候选观察失败");
        }
        throw new IOException("同端点候选观察未成功", last);
    }
    sealed class Resource(MeshCandidateFactory owner, MeshMember peer, MeshTraversalCandidate candidate,
        TcpEndpointLease? tcp, UdpTraversal? udp, MeshTcpEndpointPool.Use? pooled) : IMeshCandidateResource
    {
        bool prepared;
        public MeshTraversalCandidate Candidate => candidate;
        public async Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context, IPEndPoint remote, CancellationToken token)
        {
            if (prepared) throw new IOException("候选资源已被接入");
            owner.CheckRoute(remote, tcp?.Local.Address ?? udp!.Local.Address);
            if (udp != null) { var result = udp.PreparePath(context, owner.generation, remote); prepared = true; return result; }
            byte[] shared = MeshIdentity.SharedKey(owner.options.Mesh!, peer);
            try {
                var result = await NativeDatagramPath.Prepare(owner.binary, owner.root, tcp!, owner.generation, context, remote, shared, token,
                    captureOwner: pooled?.Owner);
                prepared = true; return result;
            } finally { CryptographicOperations.ZeroMemory(shared); }
        }
        public async ValueTask DisposeAsync()
        {
            if (pooled != null) pooled.Dispose(); else tcp?.Dispose();
            if (udp != null && !prepared) await udp.DisposeAsync(); // Prepared owns original UDP reference after transfer.
        }
    }
    public async ValueTask DisposeAsync() { if (pool != null) await pool.DisposeAsync(); }
}
