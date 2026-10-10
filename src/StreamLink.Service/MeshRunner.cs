using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed class MeshRunner(DeviceProfile profile, Action<string> log, Action<SessionStatus> report, Action<MeshDirectory> remember)
{
    readonly MeshProfile mesh = profile.Mesh!;
    readonly object gate = new();
    MeshRouter? router;
    MeshDirectory? pendingDirectory;
    public void UpdateDirectory(MeshDirectory directory)
    {
        lock (gate) { MeshIdentity.ValidateDirectory(directory, mesh.Pair.Network, mesh.OwnerKey, mesh.Directory?.Revision ?? 0); pendingDirectory = directory; router?.ApplyDirectory(directory); }
    }
    string? QualityKey(IPAddress address)
    {
        lock (gate) {
            var peer = mesh.Directory?.Members.FirstOrDefault(m => m.Slot != mesh.Self.Slot && MeshIdentity.Address(mesh.Pair.Network, m.Slot) == address.ToString());
            if (peer == null) return null;
            byte[] key = MeshIdentity.SharedKey(mesh, peer); try { return Convert.ToHexString(key); } finally { CryptographicOperations.ZeroMemory(key); }
        }
    }
    public Task<QualityResult> Measure(int mbps, int slot, CancellationToken token)
    {
        var connected = router?.Status().Where(p => p.Connected).ToArray() ?? [];
        if (slot == 0 && connected.Length == 1) slot = connected[0].Slot;
        var peer = connected.FirstOrDefault(p => p.Slot == slot) ?? throw new IOException("请选择已直连的设备进行测速");
        return Quality.Measure(peer.Ip, QualityKey(IPAddress.Parse(peer.Ip))!, mbps, token, local: mesh.LocalIp);
    }
    public async Task Run(CancellationToken token)
    {
        mesh.Validate();
        string components = Path.Combine(AppContext.BaseDirectory, "components");
        string folder = Path.Combine(ProfileStore.Root, "sessions", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string rule = "StreamLink-" + Guid.NewGuid().ToString("N");
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        CancellationToken stop = cancellation.Token;
        using var discovery = new MeshDiscoveryClient(mesh);
        IMapping? mapping = null; Task<IMapping>? probe = null; Task? maintain = null, monitoring = null, quality = null;
        MeshTransport? server = null;
        var clients = new Dictionary<int, (string Endpoint, MeshTransport Transport)>();
        var revisions = new Dictionary<int, long>();
        var announcements = new Dictionary<int, MeshAnnouncement>();
        long revision = DateTime.UtcNow.Ticks, savedDirectory = 0;
        DateTime nextProbe = DateTime.MinValue, lastWarning = DateTime.MinValue;
        string firewallMembers = "";
        var timeline = new ConnectionTimeline(log);
        async Task<IMapping> Probe() => mesh.Pair.Mode == "udp" ? await UdpMapping.Create(profile.ListenPort, profile.ListenPort, log, stop, profile.UdpStun, profile.Device) : await TcpMapping.Create(profile.SourcePort, profile.ListenPort, log, stop, profile.OrderedTcp(), profile.Device);
        string Candidate() => server != null && !server.Exited ? mapping?.PublicEndpoint.ToString() ?? profile.ManualEndpoint : "";
        async Task Monitor()
        {
            while (!stop.IsCancellationRequested) {
                var peers = router!.Status(); int count = peers.Count(p => p.Connected);
                var first = peers.FirstOrDefault(p => p.Connected);
                report(new(peers.Length == 0 ? "等待成员加入" : count == peers.Length ? "已直连" : count > 0 ? "部分设备已直连" : "正在连接", mesh.LocalIp, first?.Ip ?? "", mesh.Pair.Mode, count > 0, first?.RttMs, $"{count}/{peers.Length} 台设备直连 · 原生组网 · 业务不经中继", first?.Name ?? "", peers));
                await Task.Delay(1000, stop);
            }
        }
        try {
            timeline.Mark("原生网络开始启动");
            if (profile.ManualEndpoint.Length == 0) probe = Probe();
            report(new("正在创建虚拟网卡", mesh.LocalIp, "", mesh.Pair.Mode, false, null, "正在准备原生组网，同时探测公网入口"));
            var adapter = await Task.Run(() => new NativeAdapter(components, mesh.Pair.Network, mesh.Self.Slot), CancellationToken.None);
            try { router = new(mesh, adapter); } catch { adapter.Dispose(); throw; }
            timeline.Mark("原生虚拟网卡就绪");
            Recovery.Record(folder, rule);
            quality = Quality.Serve(mesh.LocalIp, QualityKey, stop); monitoring = Monitor();
            while (!stop.IsCancellationRequested) {
                if (router.Completion.IsCompleted) await router.Completion;
                if (quality.IsCompleted) { await quality; throw new IOException("质量服务停止"); }
                lock (gate) if (pendingDirectory != null) { mesh.Directory = pendingDirectory; pendingDirectory = null; }
                if (probe == null && mapping == null && profile.ManualEndpoint.Length == 0 && DateTime.UtcNow >= nextProbe) probe = Probe();
                if (probe?.IsCompleted == true) {
                    try { mapping = await probe; maintain = mapping.Maintain(stop); timeline.Mark("本机候选入口就绪"); }
                    catch (Exception ex) when (!stop.IsCancellationRequested) { log("入口暂不可用，可使用其他成员入口：" + ex.Message); nextProbe = DateTime.UtcNow.AddSeconds(45); }
                    probe = null;
                }
                if (maintain?.IsCompleted == true) {
                    try { await maintain; } catch (Exception ex) when (!stop.IsCancellationRequested) { log("重新建立映射：" + ex.Message); }
                    server?.Dispose(); server = null; await mapping!.DisposeAsync(); mapping = null; maintain = null; nextProbe = DateTime.UtcNow.AddSeconds(5);
                }
                if (server?.Exited == true) { server.Dispose(); server = null; }
                if (server == null && (mapping != null || profile.ManualEndpoint.Length > 0)) server = new(components, folder, mesh, router.LocalEndpoint, true, profile.ListenPort, mapping, profile.LogLevel);
                try {
                    if (mesh.IsOwner && mesh.Directory != null && savedDirectory < mesh.Directory.Revision) { await discovery.SaveDirectory(mesh.Directory, stop); savedDirectory = mesh.Directory.Revision; }
                    var snapshot = await discovery.Read(stop);
                    if (snapshot != null && snapshot.Directory.Revision >= (mesh.Directory?.Revision ?? 0)) {
                        MeshIdentity.ValidateDirectory(snapshot.Directory, mesh.Pair.Network, mesh.OwnerKey, mesh.Directory?.Revision ?? 0);
                        router.ApplyDirectory(snapshot.Directory);
                        lock (gate) mesh.Directory = snapshot.Directory;
                        remember(snapshot.Directory);
                        foreach (var envelope in snapshot.Nodes) {
                            var member = snapshot.Directory.Members.FirstOrDefault(m => m.Slot == envelope.Slot && m.Slot != mesh.Self.Slot); if (member == null) continue;
                            try {
                                var announcement = MeshMetadata.Open(mesh, member, envelope);
                                if (revisions.GetValueOrDefault(member.Slot) > announcement.Revision) continue;
                                revisions[member.Slot] = announcement.Revision; announcements[member.Slot] = announcement;
                            } catch (Exception ex) when (ex is CryptographicException or FormatException) { log("已拒绝无效成员公告"); }
                        }
                    }
                    await discovery.Publish(new(mesh.Self.Slot, mesh.Self.Device, ++revision, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), Candidate(), profile.DeviceName), stop);
                } catch (Exception ex) when (!stop.IsCancellationRequested && ex is not MeshRevokedException) {
                    if ((DateTime.UtcNow - lastWarning).TotalSeconds > 30) { log("协调服务暂不可用，已有直连继续运行：" + ex.Message); lastWarning = DateTime.UtcNow; }
                }
                var members = mesh.Directory?.Members.Where(m => m.Slot != mesh.Self.Slot).ToArray() ?? [];
                string remoteAddresses = string.Join(',', members.Select(m => MeshIdentity.Address(mesh.Pair.Network, m.Slot)));
                if (firewallMembers != remoteAddresses) {
                    WindowsHost.RemoveFirewall(rule); if (remoteAddresses.Length > 0) WindowsHost.AddFirewall(rule, mesh.LocalIp, remoteAddresses); firewallMembers = remoteAddresses;
                }
                foreach (int slot in clients.Keys.Where(s => !members.Any(m => m.Slot == s)).ToArray()) { clients[slot].Transport.Dispose(); clients.Remove(slot); announcements.Remove(slot); }
                foreach (var member in members) {
                    announcements.TryGetValue(member.Slot, out var announcement);
                    string endpoint = announcement?.Expires > DateTimeOffset.UtcNow.ToUnixTimeSeconds() ? announcement.Endpoint : "";
                    if (clients.TryGetValue(member.Slot, out var existing) && (existing.Transport.Exited || endpoint.Length > 0 && existing.Endpoint != endpoint)) { existing.Transport.Dispose(); clients.Remove(member.Slot); }
                    if (!clients.ContainsKey(member.Slot) && endpoint.Length > 0) {
                        try { clients[member.Slot] = (endpoint, new(components, folder, mesh, IPEndPoint.Parse(endpoint), false, profile.ListenPort, null, profile.LogLevel)); }
                        catch (Exception ex) { log($"设备 {member.Slot} 传输重试：{ex.Message}"); }
                    }
                    var candidate = clients.TryGetValue(member.Slot, out var client) ? client.Transport.ClientEndpoint : null;
                    router.SetCandidate(member.Slot, candidate, announcement?.Name ?? "", endpoint.Length > 0 ? "正在验证直连" : Candidate().Length > 0 ? "等待成员连接本机入口" : "双方暂无可用入口，业务不会转发");
                }
                await Task.Delay(5000, stop);
            }
        } finally {
            cancellation.Cancel();
            if (probe != null) { try { mapping = await probe; } catch { } }
            foreach (var task in new[] { maintain, quality, monitoring }) if (task != null) { try { await task; } catch (Exception ex) { if (ex is not OperationCanceledException) log("退出任务：" + ex.Message); } }
            foreach (var client in clients.Values) client.Transport.Dispose(); server?.Dispose();
            if (mapping != null) await mapping.DisposeAsync();
            if (router != null) { try { await router.DisposeAsync(); } catch (Exception ex) { log("原生网络已停止：" + ex.Message); } router = null; }
            try { WindowsHost.RemoveFirewall(rule); File.Delete(Path.Combine(folder, "owner.json")); } catch (Exception ex) { log("会话规则等待下次恢复：" + ex.Message); }
        }
    }
}
