using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed class MeshRunner
{
    readonly DeviceProfile profile;
    readonly MeshProfile mesh;
    readonly Action<string> log, rememberStun;
    readonly Action<SessionStatus> report;
    readonly Action<MeshDirectory> remember;
    readonly MeshRuntimeServices services;
    public MeshRunner(DeviceProfile profile, Action<string> log, Action<SessionStatus> report, Action<MeshDirectory> remember, Action<string>? rememberStun = null)
        : this(profile, log, report, remember, rememberStun ?? (_ => { }), MeshRuntimeServices.Default) { }
    internal MeshRunner(DeviceProfile profile, Action<string> log, Action<SessionStatus> report, Action<MeshDirectory> remember, Action<string> rememberStun, MeshRuntimeServices services)
    { this.profile = profile; mesh = profile.Mesh!; this.log = log; this.report = report; this.remember = remember; this.rememberStun = rememberStun; this.services = services; }
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
        string folder = Path.Combine(services.SessionRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string rule = "StreamLink-" + Guid.NewGuid().ToString("N");
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        CancellationToken stop = cancellation.Token;
        using var discovery = services.Discovery(mesh);
        IMapping? mapping = null; Task<IMapping>? probe = null; Task? maintain = null, quality = null, releasing = null;
        Task<IPacketAdapter>? opening = null;
        Task<MeshSnapshot?>? reading = null;
        Task? publishing = null, saving = null;
        IMeshTransport? server = null;
        var clients = new Dictionary<int, MeshPeerTransports>();
        var revisions = new Dictionary<int, long>();
        var announcements = new Dictionary<int, MeshAnnouncement>();
        long revision = DateTime.UtcNow.Ticks, savedDirectory = 0, savingRevision = 0;
        long nextProbe = 0, nextRead = 0, nextSave = 0, lastPublish = 0, nextReport = 0, lastWarning = 0, nextServer = 0, serverStarted = 0;
        int probeFailures = 0, readFailures = 0, serverFailures = 0;
        string publishedEndpoint = "\0", publishingEndpoint = "";
        string firewallMembers = "";
        var timeline = new ConnectionTimeline(log);
        string Candidate() => server != null && !server.Exited ? mapping?.PublicEndpoint.ToString() ?? profile.ManualEndpoint : "";
        void Warning(Exception ex)
        {
            if (lastWarning == 0 || Environment.TickCount64 - lastWarning >= 30000) { log("协调服务暂不可用，已有直连继续运行：" + ex.Message); lastWarning = Environment.TickCount64; }
        }
        try {
            timeline.Mark("原生网络开始启动");
            report(new("正在创建虚拟网卡", mesh.LocalIp, "", mesh.Pair.Mode, false, null, "正在准备原生组网，同时探测公网入口"));
            opening = services.Adapter(mesh);
            while (!stop.IsCancellationRequested) {
                long now = Environment.TickCount64;
                if (opening?.IsCompleted == true) {
                    var adapter = await opening; opening = null;
                    try { router = new(mesh, adapter, (discovery as IMeshTraversalDiscovery)?.BootId); } catch { adapter.Dispose(); throw; }
                    services.Record(folder, rule); quality = services.QualityServer(mesh.LocalIp, QualityKey, stop);
                    timeline.Mark("原生虚拟网卡就绪");
                }
                if (router?.Completion.IsCompleted == true) await router.Completion;
                if (quality?.IsCompleted == true) { await quality; throw new IOException("质量服务停止"); }
                lock (gate) if (pendingDirectory != null) { mesh.Directory = pendingDirectory; pendingDirectory = null; }
                if (releasing?.IsCompleted == true) {
                    try { await releasing; } catch (Exception ex) { log("旧映射清理：" + ex.Message); }
                    releasing = null;
                }
                if (probe == null && mapping == null && releasing == null && profile.ManualEndpoint.Length == 0 && now >= nextProbe) probe = services.Probe(profile, log, stop);
                if (probe?.IsCompleted == true) {
                    try { mapping = await probe; maintain = mapping.Maintain(stop); probeFailures = 0; timeline.Mark("本机候选入口就绪"); }
                    catch (Exception ex) when (!stop.IsCancellationRequested) { log("入口暂不可用，可使用其他成员入口：" + ex.Message); nextProbe = now + Math.Min(45000, 5000L << Math.Min(probeFailures++, 4)); }
                    finally { probe = null; }
                }
                if (mapping is TcpMapping tcp && profile.LastStun != tcp.StunServer) {
                    profile.LastStun = tcp.StunServer; rememberStun(tcp.StunServer);
                }
                if (maintain?.IsCompleted == true) {
                    try { await maintain; } catch (Exception ex) when (!stop.IsCancellationRequested) { log("重新建立映射：" + ex.Message); }
                    server?.Dispose(); server = null; releasing = mapping!.DisposeAsync().AsTask(); mapping = null; maintain = null; nextProbe = now + 1000;
                }
                if (server?.Exited == true) {
                    if (now - serverStarted >= 30000) serverFailures = 0;
                    server.Dispose(); server = null; nextServer = now + Math.Min(15000, 250L << Math.Min(serverFailures++, 6));
                }
                if (router != null && server == null && (mapping != null || profile.ManualEndpoint.Length > 0) && now >= nextServer) {
                    try { server = services.Transport(new(folder, mesh, router.LocalEndpoint, true, profile.ListenPort, mapping, profile.LogLevel)); serverStarted = now; }
                    catch (Exception ex) { nextServer = now + Math.Min(15000, 1000L << Math.Min(serverFailures++, 4)); log("本机传输入口启动重试：" + ex.Message); }
                }
                // Independent HTTP operations: neither a slow GET/PUT nor adapter
                // startup can hold up local child recovery or the other direction.
                if (saving?.IsCompleted == true) {
                    try { await saving; savedDirectory = savingRevision; }
                    catch (Exception ex) when (!stop.IsCancellationRequested) { Warning(ex); }
                    saving = null;
                }
                if (publishing?.IsCompleted == true) {
                    try { await publishing; publishedEndpoint = publishingEndpoint; }
                    catch (Exception ex) when (!stop.IsCancellationRequested) { Warning(ex); }
                    publishing = null;
                }
                if (reading?.IsCompleted == true) {
                    try {
                        var snapshot = await reading; readFailures = 0;
                        if (snapshot != null && snapshot.Directory.Revision >= (mesh.Directory?.Revision ?? 0)) {
                            long previous = mesh.Directory?.Revision ?? 0;
                            MeshIdentity.ValidateDirectory(snapshot.Directory, mesh.Pair.Network, mesh.OwnerKey, previous);
                            router?.ApplyDirectory(snapshot.Directory);
                            lock (gate) mesh.Directory = snapshot.Directory;
                            if (snapshot.Directory.Revision > previous) remember(snapshot.Directory);
                            foreach (var envelope in snapshot.Nodes) {
                                var member = snapshot.Directory.Members.FirstOrDefault(m => m.Slot == envelope.Slot && m.Slot != mesh.Self.Slot); if (member == null) continue;
                                try {
                                    var announcement = MeshMetadata.Open(mesh, member, envelope);
                                    if (revisions.GetValueOrDefault(member.Slot) > announcement.Revision) continue;
                                    revisions[member.Slot] = announcement.Revision; announcements[member.Slot] = announcement;
                                } catch (Exception ex) when (ex is CryptographicException or FormatException) { log("已拒绝无效成员公告"); }
                            }
                        }
                    } catch (Exception ex) when (!stop.IsCancellationRequested && ex is not MeshRevokedException) {
                        Warning(ex); nextRead = now + Math.Min(30000, 2500L << Math.Min(++readFailures, 4));
                    }
                    reading = null;
                }
                if (saving == null && mesh.IsOwner && mesh.Directory is {} directory && savedDirectory < directory.Revision && now >= nextSave) {
                    savingRevision = directory.Revision; saving = discovery.SaveDirectory(directory, stop); nextSave = now + 5000;
                }
                var statuses = router?.Status() ?? [];
                bool allConnected = statuses.Length > 0 && statuses.All(p => p.Connected);
                if (reading == null && now >= nextRead) {
                    bool watching = discovery is IMeshChangeDiscovery { SupportsLongPolling: true };
                    reading = watching ? ((IMeshChangeDiscovery)discovery).WaitForChanges(stop) : discovery.Read(stop);
                    // Even a busy event feed cannot issue more requests than the
                    // former disconnected polling schedule. Idle waits hold 25s.
                    nextRead = now + (watching ? 2500 : allConnected ? 5000 : 2500);
                }
                string candidate = Candidate();
                if (publishing == null && (lastPublish == 0 || now - lastPublish >= (candidate != publishedEndpoint ? 2500 : 15000))) {
                    publishingEndpoint = candidate; lastPublish = now;
                    publishing = discovery.Publish(new(mesh.Self.Slot, mesh.Self.Device, ++revision, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), candidate, profile.DeviceName), stop);
                }
                // 8 members * (24 reads + <=24 writes)/minute, plus <=12 directory
                // writes by the owner, stays below the server's 512/minute budget.
                if (router == null) { await Task.Delay(100, stop); continue; }
                var members = mesh.Directory?.Members.Where(m => m.Slot != mesh.Self.Slot).ToArray() ?? [];
                string remoteAddresses = string.Join(',', members.Select(m => MeshIdentity.Address(mesh.Pair.Network, m.Slot)));
                if (firewallMembers != remoteAddresses) {
                    services.Firewall(rule, mesh.LocalIp, remoteAddresses); firewallMembers = remoteAddresses;
                }
                foreach (int slot in clients.Keys.Where(s => !members.Any(m => m.Slot == s)).ToArray()) { clients[slot].Dispose(); clients.Remove(slot); announcements.Remove(slot); }
                foreach (var member in members) {
                    announcements.TryGetValue(member.Slot, out var announcement);
                    string endpoint = announcement?.Expires > DateTimeOffset.UtcNow.ToUnixTimeSeconds() ? announcement.Endpoint : "";
                    if (!clients.TryGetValue(member.Slot, out var paths)) clients[member.Slot] = paths = new(router, ep => services.Transport(new(folder, mesh, IPEndPoint.Parse(ep), false, profile.ListenPort, null, profile.LogLevel)), log);
                    paths.Update(member.Slot, endpoint, announcement?.Name ?? "", endpoint.Length > 0 ? "正在验证直连" : candidate.Length > 0 ? "等待成员连接本机入口" : "双方暂无可用入口，业务不会转发");
                }
                if (now >= nextReport) {
                    int count = statuses.Count(p => p.Connected); var first = statuses.FirstOrDefault(p => p.Connected);
                    report(new(statuses.Length == 0 ? "等待成员加入" : count == statuses.Length ? "已直连" : count > 0 ? "部分设备已直连" : "正在连接", mesh.LocalIp, first?.Ip ?? "", mesh.Pair.Mode, count > 0, first?.RttMs, $"{count}/{statuses.Length} 台设备直连 · 原生组网 · 业务不经中继", first?.Name ?? "", statuses));
                    nextReport = now + 1000;
                }
                await Task.Delay(100, stop);
            }
        } finally {
            cancellation.Cancel();
            if (probe != null) { try { mapping = await probe; } catch { } }
            if (opening != null) { try { (await opening).Dispose(); } catch { } }
            foreach (var task in new[] { maintain, quality, reading, publishing, saving, releasing }) if (task != null) { try { await task; } catch (Exception ex) { if (ex is not OperationCanceledException) log("退出任务：" + ex.Message); } }
            foreach (var client in clients.Values) { try { client.Dispose(); } catch (Exception ex) { log("传输清理：" + ex.Message); } }
            try { server?.Dispose(); } catch (Exception ex) { log("入口清理：" + ex.Message); }
            if (mapping != null) { try { await mapping.DisposeAsync(); } catch (Exception ex) { log("映射清理：" + ex.Message); } }
            if (router != null) { try { await router.DisposeAsync(); } catch (Exception ex) { log("原生网络已停止：" + ex.Message); } router = null; }
            try { services.Firewall(rule, mesh.LocalIp, ""); File.Delete(Path.Combine(folder, "owner.json")); } catch (Exception ex) { log("会话规则等待下次恢复：" + ex.Message); }
        }
    }
}
