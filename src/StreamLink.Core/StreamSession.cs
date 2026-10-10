using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record SessionStatus(string State, string LocalIp, string PeerIp, string Transport, bool Connected, double? RttMs, string Detail, string PeerName = "");

[SupportedOSPlatform("windows")]
public sealed class StreamSession : IAsyncDisposable
{
    readonly string bin;
    readonly Action<string> log;
    readonly string root;
    readonly string sessionsRoot;
    bool ownsMapping = true;
    readonly CancellationTokenSource stop = new();
    ChildJob? job;
    IMapping? mapping;
    Task? mappingTask;
    Task? monitor;
    Task? qualityServer;
    string rule = "";
    int rpc;
    bool disposed;
    public Invitation? Ticket { get; private set; }
    public string LocalIp { get; private set; } = "";
    public string PeerIp { get; private set; } = "";
    public string EvidenceDirectory => root;
    public bool IsConnected { get; private set; }
    public event Action<SessionStatus>? StatusChanged;
    public event Action<string>? InviteChanged;
    public StreamSession(string bin, Action<string> log, string? sessionsRoot = null) { this.bin = Path.GetFullPath(bin); this.log = log; this.sessionsRoot = sessionsRoot ?? Recovery.Root; root = Path.Combine(this.sessionsRoot, Guid.NewGuid().ToString("N")); }
    static string Q(string value) => JsonSerializer.Serialize(value);
    static int FreePort(SocketType type)
    {
        using var s = new Socket(AddressFamily.InterNetwork, type, type == SocketType.Stream ? ProtocolType.Tcp : ProtocolType.Udp);
        s.Bind(new IPEndPoint(IPAddress.Loopback, 0)); return ((IPEndPoint)s.LocalEndPoint!).Port;
    }
    void Report(string state, bool connected, string detail, double? rtt = null) { IsConnected = connected; StatusChanged?.Invoke(new(state, LocalIp, PeerIp, Ticket?.Mode ?? "faketcp", connected, rtt, detail)); }
    public async Task<QualityResult> Measure(int mbps, CancellationToken token)
    {
        if(!IsConnected) throw new IOException("请先连接对端，再启动链路质量测试");
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(stop.Token,token);
        var result = await Quality.Measure(PeerIp,Ticket!.Secret,mbps,linked.Token,local:LocalIp);
        await File.WriteAllTextAsync(Path.Combine(root,$"quality-{DateTime.Now:yyyyMMdd-HHmmss}.json"),JsonSerializer.Serialize(result),linked.Token);
        return result;
    }

    public async Task Start(SessionOptions options, CancellationToken cancellation = default, IMapping? preparedMapping = null)
    {
        if (!WindowsHost.IsAdmin) throw new IOException("启动虚拟网络需要管理员权限，请以管理员身份运行");
        Recovery.Recover(log, sessionsRoot);
        foreach (string file in new[] { "udp2raw-native.exe", "WinDivert.dll", "WinDivert64.sys", "easytier-core.exe", "easytier-cli.exe", "wintun.dll" })
            if (!File.Exists(Path.Combine(bin, file))) throw new FileNotFoundException("配套组件不完整：" + file);
        if (NetworkInterface.GetAllNetworkInterfaces().SelectMany(n => n.GetIPProperties().UnicastAddresses).Any(a => a.Address.ToString().StartsWith("10.129.129.")))
            throw new IOException("初版虚拟网段 10.129.129.0/24 已占用，请先停止本软件其他会话");
        if (options.ListenPort is < 1024 or > 65535) throw new ArgumentException("监听端口无效");
        Directory.CreateDirectory(root);
        string logsRoot = options.LogDirectory.Length > 0 ? Path.Combine(options.LogDirectory, Path.GetFileName(root)) : root;
        if (options.LogLevel != "off") Directory.CreateDirectory(logsRoot);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(stop.Token, cancellation);
        var token = linked.Token;
        try
        {
            int slot = options.LocalSlot == 0 ? (options.Host ? 1 : 2) : options.LocalSlot;
            if (slot is < 1 or > 2) throw new ArgumentException("虚拟地址槽位无效");
            LocalIp = slot == 1 ? "10.129.129.1" : "10.129.129.2";
            PeerIp = slot == 1 ? "10.129.129.2" : "10.129.129.1";
            IPAddress local = IPAddress.Any;
            if (options.PersistentTicket != null)
            {
                Ticket = options.PersistentTicket; Ticket.Validate();
                mapping = preparedMapping; ownsMapping = false;
                if (options.Host) local = mapping?.LocalAddress ?? Stun.LocalAddress(IPEndPoint.Parse(Ticket.Endpoint));
            }
            else if (options.Host)
            {
                string endpoint = options.PublicEndpoint;
                if (options.AutomaticMapping)
                {
                    if (options.Mode is not ("faketcp" or "udp" or "udp-stun")) throw new IOException("传输模式无效");
                    Report("正在建立映射", false, "探测 STUN 与路由器能力");
                    mapping = options.Mode.StartsWith("udp") ? await UdpMapping.Create(options.ListenPort, options.ListenPort, log, token) : await TcpMapping.Create(options.SourcePort, options.ListenPort, log, token);
                    endpoint = mapping.PublicEndpoint.ToString(); local = mapping.LocalAddress;
                }
                else if (IPEndPoint.TryParse(endpoint, out var ep)) local = Stun.LocalAddress(ep);
                Ticket = Invitation.Create(endpoint, options.Mode, options.HttpHost); Ticket.Validate();
            }
            else { Ticket = Invitation.Decode(options.Invite); }
            int appPort = FreePort(SocketType.Dgram); rpc = FreePort(SocketType.Stream);
            string id = Guid.NewGuid().ToString("N");
            string listen = options.Host ? $"udp://127.0.0.1:{appPort}" : "";
            string network = "streamlink-" + Ticket.Network;
            string coreConfig = $"instance_name = {Q("sl-" + id[..8])}\nhostname = {Q(slot == 1 ? "StreamLink-Host" : "StreamLink-Guest")}\nipv4 = {Q(LocalIp)}\ndev_name = {Q("sl_" + id[..8])}\nlisteners = [{(options.Host ? Q(listen) : "")}]\n[network_identity]\nnetwork_name = {Q(network)}\nnetwork_secret = {Q(Ticket.Secret)}\n";
            if (!options.Host) coreConfig += $"[[peer]]\nuri = {Q($"udp://127.0.0.1:{appPort}")}\n";
            coreConfig += "[flags]\nmtu = 1280\nenable_ipv6 = false\ndisable_p2p = true\np2p_only = true\ndisable_udp_hole_punching = true\ndisable_tcp_hole_punching = true\ndisable_upnp = true\nbind_device = false\naccept_dns = false\n";
            string corePath = Path.Combine(root, "network.toml"); await File.WriteAllTextAsync(corePath, coreConfig, token);
            string raw = options.Host ? $"-s\n-l {local}:{options.ListenPort}\n-r 127.0.0.1:{appPort}\n" : $"-c\n-l 127.0.0.1:{appPort}\n-r {Ticket.Endpoint}\n";
            int rawLog = options.LogLevel == "debug" ? 5 : options.LogLevel == "error" ? 2 : 4;
            raw += $"-k {Ticket.RawKey}\n--raw-mode {(Ticket.Mode.StartsWith("udp") ? "udp" : "faketcp")}\n--fix-gro\n--seq-mode 3\n--log-level {rawLog}\n";
            if (Ticket.Mode == "faketcp" && Ticket.HttpHost.Length > 0) raw += $"--fake-http {Ticket.HttpHost}\n";
            string rawPath = Path.Combine(root, "transport.conf"); await File.WriteAllTextAsync(rawPath, raw, token);
            rule = "StreamLink-" + id;
            Recovery.Record(root,rule);
            await File.WriteAllTextAsync(Path.Combine(root, "owned-rule.txt"), rule, token);
            WindowsHost.AddFirewall(rule, LocalIp, PeerIp);
            job = new ChildJob();
            Report("正在启动", false, "建立本机传输与虚拟网卡");
            var rawEnvironment = new Dictionary<string,string> { ["STREAMLINK_ALLOW_DRIVER_INSTALL"] = "1" };
            if(Ticket.Mode == "udp-stun") rawEnvironment["STREAMLINK_UDP_SHAPE"]="stun";
            if(mapping is UdpMapping udpMapping) { rawEnvironment["STREAMLINK_UDP_SHARED_BIND"]="1"; rawEnvironment["STREAMLINK_STUN_ENDPOINT"]=udpMapping.StunEndpoint.ToString(); }
            job.Start(Path.Combine(bin, "udp2raw-native.exe"), ["--conf-file", rawPath], options.LogLevel == "off" ? null : Path.Combine(logsRoot, "transport.log"), rawEnvironment, [Ticket.Secret, Ticket.RawKey]);
            job.Start(Path.Combine(bin, "easytier-core.exe"), ["--config-file", corePath, "--disable-env-parsing", "--rpc-portal", $"127.0.0.1:{rpc}", "--console-log-level", options.LogLevel == "debug" ? "debug" : options.LogLevel == "error" ? "error" : "warn", "--file-log-level", "off", "--disable-upnp", "true", "--accept-dns", "false"], options.LogLevel == "off" ? null : Path.Combine(logsRoot, "network.log"), secrets: [Ticket.Secret, Ticket.RawKey]);
            for (int i = 0; i < 40; i++)
            {
                await Task.Delay(250, token);
                if (job.AnyExited) throw new IOException("配套组件退出，请查看诊断日志：" + root);
                if (NetworkInterface.GetAllNetworkInterfaces().SelectMany(n => n.GetIPProperties().UnicastAddresses).Any(a => a.Address.ToString() == LocalIp)) break;
                if (i == 39) throw new IOException("虚拟网卡启动超时");
            }
            if (mapping != null && ownsMapping)
            {
                mapping.Changed += endpoint => { Ticket = Ticket with { Endpoint = endpoint.ToString() }; InviteChanged?.Invoke(Ticket.Encode()); Report("映射已更新", false, "请向对端发送更新后的邀请"); };
                mappingTask = mapping.Maintain(stop.Token);
            }
            if(options.Host) InviteChanged?.Invoke(Ticket.Encode());
            qualityServer = Quality.Serve(LocalIp,PeerIp,Ticket.Secret,stop.Token);
            log("组件已启动；邀请信息包含密钥，请只分享给配对设备");
            Report("等待对端", false, "公网映射尚待实际握手确认");
            monitor = Monitor(stop.Token);
        }
        catch { await DisposeAsync(); throw; }
    }

    async Task Monitor(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                if (job!.AnyExited) { Report("组件停止", false, "请停止后重新启动，日志已保留"); return; }
                if (mappingTask?.IsFaulted == true) { Report("映射保活失败", false, mappingTask.Exception!.GetBaseException().Message); return; }
                var info = new ProcessStartInfo(Path.Combine(bin, "easytier-cli.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                foreach (string arg in new[] { "-p", $"127.0.0.1:{rpc}", "-v", "peer" }) info.ArgumentList.Add(arg);
                using var cli = Process.Start(info)!;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(2500);
                try
                {
                    var outputTask = cli.StandardOutput.ReadToEndAsync(timeout.Token);
                    var errorTask = cli.StandardError.ReadToEndAsync(timeout.Token);
                    await cli.WaitForExitAsync(timeout.Token); string output = await outputTask; await errorTask;
                    using var peers = JsonDocument.Parse(output);
                    bool connected = false; double? rtt = null;
                    foreach(var peer in peers.RootElement.EnumerateArray())
                    {
                        if (!peer.TryGetProperty("route", out var route) || !route.TryGetProperty("hostname", out var hostname) || hostname.GetString() != (LocalIp.EndsWith(".1") ? "StreamLink-Guest" : "StreamLink-Host")) continue;
                        if (route.GetProperty("cost").GetInt32() != 1 || route.GetProperty("peer_id").GetUInt32() != route.GetProperty("next_hop_peer_id").GetUInt32()) continue;
                        if (!peer.TryGetProperty("peer", out var detail) || detail.ValueKind == JsonValueKind.Null) continue;
                        foreach(var connection in detail.GetProperty("conns").EnumerateArray())
                        {
                            if(connection.TryGetProperty("is_closed",out var closed) && closed.GetBoolean()) continue;
                            var tunnel = connection.GetProperty("tunnel");
                            if (tunnel.GetProperty("tunnel_type").GetString() != "udp") continue;
                            var remote = tunnel.GetProperty("remote_addr").GetProperty("url").GetString()!;
                            if (!remote.StartsWith("udp://127.0.0.1:")) continue;
                            connected = true;
                            rtt = connection.GetProperty("stats").GetProperty("latency_us").GetDouble() / 1000;
                        }
                    }
                    Report(connected ? "已直连" : "等待对端", connected, connected ? "已确认独立传输链路；实际可用码率请运行质量测试" : "尚未完成对端握手，请核对映射与邀请", rtt);
                }
                finally { if (!cli.HasExited) cli.Kill(); }
            }
            catch(OperationCanceledException) when(token.IsCancellationRequested) { break; }
            catch(Exception ex) { Report("正在检查", false, ex.Message); }
            try { await Task.Delay(2000, token); } catch(OperationCanceledException) { break; }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed) return; disposed = true; stop.Cancel();
        if (monitor != null) { try { await monitor; } catch { } }
        if (mappingTask != null) { try { await mappingTask; } catch { } }
        if (qualityServer != null) { try { await qualityServer; } catch(OperationCanceledException) { } catch(Exception ex) { log("质量测试服务已停止：" + ex.Message); } }
        job?.Dispose(); job = null;
        if (mapping != null && ownsMapping) await mapping.DisposeAsync();
        bool firewallRemoved=true;
        if (rule.Length > 0) { try { WindowsHost.RemoveFirewall(rule); } catch(Exception ex) { firewallRemoved=false; log("清理防火墙失败：" + ex.Message); } }
        foreach (var file in new[] { "network.toml", "transport.conf" }) { try { File.Delete(Path.Combine(root, file)); } catch { } }
        if(firewallRemoved) {try{File.Delete(Path.Combine(root,"owner.json"));File.Delete(Path.Combine(root,"owned-rule.txt"));}catch{}}
        Report("已停止", false, firewallRemoved ? "本会话组件已停止；临时规则已清理或等待租约到期" : "组件已停止，仍有防火墙规则待下次启动恢复"); log("会话已停止");
        stop.Dispose();
    }
}
