using System.Text.RegularExpressions;

namespace StreamLink.Core;

public sealed class DeviceProfile
{
    public int Version { get; set; } = 2;
    public string Device { get; set; } = Guid.NewGuid().ToString("N");
    public Pairing? Pair { get; set; }
    public MeshProfile? Mesh { get; set; }
    public int Slot { get; set; } = 1;
    public bool Enabled { get; set; }
    public string Preference { get; set; } = "auto";
    public int LastEntry { get; set; }
    public int ListenPort { get; set; } = 42680;
    public int SourcePort { get; set; } = 42691;
    public string ManualEndpoint { get; set; } = "";
    public string[] TcpStun { get; set; } = Stun.TcpServers.ToArray();
    public string[] UdpStun { get; set; } = Stun.UdpServers.ToArray();
    public string LastStun { get; set; } = "";
    public string DeviceName { get; set; } = Environment.MachineName;
    public string TransportMode { get; set; } = "faketcp";
    // Staged rollout: existing installations retain the verified explicit path.
    // New traversal is opt-in until the independent Windows/WAN gates pass.
    public string TraversalMode { get; set; } = "legacy";
    public string PathSelection { get; set; } = "prefer-faketcp";
    public bool AllowUdpFallback { get; set; }
    // Diagnostics only, off by default. Requires a separately configured raw
    // SYN observer on the authenticated coordinator; never promotes a path.
    public bool TcpSynObservation { get; set; }
    // Independent-source calibration only; does not enable predicted paths.
    // Opt-in and requires the ordinary authenticated observer feature as well.
    public bool TcpPortCalibration { get; set; }
    public bool TcpPortPrediction { get; set; }
    // Experimental same-IP initial TCP source learning; requires bilateral and
    // coordinator capability plus an accounted native IPv4 capture broker.
    public bool TcpPeerReflexive { get; set; }
    public bool UdpExploration { get; set; }
    public bool QualityFeedback { get; set; }
    public bool StandbyPaths { get; set; }
    public bool PathDiagnostics { get; set; }
    public int DiagnosticMbps { get; set; }=50;
    // Opt-in gateway fallback: TCP after UPnP; alternating later UDP_DIRECT
    // rounds. It does not enable UDP itself or bypass path-quality selection.
    public bool PortControlMapping { get; set; }
    // Experimental native outer IPv6 UDP. Requires both peers and coordinator
    // support, physical IPv6 and the existing explicit UDP fallback policy.
    public bool UdpIpv6 { get; set; }
    public bool FakeTcpIpv6 { get; set; }
    // Outer IP Mbps, shared by all managed paths. Zero keeps existing behavior.
    // Legacy native processes and kernel helper/control HTTPS are not paced.
    public int ManagedEgressMbps { get; set; }
    public PathSelection Selection() => new(PathSelection switch {
        "prefer-faketcp" => PathPolicy.PreferFakeTcp, "faketcp-only" => PathPolicy.FakeTcpOnly,
        "auto-quality" => PathPolicy.AutoQuality, _ => throw new FormatException("选路策略无效")
    }, AllowUdpFallback);
    public string LogLevel { get; set; } = "info";
    public string LogDirectory { get; set; } = "";
    public void Validate()
    {
        if (Version != 2 || !Guid.TryParseExact(Device, "N", out _) || Slot is < 1 or > 2 || LastEntry is < 0 or > 2 || Preference is not ("auto" or "local" or "peer")) throw new FormatException("设备配置无效");
        if (ListenPort is < 1024 or > 65535 || SourcePort is < 1024 or > 65535 || SourcePort == ListenPort) throw new FormatException("源端口与监听端口必须是不同的 1024–65535 端口");
        ValidateServers(TcpStun); ValidateServers(UdpStun); Pair?.Validate();
        if (DeviceName is null || DeviceName.Length is < 1 or > 64 || DeviceName.Any(char.IsControl)) throw new FormatException("设备名称需为 1–64 个可见字符");
        if (TransportMode is not ("faketcp" or "udp") || LogLevel is not ("off" or "error" or "info" or "debug")) throw new FormatException("传输或日志选项无效");
        if (TraversalMode is not ("legacy" or "tcp" or "tcp-udp")) throw new FormatException("打洞试验模式无效");
        if (TcpPortCalibration && (!TcpSynObservation || TraversalMode == "legacy")) throw new FormatException("TCP 端口校准需同时开启受管打洞和 TCP 观察诊断");
        if (TcpPortPrediction && !TcpPortCalibration) throw new FormatException("实验 TCP 预测需启用独立端口校准");
        if (ManagedEgressMbps is < 0 or > 10000) throw new FormatException("实验链路出口上限需为 0–10000 Mbps（0 为关闭）");
        Selection().Validate();
        if (QualityFeedback && TraversalMode == "legacy") throw new FormatException("路径送达反馈需要实验受管打洞模式");
        if (StandbyPaths && TraversalMode == "legacy") throw new FormatException("备用路径需要实验受管打洞模式");
        if (DiagnosticMbps is < 1 or > 50) throw new FormatException("诊断目标需为1–50Mbps");
        if (PathDiagnostics && (!StandbyPaths || TraversalMode == "legacy" || ManagedEgressMbps < Math.Ceiling(DiagnosticMbps * 1.4)))
            throw new FormatException("路径诊断需开启独立备用，并设置至少目标1.4倍的共享出口额度；诊断仅在业务空闲时进行");
        if (UdpExploration && (TraversalMode != "tcp-udp" || !Selection().Allows(TraversalProfile.UdpDirect)))
            throw new FormatException("UDP 多源探索需要 UDP 备用许可与实验 TCP/UDP 打洞");
        if (TcpPeerReflexive && (TraversalMode == "legacy" || TransportMode != "faketcp" || Pair?.Mode == "udp" || Mesh?.Pair.Mode == "udp"))
            throw new FormatException("TCP 来源学习需要实验 TCP 打洞与 FakeTCP 网络");
        if (PathSelection == "faketcp-only" && (TransportMode == "udp" || Pair?.Mode == "udp" || Mesh?.Pair.Mode == "udp"))
            throw new FormatException("仅 FakeTCP 与 UDP 网络不兼容，请使用 FakeTCP 网络或更改选路策略");
        if (LogDirectory is null || LogDirectory.Length > 240 || (LogDirectory.Length > 0 && (!Path.IsPathFullyQualified(LogDirectory) || LogDirectory.StartsWith(@"\\")))) throw new FormatException("日志目录需为本机绝对路径");
        if (ManualEndpoint.Length > 0) Invitation.Create(ManualEndpoint, "faketcp", "").Validate();
        Mesh?.Validate();
        if (Mesh != null && Pair != null) throw new FormatException("不能同时运行旧版配对和多机网络");
        if (Enabled && Pair == null && Mesh == null) throw new FormatException("请先创建或加入网络");
    }
    public static void ValidateServers(string[]? servers)
    {
        if (servers == null || servers.Length is < 1 or > 256) throw new FormatException("STUN 列表需包含 1–256 项");
        foreach (var server in servers)
        {
            bool literal6 = server != null && server.StartsWith('[') && System.Net.IPEndPoint.TryParse(server, out var ep) && Ipv6Direct.UnscopedUnicast(ep.Address);
            if (server == null || server.Length > 260 || !literal6 && !Regex.IsMatch(server, "^[A-Za-z0-9][A-Za-z0-9.-]*:[0-9]{1,5}$") || !int.TryParse(server[(server.LastIndexOf(':') + 1)..], out int port) || port is < 1 or > 65535) throw new FormatException("STUN 应按每行 主机名:端口 或 [IPv6]:端口 填写");
        }
    }
    public string[] OrderedTcp() => TcpStun.OrderByDescending(s => s == LastStun).ToArray();
}
