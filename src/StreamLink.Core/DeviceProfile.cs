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
        Selection().Validate();
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
            if (server == null || server.Length > 260 || !Regex.IsMatch(server, "^[A-Za-z0-9][A-Za-z0-9.-]*:[0-9]{1,5}$") || !int.TryParse(server[(server.LastIndexOf(':') + 1)..], out int port) || port is < 1 or > 65535) throw new FormatException("STUN 应按每行 主机名:端口 填写");
        }
    }
    public string[] OrderedTcp() => TcpStun.OrderByDescending(s => s == LastStun).ToArray();
}
