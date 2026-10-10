using System.Text.RegularExpressions;

namespace StreamLink.Core;

public sealed class DeviceProfile
{
    public int Version { get; set; } = 2;
    public string Device { get; set; } = Guid.NewGuid().ToString("N");
    public Pairing? Pair { get; set; }
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
    public void Validate()
    {
        if (Version != 2 || !Guid.TryParseExact(Device, "N", out _) || Slot is < 1 or > 2 || LastEntry is < 0 or > 2 || Preference is not ("auto" or "local" or "peer")) throw new FormatException("设备配置无效");
        if (ListenPort is < 1024 or > 65535 || SourcePort is < 1024 or > 65535 || SourcePort == ListenPort) throw new FormatException("源端口与监听端口必须是不同的 1024–65535 端口");
        ValidateServers(TcpStun); ValidateServers(UdpStun); Pair?.Validate();
        if (ManualEndpoint.Length > 0) Invitation.Create(ManualEndpoint, "faketcp", "").Validate();
        if (Enabled && Pair == null) throw new FormatException("请先创建或加入网络");
    }
    public static void ValidateServers(string[]? servers)
    {
        if (servers == null || servers.Length is < 1 or > 64) throw new FormatException("STUN 列表需包含 1–64 项");
        foreach (var server in servers)
        {
            if (server == null || server.Length > 260 || !Regex.IsMatch(server, "^[A-Za-z0-9][A-Za-z0-9.-]*:[0-9]{1,5}$") || !int.TryParse(server[(server.LastIndexOf(':') + 1)..], out int port) || port is < 1 or > 65535) throw new FormatException("STUN 应按每行 主机名:端口 填写");
        }
    }
    public string[] OrderedTcp() => TcpStun.OrderByDescending(s => s == LastStun).ToArray();
}
