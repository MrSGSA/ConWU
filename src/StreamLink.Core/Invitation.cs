using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace StreamLink.Core;

public sealed record Invitation(int Version, string Network, string Secret, string Endpoint, string Mode, string HttpHost, long Expires)
{
    static string Url64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static Invitation Create(string endpoint, string mode, string httpHost) => new(1, Guid.NewGuid().ToString("N"), Url64(RandomNumberGenerator.GetBytes(32)), endpoint, mode, httpHost, DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeSeconds());
    public string Encode() => "SL1." + Url64(JsonSerializer.SerializeToUtf8Bytes(this));
    public string RawKey => Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(Secret), "streamlink-udp2raw-v1"u8.ToArray())).ToLowerInvariant();
    public static Invitation Decode(string text)
    {
        text = text.Trim();
        if (text.Length > 4096 || !text.StartsWith("SL1.")) throw new FormatException("邀请信息格式无效");
        string encoded = text[4..].Replace('-', '+').Replace('_', '/');
        encoded = encoded.PadRight((encoded.Length + 3) / 4 * 4, '=');
        var invite = JsonSerializer.Deserialize<Invitation>(Convert.FromBase64String(encoded)) ?? throw new FormatException("邀请信息为空");
        invite.Validate(); return invite;
    }
    public void Validate()
    {
        if (Version != 1 || !Guid.TryParseExact(Network, "N", out _) || !Regex.IsMatch(Secret ?? "", "^[A-Za-z0-9_-]{43}$")) throw new FormatException("邀请版本或密钥无效");
        if (!IPEndPoint.TryParse(Endpoint, out var endpoint) || endpoint.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || endpoint.Port is < 1 or > 65535 || endpoint.Address.Equals(IPAddress.Any)) throw new FormatException("邀请必须含 IPv4 地址和有效端口");
        if (Mode is not ("faketcp" or "udp" or "udp-stun")) throw new FormatException("不支持的传输模式");
        if (HttpHost is null || HttpHost.Length > 253 || (HttpHost.Length != 0 && !Regex.IsMatch(HttpHost, "^[a-zA-Z0-9][a-zA-Z0-9.-]*$"))) throw new FormatException("HTTP Host 格式无效");
        if (Expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() || Expires > DateTimeOffset.UtcNow.AddDays(2).ToUnixTimeSeconds()) throw new FormatException("邀请已过期或时间不正确");
    }
}

public sealed class SessionOptions
{
    // Trusted local persistent pairing supplies a refreshed runtime ticket.
    [System.Text.Json.Serialization.JsonIgnore] public Invitation? PersistentTicket { get; set; }
    public int LocalSlot { get; set; }
    // Legacy JSON name: the node providing the initial network entry point.
    // This says nothing about applications or the direction of user traffic.
    public bool Host { get; set; } = true;
    public string Invite { get; set; } = "";
    public bool AutomaticMapping { get; set; } = true;
    public string PublicEndpoint { get; set; } = "";
    public int ListenPort { get; set; } = 42680;
    public int SourcePort { get; set; } = 42691;
    public string HttpHost { get; set; } = "test.ustc.edu.cn";
    public string Mode { get; set; } = "faketcp";
    public string LogLevel { get; set; } = "info";
    public string LogDirectory { get; set; } = "";
}
