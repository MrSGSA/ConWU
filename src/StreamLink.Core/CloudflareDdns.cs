// Legacy serialized data only. DNS publishing was retired in preview.2.
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace StreamLink.Core;

public sealed record CloudflareDdnsSettings(bool Enabled = false, string Domain = "", string ZoneId = "", bool Publish = false, int RefreshSeconds = 60)
{
    public void Validate() {
        if (Domain == null || Domain.Length > 160 || Domain.Length > 0 && !ValidDomain(Domain))
            throw new FormatException("DDNS 域名需为完整的 ASCII 域名，不带网址、端口或路径（国际域名请使用 Punycode）");
        if (ZoneId == null || ZoneId.Length != 0 && !Regex.IsMatch(ZoneId, "^[a-fA-F0-9]{32}$"))
            throw new FormatException("Cloudflare Zone ID 应为 32 位十六进制值");
        if (RefreshSeconds is < 30 or > 600) throw new FormatException("DDNS 检查间隔需为 30–600 秒");
        if (Enabled && Domain.Length == 0) throw new FormatException("启用 DDNS 前请填写共用域名");
        if (Enabled && Publish && ZoneId.Length == 0) throw new FormatException("发布 DDNS 需要 Cloudflare Zone ID");
    }
    public static bool ValidDomain(string domain) => domain.Contains('.') && !IPAddress.TryParse(domain, out _) &&
        domain.Split('.').All(label => label.Length is > 0 and <= 63 && char.IsAsciiLetterOrDigit(label[0]) && char.IsAsciiLetterOrDigit(label[^1]) && label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'));
    public static void ValidateToken(string token) {
        if (token == null || token.Length > 512 || token.Length > 0 && (token.Length < 20 || token.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_'))))
            throw new FormatException("Cloudflare API 令牌格式无效；请使用 API Token，不使用 Global API Key");
    }
}

public sealed record CloudflareDdnsStatus(string State, string PublishState, string ReadState, string RecordName = "", long PublishedAt = 0, long CheckedAt = 0, int PeerEntries = 0)
{
    public string[] PublishedEndpoints {get;init;}=[];
    public string[] ReadEndpoints {get;init;}=[];
    public string EntryLink {get;init;}="";
    public string ThirdPartyRecordName {get;init;}="";
    public string ThirdPartyReadState {get;init;}="";
}
