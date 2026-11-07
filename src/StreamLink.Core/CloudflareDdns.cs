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
public sealed record DdnsAddressRecord(int Version, string Domain, string Network, string Device, int Slot, string Mode,
    long IssuedAt, long ExpiresAt, string[] Endpoints, string Signature);

// DNS carries discovery hints, never enrollment credentials or online proof.
// Each record is bound to the already trusted member signing key and domain.
public static class DdnsAddressRecords
{
    public const string Prefix = "conwu-ddns-v1=";
    public const int MaximumText = 2048;
    public static string Name(string domain, string network, string device) {
        if (!CloudflareDdnsSettings.ValidDomain(domain) || domain.Length > 160 || !Guid.TryParseExact(network, "N", out _) || !Guid.TryParseExact(device, "N", out _))
            throw new FormatException("DDNS 记录身份或域名无效");
        return $"d-{device}.n-{network}.{domain}".ToLowerInvariant();
    }
    public static string Ownership(string network, string device) => $"ConWU-DDNS/v1:{network}:{device}";
    static byte[] Data(DdnsAddressRecord record) => JsonSerializer.SerializeToUtf8Bytes(record with { Signature = "" });

    public static bool PublicEndpoint(string value) {
        if (value == null || value.Length > 32 || !IPEndPoint.TryParse(value, out var endpoint) || endpoint.Port == 0 || endpoint.AddressFamily != AddressFamily.InterNetwork) return false;
        byte[] a = endpoint.Address.GetAddressBytes();
        return ExistingEntryResolver.EndpointAddress(endpoint.Address) && a[0] != 10 && !(a[0] == 172 && a[1] is >= 16 and <= 31) &&
            !(a[0] == 192 && a[1] == 168) && !(a[0] == 100 && a[1] is >= 64 and <= 127) && !(a[0] == 198 && a[1] is 18 or 19);
    }
    public static DdnsAddressRecord Create(MeshProfile mesh, string domain, string mode, string[] endpoints, long now, int lifetimeSeconds) {
        domain = domain.ToLowerInvariant(); _ = Name(domain, mesh.Pair.Network, mesh.Self.Device);
        if (mode is not ("faketcp" or "udp") || lifetimeSeconds is < 180 or > 1800 || endpoints.Length > 4 || endpoints.Any(e => !PublicEndpoint(e)))
            throw new FormatException("DDNS 只发布当前可接受连接的公网 IPv4 入口，不能发布临时打洞元组或内网地址");
        var record = new DdnsAddressRecord(1, domain, mesh.Pair.Network, mesh.Self.Device, mesh.Self.Slot, mode, now, checked(now + lifetimeSeconds),
            endpoints.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(), "");
        return record with { Signature = MeshIdentity.Sign(mesh.SigningPrivate, Data(record)) };
    }
    public static string Encode(DdnsAddressRecord record) {
        string text = Prefix + Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(record));
        if (text.Length > MaximumText) throw new FormatException("DDNS 地址记录超过大小限制");
        return text;
    }
    public static DdnsAddressRecord Decode(string text) {
        if (text == null || text.Length > MaximumText || !text.StartsWith(Prefix, StringComparison.Ordinal)) throw new FormatException("不是 ConWU DDNS 地址记录");
        return JsonSerializer.Deserialize<DdnsAddressRecord>(Convert.FromBase64String(text[Prefix.Length..])) ?? throw new FormatException("DDNS 记录为空");
    }
    public static bool Verify(DdnsAddressRecord record, string domain, string network, MeshMember member, string mode, long now) {
        try {
            return record.Version == 1 && record.Domain == domain.ToLowerInvariant() && record.Network == network && record.Device == member.Device && record.Slot == member.Slot && record.Mode == mode &&
                record.IssuedAt <= now + 60 && record.IssuedAt > 0 && record.ExpiresAt > now && record.ExpiresAt > record.IssuedAt && record.ExpiresAt - record.IssuedAt <= 1800 &&
                record.Endpoints is { Length: <= 4 } && record.Endpoints.All(PublicEndpoint) && record.Endpoints.Distinct(StringComparer.Ordinal).Count() == record.Endpoints.Length &&
                record.Signature is { Length: > 0 and <= 128 } && MeshIdentity.Verify(member.SigningKey, Data(record), record.Signature);
        } catch (Exception ex) when (ex is FormatException or ArgumentException or System.Security.Cryptography.CryptographicException) { return false; }
    }
    public static string Quote(string value) {
        if (value.Length > MaximumText || !value.StartsWith(Prefix, StringComparison.Ordinal) || value.Any(c => c > 127 || c is '"' or '\\' || char.IsControl(c))) throw new FormatException("DDNS TXT 内容无效");
        return string.Join(" ", Enumerable.Range(0, (value.Length + 199) / 200).Select(i => "\"" + value.Substring(i * 200, Math.Min(200, value.Length - i * 200)) + "\""));
    }
    public static string Unquote(string value) {
        if (value.Length > MaximumText + 64) throw new FormatException("DDNS TXT 内容过长");
        if (!value.StartsWith('"')) return value;
        var result = new StringBuilder(); int at = 0;
        while (at < value.Length) {
            while (at < value.Length && value[at] == ' ') at++;
            if (at == value.Length) break;
            if (value[at++] != '"') throw new FormatException("DDNS TXT 分段格式无效");
            int start = at; while (at < value.Length && value[at] != '"') { if (value[at] == '\\' || value[at] > 127 || char.IsControl(value[at])) throw new FormatException("DDNS TXT 字符无效"); at++; }
            if (at == value.Length) throw new FormatException("DDNS TXT 分段未结束");
            result.Append(value, start, at - start); at++;
        }
        if (result.Length > MaximumText) throw new FormatException("DDNS TXT 内容过长");
        return result.ToString();
    }
    public static async Task<DdnsAddressRecord?> Read(string domain, string network, MeshMember member, string mode, CancellationToken token) {
        string[] records = await DnsTextLookup.Query(Name(domain, network, member.Device), token);
        DdnsAddressRecord? latest = null;
        foreach (string text in records.Take(8)) {
            DdnsAddressRecord candidate;
            try { candidate = Decode(text); } catch (Exception ex) when (ex is FormatException or JsonException) { continue; }
            if (Verify(candidate, domain, network, member, mode, DateTimeOffset.UtcNow.ToUnixTimeSeconds()) && (latest == null || candidate.IssuedAt > latest.IssuedAt)) latest = candidate;
        }
        return latest;
    }
}
