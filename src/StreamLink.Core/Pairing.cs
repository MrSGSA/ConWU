using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace StreamLink.Core;

public sealed record Pairing(string Network, string Secret, string Service, string CertificatePin, string Mode = "faketcp")
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public bool Direct { get; init; }
    public static Pairing Create(string service, string pin, string mode = "faketcp")
    {
        var ticket = Invitation.Create("127.0.0.1:1", "faketcp", "");
        var pair = new Pairing(ticket.Network, ticket.Secret, service, pin, mode); pair.Validate(); return pair;
    }
    public void Validate()
    {
        if (!Guid.TryParseExact(Network, "N", out _) || !Regex.IsMatch(Secret ?? "", "^[A-Za-z0-9_-]{43}$")) throw new FormatException("配对身份无效");
        if (Direct ? Service != "" || CertificatePin != "" : !Uri.TryCreate(Service, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length != 0 || !uri.AbsolutePath.EndsWith('/') || uri.Query.Length != 0 || uri.Fragment.Length != 0) throw new FormatException("发现服务必须是以 / 结尾的 HTTPS 地址；无服务器网络不使用协调地址");
        if (CertificatePin is null || (CertificatePin.Length != 0 && !Regex.IsMatch(CertificatePin, "^[A-Fa-f0-9]{64}$"))) throw new FormatException("证书指纹无效");
        if (Mode is not ("faketcp" or "udp")) throw new FormatException("传输方式无效");
    }
    public byte[] Key(string purpose) => HMACSHA256.HashData(Encoding.UTF8.GetBytes(Secret), Encoding.UTF8.GetBytes("streamlink-v2/" + purpose));
    public string Auth => Convert.ToHexString(Key("discovery-auth"));
    public string Invite() => "SL2." + Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new PairInvite(this, DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeSeconds())));
    public static Pairing Import(string value)
    {
        value = value.Trim();
        if (!value.StartsWith("SL2.") || value.Length > 4096) throw new FormatException("请使用 SL2. 持久配对邀请");
        var invite = JsonSerializer.Deserialize<PairInvite>(Convert.FromBase64String(value[4..])) ?? throw new FormatException("邀请为空");
        invite.Pair.Validate();
        if (invite.Expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() || invite.Expires > DateTimeOffset.UtcNow.AddDays(2).ToUnixTimeSeconds()) throw new FormatException("首次配对邀请已过期");
        return invite.Pair;
    }
    public Envelope Seal(NodeAnnouncement node)
    {
        node.Validate();
        byte[] plain = JsonSerializer.SerializeToUtf8Bytes(node), nonce = RandomNumberGenerator.GetBytes(12), cipher = new byte[plain.Length], tag = new byte[16];
        using var aes = new AesGcm(Key("metadata"), 16);
        aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(Network + "/" + node.Slot));
        return new(node.Device, node.Revision, Convert.ToBase64String(nonce.Concat(tag).Concat(cipher).ToArray()));
    }
    public NodeAnnouncement Open(int slot, Envelope envelope)
    {
        byte[] bytes = Convert.FromBase64String(envelope.Data);
        if (bytes.Length is < 29 or > 4096) throw new FormatException("发现消息大小无效");
        byte[] plain = new byte[bytes.Length - 28];
        using var aes = new AesGcm(Key("metadata"), 16);
        aes.Decrypt(bytes.AsSpan(0, 12), bytes.AsSpan(28), bytes.AsSpan(12, 16), plain, Encoding.UTF8.GetBytes(Network + "/" + slot));
        var node = JsonSerializer.Deserialize<NodeAnnouncement>(plain) ?? throw new FormatException("发现消息为空"); node.Validate();
        if (node.Device != envelope.Device || node.Revision != envelope.Revision || node.Slot != slot) throw new FormatException("发现消息身份不符");
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (node.Expires <= now || node.Expires > now + 300) throw new FormatException("发现消息已过期或系统时间不正确");
        return node;
    }
}
public sealed record PairInvite(Pairing Pair, long Expires);
public sealed record Envelope(string Device, long Revision, string Data);
public sealed record NodeAnnouncement(string Device, int Slot, long Revision, long Expires, string Endpoint, string Preference, int LastEntry, int SelectedEntry, bool Connected, string Name = "")
{
    public void Validate()
    {
        if (!Guid.TryParseExact(Device, "N", out _) || Slot is < 1 or > 2 || Revision <= 0 || LastEntry is < 0 or > 2 || SelectedEntry is < 0 or > 2 || Preference is not ("auto" or "local" or "peer")) throw new FormatException("设备公告无效");
        if (Name is null || Name.Length > 64 || Name.Any(char.IsControl)) throw new FormatException("设备名称无效");
        if (Endpoint != "" && (!IPEndPoint.TryParse(Endpoint, out var ep) || ep.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || ep.Address.Equals(IPAddress.Any) || ep.Port == 0)) throw new FormatException("候选端点无效");
    }
}
public static class EntryElection
{
    // Slot 1 coordinates; slots describe persistent IP identity, never traffic direction.
    public static int Choose(NodeAnnouncement one, NodeAnnouncement? two, int failed = 0)
    {
        var nodes = new[] { one, two }.Where(n => n != null && n.Endpoint.Length > 0 && n.Slot != failed).Cast<NodeAnnouncement>().ToArray();
        return nodes.OrderByDescending(n => (n.Preference == "local" ? 1 : n.Preference == "peer" ? -1 : 0) + ((n.Slot == 1 ? two : one)?.Preference == "peer" ? 1 : 0))
            .ThenByDescending(n => n.Slot == one.LastEntry || n.Slot == two?.LastEntry)
            .ThenBy(n => n.Slot).Select(n => n.Slot).FirstOrDefault();
    }
}
public interface IDiscoveryClient : IDisposable
{
    Task Publish(NodeAnnouncement node, CancellationToken token);
    Task<NodeAnnouncement?> Read(int slot, CancellationToken token);
}
public sealed class DiscoveryClient : IDiscoveryClient
{
    readonly Pairing pair;
    readonly HttpClient http;
    readonly Dictionary<int, long> revisions = [];
    public DiscoveryClient(Pairing pair)
    {
        pair.Validate(); this.pair = pair;
        var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false };
        if (pair.CertificatePin.Length > 0)
            handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert != null && DateTime.UtcNow >= cert.NotBefore.ToUniversalTime() && DateTime.UtcNow <= cert.NotAfter.ToUniversalTime() && CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.RawData), Convert.FromHexString(pair.CertificatePin));
        http = new(handler) { BaseAddress = new Uri(pair.Service), Timeout = TimeSpan.FromSeconds(8), MaxResponseContentBufferSize = 16384 };
        http.DefaultRequestHeaders.Authorization = new("Bearer", pair.Auth);
    }
    public async Task Publish(NodeAnnouncement node, CancellationToken token)
    {
        using var result = await http.PutAsJsonAsync($"v1/{pair.Network}/{node.Slot}", pair.Seal(node), token); result.EnsureSuccessStatusCode();
    }
    public async Task<NodeAnnouncement?> Read(int slot, CancellationToken token)
    {
        using var result = await http.GetAsync($"v1/{pair.Network}/{slot}", token);
        if (result.StatusCode == HttpStatusCode.NoContent || result.StatusCode == HttpStatusCode.NotFound) return null;
        result.EnsureSuccessStatusCode(); var envelope = await result.Content.ReadFromJsonAsync<Envelope>(token) ?? throw new IOException("发现响应为空");
        var node = pair.Open(slot, envelope);
        if (revisions.TryGetValue(slot, out long last) && node.Revision < last) throw new IOException("拒绝旧版端点公告");
        revisions[slot] = node.Revision; return node;
    }
    public void Dispose() => http.Dispose();
}
