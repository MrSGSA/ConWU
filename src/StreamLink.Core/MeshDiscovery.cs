using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record MeshAnnouncement(int Slot, string Device, long Revision, long Expires, string Endpoint, string Name,
    MeshTraversalCapabilities? Traversal = null);
public sealed record MeshEnvelope(int Slot, string Device, long Revision, string Data, string Signature);
public sealed record MeshSnapshot(MeshDirectory Directory, MeshEnvelope[] Nodes,
    MeshTraversalMessage[]? Traversal = null, int TraversalVersion = 0, int UdpIpv6 = 0);
public static class MeshMetadata
{
    static byte[] SignedData(string network, MeshEnvelope e) => JsonSerializer.SerializeToUtf8Bytes(new { domain = "streamlink-metadata-v4", network, e.Slot, e.Device, e.Revision, e.Data });
    public static void ValidateEnvelope(string network, MeshMember member, MeshEnvelope e)
    {
        if (e.Slot != member.Slot || e.Device != member.Device || e.Revision <= 0 || e.Data is null || e.Data.Length is < 40 or > 4096 || !MeshIdentity.Verify(member.SigningKey, SignedData(network, e), e.Signature)) throw new CryptographicException("端点公告签名无效");
    }
    public static MeshEnvelope Seal(MeshProfile profile, MeshAnnouncement node)
    {
        Validate(node); if (node.Slot != profile.Self.Slot || node.Device != profile.Self.Device) throw new CryptographicException("公告身份无效");
        byte[] nonce = RandomNumberGenerator.GetBytes(12), plain = JsonSerializer.SerializeToUtf8Bytes(node), cipher = new byte[plain.Length], tag = new byte[16];
        using var aes = new AesGcm(profile.Pair.Key("mesh-metadata-v4"), 16);
        aes.Encrypt(nonce, plain, cipher, tag, Encoding.ASCII.GetBytes(profile.Pair.Network + "/" + node.Slot));
        var envelope = new MeshEnvelope(node.Slot, node.Device, node.Revision, Convert.ToBase64String(nonce.Concat(tag).Concat(cipher).ToArray()), "");
        if (envelope.Data.Length > 4096) throw new FormatException("公告超过大小限制");
        return envelope with { Signature = MeshIdentity.Sign(profile.SigningPrivate, SignedData(profile.Pair.Network, envelope)) };
    }
    public static MeshAnnouncement Open(MeshProfile profile, MeshMember member, MeshEnvelope envelope)
    {
        ValidateEnvelope(profile.Pair.Network, member, envelope);
        byte[] bytes = Convert.FromBase64String(envelope.Data); if (bytes.Length < 29) throw new FormatException("端点公告截断");
        byte[] plain = new byte[bytes.Length - 28]; using var aes = new AesGcm(profile.Pair.Key("mesh-metadata-v4"), 16);
        aes.Decrypt(bytes.AsSpan(0, 12), bytes.AsSpan(28), bytes.AsSpan(12, 16), plain, Encoding.ASCII.GetBytes(profile.Pair.Network + "/" + member.Slot));
        var node = JsonSerializer.Deserialize<MeshAnnouncement>(plain) ?? throw new FormatException("公告为空"); Validate(node);
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (node.Slot != member.Slot || node.Device != member.Device || node.Revision != envelope.Revision || node.Expires <= now || node.Expires > now + 180) throw new CryptographicException("公告已过期或身份不匹配");
        return node;
    }
    static void Validate(MeshAnnouncement node)
    {
        if (node.Slot is < 1 or > 254 || !Guid.TryParseExact(node.Device, "N", out _) || node.Revision <= 0 || node.Name is null || node.Name.Length is < 1 or > 64 || node.Name.Any(char.IsControl)) throw new FormatException("公告内容无效");
        if (node.Endpoint is null || node.Endpoint.Length > 64 || node.Endpoint.Length > 0 && (!IPEndPoint.TryParse(node.Endpoint, out var ep) || ep.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || ep.Address.Equals(IPAddress.Any) || ep.Port == 0)) throw new FormatException("端点无效");
        MeshTraversal.ValidateCapabilities(node.Traversal);
    }
}
public interface IMeshDiscovery : IDisposable
{
    Task SaveDirectory(MeshDirectory directory, CancellationToken token);
    Task Publish(MeshAnnouncement announcement, CancellationToken token);
    Task<MeshSnapshot?> Read(CancellationToken token);
}
public sealed partial class MeshDiscoveryClient : IMeshDiscovery, IMeshChangeDiscovery, IMeshTraversalDiscovery, ITcpObservationControl
{
    readonly MeshProfile profile;
    readonly HttpClient http;
    readonly HttpClient watchHttp;
    readonly Guid boot = Guid.NewGuid();
    Guid serverEpoch;
    long cursor;
    int waiting;
    public bool SupportsLongPolling { get; private set; } = true;
    public Guid BootId => boot;
    public bool SupportsTraversal { get; private set; }
    public bool SupportsUdpIpv6 { get; private set; }
    public MeshDiscoveryClient(MeshProfile profile)
    {
        profile.Validate(); this.profile = profile;
        var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false };
        if (profile.Pair.CertificatePin.Length > 0) handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert != null && DateTime.UtcNow >= cert.NotBefore.ToUniversalTime() && DateTime.UtcNow <= cert.NotAfter.ToUniversalTime() && CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.RawData), Convert.FromHexString(profile.Pair.CertificatePin));
        http = new(handler, disposeHandler: false) { BaseAddress = new(profile.Pair.Service), Timeout = TimeSpan.FromSeconds(8), MaxResponseContentBufferSize = 65536 };
        http.DefaultRequestHeaders.Authorization = new("Bearer", profile.Pair.Auth);
        watchHttp = new(handler) { BaseAddress = new(profile.Pair.Service), Timeout = TimeSpan.FromSeconds(TraversalLimits.LongPollTimeoutSeconds), MaxResponseContentBufferSize = MeshTraversal.MaxWatchBytes };
        watchHttp.DefaultRequestHeaders.Authorization = new("Bearer", profile.Pair.Auth);
    }
    public async Task SaveDirectory(MeshDirectory directory, CancellationToken token) { using var response = await http.PutAsJsonAsync($"v3/mesh/{profile.Pair.Network}/directory", directory, token); response.EnsureSuccessStatusCode(); }
    public async Task Publish(MeshAnnouncement announcement, CancellationToken token) { using var response = await http.PutAsJsonAsync($"v3/mesh/{profile.Pair.Network}/nodes/{profile.Self.Slot}", MeshMetadata.Seal(profile, announcement), token); response.EnsureSuccessStatusCode(); }
    public async Task<MeshSnapshot?> Read(CancellationToken token)
    {
        using var response = await http.GetAsync($"v3/mesh/{profile.Pair.Network}", token); if (response.StatusCode == HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode(); return await response.Content.ReadFromJsonAsync<MeshSnapshot>(token);
    }
    public async Task<MeshSnapshot?> WaitForChanges(CancellationToken token)
    {
        if (!SupportsLongPolling) return await Read(token);
        if (Interlocked.Exchange(ref waiting, 1) != 0) throw new InvalidOperationException("每台设备只能保持一个协调等待请求");
        try {
            var request = MeshWatch.Create(profile, boot, serverEpoch, cursor);
            using var response = await watchHttp.PostAsJsonAsync($"v3/mesh/{profile.Pair.Network}/watch", request, token);
            // Initial registration may race the first watch; retry normally,
            // without disabling watch or invoking failure backoff.
            if (response.StatusCode == HttpStatusCode.PreconditionFailed) return null;
            if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed) {
                // Only an explicit old-server route response enables fallback.
                // Auth failures, rate limiting and malformed data are not downgraded.
                SupportsLongPolling = false; SupportsTraversal = false; SupportsUdpIpv6 = false; return await Read(token);
            }
            response.EnsureSuccessStatusCode();
            var change = await response.Content.ReadFromJsonAsync<MeshWatchResponse>(token) ?? throw new IOException("协调通知为空");
            if (change.ServerEpoch == Guid.Empty || change.Cursor < 0 || change.Changes is null || change.Changes.Length > TraversalLimits.EventQueueSize || change.Snapshot is null ||
                change.ServerEpoch == serverEpoch && change.Cursor < cursor || change.ServerEpoch != serverEpoch && !change.Reset ||
                change.Snapshot.TraversalVersion is not (0 or MeshTraversal.Version) || change.Snapshot.UdpIpv6 is < 0 or > 1 || change.Snapshot.Traversal is { Length: > MeshTraversal.MaxInbox })
                throw new IOException("协调通知游标无效");
            // Membership and every announcement are still verified by MeshRunner.
            SupportsTraversal = change.Snapshot.TraversalVersion == MeshTraversal.Version;
            SupportsUdpIpv6 = SupportsTraversal && change.Snapshot.UdpIpv6 == 1;
            serverEpoch = change.ServerEpoch; cursor = change.Cursor; return change.Snapshot;
        } finally { Volatile.Write(ref waiting, 0); }
    }
    public async Task PublishTraversal(MeshTraversalMessage[] messages, CancellationToken token)
    {
        if (!SupportsTraversal) throw new NotSupportedException("协调服务未声明打洞控制能力");
        if (messages.Length is < 1 or > MeshTraversal.MaxBatch || messages.Select(m => m.ToSlot).Distinct().Count() != messages.Length)
            throw new ArgumentException("每个批次最多包含每个对端的一条状态");
        foreach (var message in messages) {
            var peer = profile.Directory?.Members.FirstOrDefault(p => p.Slot == message.ToSlot) ?? throw new MeshRevokedException();
            MeshTraversal.Verify(profile.Pair.Network, profile.Self, peer, message);
            if (message.FromBoot != boot) throw new CryptographicException("打洞消息不属于当前启动代次");
        }
        using var response = await http.PostAsJsonAsync($"v3/mesh/{profile.Pair.Network}/traversal", new MeshTraversalBatch(messages), token);
        response.EnsureSuccessStatusCode();
    }
    public void Dispose() { http.Dispose(); watchHttp.Dispose(); }
}
