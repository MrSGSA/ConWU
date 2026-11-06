using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace StreamLink.Core;

public sealed class PairRoomUnavailableException() : IOException("配对码无效、已使用、已过期或协调服务已重启，请让邀请端生成新码；已确认的成员身份不受影响");
public sealed record PairRoomCreate(string Commitment, string Name);
public sealed record PairRoomJoin(string Code, string Commitment, string Name, string RequestedIp="", int Addressing=0)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public int Governance {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public MeshRejoinProof? Rejoin {get;init;}
}
public sealed record PairRoomTicket(string Room, string Code, string Token, string HostCommitment, string HostName, long Expires, string Candidate = "");
public sealed record PairRoomState(string Candidate, string GuestCommitment, string GuestName, string HostPublic, string GuestPublic, string Ciphertext, bool Approved, long Expires)
{
    public string Outcome {get;init;}="";
    public string RequestedIp {get;init;}="";
    public int Addressing {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public int Governance {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? RejoinDigest {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public MeshRejoinProof? Rejoin {get;init;}
}
public sealed record PairRoomReveal(string PublicKey);
public sealed record PairRoomApproval(string Candidate, string Ciphertext);

// Six digits locate an expiring rendezvous, never an encryption key.
// Both public keys are committed before either is revealed. Users compare the
// derived authentication string before the owner releases an encrypted invite.
public sealed class PairKeyExchange : IDisposable
{
    readonly ECDiffieHellman key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    public string PublicKey => Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    public string Commitment => Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(PublicKey)));
    public static bool ValidCommitment(string value) => value != null && Regex.IsMatch(value, "^[A-F0-9]{64}$");
    public static void ValidatePublic(string value, string commitment)
    {
        if (!ValidCommitment(commitment) || value is null || value.Length > 180) throw new FormatException("配对公钥无效");
        byte[] bytes = Convert.FromBase64String(value);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), Convert.FromHexString(commitment))) throw new CryptographicException("配对公钥承诺不符");
        using var peer = ECDiffieHellman.Create(); peer.ImportSubjectPublicKeyInfo(bytes, out int used);
        if (used != bytes.Length || peer.KeySize != 256 || peer.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7") throw new CryptographicException("配对曲线无效");
    }
    public byte[] Derive(string remotePublic, string commitment, string room, string candidate, bool owner)
    {
        ValidatePublic(remotePublic, commitment);
        if (!Guid.TryParseExact(room, "N", out _) || !Guid.TryParseExact(candidate, "N", out _)) throw new FormatException("配对会话无效");
        using var peer = ECDiffieHellman.Create(); peer.ImportSubjectPublicKeyInfo(Convert.FromBase64String(remotePublic), out _);
        byte[] shared = key.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256);
        string host = owner ? PublicKey : remotePublic, guest = owner ? remotePublic : PublicKey;
        try { return HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, Encoding.UTF8.GetBytes(room + candidate), Encoding.UTF8.GetBytes("streamlink-pair-v3/" + host + "/" + guest)); }
        finally { CryptographicOperations.ZeroMemory(shared); }
    }
    public static void ValidateState(PairRoomTicket ticket, PairRoomState? previous, PairRoomState state, PairKeyExchange key, bool owner)
    {
        if (state.Expires != ticket.Expires || (!owner && state.Candidate != ticket.Candidate) ||
            (previous?.Candidate.Length > 0 && (previous.Candidate != state.Candidate || previous.GuestCommitment != state.GuestCommitment)) ||
            (state.HostPublic.Length > 0 && owner && state.HostPublic != key.PublicKey) ||
            (state.GuestPublic.Length > 0 && !owner && state.GuestPublic != key.PublicKey))
            throw new CryptographicException("配对会话发生变化，请重新生成配对码");
        if (state.HostPublic.Length > 0) ValidatePublic(state.HostPublic, ticket.HostCommitment);
        if (state.GuestPublic.Length > 0) ValidatePublic(state.GuestPublic, state.GuestCommitment);
    }
    public static string Verification(byte[] shared) => (BitConverter.ToUInt32(HMACSHA256.HashData(shared, "verification"u8.ToArray()), 0) % 1_000_000).ToString("D6");
    public static string Encrypt(byte[] shared, Pairing pair, string room, string candidate)
        => EncryptInvitation(shared, pair.Invite(), room, candidate);
    public static string EncryptInvitation(byte[] shared, string invitation, string room, string candidate)
    {
        byte[] plain = Encoding.UTF8.GetBytes(invitation), nonce = RandomNumberGenerator.GetBytes(12), cipher = new byte[plain.Length], tag = new byte[16];
        try {
            using var aes = new AesGcm(shared, 16); aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(room + "/" + candidate));
            return Convert.ToBase64String(nonce.Concat(tag).Concat(cipher).ToArray());
        } finally { CryptographicOperations.ZeroMemory(plain); }
    }
    public static Pairing Decrypt(byte[] shared, string cipher, string room, string candidate, string service, string pin)
    {
        var pair = Pairing.Import(DecryptInvitation(shared, cipher, room, candidate));
        if (new Uri(pair.Service) != new Uri(service) || !pair.CertificatePin.Equals(pin, StringComparison.OrdinalIgnoreCase)) throw new CryptographicException("邀请中的协调服务器不符");
        return pair;
    }
    public static string DecryptInvitation(byte[] shared, string cipher, string room, string candidate, int maximumCipher=6000)
    {
        if (cipher is null || cipher.Length > maximumCipher) throw new FormatException("加密邀请过大");
        byte[] data = Convert.FromBase64String(cipher); if (data.Length < 29) throw new FormatException("加密邀请截断");
        byte[] plain = new byte[data.Length - 28]; using var aes = new AesGcm(shared, 16);
        aes.Decrypt(data.AsSpan(0, 12), data.AsSpan(28), data.AsSpan(12, 16), plain, Encoding.UTF8.GetBytes(room + "/" + candidate));
        try {
            return Encoding.UTF8.GetString(plain);
        } finally { CryptographicOperations.ZeroMemory(plain); }
    }
    public void Dispose() => key.Dispose();
}

public interface IShortPairClient : IDisposable
{
    Task<PairRoomTicket> Create(PairKeyExchange key,string name,CancellationToken cancel);
    Task<PairRoomTicket> Join(string code,PairKeyExchange key,string name,CancellationToken cancel,string requestedIp="",MeshRejoinProof? rejoin=null);
    Task<PairRoomState> Poll(PairRoomTicket ticket,bool owner,CancellationToken cancel);
    Task<PairRoomState> Reveal(PairRoomTicket ticket,bool owner,PairKeyExchange key,CancellationToken cancel);
    Task<PairRoomState> Approve(PairRoomTicket ticket,string candidate,string cipher,CancellationToken cancel);
    Task Close(PairRoomTicket ticket,CancellationToken cancel);
    Task<PairRoomState> Finish(PairRoomTicket ticket,bool owner,CancellationToken cancel);
}
public sealed class ShortPairClient : IShortPairClient
{
    readonly HttpClient http;
    public ShortPairClient(string service, string pin)
    {
        Pairing.Create(service, pin).Validate();
        var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false };
        if (pin.Length > 0) handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert != null && DateTime.UtcNow >= cert.NotBefore.ToUniversalTime() && DateTime.UtcNow <= cert.NotAfter.ToUniversalTime() && CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.RawData), Convert.FromHexString(pin));
        http = new(handler) { BaseAddress = new(service), Timeout = TimeSpan.FromSeconds(12), MaxResponseContentBufferSize = MeshGovernance.MaximumCipher + 16384 };
    }
    async Task<T> Send<T>(HttpMethod method, string path, object? body, string? token, CancellationToken cancel)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body != null) request.Content = JsonContent.Create(body);
        if (token != null) request.Headers.Authorization = new("Bearer", token);
        HttpResponseMessage received;
        try { received = await http.SendAsync(request, cancel); }
        catch(OperationCanceledException ex)when(!cancel.IsCancellationRequested){throw new IOException("HTTPS 协调服务响应超时，请检查协调地址或稍后重试；这不表示目标设备离线",ex);}
        catch(HttpRequestException ex){
            string reason=ex.HttpRequestError switch {
                HttpRequestError.NameResolutionError=>"域名解析失败",
                HttpRequestError.SecureConnectionError=>"TLS 安全连接失败，请核对证书或指纹",
                HttpRequestError.ResponseEnded=>"响应提前结束",
                HttpRequestError.InvalidResponse=>"响应格式无效",
                _=>"连接失败（"+ex.HttpRequestError+"）"
            };
            throw new IOException("HTTPS 协调服务："+reason+"。",ex);
        }
        using var response = received;
        if (response.StatusCode == HttpStatusCode.TooManyRequests) throw new IOException("配对请求过于频繁，请稍后重试");
        if(response.StatusCode==HttpStatusCode.NotFound&&path=="health")throw new IOException("该 HTTPS 地址未提供 ConWU 协调服务，请检查协调地址与路径");
        if (response.StatusCode == HttpStatusCode.NotFound) throw new PairRoomUnavailableException();
        if (response.StatusCode == HttpStatusCode.Conflict) throw new IOException("此配对码已有设备申请，请创建端确认或生成新码");
        if ((int)response.StatusCode == 507) throw new IOException("协调存储已达上限，请联系该协调服务的管理员；本机设置及成员身份保持不变");
        if ((int)response.StatusCode >= 500) throw new IOException($"协调代理或源站暂不可用（HTTP {(int)response.StatusCode}），请检查协调服务和 Tunnel；这不表示目标设备离线");
        if (!response.IsSuccessStatusCode) throw new IOException($"协调服务未完成配对请求（HTTP {(int)response.StatusCode}）");
        return await response.Content.ReadFromJsonAsync<T>(cancel) ?? throw new IOException("配对响应为空");
    }
    public Task<PairRoomTicket> Create(PairKeyExchange key, string name, CancellationToken cancel) => Send<PairRoomTicket>(HttpMethod.Post, "v2/pair", new PairRoomCreate(key.Commitment, name), null, cancel);
    public async Task RequireMeshSupport(CancellationToken cancel,bool requireDecisions=false,bool requireAddressing=false,bool requireRejoin=false,bool requireGovernance=false)
    {
        var document = await Send<JsonElement>(HttpMethod.Get,"health",null,null,cancel);
        if (!document.TryGetProperty("meshProtocol", out var version) || version.GetInt32() != 4)
            throw new IOException("协调服务器尚未支持多机网络。请先部署随包提供的协调服务，再创建或加入网络；当前连接已保留。");
        if(requireDecisions && (!document.TryGetProperty("pairingDecisions",out var decisions)||decisions.GetInt32()!=1))
            throw new IOException("新版加入审批需要更新协调服务（拒绝与取消支持）。请部署本次附带的协调服务包；已有直连不受影响");
        if(requireAddressing && (!document.TryGetProperty("meshAddressing",out var addressing)||addressing.GetInt32()!=1))
            throw new IOException("自定义虚拟 IP 需要新版协调服务；请部署本次附带的协调服务包");
        if(requireGovernance && (!document.TryGetProperty("meshGovernance",out var governance)||governance.GetInt32()!=1))
            throw new IOException("成员平等网络需要更新协调服务；请先部署本版协调服务包，原网络仍保留");
        if(requireRejoin && (!document.TryGetProperty("memberRejoin",out var rejoin)||rejoin.GetInt32()!=1))
            throw new IOException("退出后重新加入需要 1.0.3 协调服务，请更新协调服务后重试，避免留下重复成员");
    }
    public async Task RequireAddressing(CancellationToken cancel)
    {
        var document=await Send<JsonElement>(HttpMethod.Get,"health",null,null,cancel);
        if(!document.TryGetProperty("meshAddressing",out var value)||value.GetInt32()!=1)
            throw new IOException("自定义虚拟 IP 需要新版协调服务；请部署本次协调服务包后再使用，原网络仍保留");
    }
    public Task<PairRoomTicket> Join(string code, PairKeyExchange key, string name, CancellationToken cancel,string requestedIp="",MeshRejoinProof? rejoin=null)
    {
        if (!Regex.IsMatch(code, "^[0-9]{6}$")) throw new FormatException("请输入 6 位数字配对码");
        return Send<PairRoomTicket>(HttpMethod.Post, "v2/pair/join", new PairRoomJoin(code, key.Commitment, name,requestedIp,1){Rejoin=rejoin,Governance=1}, null, cancel);
    }
    public Task<PairRoomState> Poll(PairRoomTicket ticket, bool owner, CancellationToken cancel) => Send<PairRoomState>(HttpMethod.Get, $"v2/pair/{ticket.Room}/{(owner ? "owner" : "guest")}", null, ticket.Token, cancel);
    public Task<PairRoomState> Reveal(PairRoomTicket ticket, bool owner, PairKeyExchange key, CancellationToken cancel) => Send<PairRoomState>(HttpMethod.Post, $"v2/pair/{ticket.Room}/{(owner ? "owner" : "guest")}/reveal", new PairRoomReveal(key.PublicKey), ticket.Token, cancel);
    public Task<PairRoomState> Approve(PairRoomTicket ticket, string candidate, string cipher, CancellationToken cancel) => Send<PairRoomState>(HttpMethod.Post, $"v2/pair/{ticket.Room}/approve", new PairRoomApproval(candidate, cipher), ticket.Token, cancel);
    public async Task Close(PairRoomTicket ticket, CancellationToken cancel) => _ = await Send<JsonElement>(HttpMethod.Delete, $"v2/pair/{ticket.Room}", null, ticket.Token, cancel);
    public Task<PairRoomState> Finish(PairRoomTicket ticket,bool owner,CancellationToken cancel) => Send<PairRoomState>(HttpMethod.Post,$"v2/pair/{ticket.Room}/{(owner?"reject":"guest/cancel")}",new {},ticket.Token,cancel);
    public void Dispose() => http.Dispose();
}
