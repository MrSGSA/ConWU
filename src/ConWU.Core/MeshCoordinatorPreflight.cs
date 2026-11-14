using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

public static class MeshCoordinatorPreflight
{
    public static async Task Check(Pairing pair, CancellationToken token)
    {
        pair.Validate();
        var result = await Probe(pair.Service, pair.CertificatePin, null, token);
        if (!result.Reachable) throw new IOException(result.Detail);
    }

    // No redirects, proxy, credentials or user-supplied response text. An
    // instance challenge distinguishes a wrong Tunnel origin and stale caches.
    public static async Task<CoordinatorDiagnostic> Probe(string url, string pin, string? expectedInstance, CancellationToken token)
    {
        CoordinatorSettings.ValidatePublicEndpoint(url, pin);
        if (url.Length == 0) return Result("unconfigured", "尚未设置外部 HTTPS 地址，未检查外部访问路径");
        using var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false };
        if (pin.Length > 0) handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert != null &&
            DateTime.UtcNow >= cert.NotBefore.ToUniversalTime() && DateTime.UtcNow <= cert.NotAfter.ToUniversalTime() &&
            CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.RawData), Convert.FromHexString(pin));
        using var http = new HttpClient(handler) { BaseAddress = new(url), Timeout = TimeSpan.FromSeconds(8), MaxResponseContentBufferSize = 16384 };
        string challenge = expectedInstance == null ? "" : Guid.NewGuid().ToString("N");
        try {
            using var reply = await http.GetAsync(challenge.Length == 0 ? "health" : "health?challenge=" + challenge, token);
            if (!reply.IsSuccessStatusCode) return HttpFailure(reply.StatusCode);
            using var health = JsonDocument.Parse(await reply.Content.ReadAsByteArrayAsync(token));
            var h = health.RootElement;
            if (h.ValueKind != JsonValueKind.Object || !Integer(h, "meshProtocol", 4) || !Integer(h, "meshTraversal", MeshTraversal.Version) ||
                !h.TryGetProperty("relay", out var relay) || relay.ValueKind != JsonValueKind.False)
                return Result("protocol", "地址已响应，但未提供兼容的 ConWU 协调能力；请检查地址和代理转发目标");
            if (expectedInstance != null && (!Text(h, "instanceId", expectedInstance) || !Text(h, "challenge", challenge)))
                return Result("origin-mismatch", "HTTPS 已响应，但不是本次运行的协调实例或返回了缓存；请检查 Tunnel 目标、代理路径和缓存规则");
            return Result("reachable", expectedInstance == null ? "协调服务可访问" : "本机通过外部 HTTPS 地址访问并确认了当前协调实例；其他网络的可达性仍需在对端检查", true);
        } catch (OperationCanceledException) when (!token.IsCancellationRequested) {
            return Result("timeout", "协调 HTTPS 在 8 秒内未完成响应；请检查网络、Tunnel 和代理源站状态");
        } catch (HttpRequestException ex) {
            return ex.HttpRequestError switch {
                HttpRequestError.NameResolutionError => Result("dns", "协调域名解析失败，请检查 DNS 记录和当前设备的 DNS 网络"),
                HttpRequestError.SecureConnectionError => Result("tls", "协调 HTTPS 证书校验或 TLS 握手失败，请检查证书、域名、有效期、指纹及系统时间"),
                HttpRequestError.ConnectionError => Result("connect", "无法建立到协调地址的连接，请检查监听、端口转发、防火墙或 Tunnel"),
                _ => Result("response", "协调 HTTPS 响应中断、格式异常或超过 16 KiB 限制，请检查代理及源站")
            };
        } catch (JsonException) { return Result("protocol", "地址返回的不是协调状态 JSON，请检查代理转发是否指向 ConWU"); }
    }

    static bool Integer(JsonElement root, string name, int expected) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n) && n == expected;
    static bool Text(JsonElement root, string name, string expected) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() == expected;
    static CoordinatorDiagnostic Result(string code, string detail, bool reachable = false) => new(code, detail, DateTimeOffset.UtcNow, reachable);
    static CoordinatorDiagnostic HttpFailure(HttpStatusCode status) => Result("http-" + (int)status, (int)status switch {
        401 or 403 => "协调 HTTPS 返回 HTTP " + (int)status + "：访问被拒绝，请检查 Cloudflare Access、WAF 或代理访问限制",
        429 => "协调 HTTPS 返回 HTTP 429：请求受到限流，请稍后重试",
        507 => "协调 HTTPS 返回 HTTP 507：协调存储达到上限，请由服务管理员检查",
        >= 500 => "协调 HTTPS 返回 HTTP " + (int)status + "：代理或源站不可用，请检查 Tunnel 连接和协调进程",
        >= 300 and < 400 => "协调地址发生重定向，已拒绝跟随；请填写最终 HTTPS 地址",
        _ => "协调 HTTPS 返回 HTTP " + (int)status + "，请检查协调地址及代理路径"
    });
}
