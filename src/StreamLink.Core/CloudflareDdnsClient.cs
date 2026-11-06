using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace StreamLink.Core;

public sealed class CloudflareDdnsException(string message, int retrySeconds = 60) : IOException(message)
{
    public int RetrySeconds { get; } = Math.Clamp(retrySeconds, 30, 3600);
}

public sealed class CloudflareDdnsClient : IDisposable
{
    readonly HttpClient http;
    public CloudflareDdnsClient() : this(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false, UseCookies = false }) { }
    internal CloudflareDdnsClient(HttpMessageHandler handler) {
        http = new(handler) { BaseAddress = new("https://api.cloudflare.com/client/v4/"), Timeout = TimeSpan.FromSeconds(10), MaxResponseContentBufferSize = 65536 };
    }
    async Task<JsonDocument> Send(HttpMethod method, string path, string token, object? body, CancellationToken cancel) {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new("Bearer", token);
        if (body != null) request.Content = JsonContent.Create(body);
        try {
            using var response = await http.SendAsync(request, cancel);
            if (!response.IsSuccessStatusCode) {
                var retryDelay = response.Headers.RetryAfter?.Delta ?? (response.Headers.RetryAfter?.Date is {} date ? date - DateTimeOffset.UtcNow : TimeSpan.FromSeconds(60));
                int retry = (int)Math.Clamp(retryDelay.TotalSeconds, 30, 3600);
                throw new CloudflareDdnsException(response.StatusCode switch {
                    HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => "Cloudflare 拒绝 DDNS 更新，请检查 API Token、Zone ID 和该区域的 DNS 编辑权限",
                    HttpStatusCode.TooManyRequests => "Cloudflare DDNS 更新受到限流，已延长重试间隔",
                    HttpStatusCode.BadRequest => "Cloudflare 拒绝此 DNS 记录，请检查域名是否属于所填 Zone ID，以及是否已有冲突记录",
                    _ => "Cloudflare DDNS 请求未完成（HTTP " + (int)response.StatusCode + "）"
                }, retry);
            }
            var result = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(cancel));
            if (result.RootElement.ValueKind != JsonValueKind.Object || !result.RootElement.TryGetProperty("success", out var ok) || ok.ValueKind != JsonValueKind.True) {
                result.Dispose(); throw new CloudflareDdnsException("Cloudflare 未确认 DDNS 更新，请核对区域权限与记录配置");
            }
            return result;
        } catch (OperationCanceledException) when (!cancel.IsCancellationRequested) { throw new CloudflareDdnsException("Cloudflare DDNS 请求超时，下轮将先查询记录，避免重复创建"); }
        catch (HttpRequestException) { throw new CloudflareDdnsException("无法完成 Cloudflare DDNS HTTPS 请求，请检查 DNS、TLS 和网络连接"); }
        catch (JsonException) { throw new CloudflareDdnsException("Cloudflare DDNS 返回了无效响应"); }
    }
    public async Task Publish(CloudflareDdnsSettings settings, string token, DdnsAddressRecord record, CancellationToken cancel) {
        settings.Validate(); CloudflareDdnsSettings.ValidateToken(token);
        if (!settings.Enabled || !settings.Publish || token.Length == 0 || record.Domain != settings.Domain.ToLowerInvariant()) throw new FormatException("DDNS 发布未启用或缺少凭据");
        string name = DdnsAddressRecords.Name(settings.Domain, record.Network, record.Device), ownership = DdnsAddressRecords.Ownership(record.Network, record.Device);
        string path = $"zones/{settings.ZoneId}/dns_records";
        using var listed = await Send(HttpMethod.Get, path + "?name=" + Uri.EscapeDataString(name) + "&per_page=5", token, null, cancel);
        if (!listed.RootElement.TryGetProperty("result", out var records) || records.ValueKind != JsonValueKind.Array) throw new CloudflareDdnsException("Cloudflare 记录查询结果无效");
        if (records.GetArrayLength() > 1 || listed.RootElement.TryGetProperty("result_info", out var info) && info.ValueKind == JsonValueKind.Object && info.TryGetProperty("total_count", out var total) && total.ValueKind == JsonValueKind.Number && total.TryGetInt32(out var count) && count > 1)
            throw new CloudflareDdnsException("本设备 DDNS 名称存在多个记录，已停止更新；请核对重复实例或冲突记录");
        string? id = null;
        if (records.GetArrayLength() == 1) {
            var existing = records[0];
            if (!Text(existing, "name", name, true) || !Text(existing, "type", "TXT") || !Text(existing, "comment", ownership))
                throw new CloudflareDdnsException("本设备 DDNS 名称已被其他记录占用，已保留原记录；请使用专用试验域名");
            id = existing.TryGetProperty("id", out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
            if (id is not { Length: 32 } || !id.All(char.IsAsciiHexDigit)) throw new CloudflareDdnsException("Cloudflare 记录 ID 无效");
        }
        // PATCH only the exact name carrying our ownership marker. No zone-wide
        // replacement, wildcard updates, record deletion or global credentials.
        using var saved = await Send(id == null ? HttpMethod.Post : HttpMethod.Patch, id == null ? path : path + "/" + id, token,
            new { type = "TXT", name, content = DdnsAddressRecords.Quote(DdnsAddressRecords.Encode(record)), ttl = 60, comment = ownership }, cancel);
        bool matches;
        try { matches = saved.RootElement.TryGetProperty("result", out var result) && Text(result, "name", name, true) && Text(result, "type", "TXT") &&
            Text(result, "comment", ownership) && result.TryGetProperty("content", out var content) && content.ValueKind == JsonValueKind.String && DdnsAddressRecords.Unquote(content.GetString()!) == DdnsAddressRecords.Encode(record); }
        catch (FormatException) { matches = false; }
        if (!matches)
            throw new CloudflareDdnsException("Cloudflare 返回的 DDNS 记录与本次发布不一致，稍后重新核对");
    }
    static bool Text(JsonElement item, string key, string expected, bool ignoreCase = false) => item.ValueKind == JsonValueKind.Object && item.TryGetProperty(key, out var field) && field.ValueKind == JsonValueKind.String &&
        string.Equals(field.GetString(), expected, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    public void Dispose() => http.Dispose();
}
