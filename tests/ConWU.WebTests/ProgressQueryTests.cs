using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Web;

static class ProgressQueryTests
{
    public static async Task Run(string root, Action<bool, string> check)
    {
        int calls = 0; string seenNetwork = "";
        var id = Guid.NewGuid();
        var operation = new ControlOperationStatus(id, "ui-network:resolve-entries", "排队", false, true);
        await using var panel = await WebPanel.Start((request, _) => {
            calls++; seenNetwork = request.NetworkId;
            return Task.FromResult(new UiControlReply(true, "", null,
                Operation: request.OperationId == id ? operation : null));
        }, root);
        using var client = new HttpClient(new HttpClientHandler { UseCookies = true }) { BaseAddress = new(panel.Origin) };
        async Task<HttpResponseMessage> Send(string path, string? origin = null, string? site = null, string? host = null) {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            if (origin != null) request.Headers.Add("Origin", origin);
            if (site != null) request.Headers.Add("Sec-Fetch-Site", site);
            if (host != null) request.Headers.Host = host;
            return await client.SendAsync(request);
        }
        string query = "/api/status?operation=" + id;
        using (var denied = await Send(query))
            check(denied.StatusCode == HttpStatusCode.Unauthorized && calls == 0, "progress ID does not replace session authorization");
        using var boot = new HttpRequestMessage(HttpMethod.Post, "/api/session") {
            Content = JsonContent.Create(new { ticket = new Uri(panel.OpenLink()).Fragment[1..] })
        };
        boot.Headers.Add("Origin", panel.Origin);
        using var session = await client.SendAsync(boot);
        check(session.IsSuccessStatusCode, "progress fixture authorized through real HTTP bootstrap");
        using (var pending = await Send(query, panel.Origin, "same-origin")) {
            check(pending.IsSuccessStatusCode, "authenticated operation query passes the HTTP boundary");
            if (pending.IsSuccessStatusCode) {
                var body = await pending.Content.ReadFromJsonAsync<JsonElement>();
                check(body.GetProperty("operation").GetProperty("id").GetGuid() == id &&
                    !body.GetProperty("operation").GetProperty("completed").GetBoolean(), "pending operation ID reaches the backend unchanged");
            }
        }
        operation = operation with { Completed = true, Cancelable = false, Phase = "已完成" };
        using (var completed = await Send(query)) {
            check(completed.IsSuccessStatusCode, "completed operation remains queryable over HTTP");
            if (completed.IsSuccessStatusCode)
                check((await completed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("operation").GetProperty("completed").GetBoolean(), "completion result is returned to the browser");
        }
        string networkId = Guid.NewGuid().ToString("N");
        using (var reply = await Send(query + "&networkId=" + networkId))
            check(reply.IsSuccessStatusCode && seenNetwork == networkId, "operation and network selectors reach backend together");
        using (var reply = await Send("/api/status?networkId=" + networkId))
            check(reply.IsSuccessStatusCode && seenNetwork == networkId, "ordinary status forwards network selector");
        foreach (string invalid in new[] { "bad", Guid.Empty.ToString("N"), Guid.NewGuid().ToString("D") }) {
            using var reply = await Send("/api/status?networkId=" + invalid);
            check(reply.StatusCode == HttpStatusCode.BadRequest, "invalid network selector rejected");
        }
        using (var reply = await Send("/api/status?networkId=" + networkId + "&networkId=" + networkId))
            check(reply.StatusCode == HttpStatusCode.Forbidden, "duplicate network selector rejected");
        int before = calls;
        foreach (string invalid in new[] { "", "bad", Guid.Empty.ToString(), id.ToString("N"), "%7B" + id + "%7D", "%20" + id }) {
            using var reply = await Send("/api/status?operation=" + invalid);
            check(reply.StatusCode == HttpStatusCode.BadRequest, "invalid or noncanonical operation ID rejected: " + invalid);
        }
        foreach (string path in new[] { query + "&token=secret", query + "&operation=" + id,
            query + "&Operation=" + id, "/api/status?token=secret", "/api/session?operation=" + id,
            "/?operation=" + id, "/app.js?operation=" + id, "/api/status?Operation=" + id }) {
            using var reply = await Send(path);
            check(reply.StatusCode == HttpStatusCode.Forbidden, "non-whitelisted query rejected: " + path.Split('?')[0]);
        }
        using (var reply = await Send(query, "https://attacker.example")) check(reply.StatusCode == HttpStatusCode.Forbidden, "progress query preserves Origin check");
        using (var reply = await Send(query, site: "cross-site")) check(reply.StatusCode == HttpStatusCode.Forbidden, "progress query preserves Fetch Metadata check");
        using (var reply = await Send(query, host: "attacker.example")) check(reply.StatusCode == HttpStatusCode.Forbidden, "progress query preserves rebinding protection");
        using var missingCsrf = new HttpRequestMessage(HttpMethod.Post, "/api/command") { Content = JsonContent.Create(new UiControlRequest("stop", OperationId: Guid.NewGuid())) };
        missingCsrf.Headers.Add("Origin", panel.Origin);
        using (var reply = await client.SendAsync(missingCsrf)) check(reply.StatusCode == HttpStatusCode.Forbidden, "progress exception does not bypass command CSRF");
        check(calls == before, "all malformed and unauthorized requests stop before backend dispatch");
    }
}
