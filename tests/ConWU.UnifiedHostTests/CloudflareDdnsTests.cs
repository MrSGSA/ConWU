using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using StreamLink.Core;
using StreamLink.Service;

static class CloudflareDdnsTests
{
    const string Domain = "conwu.example.test", Token = "test-token-never-print-0123456789";
    public static async Task Run(Action<bool, string> check)
    {
        var owner = MeshIdentity.Create("https://coord.example.test/", "", "faketcp");
        MeshGovernance.Enable(owner);
        var guest = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));
        owner.Directory = guest.Directory;
        long utc = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var settings = new CloudflareDdnsSettings(true, Domain, new string('a', 32), true, 60);
        var record = DdnsAddressRecords.Create(owner, Domain, "faketcp", ["203.0.113.8:44680"], utc, 180);
        bool Valid(DdnsAddressRecord r) => DdnsAddressRecords.Verify(r, Domain, owner.Pair.Network, owner.Self, "faketcp", utc);
        check(Valid(record), "DDNS accepts the current approved member's signature");
        check(!Valid(record with { Endpoints = ["203.0.113.9:44680"] }) && !Valid(record with { Domain = "other.example.test" }), "DDNS rejects endpoint and domain tampering");
        check(!DdnsAddressRecords.Verify(record, Domain, owner.Pair.Network, guest.Self, "faketcp", utc) &&
              !DdnsAddressRecords.Verify(record, Domain, owner.Pair.Network, owner.Self, "udp", utc), "DDNS binds records to member identity and selected protocol");
        check(!DdnsAddressRecords.Verify(record, Domain, owner.Pair.Network, owner.Self, "faketcp", utc + 180), "DDNS expires even when resolver caches retain the TXT");
        check(!Valid(DdnsAddressRecords.Create(owner, Domain, "faketcp", [], utc + 61, 180)), "DDNS rejects excessive future clock skew");
        check(Valid(DdnsAddressRecords.Create(owner, Domain, "faketcp", [], utc, 180)), "DDNS supports signed empty endpoint withdrawal");
        check(new[] { "127.0.0.1:1", "10.1.1.1:1", "172.16.0.1:1", "192.168.0.1:1", "100.64.0.1:1", "[::1]:1", "203.0.113.1:0" }.All(e => !DdnsAddressRecords.PublicEndpoint(e)), "DDNS excludes private and invalid endpoints");
        string text = DdnsAddressRecords.Encode(record), quoted = DdnsAddressRecords.Quote(text);
        check(quoted.Contains("\" \"") && DdnsAddressRecords.Unquote(quoted) == text && Valid(DdnsAddressRecords.Decode(text)), "Cloudflare multi-string TXT round trips with a valid signature");
        check(DdnsAddressRecords.Name(Domain, owner.Pair.Network, owner.Self.Device) != DdnsAddressRecords.Name(Domain, owner.Pair.Network, guest.Self.Device), "members sharing a domain cannot overwrite one another's record names");
        var profile = new DeviceProfile { Ddns = settings, CloudflareDdnsToken = Token };
        var copy = ProfileChanges.Copy(profile); copy.Ddns = copy.Ddns with { RefreshSeconds = 90 };
        check(ProfileChanges.Impact(profile, copy) != ProfileChangeImpact.RestartNetwork, "DDNS refresh changes do not rebuild the packet path");
        check(!new UiNetworkAction("settings") { DdnsToken = Token }.ToString().Contains(Token), "action diagnostic text never prints DDNS credentials");
        check(!JsonSerializer.Serialize(new UiNetworkSettings { Ddns = settings }).Contains(Token), "public settings contain no DDNS token");

        using (var api = new FakeApi())
        using (var client = new CloudflareDdnsClient(api)) {
            await client.Publish(settings, Token, record, CancellationToken.None);
            check(api.Methods.SequenceEqual(["GET", "POST"]), "DDNS queries the exact name before creating a record");
            await client.Publish(settings, Token, record, CancellationToken.None);
            check(api.Methods.TakeLast(2).SequenceEqual(["GET", "PATCH"]), "DDNS updates only its exact owned record ID");
            api.Stored!["comment"] = "foreign record";
            int before = api.Methods.Count;
            await Reject(() => client.Publish(settings, Token, record, CancellationToken.None));
            check(api.Methods.Count == before + 1, "DDNS refuses foreign ownership without writing or deleting");
            api.Stored["comment"] = DdnsAddressRecords.Ownership(record.Network, record.Device); api.Duplicates = true;
            before = api.Methods.Count;
            await Reject(() => client.Publish(settings, Token, record, CancellationToken.None));
            check(api.Methods.Count == before + 1, "DDNS refuses ambiguous duplicate records");
        }
        using (var api = new FakeApi { LoseFirstResponse = true })
        using (var client = new CloudflareDdnsClient(api)) {
            await Reject(() => client.Publish(settings, Token, record, CancellationToken.None));
            await client.Publish(settings, Token, record, CancellationToken.None);
            check(api.Methods.SequenceEqual(["GET", "POST", "GET", "PATCH"]), "lost create response is reconciled before retrying, without duplicate creation");
        }
        using (var api = new FakeApi { Failure = HttpStatusCode.TooManyRequests })
        using (var client = new CloudflareDdnsClient(api)) {
            var ex = await Reject(() => client.Publish(settings, Token, record, CancellationToken.None));
            check(ex.RetrySeconds >= 120 && !ex.ToString().Contains(Token), "DDNS honors Retry-After and keeps server error bodies out of diagnostics");
        }
        using (var api = new FakeApi { CorruptResponse = true })
        using (var client = new CloudflareDdnsClient(api)) {
            await Reject(() => client.Publish(settings, Token, record, CancellationToken.None));
            check(true, "DDNS does not report success for malformed returned TXT");
        }

        var remote = DdnsAddressRecords.Create(guest, Domain, "faketcp", ["203.0.113.10:44680"], utc, 180);
        var pending = new TaskCompletionSource<DdnsAddressRecord?>(TaskCreationOptions.RunContinuationsAsynchronously);
        int reads = 0;
        await using (var session = new MeshDdnsSession(CancellationToken.None, new(new FakeApi()),
            (_, _, _, _, _) => { reads++; return pending.Task; })) {
            var readOnly = settings with { Publish = false };
            session.Tick(readOnly, "", owner, "faketcp", [], 100000);
            session.Tick(readOnly with { Domain = "changed.example.test" }, "", owner, "faketcp", [], 100001);
            pending.SetResult(remote);
            for (int i = 0; i < 30 && reads < 2; i++) { await Task.Yield(); session.Tick(readOnly with { Domain = "changed.example.test" }, "", owner, "faketcp", [], 100002 + i); }
            check(session.ForMember(owner, guest.Self, "faketcp").Length == 0, "late DNS result cannot restore a record from the previous domain");
        }
        int attempt = 0;
        await using (var session = new MeshDdnsSession(CancellationToken.None, new(new FakeApi()),
            (_, _, _, _, _) => ++attempt == 1 ? Task.FromResult<DdnsAddressRecord?>(remote) : Task.FromException<DdnsAddressRecord?>(new IOException("DNS unavailable")))) {
            var readOnly = settings with { Publish = false };
            session.Tick(readOnly, "", owner, "faketcp", [], 200000);
            session.Tick(readOnly, "", owner, "faketcp", [], 200001);
            check(session.ForMember(owner, guest.Self, "faketcp").SequenceEqual(remote.Endpoints), "read-only devices discover signed endpoints without any API token");
            session.Tick(readOnly, "", owner, "faketcp", [], 270000);
            session.Tick(readOnly, "", owner, "faketcp", [], 270001);
            check(session.ForMember(owner, guest.Self, "faketcp").SequenceEqual(remote.Endpoints), "temporary DNS failure retains the unexpired authenticated hint");
            session.Tick(new(), "", owner, "faketcp", [], 280000);
            check(session.ForMember(owner, guest.Self, "faketcp").Length == 0, "disabling DDNS retires hints immediately");
        }
        using (var api = new FakeApi { HoldFirstWrite = true })
        await using (var session = new MeshDdnsSession(CancellationToken.None, new(api), (_, _, _, _, _) => Task.FromResult<DdnsAddressRecord?>(null))) {
            session.Tick(settings, Token, owner, "faketcp", ["203.0.113.8:44680"], 300000);
            session.Tick(settings, Token, owner, "faketcp", ["203.0.113.9:44680"], 315000);
            api.Release.TrySetResult(true);
            var until = DateTime.UtcNow.AddSeconds(3);
            while (api.Methods.Count < 4 && DateTime.UtcNow < until) { await Task.Delay(10); session.Tick(settings, Token, owner, "faketcp", ["203.0.113.9:44680"], 315001); }
            check(api.Methods.Count == 4 && DdnsAddressRecords.Decode(DdnsAddressRecords.Unquote(api.Stored!["content"]!.GetValue<string>())).Endpoints.Single() == "203.0.113.9:44680", "an old write completion cannot delay publishing the changed listener address");
        }
        long time = utc - 100;
        var recent = DdnsAddressRecords.Create(guest, Domain, "faketcp", ["203.0.113.11:44680"], utc - 200, 180);
        var older = DdnsAddressRecords.Create(guest, Domain, "faketcp", ["203.0.113.12:44680"], utc - 300, 600);
        DdnsAddressRecord next = recent;
        await using (var session = new MeshDdnsSession(CancellationToken.None, new(new FakeApi()),
            (_, _, _, _, _) => Task.FromResult<DdnsAddressRecord?>(next), () => time)) {
            var readOnly = settings with { Publish = false };
            session.Tick(readOnly, "", owner, "faketcp", [], 400000); session.Tick(readOnly, "", owner, "faketcp", [], 400001);
            check(session.ForMember(owner, guest.Self, "faketcp").SequenceEqual(recent.Endpoints), "DDNS verifies the current record before caching");
            time = utc; next = older;
            session.Tick(readOnly, "", owner, "faketcp", [], 470000); session.Tick(readOnly, "", owner, "faketcp", [], 470001);
            check(session.ForMember(owner, guest.Self, "faketcp").Length == 0, "expired newer records cannot be replaced by older records with longer validity");
            session.Tick(readOnly with { RefreshSeconds = 90 }, "", owner, "faketcp", [], 480000);
            session.Tick(readOnly with { RefreshSeconds = 90 }, "", owner, "faketcp", [], 480001);
            check(session.ForMember(owner, guest.Self, "faketcp").Length == 0, "refresh setting changes retain the in-session replay watermark");
        }
    }

    static async Task<CloudflareDdnsException> Reject(Func<Task> operation) {
        try { await operation(); } catch (CloudflareDdnsException ex) { return ex; }
        throw new Exception("DDNS unexpectedly accepted unsafe or failed API operation");
    }
    sealed class FakeApi : HttpMessageHandler
    {
        public List<string> Methods { get; } = [];
        public JsonObject? Stored;
        public bool Duplicates, LoseFirstResponse, CorruptResponse, HoldFirstWrite;
        public HttpStatusCode? Failure;
        public TaskCompletionSource<bool> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) {
            if (request.RequestUri!.Host != "api.cloudflare.com" || request.Headers.Authorization?.Parameter != Token) throw new Exception("unexpected DDNS authority/credential");
            Methods.Add(request.Method.Method);
            if (Failure is {} status) {
                var failed = new HttpResponseMessage(status) { Content = new StringContent(Token) };
                failed.Headers.RetryAfter = new(TimeSpan.FromSeconds(120)); return failed;
            }
            if (request.Method == HttpMethod.Get) {
                if (!request.RequestUri.Query.StartsWith("?name=d-", StringComparison.Ordinal)) throw new Exception("unscoped DNS query");
                var rows = new JsonArray(); if (Stored != null) rows.Add(Stored.DeepClone()); if (Duplicates) rows.Add(Stored!.DeepClone());
                return Reply(new JsonObject { ["success"] = true, ["result"] = rows });
            }
            if (request.Method != HttpMethod.Post && request.Method != HttpMethod.Patch) throw new Exception("unexpected DDNS write method");
            if (request.Method == HttpMethod.Patch && !request.RequestUri.AbsolutePath.EndsWith(new string('b', 32))) throw new Exception("unexpected DNS record ID");
            Stored = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!.AsObject(); Stored["id"] = new string('b', 32);
            if (HoldFirstWrite) { HoldFirstWrite = false; await Release.Task.WaitAsync(token); }
            if (LoseFirstResponse) { LoseFirstResponse = false; throw new HttpRequestException("private-server-body:" + Token); }
            var result = Stored.DeepClone().AsObject(); if (CorruptResponse) result["content"] = "\"unterminated";
            return Reply(new JsonObject { ["success"] = true, ["result"] = result });
        }
        static HttpResponseMessage Reply(JsonNode body) => new(HttpStatusCode.OK) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };
    }
}
