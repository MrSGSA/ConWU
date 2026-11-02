using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using StreamLink.Core;
using StreamLink.Discovery;

int count = 0;
void Check(bool value, string reason) { if (!value) throw new Exception(reason); count++; }
void Reject(Action action) { try { action(); } catch (Exception ex) when (ex is CryptographicException or FormatException or IOException or ArgumentException) { count++; return; } throw new Exception("Expected rejection"); }
using var host = new PairKeyExchange(); using var guest = new PairKeyExchange(); using var attacker = new PairKeyExchange();
string roomId = Guid.NewGuid().ToString("N"), candidate = Guid.NewGuid().ToString("N");
byte[] first = host.Derive(guest.PublicKey, guest.Commitment, roomId, candidate, true), second = guest.Derive(host.PublicKey, host.Commitment, roomId, candidate, false);
Check(first.SequenceEqual(second), "ECDH directions disagree"); Check(PairKeyExchange.Verification(first) == PairKeyExchange.Verification(second), "Verification mismatch");
Reject(() => PairKeyExchange.ValidatePublic(attacker.PublicKey, host.Commitment));
using (var wrongCurve = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384)) { var pub = wrongCurve.ExportSubjectPublicKeyInfo(); Reject(() => PairKeyExchange.ValidatePublic(Convert.ToBase64String(pub), Convert.ToHexString(SHA256.HashData(pub)))); }
var pair = Pairing.Create("https://example.com/", "", "udp"); string cipher = PairKeyExchange.Encrypt(first, pair, roomId, candidate);
Check(PairKeyExchange.Decrypt(second, cipher, roomId, candidate, pair.Service, "") == pair, "Encrypted invite roundtrip");
Reject(() => PairKeyExchange.Decrypt(second, cipher, Guid.NewGuid().ToString("N"), candidate, pair.Service, ""));
Reject(() => PairKeyExchange.Decrypt(second, cipher, roomId, Guid.NewGuid().ToString("N"), pair.Service, ""));
Reject(() => PairKeyExchange.Decrypt(second, cipher, roomId, candidate, "https://evil.example/", ""));
var bytes = Convert.FromBase64String(cipher); bytes[^1] ^= 1; Reject(() => PairKeyExchange.Decrypt(second, Convert.ToBase64String(bytes), roomId, candidate, pair.Service, ""));
Check(!host.Derive(guest.PublicKey, guest.Commitment, Guid.NewGuid().ToString("N"), candidate, true).SequenceEqual(first), "Room transcript not bound");
Reject(() => new DeviceProfile { LogLevel = "invalid" }.Validate()); Reject(() => new DeviceProfile { LogDirectory = "relative" }.Validate());
Check(Stun.TcpServers.Length > 20 && Stun.TcpServers.Distinct(StringComparer.OrdinalIgnoreCase).Count() == Stun.TcpServers.Length, "STUN snapshot missing or duplicate");
Reject(() => StunCatalog.Parse("valid.example:3478\nhttps://evil.example"));
using var services = new ServiceCollection().AddLogging().Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(_ => { }).BuildServiceProvider();
async Task<(int Status, JsonElement Body)> Execute(IResult result)
{
    var context = new DefaultHttpContext { RequestServices = services }; context.Response.Body = new MemoryStream(); await result.ExecuteAsync(context); context.Response.Body.Position = 0;
    using var reader = new StreamReader(context.Response.Body); string json = await reader.ReadToEndAsync(); return (context.Response.StatusCode, json.Length == 0 ? default : JsonSerializer.Deserialize<JsonElement>(json));
}
T Value<T>(JsonElement json) => json.Deserialize<T>(new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
DefaultHttpContext Auth(string token) { var c = new DefaultHttpContext(); c.Request.Headers.Authorization = "Bearer " + token; return c; }
var clock = new TestClock(); var rooms = new PairRooms(clock);
var created = await Execute(rooms.Create(new(host.Commitment, "Host"))); var ticket = Value<PairRoomTicket>(created.Body);
Check(created.Status == 200 && ticket.Code.Length == 6, "Create failed");
Check((await Execute(rooms.Exchange(Auth(new string('0',64)), ticket.Room, true))).Status == 401, "Owner token not checked");
Check((await Execute(rooms.Exchange(Auth(ticket.Token), ticket.Room, true, new(host.PublicKey)))).Status == 409, "Host reveals before guest commitment");
var rejoinOwner=MeshIdentity.Create("https://example.com/","","faketcp");
var former=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(rejoinOwner)));
var rejoinProof=MeshRejoin.Create(MeshRejoin.Retain(former),ticket.Code,guest);
var joinBody=new PairRoomJoin(ticket.Code,guest.Commitment,"Guest"){Rejoin=rejoinProof};
var joined = await Execute(rooms.Join(joinBody)); var join = Value<PairRoomTicket>(joined.Body); Check(joined.Status == 200 && join.Candidate.Length == 32, "Join failed");
var duplicate=await Execute(rooms.Join(joinBody));Check(duplicate.Status==200&&Value<PairRoomTicket>(duplicate.Body)==join,"lost join reply can be observed with the same committed request without allocating another candidate");
var ownerView=Value<PairRoomState>((await Execute(rooms.Exchange(Auth(ticket.Token),ticket.Room,true))).Body);
Check(ownerView.Rejoin==rejoinProof&&MeshRejoin.Resolve(rejoinOwner,ownerView.Rejoin,ticket.Code,ownerView.GuestCommitment)==former.Self,"coordination preserves the old-key proof for owner verification without granting membership");
Check((await Execute(rooms.Join(new(ticket.Code, attacker.Commitment, "Attacker")))).Status == 409, "Second guest accepted");
Check((await Execute(rooms.Exchange(Auth(join.Token), ticket.Room, true))).Status == 401, "Guest acquired owner access");
Check((await Execute(rooms.Exchange(Auth(join.Token), ticket.Room, false, new(guest.PublicKey)))).Status == 409, "Guest reveals before host");
Check((await Execute(rooms.Exchange(Auth(ticket.Token), ticket.Room, true, new(attacker.PublicKey)))).Status == 400, "Commitment substitution accepted");
Check((await Execute(rooms.Exchange(Auth(ticket.Token), ticket.Room, true, new(host.PublicKey)))).Status == 200, "Host reveal failed");
Check((await Execute(rooms.Exchange(Auth(join.Token), ticket.Room, false, new(guest.PublicKey)))).Status == 200, "Guest reveal failed");
first = host.Derive(guest.PublicKey, guest.Commitment, ticket.Room, join.Candidate, true); second = guest.Derive(host.PublicKey, host.Commitment, ticket.Room, join.Candidate, false);
cipher = PairKeyExchange.Encrypt(first, pair, ticket.Room, join.Candidate);
Check((await Execute(rooms.Exchange(Auth(ticket.Token), ticket.Room, true, approve: new(Guid.NewGuid().ToString("N"), cipher)))).Status == 409, "Wrong candidate approved");
Check((await Execute(rooms.Exchange(Auth(ticket.Token), ticket.Room, true, approve: new(join.Candidate, cipher)))).Status == 200, "Approval failed");
Check((await Execute(rooms.Exchange(Auth(ticket.Token), ticket.Room, true, approve: new(join.Candidate, cipher)))).Status == 200, "Identical approval retry recovers its original result");
Check((await Execute(rooms.Exchange(Auth(ticket.Token), ticket.Room, true, approve: new(join.Candidate, PairKeyExchange.Encrypt(first,pair,roomId,candidate))))).Status == 409, "Approved authorization cannot be replaced by a different ciphertext");
Check((await Execute(rooms.Join(new(ticket.Code, attacker.Commitment, "Attacker")))).Status == 404, "Consumed code reused");
var state = Value<PairRoomState>((await Execute(rooms.Exchange(Auth(join.Token), ticket.Room, false))).Body);
PairKeyExchange.ValidateState(join, null, state, guest, false); count++;
Reject(() => PairKeyExchange.ValidateState(join, null, state with { Candidate = Guid.NewGuid().ToString("N") }, guest, false));
Reject(() => PairKeyExchange.ValidateState(ticket, state, state with { GuestCommitment = attacker.Commitment }, host, true));
Reject(() => PairKeyExchange.ValidateState(ticket, state, state with { HostPublic = attacker.PublicKey }, host, true));
Check(PairKeyExchange.Decrypt(second, state.Ciphertext, ticket.Room, join.Candidate, pair.Service, "") == pair, "Approved delivery corrupt");
clock.Advance(TimeSpan.FromMinutes(6)); Check((await Execute(rooms.Exchange(Auth(join.Token), ticket.Room, false))).Status == 404, "Expired room still exists");
var revoked = Value<PairRoomTicket>((await Execute(rooms.Create(new(host.Commitment, "Host")))).Body);
Check((await Execute(rooms.Exchange(Auth(revoked.Token), revoked.Room, true, close: true))).Status == 200, "Revoke failed"); Check((await Execute(rooms.Join(new(revoked.Code, guest.Commitment, "Guest")))).Status == 404, "Revoked code reused");
// Rejection/cancellation are explicit terminal states, readable by both roles.
foreach(bool reject in new[]{true,false}) {
    var offer=Value<PairRoomTicket>((await Execute(rooms.Create(new(host.Commitment,"Decision Host")))).Body);
    var applicant=Value<PairRoomTicket>((await Execute(rooms.Join(new(offer.Code,guest.Commitment,"Decision Guest","10.171.139.5",1)))).Body);
    var requested=Value<PairRoomState>((await Execute(rooms.Exchange(Auth(offer.Token),offer.Room,true))).Body);
    Check(requested.RequestedIp=="10.171.139.5"&&requested.Addressing==1,"Requested address capability preserved for owner approval");
    Check((await Execute(rooms.Exchange(Auth(applicant.Token),offer.Room,true,finish:true))).Status==401,"Guest cannot impersonate host rejection");
    var finished=await Execute(rooms.Exchange(Auth(reject?offer.Token:applicant.Token),offer.Room,reject,finish:true));
    Check(finished.Status==200,"Explicit decision accepted for authenticated role");
    var outcome=Value<PairRoomState>((await Execute(rooms.Exchange(Auth(applicant.Token),offer.Room,false))).Body);
    Check(outcome.Outcome==(reject?"Rejected":"Cancelled")&&!outcome.Approved,"Decision is visible to waiting applicant without expiry guess");
    Check((await Execute(rooms.Exchange(Auth(offer.Token),offer.Room,true,new(host.PublicKey)))).Status==409,"Cancelled/rejected exchange cannot resume");
    Check((await Execute(rooms.Join(new(offer.Code,attacker.Commitment,"Late")))).Status==404,"Terminal decision cannot reuse pairing code");
}
Console.WriteLine($"PASS {count}: committed key exchange, authenticated invite, replay/expiry/revocation, role separation, STUN and settings.");
if (args.Length >= 2 && args[0] == "--server") {
    string pin = args.Length >= 4 && args[2] == "--pin" ? args[3] : "";
    using var client = new ShortPairClient(args[1], pin); using var timeout = new CancellationTokenSource(45000);
    var a = await client.Create(host, "Integration-A", timeout.Token); var b = await client.Join(a.Code, guest, "Integration-B", timeout.Token);
    await client.Reveal(a, true, host, timeout.Token); await client.Reveal(b, false, guest, timeout.Token); var status = await client.Poll(a, true, timeout.Token);
    byte[] aKey = host.Derive(status.GuestPublic, status.GuestCommitment, a.Room, b.Candidate, true), bKey = guest.Derive(host.PublicKey, a.HostCommitment, a.Room, b.Candidate, false);
    var remotePair = Pairing.Create(args[1], pin); await client.Approve(a, b.Candidate, PairKeyExchange.Encrypt(aKey, remotePair, a.Room, b.Candidate), timeout.Token);
    var delivery = await client.Poll(b, false, timeout.Token); Check(PairKeyExchange.Decrypt(bKey, delivery.Ciphertext, a.Room, b.Candidate, args[1], pin) == remotePair, "Live short pairing failed");
    await client.Close(a, timeout.Token); Console.WriteLine($"PASS {count}: live HTTPS pairing exchange and cleanup");
    if (args.Contains("--exercise-limits")) {
        var handler = new HttpClientHandler();
        if (pin.Length > 0) handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert != null && Convert.ToHexString(SHA256.HashData(cert.RawData)) == pin;
        using var http = new HttpClient(handler) { BaseAddress = new(args[1]), Timeout = TimeSpan.FromSeconds(10) };
        using var health = await http.GetAsync("health");
        Check(health.IsSuccessStatusCode && health.Headers.CacheControl?.NoStore == true, "Pairing service must prohibit caches");
        var fresh = await client.Create(host, "Authorization-Test", timeout.Token);
        using var unauthorized = await http.GetAsync($"v2/pair/{fresh.Room}/owner");
        Check(unauthorized.StatusCode == System.Net.HttpStatusCode.Unauthorized, "Live owner endpoint accepted missing token");
        await client.Close(fresh, timeout.Token);
        System.Net.HttpStatusCode limited = 0;
        for (int i = 0; i < 5; i++) {
            using var response = await http.PostAsync("v2/pair/join", new StringContent(JsonSerializer.Serialize(new PairRoomJoin("000000", guest.Commitment, "Limit-Test")), System.Text.Encoding.UTF8, "application/json"));
            limited = response.StatusCode;
        }
        Check(limited == System.Net.HttpStatusCode.TooManyRequests, "Live join rate limit failed");
        using var badPin = new ShortPairClient(args[1], new string('0',64)); bool rejected = false;
        try { await badPin.Create(host, "Pin-Test", timeout.Token); } catch (IOException ex) when (ex.InnerException is HttpRequestException) { rejected = true; }
        Check(rejected, "TLS pin mismatch accepted");
        Console.WriteLine($"PASS {count}: HTTPS role checks, no-store, join rate limit and TLS pin mismatch");
    }
}
sealed class TestClock : TimeProvider { DateTimeOffset now = DateTimeOffset.UtcNow; public override DateTimeOffset GetUtcNow() => now; public void Advance(TimeSpan time) => now += time; }
