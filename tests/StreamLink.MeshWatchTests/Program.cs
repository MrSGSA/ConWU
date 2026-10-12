using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Discovery;

int checks = 0;
void Check(bool value, string detail) { if (!value) throw new Exception(detail); checks++; Console.WriteLine("PASS " + detail); }
int Status(IResult value) => ((IStatusCodeHttpResult)value).StatusCode ?? 200;
MeshWatchResponse Body(IResult value) => (MeshWatchResponse)((IValueHttpResult)value).Value!;
MeshProfile Guest(MeshProfile owner) => MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));
DefaultHttpContext Context(MeshProfile profile, CancellationToken token = default) {
    var c = new DefaultHttpContext { RequestAborted = token }; c.Request.Headers.Authorization = "Bearer " + profile.Pair.Auth; return c;
}
MeshEnvelope Announcement(MeshProfile p, long revision) => MeshMetadata.Seal(p, new(p.Self.Slot, p.Self.Device, revision,
    DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), "192.0.2.1:" + (40000 + revision), "isolated-test"));
string root = Path.Combine(Path.GetTempPath(), "streamlink-watch-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
string output = args.Length == 2 && args[0] == "--output" ? Path.GetFullPath(args[1]) : Path.Combine(root, "result.json");
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
using var all = new CancellationTokenSource(TimeSpan.FromSeconds(100));
try {
    var registry = new MeshRegistry(root);
    var owner = MeshIdentity.Create("https://example.com/", "", "faketcp");
    var profiles = new List<MeshProfile> { owner }; for (int i = 1; i < 8; i++) profiles.Add(Guest(owner));
    string net = owner.Pair.Network;
    Check(Status(registry.Directory(Context(owner), net, owner.Directory!)) == 204, "register signed eight-member directory");
    var requests = profiles.Select(p => MeshWatch.Create(p, Guid.NewGuid(), Guid.Empty, 0)).ToArray();
    long issued = requests[0].Expires - 40;
    Check(MeshWatch.Validate(net, owner.Self, requests[0], issued - 5) && MeshWatch.Validate(net, owner.Self, requests[0], issued + 5) &&
          !MeshWatch.Validate(net, owner.Self, requests[0], requests[0].Expires), "watch tolerates five-second clock skew while retaining the expiration bound");
    var initial = await Task.WhenAll(profiles.Select((p, i) => registry.Watch(Context(p, all.Token), net, requests[i])));
    Check(initial.All(r => Status(r) == 200 && Body(r).Reset && Body(r).Snapshot.Directory.Members.Length == 8), "eight independent readers bootstrap at one server epoch");
    var feed = Body(initial[0]);
    var waits = profiles.Select(p => registry.Watch(Context(p, all.Token), net, MeshWatch.Create(p, Guid.NewGuid(), feed.ServerEpoch, feed.Cursor))).ToArray();
    Check(waits.All(t => !t.IsCompleted), "one bounded pending wait per device");
    Check(Status(await registry.Watch(Context(owner), net, MeshWatch.Create(owner, Guid.NewGuid(), feed.ServerEpoch, feed.Cursor))) == 409, "second concurrent wait cannot displace the first");
    Check(Status(registry.Publish(Context(profiles[1]), net, 2, Announcement(profiles[1], 1))) == 204 &&
          Status(registry.Publish(Context(profiles[2]), net, 3, Announcement(profiles[2], 1))) == 204, "two nearby publications accepted");
    var batch = await Task.WhenAll(waits).WaitAsync(TimeSpan.FromSeconds(2));
    Check(batch.All(r => Body(r).Snapshot.Nodes.Length == 2 && Body(r).Changes.Length >= 1), "eight waiters receive batched peer changes, not per-peer HTTP loops");
    Check(Body(batch[0]).Changes.Length == 2, "coalesced response includes both changed peers");
    Check(Status(await registry.Watch(Context(owner), net, requests[0])) == 409, "signed request replay rejected");
    var forged = MeshWatch.Create(owner, Guid.NewGuid(), feed.ServerEpoch, feed.Cursor) with { Slot = 4, Device = profiles[3].Self.Device };
    Check(Status(await registry.Watch(Context(owner), net, forged)) == 403, "network bearer cannot impersonate another member's waiter");
    feed = Body(batch[3]);
    using (var canceled = new CancellationTokenSource()) {
        var pending = registry.Watch(Context(profiles[3], canceled.Token), net, MeshWatch.Create(profiles[3], Guid.NewGuid(), feed.ServerEpoch, feed.Cursor));
        canceled.Cancel(); bool canceledOk = false;
        try { await pending; } catch (OperationCanceledException) { canceledOk = true; }
        Check(canceledOk, "HTTP disconnect releases a waiting request");
    }
    var retry = registry.Watch(Context(profiles[3], all.Token), net, MeshWatch.Create(profiles[3], Guid.NewGuid(), feed.ServerEpoch, feed.Cursor));
    Check(!retry.IsCompleted, "same member can wait again after cancellation");
    MeshIdentity.Revoke(owner, 4); registry.Directory(Context(owner), net, owner.Directory!);
    Check(Status(await retry) == 403, "revocation wakes and terminates the revoked member's pending wait");
    var restarted = new MeshRegistry(root);
    var restart = Body(await restarted.Watch(Context(owner), net, MeshWatch.Create(owner, Guid.NewGuid(), feed.ServerEpoch, feed.Cursor)));
    Check(restart.Reset && restart.ServerEpoch != feed.ServerEpoch, "server restart resets cursors against persisted membership");

    var capacity = new MeshRegistry(root);
    var held = new List<Task<IResult>>(); using var release = new CancellationTokenSource();
    try {
        for (int n = 0; n < 8; n++) {
            var group = MeshIdentity.Create("https://example.com/", "", "faketcp");
            var members = new List<MeshProfile> { group }; for (int j = 1; j < 8; j++) members.Add(Guest(group));
            capacity.Directory(Context(group), group.Pair.Network, group.Directory!);
            foreach (var member in members) {
                var current = Body(await capacity.Watch(Context(member), group.Pair.Network, MeshWatch.Create(member, Guid.NewGuid(), Guid.Empty, 0)));
                held.Add(capacity.Watch(Context(member, release.Token), group.Pair.Network, MeshWatch.Create(member, Guid.NewGuid(), current.ServerEpoch, current.Cursor)));
            }
        }
        var overflow = MeshIdentity.Create("https://example.com/", "", "faketcp");
        capacity.Directory(Context(overflow), overflow.Pair.Network, overflow.Directory!);
        Check(held.Count == 64 && held.All(t => !t.IsCompleted) && Status(await capacity.Watch(Context(overflow), overflow.Pair.Network,
            MeshWatch.Create(overflow, Guid.NewGuid(), Guid.Empty, 0))) == 503, "global 64-waiter cap reserves capacity for short requests");
        Check(Status(capacity.Read(Context(overflow), overflow.Pair.Network)) == 200, "ordinary read remains available when waiters are full");
    } finally {
        release.Cancel(); foreach (var task in held) { try { await task; } catch (OperationCanceledException) { } }
    }
    Check(held.All(t => t.IsCanceled), "cancellation releases all 64 waiters");
    var limited = MeshIdentity.Create("https://example.com/", "", "faketcp");
    capacity.Directory(Context(limited), limited.Pair.Network, limited.Directory!);
    var statuses = new List<int>();
    for (int i = 0; i < 10; i++) statuses.Add(Status(await capacity.Watch(Context(limited), limited.Pair.Network, MeshWatch.Create(limited, Guid.NewGuid(), Guid.Empty, 0))));
    Check(statuses.Count(s => s == 200) == 8 && statuses.Skip(8).All(s => s == 429), "per-device eight-request burst cannot bypass the shared request budget");

    // Real loopback HTTPS verifies the client timeout, certificate pin, fallback,
    // and server wait together. No external service or network configuration.
    using var rsa = RSA.Create(2048);
    var certRequest = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); certRequest.CertificateExtensions.Add(san.Build());
    using var generated = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
    // Reimport for Windows Schannel; do not install a root/trust certificate.
    using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
    var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
    builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, l => l.UseHttps(certificate)));
    await using var app = builder.Build(); bool legacy = false, forbidden = false; int watches = 0, reads = 0;
    MeshDirectory? readOverride = null;
    var online = new MeshRegistry(root);
    app.MapPost("/v3/mesh/{network}/watch", async (HttpContext c, string network, MeshWatchRequest r) => {
        Interlocked.Increment(ref watches); return forbidden ? Results.StatusCode(403) : legacy ? Results.NotFound() : await online.Watch(c, network, r);
    });
    app.MapGet("/v3/mesh/{network}", (HttpContext c, string network) => { Interlocked.Increment(ref reads); return readOverride != null ? Results.Json(new MeshSnapshot(readOverride, [])) : online.Read(c, network); });
    app.MapPut("/v3/mesh/{network}/directory", (HttpContext c, string network, MeshDirectory d) => online.Directory(c, network, d));
    app.MapPut("/v3/mesh/{network}/nodes/{slot:int}", (HttpContext c, string network, int slot, MeshEnvelope e) => online.Publish(c, network, slot, e));
    await app.StartAsync(all.Token);
    string url = app.Urls.Single(); string pin = Convert.ToHexString(SHA256.HashData(certificate.RawData));
    var fresh = MeshIdentity.Create(url, pin, "faketcp"); var beforeEnrollment = fresh.Directory!;
    var friend = Guest(fresh); friend.Directory = fresh.Directory;
    using var client = new MeshDiscoveryClient(fresh);
    using var publisher = new MeshDiscoveryClient(friend);
    Check(await client.WaitForChanges(all.Token) == null && client.SupportsLongPolling, "first watch racing network registration keeps capability and normal retry cadence");
    await client.SaveDirectory(fresh.Directory!, all.Token);
    Check((await client.WaitForChanges(all.Token))!.Directory.Members.Length == 2, "production client reads new watch API over pinned HTTPS");
    Check(client.SupportsTcpPeerReflexive, "HTTPS watch independently negotiates TCP source-learning capability");
    var clock = Stopwatch.StartNew();
    var idle = await client.WaitForChanges(all.Token);
    clock.Stop();
    Check(clock.Elapsed.TotalSeconds is >= 24 and < 34 && idle != null, "25-second server hold survives client's independent 35-second timeout");
    var changed = client.WaitForChanges(all.Token);
    await publisher.Publish(new(2, friend.Self.Device, 1, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), "192.0.2.1:45000", "peer"), all.Token);
    Check((await changed.WaitAsync(TimeSpan.FromSeconds(2)))!.Nodes.Length == 1, "real HTTPS publication wakes long poll within two seconds");
    using (var canceled = new CancellationTokenSource(100)) {
        try { await client.WaitForChanges(canceled.Token); throw new Exception("client cancellation ignored"); }
        catch (OperationCanceledException) { Check(true, "client cancellation interrupts held HTTPS without waiting 25 seconds"); }
    }
    legacy = true; using var oldServer = new MeshDiscoveryClient(fresh);
    Check((await oldServer.WaitForChanges(all.Token)) != null && !oldServer.SupportsLongPolling, "explicit old-server 404 falls back to the existing read API");
    Check(!oldServer.SupportsTcpPeerReflexive, "old-server read fallback cannot retain source-learning permission");
    int attempts = watches;
    await oldServer.WaitForChanges(all.Token);
    Check(watches == attempts && reads >= 2, "fallback is remembered rather than retrying unsupported route every poll");
    legacy = false;
    using var membership = new MeshDiscoveryClient(friend);
    await membership.WaitForChanges(all.Token);
    int oldReads = reads; forbidden = true;
    async Task ForbiddenPoll() {
        bool denied = false; try { await membership.WaitForChanges(all.Token); } catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Forbidden) { denied = true; }
        Check(denied && membership.SupportsLongPolling && membership.SupportsTraversal, "403 preserves capabilities and requires signed revocation evidence");
    }
    await ForbiddenPoll();
    Check(reads == oldReads, "failed watch does not hide an additional HTTP request from the Runner budget");
    Check((await membership.WaitForChanges(all.Token))!.Directory.Members.Contains(friend.Self) && reads == oldReads + 1,
        "next budgeted poll verifies still-authorized membership without downgrading transport");
    await ForbiddenPoll(); readOverride = fresh.Directory! with { Members = [fresh.Self] };
    bool forgedRejected = false; try { await membership.WaitForChanges(all.Token); } catch (CryptographicException) { forgedRejected = true; }
    Check(forgedRejected, "unsigned membership removal cannot stop a healthy path"); readOverride = null;
    await ForbiddenPoll(); readOverride = beforeEnrollment;
    bool rollbackRejected = false; try { await membership.WaitForChanges(all.Token); } catch (CryptographicException) { rollbackRejected = true; }
    Check(rollbackRejected, "signed older directory cannot revoke a subsequently enrolled member"); readOverride = null;
    await ForbiddenPoll();
    MeshIdentity.Revoke(fresh, friend.Self.Slot); await client.SaveDirectory(fresh.Directory!, all.Token);
    bool revoked = false; try { await membership.WaitForChanges(all.Token); } catch (MeshRevokedException) { revoked = true; }
    Check(revoked && membership.SupportsLongPolling, "owner-signed removal terminates revoked member even when its watch returns only 403");
    await app.StopAsync(all.Token);
    await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { checks, eightIsolatedMembers = true, realHttps = true,
        holdSeconds = 25, measuredHoldSeconds = clock.Elapsed.TotalSeconds, realWindowsEndpoints = 1, realEightDevices = false }, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine($"PASS {checks} watch checks. Isolated eight-member model and real loopback HTTPS; not eight real devices.");
} catch (Exception ex) {
    await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, failure = ex.ToString() }));
    throw;
} finally {
    foreach (string file in Directory.GetFiles(root)) File.Delete(file);
    Directory.Delete(root);
}
