using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.EndpointPoc;

string binary = args is ["--native", var exe, "--output", _] ? Path.GetFullPath(exe) : "";
string output = args.Length >= 2 ? Path.GetFullPath(args[^1]) : throw new ArgumentException("--output report.json or --native binary --output report.json");
string root = Path.Combine(Path.GetTempPath(), "streamlink-traversal-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
int checks = 0;
void Check(bool value, string why) { if (!value) throw new Exception(why); checks++; Console.WriteLine("PASS " + why); }
void Reject(Action action, string why) { bool rejected = false; try { action(); } catch (Exception ex) when (ex is IOException or CryptographicException or FormatException or InvalidOperationException) { rejected = true; } Check(rejected, why); }
int Status(IResult value) => ((IStatusCodeHttpResult)value).StatusCode ?? 200;
MeshWatchResponse Body(IResult value) => (MeshWatchResponse)((IValueHttpResult)value).Value!;
DefaultHttpContext Http(MeshProfile p, CancellationToken token = default) { var c = new DefaultHttpContext { RequestAborted = token }; c.Request.Headers.Authorization = "Bearer " + p.Pair.Auth; return c; }
MeshTraversalCapabilities Caps(Guid? boot = null) => new(1, 1, boot ?? Guid.NewGuid(), [TraversalProfile.FakeTcpHttpSo, TraversalProfile.UdpDirect]);
MeshTraversalCandidate Candidate(string endpoint = "192.0.2.1:40000") => new(Guid.NewGuid(), 1, endpoint, "192.0.2.9:3478", DateTimeOffset.UtcNow.ToUnixTimeSeconds(), DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), CandidatePurpose.SimultaneousOpen);
(MeshProfile A, MeshProfile B) Pair(string service = "https://example.com/", string pin = "") {
    var a = MeshIdentity.Create(service, pin, "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory; return (a, b);
}
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(220)); var token = deadline.Token;
var rows = new List<object>();
try {
    var registry = new MeshRegistry(root);
    {
        var (a, b) = Pair(); var ca = Caps(); var cb = Caps(); long seqA = 0, seqB = 0;
        await using var leader = MeshTraversalAttempt.Offer(a, b.Self, ca, cb, TraversalProfile.FakeTcpHttpSo, Candidate(), 1, () => ++seqA);
        var offer = leader.Outbound!; MeshTraversal.Verify(a.Pair.Network, a.Self, b.Self, offer);
        long advertisedAt = offer.Expires - MeshTraversal.PublishSeconds;
        MeshTraversal.ValidateShape(offer, advertisedAt - 5); MeshTraversal.ValidateShape(offer, advertisedAt + 5);
        Reject(() => MeshTraversal.ValidateShape(offer, offer.Expires), "five-second clock allowance never accepts an expired control message");
        Reject(() => MeshTraversal.Verify(a.Pair.Network, a.Self, b.Self, offer with { ToBoot = Guid.NewGuid() }), "signature binds receiver boot and every control field");
        Reject(() => MeshTraversalAttempt.ValidateOffer(b, a.Self, cb with { BootId = Guid.NewGuid() }, ca, offer), "valid but stale receiver boot rejected before resource allocation");
        Reject(() => MeshTraversalAttempt.ValidateOffer(b, a.Self, cb, ca with { BootId = Guid.NewGuid() }, offer), "valid old sender boot rejected against current member capability");
        await using var follower = MeshTraversalAttempt.Answer(b, a.Self, cb, ca, offer, Candidate("192.0.2.2:41000"), () => ++seqB);
        Check(follower.Outbound == null && follower.Phase == MeshAttemptPhase.Preparing, "receiving Offer alone cannot claim Ready");
        var unarmed = new Prepared(follower.Context, false);
        Reject(() => follower.Prepared(unarmed), "Ready requires an armed resource with matching authenticated context");
        var preparedB = new Prepared(follower.Context); follower.Prepared(preparedB);
        Check(follower.Outbound!.Stage == MeshTraversalStage.Ready && leader.Receive(follower.Outbound), "authenticated Ready completes the leader candidate pair");
        Check(PathNomination.ContextDigest(leader.Context).SequenceEqual(PathNomination.ContextDigest(follower.Context)), "both roles derive the identical nomination context");
        var changed = MeshTraversal.Sign(b, follower.Outbound with { MessageId = Guid.NewGuid(), Sequence = ++seqB, Candidate = follower.Outbound.Candidate! with { Endpoint = "192.0.2.3:45000" } });
        Reject(() => leader.Receive(changed), "same candidate version cannot silently change its public endpoint");
        var preparedA = new Prepared(leader.Context); leader.Prepared(preparedA);
        Check(leader.Outbound!.Stage == MeshTraversalStage.Start && follower.Receive(leader.Outbound), "Start is accepted only after local Prepared and valid remote Ready");
        Check(!follower.Receive(leader.Outbound), "duplicate Start never repeats activation");
        follower.Cancel(); Check(!follower.Receive(leader.Outbound) && follower.Phase == MeshAttemptPhase.Cancelled, "late Start cannot revive canceled Attempt");
        var expired = leader.Outbound with { MessageId = Guid.NewGuid(), Sequence = ++seqA, Expires = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 1 };
        Reject(() => MeshTraversal.Sign(a, expired), "expired control message cannot be published");
        var oldCandidate = leader.Outbound.Candidate! with { ObservedAt = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds(), Expires = DateTimeOffset.UtcNow.AddMinutes(-8).ToUnixTimeSeconds() };
        var selected = MeshTraversal.Sign(a, leader.Outbound with { MessageId = Guid.NewGuid(), Sequence = ++seqA, Stage = MeshTraversalStage.Selected, Candidate = oldCandidate });
        Check(selected.Stage == MeshTraversalStage.Selected, "Active-state reporting does not expire solely with candidate announcement TTL");
        Reject(() => MeshTraversal.Sign(a, selected with { Stage = MeshTraversalStage.Start }), "expired observation still cannot authorize a new Start");
        var metadata = new MeshAnnouncement(1, a.Self.Device, 1, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), "", "test", ca);
        Check(MeshMetadata.Open(b, a.Self, MeshMetadata.Seal(a, metadata)).Traversal!.BootId == ca.BootId, "capability negotiation remains inside authenticated metadata");

        registry.Directory(Http(a), a.Pair.Network, a.Directory!);
        var initial = Body(await registry.Watch(Http(b), a.Pair.Network, MeshWatch.Create(b, cb.BootId, Guid.Empty, 0)));
        Check(initial.Snapshot.TraversalVersion == 1 && initial.Snapshot.Traversal!.Length == 0, "watch explicitly advertises traversal-control version");
        var pending = registry.Watch(Http(b, token), a.Pair.Network, MeshWatch.Create(b, cb.BootId, initial.ServerEpoch, initial.Cursor));
        Check(Status(registry.Traversal(Http(a), a.Pair.Network, new([offer]))) == 204, "signed Offer stored by typed control endpoint");
        var delivered = Body(await pending.WaitAsync(TimeSpan.FromSeconds(1)));
        Check(delivered.Snapshot.Traversal!.Single() == offer && delivered.Changes.Single().TargetSlot == 2, "targeted Offer wakes the existing device wait without a separate peer poll");
        Check(Status(registry.Traversal(Http(a), a.Pair.Network, new([offer]))) == 204, "exact current HTTP retry is idempotent");
        Check(Status(registry.Traversal(Http(a), a.Pair.Network, new([leader.Outbound!]))) == 204, "newer Start replaces that boot pair's Offer");
        Check(Status(registry.Traversal(Http(a), a.Pair.Network, new([offer]))) == 409, "replaying formerly accepted Offer after Start cannot roll mailbox backward");
        var forged = leader.Outbound! with { MessageId = Guid.NewGuid(), Sequence = 100, FromDevice = Guid.NewGuid().ToString("N") };
        Check(Status(registry.Traversal(Http(a), a.Pair.Network, new([forged]))) == 403, "network bearer alone cannot impersonate a member");
        var wrongBoot = Body(await registry.Watch(Http(b), a.Pair.Network, MeshWatch.Create(b, Guid.NewGuid(), Guid.Empty, 0)));
        Check(wrongBoot.Snapshot.Traversal!.Length == 0, "new boot does not receive old boot's pending Start");
        var ordinary = (MeshSnapshot)((IValueHttpResult)registry.Read(Http(a), a.Pair.Network)).Value!;
        Check(ordinary.Traversal == null && ordinary.TraversalVersion == 0, "legacy bearer-only snapshot never exposes targeted control inbox");
        MeshIdentity.Revoke(a, 2); registry.Directory(Http(a), a.Pair.Network, a.Directory!);
        Check(Status(registry.Traversal(Http(a), a.Pair.Network, new([leader.Outbound!]))) == 403, "revocation immediately rejects targeted control to removed member");
    }
    // Different targets share one publish and one wait; invalid batches do not
    // partially mutate other peers' state or manufacture unrelated wakeups.
    {
        var (a, b) = Pair(); var d = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = d.Directory = a.Directory;
        var ca = Caps(); var cb = Caps(); var cd = Caps(); long sequence = 0;
        registry.Directory(Http(a), a.Pair.Network, a.Directory!);
        await using var ab = MeshTraversalAttempt.Offer(a, b.Self, ca, cb, TraversalProfile.FakeTcpHttpSo, Candidate(), 1, () => ++sequence);
        await using var ad = MeshTraversalAttempt.Offer(a, d.Self, ca, cd, TraversalProfile.FakeTcpHttpSo, Candidate(), 1, () => ++sequence);
        var unrelated = Body(await registry.Watch(Http(d), a.Pair.Network, MeshWatch.Create(d, cd.BootId, Guid.Empty, 0)));
        using var hold = CancellationTokenSource.CreateLinkedTokenSource(token);
        var waiting = registry.Watch(Http(d, hold.Token), a.Pair.Network, MeshWatch.Create(d, cd.BootId, unrelated.ServerEpoch, unrelated.Cursor));
        Check(Status(registry.Traversal(Http(a), a.Pair.Network, new([ab.Outbound!]))) == 204, "first directed member state published");
        await Task.Delay(120, token); Check(!waiting.IsCompleted, "control changes do not wake unrelated member waits");
        var invalid = ad.Outbound! with { Signature = "invalid" };
        Check(Status(registry.Traversal(Http(a), a.Pair.Network, new([ab.Outbound!, invalid]))) == 403, "invalid batch rejected before any mutation");
        Check(Status(registry.Traversal(Http(a), a.Pair.Network, new([ab.Outbound!, ad.Outbound!]))) == 204, "batch can idempotently include one old state plus another member update");
        Check(Body(await waiting.WaitAsync(TimeSpan.FromSeconds(1))).Snapshot.Traversal!.Single().ToSlot == d.Self.Slot, "recipient receives only its own control messages");
    }

    {
        var (a, b) = Pair(); var ca = Caps(); var cb = Caps(); long seqA = 0, seqB = 0;
        Guid generation = Guid.NewGuid(), attemptId = Guid.NewGuid(); byte[] shared = MeshIdentity.SharedKey(a, b.Self);
        await using var udpA = UdpTraversal.Create(new(IPAddress.Loopback, 0), generation, attemptId, 1, 2, shared, new());
        await using var udpB = UdpTraversal.Create(new(IPAddress.Loopback, 0), generation, attemptId, 2, 1, shared, new());
        CryptographicOperations.ZeroMemory(shared);
        var adapterA = new Adapter(); var adapterB = new Adapter();
        await using var routerA = new MeshRouter(a, adapterA, ca.BootId); await using var routerB = new MeshRouter(b, adapterB, cb.BootId);
        await using var leader = MeshTraversalAttempt.Offer(a, b.Self, ca, cb, TraversalProfile.UdpDirect,
            Candidate(udpA.Local.ToString()) with { Purpose = CandidatePurpose.UdpDirect }, 1, () => ++seqA, attemptId);
        await using var follower = MeshTraversalAttempt.Answer(b, a.Self, cb, ca, leader.Outbound!,
            Candidate(udpB.Local.ToString()) with { Purpose = CandidatePurpose.UdpDirect }, () => ++seqB);
        follower.Prepared(udpB.PreparePath(follower.Context, generation, udpA.Local)); leader.Receive(follower.Outbound!);
        leader.Prepared(udpA.PreparePath(leader.Context, generation, udpB.Local)); follower.Receive(leader.Outbound!);
        await Task.WhenAll(leader.ActivateAndRegister(routerA, token), follower.ActivateAndRegister(routerB, token));
        var clock = Stopwatch.StartNew();
        while (leader.Phase != MeshAttemptPhase.Selected || follower.Phase != MeshAttemptPhase.Selected) {
            leader.ObserveRouter(); follower.ObserveRouter(); if (clock.ElapsedMilliseconds > 5000) throw new TimeoutException("UDP nomination failed"); await Task.Delay(10, token);
        }
        await leader.DisposeAsync(); await follower.DisposeAsync();
        Check(!udpA.Closed && !udpB.Closed, "UDP preparation owner can end after transfer without closing the retained winning sockets");
        adapterA.Outgoing.Add(Packet(a.LocalIp, b.LocalIp));
        await Task.Delay(150, token); Check(adapterB.Incoming.Count == 1, "actual Router business uses the same UDP socket after coordinated Attempt ends");
        await routerA.DisposeAsync(); await routerB.DisposeAsync();
        Check(udpA.Closed && udpB.Closed, "separate UDP preparation reference is released, not leaked when Router owns the path");
    }

    if (binary.Length > 0) {
        using var rsa = RSA.Create(2048); var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build());
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, l => l.UseHttps(certificate)));
        await using var app = builder.Build(); var online = new MeshRegistry(root);
        app.MapPost("/v3/mesh/{network}/watch", (HttpContext c, string network, MeshWatchRequest r) => online.Watch(c, network, r));
        app.MapPost("/v3/mesh/{network}/traversal", (HttpContext c, string network, MeshTraversalBatch r) => online.Traversal(c, network, r));
        app.MapPut("/v3/mesh/{network}/directory", (HttpContext c, string network, MeshDirectory d) => online.Directory(c, network, d));
        app.MapPut("/v3/mesh/{network}/nodes/{slot:int}", (HttpContext c, string network, int slot, MeshEnvelope e) => online.Publish(c, network, slot, e));
        await app.StartAsync(token);
        string url = app.Urls.Single(), pin = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        string logs = Path.Combine(Path.GetDirectoryName(output)!, Path.GetFileNameWithoutExtension(output) + "-logs"); Directory.CreateDirectory(logs);
        for (int round = 1; round <= 30; round++) {
            var (a, b) = Pair(url, pin); using var discoveryA = new MeshDiscoveryClient(a); using var discoveryB = new MeshDiscoveryClient(b);
            var capsA = Caps(discoveryA.BootId); var capsB = Caps(discoveryB.BootId); long seqA = 0, seqB = 0;
            var adapterA = new Adapter(); var adapterB = new Adapter();
            await using var routerA = new MeshRouter(a, adapterA, discoveryA.BootId); await using var routerB = new MeshRouter(b, adapterB, discoveryB.BootId);
            await discoveryA.SaveDirectory(a.Directory!, token);
            await discoveryA.Publish(new(1, a.Self.Device, 1, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), "", "a", capsA), token);
            await discoveryB.Publish(new(2, b.Self.Device, 1, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), "", "b", capsB), token);
            var snapA = await discoveryA.WaitForChanges(token); var snapB = await discoveryB.WaitForChanges(token);
            capsB = MeshMetadata.Open(a, b.Self, snapA!.Nodes.Single(n => n.Slot == 2)).Traversal!;
            capsA = MeshMetadata.Open(b, a.Self, snapB!.Nodes.Single(n => n.Slot == 1)).Traversal!;
            Check(discoveryA.SupportsTraversal && discoveryB.SupportsTraversal, "both peers negotiate typed control API and signed boot capabilities over HTTPS");
            await using var reflector = new Reflector { Silent = false }; Guid generation = Guid.NewGuid();
            using var leaseA = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, token);
            using var leaseB = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, token);
            using var queryA = leaseA.AcquireAttempt(generation); using var queryB = leaseB.AcquireAttempt(generation);
            var observationA = await queryA.Observe(token); var observationB = await queryB.Observe(token);
            await using var leader = MeshTraversalAttempt.Offer(a, b.Self, capsA, capsB, TraversalProfile.FakeTcpHttpSo, Candidate(observationA.Public.ToString()), 1, () => ++seqA);
            var waitB = discoveryB.WaitForChanges(token);
            await discoveryA.PublishTraversal([leader.Outbound!], token);
            var offer = (await waitB)!.Traversal!.Single();
            await using var follower = MeshTraversalAttempt.Answer(b, a.Self, capsB, capsA, offer, Candidate(observationB.Public.ToString()), () => ++seqB);
            int aWire = 0, bWire = 0; await using var proxy = new RawProtocolProxy(aWire, bWire);
            Dictionary<string, string> Env(int localPort, int peerPort) => new() { ["STREAMLINK_TEST_BIND"] = localPort.ToString(), ["STREAMLINK_TEST_PEER"] = peerPort.ToString(), ["STREAMLINK_TEST_HELLO"] = proxy.RegistrationToken };
            byte[] keyA = MeshIdentity.SharedKey(a, b.Self), keyB = MeshIdentity.SharedKey(b, a.Self);
            await using var pathB = await NativeDatagramPath.Prepare(binary, Path.Combine(logs, round.ToString()), leaseB, generation, follower.Context,
                observationA.Public, keyB, token, new(), Env(bWire, proxy.ServerPort));
            follower.Prepared(pathB); var waitA = discoveryA.WaitForChanges(token);
            await discoveryB.PublishTraversal([follower.Outbound!], token);
            Check(leader.Receive((await waitA)!.Traversal!.Single()), "production HTTPS Ready authorizes leader preparation");
            await using var pathA = await NativeDatagramPath.Prepare(binary, Path.Combine(logs, round.ToString()), leaseA, generation, leader.Context,
                observationB.Public, keyA, token, new(), Env(aWire, proxy.ClientPort));
            CryptographicOperations.ZeroMemory(keyA); CryptographicOperations.ZeroMemory(keyB);
            leader.Prepared(pathA); Check(proxy.Snapshot().Length == 0, "both actual native captures are armed before Start is dispatched"); proxy.Begin();
            waitB = discoveryB.WaitForChanges(token); var clock = Stopwatch.StartNew();
            await discoveryA.PublishTraversal([leader.Outbound!], token);
            var activateA = leader.ActivateAndRegister(routerA, token);
            Check(follower.Receive((await waitB)!.Traversal!.Single()), "production HTTPS Start selects exactly the prepared follower context");
            var activateB = follower.ActivateAndRegister(routerB, token); await Task.WhenAll(activateA, activateB);
            while (leader.Phase != MeshAttemptPhase.Selected || follower.Phase != MeshAttemptPhase.Selected) {
                leader.ObserveRouter(); follower.ObserveRouter(); if (clock.ElapsedMilliseconds >= 8000) throw new TimeoutException("nomination exceeded shared round"); await Task.Delay(10, token);
            }
            long selectedMs = clock.ElapsedMilliseconds;
            queryA.Dispose(); queryB.Dispose(); leaseA.Dispose(); leaseB.Dispose(); await leader.DisposeAsync(); await follower.DisposeAsync();
            Check(!leaseA.Closed && !leaseB.Closed && !pathA.Closed && !pathB.Closed, "ending coordinated Attempt retains Router-owned native path resources");
            if (round == 1) await Task.Delay(8500, token); // original eight-second window expires; Active must survive
            adapterA.Outgoing.Add(Packet(a.LocalIp, b.LocalIp)); adapterB.Outgoing.Add(Packet(b.LocalIp, a.LocalIp));
            var business = Stopwatch.StartNew(); while (adapterA.Incoming.Count != 1 || adapterB.Incoming.Count != 1) {
                if (business.ElapsedMilliseconds > 1500) throw new TimeoutException("business did not arrive after coordinated Attempt ended"); await Task.Delay(10, token);
            }
            Check(true, "real C++/MeshLink full-MTU business survives ending Attempt and control-phase ownership");
            await routerA.DisposeAsync(); await routerB.DisposeAsync(); Check(leaseA.Closed && leaseB.Closed, "router shutdown releases both final native references");
            rows.Add(new { round, selectedMs, actualNativeProtocol = true, realHttps = true, realNat = false, nativeDriver = false, wintun = false });
        }
        await app.StopAsync(token);
    }
    await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows,
        scope = "typed coordination and production attempt-to-Router integration; optional actual C++ protocol over loopback test backend; not MeshRunner scheduling or WAN" }, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine($"PASS {checks} traversal checks, {rows.Count} HTTPS/native rounds");
} catch (Exception ex) { await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() })); throw; }
finally { foreach (var file in Directory.GetFiles(root)) File.Delete(file); Directory.Delete(root); }

static byte[] Packet(string from, string to) {
    byte[] p = new byte[1280]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), 1280);
    IPAddress.Parse(from).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(p, 16);
    uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
}
sealed class Adapter : IPacketAdapter {
    public readonly BlockingCollection<byte[]> Outgoing = new(); public readonly ConcurrentQueue<byte[]> Incoming = new();
    public int Read(byte[] buffer) { if (!Outgoing.TryTake(out var packet, 30)) return 0; packet.CopyTo(buffer, 0); return packet.Length; }
    public bool Write(byte[] p) { Incoming.Enqueue(p); return true; }
    public void Dispose() => Outgoing.Dispose();
}
sealed class Prepared(TraversalAttemptContext context, bool armed = true) : IPreparedMeshPath {
    public TraversalAttemptContext Context => context; public bool Armed => armed;
    public TimeSpan RemainingAttemptTime => TimeSpan.Zero;
    public Task<IMeshDatagramPath> Activate(CancellationToken token) => throw new NotSupportedException("no I/O in control negative fixture");
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
