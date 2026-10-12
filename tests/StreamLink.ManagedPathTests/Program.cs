using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.Core;

int checks = 0;
string output = args.Length == 2 && args[0] == "--output" ? Path.GetFullPath(args[1]) : "managed-paths.json";
void Check(bool value, string detail) { if (!value) throw new Exception(detail); checks++; Console.WriteLine("PASS " + detail); }
async Task Until(Func<bool> test, string detail, int milliseconds = 4000) {
    var clock = Stopwatch.StartNew(); while (!test()) { if (clock.ElapsedMilliseconds > milliseconds) throw new Exception("Timed out: " + detail); await Task.Delay(20); } Check(true, detail);
}
try {
var recoveryRows = await RecoveryTests.Run(Check, Packet);
await PolicyTests.Run(Check);
var a = MeshIdentity.Create("https://example.com/", "", "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
var aa = new Adapter(); var ab = new Adapter();
await using var ra = new MeshRouter(a, aa, selection: new(AllowUdpFallback: true)); await using var rb = new MeshRouter(b, ab, selection: new(AllowUdpFallback: true));
TraversalAttemptContext Context() => new(a.Pair.Network, a.Self.Device, ra.BootId, b.Self.Device, rb.BootId, Guid.NewGuid(),
    Guid.NewGuid(), 1, Guid.NewGuid(), 1, TraversalProfile.FakeTcpHttpSo, true, true, Guid.NewGuid());
TraversalAttemptContext Reverse(TraversalAttemptContext c) => c with { LocalNodeId = c.RemoteNodeId, LocalBootId = c.RemoteBootId,
    RemoteNodeId = c.LocalNodeId, RemoteBootId = c.LocalBootId, LocalCandidateId = c.RemoteCandidateId, RemoteCandidateId = c.LocalCandidateId,
    ProtocolClient = !c.ProtocolClient, Nominator = !c.Nominator };
(Resource A, Resource B, Reference RA, Reference RB) Prepare(TraversalAttemptContext c) {
    var left = new Resource(); var right = new Resource(); left.Peer = right.Local; right.Peer = left.Local;
    return (left, right, left.Retain(c), right.Retain(Reverse(c)));
}
void Register((Resource A, Resource B, Reference RA, Reference RB) pair, TraversalAttemptContext c, long revision, int ms = 8000) {
    ra.RegisterPath(2, pair.RA, c, revision, TimeSpan.FromMilliseconds(ms), 1);
    rb.RegisterPath(1, pair.RB, Reverse(c), revision, TimeSpan.FromMilliseconds(ms), 1);
    pair.A.Dispose(); pair.B.Dispose(); // ends Attempt/owner without closing Path
}
bool Active(MeshRouter r, int slot, Reference reference) => r.Paths(slot).Any(p => p.PathId == reference.Identity.PathId && p.Active && p.Stage == NominationStage.Selected);
async Task Data(Resource through, int expectedDelta = 1) {
    int count = ab.Incoming.Count, sent = through.Data;
    aa.Outgoing.Add(Packet(a.LocalIp, b.LocalIp));
    await Until(() => ab.Incoming.Count >= count + expectedDelta, "valid full-MTU virtual IPv4 packet reaches the addressed peer");
    Check(through.Data > sent, "business used the selected actual datagram resource");
}
var firstContext = Context(); var first = Prepare(firstContext); Register(first, firstContext, 1);
await Until(() => Active(ra, 2, first.RA) && Active(rb, 1, first.RB), "both real routers jointly nominate the first registered path");
Check(first.A.References == 1 && first.B.References == 1 && !first.A.Closed && !first.B.Closed, "ending Attempt/owner does not close the router's retained socket");
await Data(first.A);
// Rejected registrations retain caller ownership. Actual tuple uniqueness is
// checked across existing paths rather than trusting different logical IDs.
foreach (string reason in new[] { "tuple", "revision", "boot", "capability", "quality", "mtu" }) {
    var c = Context(); if (reason == "quality") c = c with { Profile = TraversalProfile.UdpDirect };
    using var candidate = new Resource { Peer = first.B.Local }; var reference = candidate.Retain(c);
    if (reason == "tuple") reference.Identity = reference.Identity with { ActualLocal = first.RA.Identity.ActualLocal, ActualRemote = first.RA.Identity.ActualRemote };
    if (reason == "boot") c = c with { LocalBootId = Guid.NewGuid() };
    if (reason == "mtu") reference.Identity = reference.Identity with { Qualification = PathQualification.Authenticated };
    bool refused = false;
    try { ra.RegisterPath(2, reference, c, reason == "revision" ? 1 : 2, TimeSpan.FromSeconds(5), reason == "capability" ? 0 : 1); }
    catch (IOException ex) { refused = reason switch {
        "tuple" => ex.Message.Contains("四元组"), "revision" => ex.Message.Contains("版本已过期"),
        "quality" => ex.Message.Contains("策略"), "mtu" => ex.Message.Contains("包长"), _ => ex.Message.Contains("成员身份") }; }
    Check(refused && candidate.References == 2 && !candidate.Closed, "registration rejects " + reason + " without stealing caller ownership");
    await reference.DisposeAsync();
}
Check(Active(ra, 2, first.RA) && !first.A.Closed, "negative candidates leave the healthy FakeTCP policy path untouched");

var nextContext = Context(); var next = Prepare(nextContext); bool blockConfirm = true; int dropped = 0;
next.B.Filter = packet => { if (blockConfirm && packet[4] == 7 && rb.Paths(1).Any(p => p.PathId == next.RB.Identity.PathId && p.Stage == NominationStage.Confirming)) { Interlocked.Increment(ref dropped); return false; } return true; };
Register(next, nextContext, 2);
await Until(() => dropped > 0, "actual candidate Confirm datagrams are suppressed by the test adapter");
await Task.Delay(300);
Check(Active(ra, 2, first.RA) && Active(rb, 1, first.RB) && !first.A.Closed && !first.B.Closed, "missing Confirm preserves both old active resources");
await Data(first.A);
blockConfirm = false;
await Until(() => Active(ra, 2, next.RA) && Active(rb, 1, next.RB), "confirmation retries converge and switch both actual routers");
int before = ab.Incoming.Count;
next.A.DuplicateDataThrough = first.A;
await Data(next.A); await Task.Delay(150);
Check(ab.Incoming.Count == before + 1, "old/new reception overlap delivers the same ciphertext only once");
next.A.DuplicateDataThrough = null;
await Task.Delay(2100);
Check(!first.A.Closed && !first.B.Closed, "old socket references remain available for rollback after receive grace ends");
ra.CancelPath(2, next.RA.Identity.PathId);
await Until(() => Active(ra, 2, first.RA) && Active(rb, 1, first.RB), "authenticated cancel restores the previous path on both routers");
await Until(() => next.A.Closed && next.B.Closed, "cancel releases only the losing candidate references");
await Data(first.A);

var finalContext = Context(); var final = Prepare(finalContext); Register(final, finalContext, 3, 1600);
await Until(() => Active(ra, 2, final.RA) && Active(rb, 1, final.RB), "higher nomination revision can select a fresh independent tuple");
await Until(() => first.A.Closed && first.B.Closed, "confirmed migration releases old resources after proof, grace and bounded rollback window", 5000);
await Data(final.A);
Check(ra.Paths(2).Length == 1 && rb.Paths(1).Length == 1, "retired and canceled resources leave the live path table");
int stable = ab.Incoming.Count;
aa.Outgoing.Add(Packet(b.LocalIp, a.LocalIp)); await Task.Delay(150);
Check(ab.Incoming.Count == stable, "managed router does not forward a different member's source packet");
await Until(() => ra.Paths(2).Single().RoundTripMs != null, "selected path records a nonce-matched same-resource round trip");
// One direction of authenticated application data and incoming peer pings keep
// arriving; only replies to our health probes are lost. This used to keep the
// receiver incorrectly healthy forever through LastReceive alone.
int arriving = aa.Incoming.Count; long repliesDropped = 0;
final.B.Filter = packet => { if (packet[4] == 6) { Interlocked.Increment(ref repliesDropped); return false; } return true; };
using (var feeding = new CancellationTokenSource()) {
    var reverseTraffic = Task.Run(async () => { try { while (true) { ab.Outgoing.Add(Packet(b.LocalIp, a.LocalIp)); await Task.Delay(200, feeding.Token); } } catch (OperationCanceledException) when (feeding.IsCancellationRequested) { } });
    try {
        await Until(() => !ra.Status().Single().Connected, "inbound-only activity cannot hide missing reverse-path proof", 15000);
        Check(aa.Incoming.Count >= arriving + 10 && repliesDropped >= 3 && rb.Status().Single().Connected,
            "negative case retained real authenticated reverse traffic and the other router's round trips");
        Check(!ra.Paths(2).Single().BidirectionalFresh && !final.A.Closed && !final.B.Closed,
            "stale health is observable without closing an otherwise owned resource in the router");
        final.B.Filter = null;
        await Until(() => ra.Status().Single().Connected && ra.Paths(2).Single().BidirectionalFresh,
            "a fresh authenticated same-path pong restores bidirectional health", 2500);
    } finally { feeding.Cancel(); await reverseTraffic; final.B.Filter = null; }
}
MeshIdentity.Revoke(a, 2); ra.ApplyDirectory(a.Directory!);
await Until(() => final.A.Closed && ra.Paths(2).Length == 0, "revocation stops the peer pump before releasing its resource");
await rb.DisposeAsync(); await ra.DisposeAsync();
Check(final.B.Closed && aa.Disposed && ab.Disposed, "shutdown releases remaining path references and packet adapters");
await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, routers = 2, realLoopbackSockets = true, recoveryRows,
    scope = "production MeshRouter/MeshLink/nomination with retained test UDP adapters; profile labels exercise policy only, no actual FakeTCP or Wintun", nativeDriver = false, realNat = false }, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"PASS {checks} managed Router checks. No installed service or driver changes.");
} catch (Exception ex) {
    await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, failure = ex.ToString() })); throw;
}

static byte[] Packet(string from, string to) {
    byte[] packet = new byte[1280]; packet[0] = 0x45; packet[8] = 64; packet[9] = 17;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 1280); IPAddress.Parse(from).GetAddressBytes().CopyTo(packet, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(packet, 16);
    uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), (ushort)~sum); return packet;
}
sealed class Adapter : IPacketAdapter {
    public readonly BlockingCollection<byte[]> Outgoing = new(); public readonly ConcurrentQueue<byte[]> Incoming = new(); public bool Disposed;
    public int Read(byte[] buffer) { if (!Outgoing.TryTake(out var packet, 50)) return 0; packet.CopyTo(buffer, 0); return packet.Length; }
    public bool Write(byte[] packet) { Incoming.Enqueue(packet); return true; }
    public void Dispose() { Disposed = true; Outgoing.Dispose(); }
}
sealed class Resource : IDisposable {
    readonly Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    readonly object gate = new(); int ownerDisposed; public int References = 1, Data; public bool Closed;
    public readonly Guid Id = Guid.NewGuid(); public IPEndPoint Peer = null!; public IPEndPoint Local { get; }
    public Func<byte[], bool>? Filter; public Resource? DuplicateDataThrough;
    public Resource() { socket.ExclusiveAddressUse = true; socket.Bind(new IPEndPoint(IPAddress.Loopback, 0)); socket.Blocking = false; Local = (IPEndPoint)socket.LocalEndPoint!; }
    public Reference Retain(TraversalAttemptContext c) { lock (gate) { References++; return new(this, new(Guid.NewGuid(), c.AttemptId, Id, null, Guid.NewGuid(), Local, Peer, c.Profile, PathQualification.MtuQualified)); } }
    public bool Send(ReadOnlySpan<byte> data) {
        byte[] packet = data.ToArray(); if (Filter?.Invoke(packet) == false) return true;
        if (packet[4] == 4) { Interlocked.Increment(ref Data); DuplicateDataThrough?.Send(packet); }
        try { return socket.SendTo(packet, Peer) == packet.Length; } catch (SocketException) { return false; }
    }
    public async ValueTask<ReadOnlyMemory<byte>> Receive(CancellationToken token) {
        for (;;) { byte[] buffer = new byte[2048]; var got = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), token);
            if (got.RemoteEndPoint.Equals(Peer)) return buffer.AsMemory(0, got.ReceivedBytes); }
    }
    public void Release() { lock (gate) { if (--References == 0) { Closed = true; socket.Dispose(); } } }
    public void Dispose() { if (Interlocked.Exchange(ref ownerDisposed, 1) == 0) Release(); }
}
sealed class Reference(Resource resource, ValidatedPathIdentity identity) : IMeshDatagramPath {
    int disposed;
    public ValidatedPathIdentity Identity { get; set; } = identity;
    public bool Failed => resource.Closed;
    public bool TrySend(ReadOnlySpan<byte> datagram) => resource.Send(datagram);
    public ValueTask<ReadOnlyMemory<byte>> Receive(CancellationToken token) => resource.Receive(token);
    public ValueTask DisposeAsync() { if (Interlocked.Exchange(ref disposed, 1) == 0) resource.Release(); return ValueTask.CompletedTask; }
}
