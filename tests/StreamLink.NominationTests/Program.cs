using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

int checks = 0; var rows = new List<object>();
void Check(bool value, string detail) { if (!value) throw new Exception(detail); checks++; }
TraversalAttemptContext Context() => new(Guid.NewGuid().ToString("N"), "A", Guid.NewGuid(), "B", Guid.NewGuid(), Guid.NewGuid(),
    Guid.NewGuid(), 1, Guid.NewGuid(), 1, TraversalProfile.FakeTcpHttpSo, true, true, Guid.NewGuid());
TraversalAttemptContext Reverse(TraversalAttemptContext c) => c with { LocalNodeId = c.RemoteNodeId, LocalBootId = c.RemoteBootId,
    RemoteNodeId = c.LocalNodeId, RemoteBootId = c.LocalBootId, LocalCandidateId = c.RemoteCandidateId, LocalCandidateVersion = c.RemoteCandidateVersion,
    RemoteCandidateId = c.LocalCandidateId, RemoteCandidateVersion = c.LocalCandidateVersion, ProtocolClient = !c.ProtocolClient, Nominator = !c.Nominator };
void Handshake(MeshLink a, MeshLink b) { var reply = b.Receive(a.Hello()); var confirm = a.Receive(reply.Reply!); b.Receive(confirm.Reply!); }
foreach (string mechanism in new[] { "normal", "lose-confirm-once", "lose-commit-once", "lose-ack-once", "all-confirm-lost", "all-commit-lost", "all-ack-lost", "wrong-actual-path", "mtu-unqualified" }) {
    for (int round = 0; round < 30; round++) {
        var time = new ManualTime(); var context = Context(); var other = Reverse(context);
        Check(PathNomination.ContextDigest(context).SequenceEqual(PathNomination.ContextDigest(other)), "canonical identities and opposite roles agree");
        var a = new PathNomination(context, Guid.NewGuid(), round + 1, TimeSpan.FromSeconds(8), mechanism != "mtu-unqualified", time);
        var b = new PathNomination(other, Guid.NewGuid(), round + 1, TimeSpan.FromSeconds(8), true, time);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var linkA = new MeshLink(1, 2, key); using var linkB = new MeshLink(2, 1, key); CryptographicOperations.ZeroMemory(key);
        Handshake(linkA, linkB);
        var wire = new Queue<(bool FromA, byte[] Plain)>(); bool dropped = false; int controls = 0, data = 0;
        bool fail = mechanism is "all-confirm-lost" or "all-commit-lost" or "all-ack-lost" or "wrong-actual-path" or "mtu-unqualified";
        for (int tick = 0; tick < 180; tick++) {
            foreach (var frame in a.Tick()) wire.Enqueue((true, frame));
            foreach (var frame in b.Tick()) wire.Enqueue((false, frame));
            while (wire.TryDequeue(out var message)) {
                controls++; if (controls > 512) throw new Exception("unbounded control loop");
                byte kind = message.Plain[4];
                byte lossKind = mechanism.Contains("confirm") ? (byte)4 : mechanism.Contains("commit") ? (byte)5 : mechanism.Contains("ack") ? (byte)6 : (byte)0;
                bool discard = kind == lossKind && (mechanism.StartsWith("all-") || !dropped);
                if (discard) { dropped = true; continue; }
                MeshLink sender = message.FromA ? linkA : linkB, receiver = message.FromA ? linkB : linkA;
                PathNomination target = message.FromA ? b : a;
                byte[] encoded = sender.Control(message.Plain)!;
                var received = receiver.Receive(encoded);
                Check(received.Control != null && received.Packet == null, "encrypted control is not an inner IP packet");
                Check(!receiver.Receive(encoded).Authenticated, "same control ciphertext cannot be delivered twice across paths");
                Guid actual = mechanism == "wrong-actual-path" ? Guid.NewGuid() : target.PathId;
                foreach (var reply in target.Receive(actual, received.Control)) wire.Enqueue((!message.FromA, reply));
            }
            // The existing session and data counter coexist with control. A lost
            // control packet never stalls a later authenticated data datagram.
            var packet = linkB.Receive(linkA.Data(new byte[1280])!);
            Check(packet.Packet?.Length == 1280, "full data datagram continues independently of candidate checks"); data++;
            if (!fail && a.PeerAdopted && b.PeerAdopted) break;
            time.Advance(50);
        }
        if (!fail) {
            Check(a.PeerAdopted && b.PeerAdopted && a.SwitchRequested && b.SwitchRequested, "both peers adopt the same confirmed nomination");
            if (mechanism != "normal") Check(dropped, "specified single-packet loss actually occurred");
        } else {
            Check(a.Stage == NominationStage.Cancelled && !a.SwitchRequested, "expired candidate cannot replace or keep the old path");
            Check(!b.SwitchRequested, "bounded cancellation converges receiver back to its retained old path");
            if (mechanism is "all-commit-lost" or "all-ack-lost") Check(a.NeedsResync, "incomplete commit explicitly records need for final-state resynchronization");
        }
        rows.Add(new { mechanism, round = round + 1, controls, data, dropped, elapsedMs = time.Milliseconds, a = a.Stage.ToString(), b = b.Stage.ToString() });
    }
    Console.WriteLine($"PASS {mechanism}: 30/30 authenticated control model rounds");
}
// Mutating any negotiated field changes the binding; a signed older candidate,
// replayed BootId or opposite role cannot silently become this current attempt.
var baseline = Context(); var clock = new ManualTime();
var source = new PathNomination(baseline, Guid.NewGuid(), 1, TimeSpan.FromSeconds(8), true, clock);
var reverse = Reverse(baseline);
var mutations = new[] { reverse with { NetworkId = "other" }, reverse with { LocalBootId = Guid.NewGuid() }, reverse with { RemoteBootId = Guid.NewGuid() },
    reverse with { AttemptId = Guid.NewGuid() }, reverse with { LocalCandidateVersion = 2 }, reverse with { RemoteCandidateVersion = 2 },
    reverse with { Profile = TraversalProfile.LegacyExplicit }, reverse with { ProtocolClient = !reverse.ProtocolClient }, reverse with { Nominator = !reverse.Nominator },
    reverse with { ValidationNonce = Guid.NewGuid() } };
byte[] hello = source.Tick().Single();
foreach (var mutation in mutations) {
    var target = new PathNomination(mutation, Guid.NewGuid(), 1, TimeSpan.FromSeconds(8), true, clock);
    Check(target.Receive(target.PathId, hello).Length == 0 && target.Stage == NominationStage.Checking, "mismatched context cannot authorize a path");
}
var cancelled = new PathNomination(reverse, Guid.NewGuid(), 1, TimeSpan.FromSeconds(8), true, clock); cancelled.Cancel();
Check(cancelled.Receive(cancelled.PathId, hello).Length == 0 && !cancelled.SwitchRequested, "late authenticated message never revives cancelled attempt");
var newer = new PathNomination(reverse, Guid.NewGuid(), 2, TimeSpan.FromSeconds(8), true, clock);
Check(newer.Receive(newer.PathId, hello).Length == 0, "older nomination revision cannot authorize the new revision");
var remaining = new PathNomination(reverse, Guid.NewGuid(), 1, TimeSpan.FromMilliseconds(200), true, clock);
clock.Advance(201); remaining.Tick();
Check(remaining.Stage == NominationStage.Cancelled, "nomination uses only the supplied remainder, not a fresh eight seconds");
byte[] sessionKey = RandomNumberGenerator.GetBytes(32);
using (var left = new MeshLink(1, 2, sessionKey))
using (var right = new MeshLink(2, 1, sessionKey)) {
    Check(left.Control(hello) == null, "control cannot precede authenticated MeshLink session");
    Handshake(left, right); byte[] stale = left.Control(hello)!;
    byte[] altered = left.Control(hello)!; altered[^1] ^= 1;
    Check(!right.Receive(altered).Authenticated, "altered nomination ciphertext is rejected before the state machine");
    using var restarted = new MeshLink(2, 1, sessionKey); Handshake(left, restarted);
    Check(!restarted.Receive(stale).Authenticated, "old receiver epoch cannot inject control after session restart");
}
CryptographicOperations.ZeroMemory(sessionKey);
string output = args.Length == 2 && args[0] == "--output" ? Path.GetFullPath(args[1]) : "nomination-results.json";
await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rounds = rows.Count,
    scope = "in-process authenticated MeshLink control models; no Router, native driver, NAT or Wintun proof", rows }, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"PASS {checks} checks in {rows.Count} model rounds; product path switching and resource references still require integration tests.");

sealed class ManualTime : TimeProvider
{
    public long Milliseconds;
    public override long TimestampFrequency => 1000;
    public override long GetTimestamp() => Milliseconds;
    public void Advance(int milliseconds) => Milliseconds += milliseconds;
}
