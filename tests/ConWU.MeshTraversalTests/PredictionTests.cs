using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

static class PredictionTests
{
    public static async Task Run(Action<bool, string> check)
    {
        void Reject(Action a, string why) { bool rejected = false; try { a(); } catch (Exception e) when (e is IOException or FormatException or CryptographicException or InvalidOperationException) { rejected = true; } check(rejected, why); }
        var a = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var ca = new MeshTraversalCapabilities(1, 1, Guid.NewGuid(), [TraversalProfile.FakeTcpHttpSo], TcpPrediction: 1);
        var cb = ca with { BootId = Guid.NewGuid() }; long sa = 0, sb = 0;
        MeshTraversalCandidate Reserve(bool stable, string ep) => new(Guid.NewGuid(), 1, ep, "192.0.2.9:3478",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(), DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(),
            CandidatePurpose.SimultaneousOpen, new(Guid.NewGuid(), stable, ""));
        MeshTraversalCandidate Final(MeshTraversalCandidate r, string ports) => r with { Version = 2,
            Endpoint = new IPEndPoint(IPEndPoint.Parse(r.Endpoint).Address, int.Parse(ports.Split(',')[0])).ToString(),
            ObservedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Expires = DateTimeOffset.UtcNow.AddSeconds(8).ToUnixTimeSeconds(),
            Prediction = r.Prediction! with { Ports = ports } };
        var ra = Reserve(true, "192.0.2.1:40000"); var rb = Reserve(false, "192.0.2.2:41000");
        await using (var ordinary = MeshTraversalAttempt.Offer(a, b.Self, ca, cb, TraversalProfile.FakeTcpHttpSo, ra with { Prediction = null }, 1, () => ++sa)) {
            var m = ordinary.Outbound!; var c = m.Candidate!;
            byte[] legacy = JsonSerializer.SerializeToUtf8Bytes(new { domain = "streamlink-traversal-state-v1", network = a.Pair.Network,
                m.Version, m.MessageId, m.FromSlot, m.FromDevice, m.FromBoot, m.ToSlot, m.ToDevice, m.ToBoot, m.Sequence,
                m.AttemptId, m.NominationRevision, m.ValidationNonce, m.Profile, m.ProtocolClientSlot, m.NominatorSlot,
                Candidate = new { c.Id, c.Version, c.Endpoint, c.ObservationTarget, c.ObservedAt, c.Expires, c.Purpose },
                PeerCandidate = (object?)null, m.Stage, m.Expires });
            check(SHA256.HashData(legacy).SequenceEqual(MeshTraversal.Fingerprint(a.Pair.Network, m)), "ordinary candidate signing bytes remain identical to the prior protocol");
            check(!JsonSerializer.Serialize(ca with { TcpPrediction = 0 }).Contains("TcpPrediction"), "absent prediction capability is omitted for old peers");
            Reject(() => MeshTraversal.Sign(a, m with { Stage = MeshTraversalStage.Measure }), "ordinary candidates cannot use prediction control stages");
        }
        Reject(() => MeshTraversalAttempt.Offer(a, b.Self, ca, cb with { TcpPrediction = 0 }, TraversalProfile.FakeTcpHttpSo, ra, 1, () => ++sa), "prediction requires bilateral advertised capability");
        foreach (string invalid in new[] { "01024", "1023", "65536", "40001,40000", "40000,40000", "40000,,40001", "40000 ", "-1", "1,2,3,4,5,6,7,8,9" })
            Reject(() => MeshTcpPrediction.Ports(new(Guid.NewGuid(), false, invalid)), "noncanonical or unbounded port window rejected: " + invalid);
        Reject(() => MeshTcpPrediction.Ports(new(Guid.NewGuid(), true, "40000,40001")), "stable-side model cannot advertise a changing source window");
        Reject(() => MeshTcpPrediction.Validate(Final(ra, "40000") with { Endpoint = "[2001:db8::1]:40000" }, TraversalProfile.FakeTcpHttpSo), "IPv6 is not silently included in IPv4 prediction");
        Reject(() => MeshTcpPrediction.Validate(Final(ra, "40000"), TraversalProfile.UdpDirect), "TCP observation cannot authorize UDP prediction");
        Reject(() => MeshTcpPrediction.Validate(Final(ra, "40000") with { Expires = DateTimeOffset.UtcNow.AddSeconds(9).ToUnixTimeSeconds() }, TraversalProfile.FakeTcpHttpSo), "prediction metadata cannot extend beyond a handshake-sized publication lifetime");
        var good = Final(rb, "41007,41014");
        check(MeshTcpPrediction.Upgrades(rb, good), "reservation accepts its own final model and public address");
        check(!MeshTcpPrediction.Upgrades(rb, good with { Id = Guid.NewGuid() }) &&
            !MeshTcpPrediction.Upgrades(rb, good with { Endpoint = "192.0.2.3:41007" }) &&
            !MeshTcpPrediction.Upgrades(rb, good with { Prediction = good.Prediction! with { ModelId = Guid.NewGuid() } }), "model, candidate and public IP cannot change during measurement");
        await using (var leader = MeshTraversalAttempt.Offer(a, b.Self, ca, cb, TraversalProfile.FakeTcpHttpSo, ra, 2, () => ++sa)) {
            await using var follower = MeshTraversalAttempt.Answer(b, a.Self, cb, ca, leader.Outbound!, rb, () => ++sb);
            check(follower.Phase == MeshAttemptPhase.Reserving && follower.Outbound == null, "prediction Answer does not claim resource readiness");
            Reject(() => follower.Reserved(false), "unarmed source cannot publish Reserved");
            follower.Reserved(true); leader.Receive(follower.Outbound!);
            var measure = leader.Outbound!;
            check(measure.Stage == MeshTraversalStage.Measure && leader.PredictionBegan == 0, "leader waits for publication acknowledgment before starting the shared clock");
            leader.BeginMeasurement(); follower.Receive(measure); long began = follower.PredictionBegan;
            var replay = MeshTraversal.Sign(a, measure with { MessageId = Guid.NewGuid(), Sequence = ++sa });
            follower.Receive(replay); check(follower.PredictionBegan == began, "repeated Measure never restarts the shared deadline");
            follower.Measured(Final(rb, "41007,41014")); leader.Receive(follower.Outbound!);
            leader.Measured(Final(ra, "40000")); follower.Receive(leader.Outbound!);
            check(leader.Phase == MeshAttemptPhase.Preparing && follower.Phase == MeshAttemptPhase.Preparing, "both authenticated final windows are required for Prepare");
            leader.Prepared(new Prepared(leader.Context)); check(leader.Phase == MeshAttemptPhase.AwaitReady && leader.Outbound!.Stage == MeshTraversalStage.Measured, "fast leader preparation cannot skip remote readiness");
            follower.Prepared(new Prepared(follower.Context)); leader.Receive(follower.Outbound!);
            check(leader.Outbound!.Stage == MeshTraversalStage.Start && follower.Receive(leader.Outbound), "matching final Ready releases prepared leader and follower exactly once");
            check(PathNomination.ContextDigest(leader.Context).SequenceEqual(PathNomination.ContextDigest(follower.Context)), "prediction versions bind the same in-path nomination context");
            follower.Cancel(); check(!follower.Receive(leader.Outbound), "late predicted Start cannot revive cancellation");
        }
        // A mailbox may replace Measured by Ready before the leader polls.
        await using (var leader = MeshTraversalAttempt.Offer(a, b.Self, ca, cb, TraversalProfile.FakeTcpHttpSo, ra, 3, () => ++sa)) {
            await using var follower = MeshTraversalAttempt.Answer(b, a.Self, cb, ca, leader.Outbound!, rb, () => ++sb);
            follower.Reserved(true); leader.Receive(follower.Outbound!); follower.Receive(leader.Outbound!); leader.BeginMeasurement();
            leader.Measured(Final(ra, "40000")); follower.Receive(leader.Outbound!); follower.Measured(Final(rb, "41007,41014"));
            follower.Prepared(new Prepared(follower.Context)); leader.Receive(follower.Outbound!);
            check(leader.Phase == MeshAttemptPhase.Preparing && MeshTcpPrediction.Final(leader.RemoteCandidate), "coalesced Ready supplies and authenticates the skipped remote Measured state");
            leader.Prepared(new Prepared(leader.Context)); check(follower.Receive(leader.Outbound!), "coalesced final states still complete the normal Start transition");
            var modified = MeshTraversal.Sign(b, follower.Outbound! with { MessageId = Guid.NewGuid(), Sequence = ++sb,
                Candidate = follower.Outbound!.Candidate! with { Prediction = rb.Prediction! with { Ports = "41007,41021" } } });
            Reject(() => leader.Receive(modified), "same final version cannot alter the port authorization after Prepare");
        }
        await using (var leader = MeshTraversalAttempt.Offer(a, b.Self, ca, cb, TraversalProfile.FakeTcpHttpSo, ra with { Prediction = ra.Prediction! with { StableModel = false } }, 4, () => ++sa)) {
            Reject(() => MeshTraversalAttempt.Answer(b, a.Self, cb, ca, leader.Outbound!, rb, () => ++sb), "two unstable models are rejected before either publishes Ready");
        }
    }
}
