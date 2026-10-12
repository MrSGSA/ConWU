using System.Diagnostics;
using StreamLink.Core;

static class RecoveryTests
{
    static void Model(Action<bool, string> check)
    {
        PathRecovery New() { var r = new PathRecovery(0); r.Select(Guid.NewGuid(), 0); r.Health(true, 0); return r; }
        void Drive(PathRecovery r, long from, long to, long? lost = null, bool allow = true) {
            for (long at = from; at <= to; at += 100) {
                r.Business(at);
                if (!r.ProbeDue(at)) continue;
                if (!allow) { r.ProbeDeferred(); continue; }
                r.ProbeSent(at, at); if (at != lost) r.Pong(at, at + 16);
            }
        }
        for (int i = 0; i < 30; i++) {
            var r = New(); r.Pong(99, 99); r.Tick(3000);
            check(r.Snapshot(3000).FirstBusinessMs == null && !r.ProbeDue(3000), "idle/unknown pong cannot create business or fast-probe traffic");
            Drive(r, 3100, 6200); var s = r.Snapshot(6200);
            check(s.FirstBusinessMs == 3100 && s.StableBusinessStartMs == 3100 && s.StableBusinessConfirmedMs >= 6100 && s.ConsecutiveProbes >= 10,
                "three monotonic timestamps preserve first business, window start and later confirmation");
            int count = s.ConsecutiveProbes; r.Pong(3100, 6250);
            check(r.Snapshot(6250).ConsecutiveProbes == count && !r.ProbeDue(6600), "duplicate pong and completed window cannot extend proof or keep fast probing");
            r.Health(false, 7000); var reset = r.Snapshot(7000);
            check(reset.EpisodeId != s.EpisodeId && reset.FirstBusinessMs == null && reset.StableBusinessConfirmedMs == null,
                "loss of health after stable confirmation begins a separate recovery episode");
        }
        var lost = New(); Drive(lost, 100, 3000, lost: 100);
        check(lost.Snapshot(3000).FirstBusinessMs == 100 && lost.Snapshot(3000).StableBusinessConfirmedMs == null && lost.Snapshot(3000).WindowRestarts > 0,
            "a missing earlier probe prevents later replies from falsely proving uninterrupted recovery");
        Drive(lost, 3100, 5200); var later = lost.Snapshot(5200);
        check(later.FirstBusinessMs == 100 && later.StableBusinessStartMs >= 1100 && later.StableBusinessConfirmedMs >= later.StableBusinessStartMs + 3000,
            "recovered loss retains first success but reports the later stable interval");
        var idle = New(); Drive(idle, 100, 700); idle.Tick(2000); Drive(idle, 2100, 5300);
        check(idle.Snapshot(5300).FirstBusinessMs == 100 && idle.Snapshot(5300).StableBusinessStartMs == 2100,
            "idle application interval is not extrapolated into continuous business evidence");
        var denied = New(); Drive(denied, 100, 5000, allow: false); var budget = denied.Snapshot(5000);
        check(budget.ProbePackets == 0 && budget.BudgetDeferred > 0 && budget.StableBusinessConfirmedMs == null,
            "budget deferral is observable and is never counted as a successful round trip");
        var changed = New(); changed.Business(100); changed.ProbeDue(100); changed.ProbeSent(1, 100);
        Guid? originalPath = changed.Snapshot(100).PathId;
        Guid path = Guid.NewGuid(); changed.Select(path, 200); changed.Business(210); changed.Pong(1, 220);
        check(changed.Snapshot(220).PathId == path && changed.Snapshot(220).FirstBusinessPathId == originalPath && changed.Snapshot(220).ConsecutiveProbes == 0,
            "old-path nonce is invalidated on a real path identity change");
        changed.Break("BusinessSendRejected", 230);
        check(changed.Snapshot(230).StableBusinessConfirmedMs == null && changed.Snapshot(230).LastInterruption == "BusinessSendRejected",
            "failed business enqueue invalidates only recovery evidence, not transport ownership");
        var unhealthy = New(); unhealthy.Health(false, 0); Drive(unhealthy, 100, 4000);
        check(unhealthy.Snapshot(4000).StableBusinessConfirmedMs == null, "business and replies cannot override an unhealthy selected path");
        var quiet = New();
        for (long at = 100; at <= 13600; at += 1500) { quiet.KeepaliveSent(at, at); quiet.Pong(at, at + 16); quiet.Pong(at, at + 17); }
        var quietProof = quiet.Snapshot(13617);
        check(quietProof.StablePathStartMs == 100 && quietProof.StablePathConfirmedMs == 13616 && quietProof.PathProbes == 10 &&
            quietProof.FirstBusinessMs == null && quietProof.StableBusinessConfirmedMs == null && quietProof.ProbePackets == 0,
            "ten ordinary keepalives establish only StablePath; duplicate replies cannot fabricate samples or business");
        quiet.Health(false, 15000); var quietLost = quiet.Snapshot(15000);
        check(quietLost.EpisodeId != quietProof.EpisodeId && quietLost.StablePathConfirmedMs == null && quietLost.FirstBusinessMs == null,
            "idle path health loss starts another episode without inventing a business recovery");
        var missed = New(); missed.KeepaliveSent(1, 100); missed.KeepaliveSent(2, 1600); missed.Pong(1, 1610); missed.Pong(2, 1616);
        check(missed.Snapshot(1616).PathProbes == 1, "expired keepalive cannot be revived by a late reply");
        for (long at = 3100; at <= 13600; at += 1500) { missed.KeepaliveSent(at, at); missed.Pong(at, at + 16); }
        check(missed.Snapshot(13616).StablePathConfirmedMs == null, "a missing ordinary reply prevents premature idle path confirmation");
        missed.KeepaliveSent(15100, 15100); missed.Pong(15100, 15116);
        check(missed.Snapshot(15116).StablePathStartMs == 1600, "idle path start excludes the missing initial round trip");
        var quietChange = New(); quietChange.KeepaliveSent(1, 100); quietChange.Select(Guid.NewGuid(), 200); quietChange.Pong(1, 220);
        check(quietChange.Snapshot(220).PathProbes == 0, "retired path keepalive cannot validate the replacement path");
        var paused = New(); paused.KeepaliveSent(1, 100); paused.Pong(1, 116); paused.Tick(4000);
        check(paused.Snapshot(4000).PathProbes == 0 && paused.Snapshot(4000).PathWindowRestarts == 1,
            "a long scheduler or maintenance-budget gap cannot be extrapolated into an uninterrupted idle path");
        var quietUnhealthy = New(); quietUnhealthy.Health(false, 0);
        for (long at = 100; at <= 13600; at += 1500) { quietUnhealthy.KeepaliveSent(at, at); quietUnhealthy.Pong(at, at + 16); }
        check(quietUnhealthy.Snapshot(13616).StablePathConfirmedMs == null, "keepalive evidence cannot override actual path health");
    }
    public static async Task<object[]> Run(Action<bool, string> check, Func<string, string, byte[]> packet)
    {
        Model(check); var rows = new List<object>();
        foreach (bool managed in new[] { false, true }) {
            var a = MeshIdentity.Create("https://example.com/", "", "faketcp");
            var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
            var aa = new Adapter(); var ab = new Adapter();
            await using var ra = new MeshRouter(a, aa); await using var rb = new MeshRouter(b, ab);
            using var left = new Resource(); using var right = new Resource(); left.Peer = right.Local; right.Peer = left.Local;
            if (managed) {
                var c = new TraversalAttemptContext(a.Pair.Network, a.Self.Device, ra.BootId, b.Self.Device, rb.BootId, Guid.NewGuid(),
                    Guid.NewGuid(), 1, Guid.NewGuid(), 1, TraversalProfile.FakeTcpHttpSo, true, true, Guid.NewGuid());
                var reverse = c with { LocalNodeId = c.RemoteNodeId, LocalBootId = c.RemoteBootId, RemoteNodeId = c.LocalNodeId, RemoteBootId = c.LocalBootId,
                    LocalCandidateId = c.RemoteCandidateId, RemoteCandidateId = c.LocalCandidateId, ProtocolClient = false, Nominator = false };
                ra.RegisterPath(2, left.Retain(c), c, 1, TimeSpan.FromSeconds(8), 1);
                rb.RegisterPath(1, right.Retain(reverse), reverse, 1, TimeSpan.FromSeconds(8), 1);
                left.Dispose(); right.Dispose();
            } else { ra.SetCandidate(2, rb.LocalEndpoint, "b", ""); rb.SetCandidate(1, ra.LocalEndpoint, "a", ""); }
            async Task Until(Func<bool> condition, int ms = 10000) {
                var clock = Stopwatch.StartNew(); while (!condition()) { if (clock.ElapsedMilliseconds >= ms) throw new Exception("recovery fixture timeout managed=" + managed); await Task.Delay(20); }
            }
            await Until(() => ra.Status().Single().Connected && rb.Status().Single().Connected);
            await Task.Delay(400);
            check(ra.Status().Single().Recovery!.FirstBusinessMs == null && rb.Status().Single().Recovery!.ProbePackets == 0,
                $"formal {(managed ? "managed" : "legacy")} routers stay idle after handshake without inventing business");
            if (managed) { var invalid = new byte[128]; invalid[4] = 4; right.Send(invalid); await Task.Delay(150);
                check(ra.Status().Single().Recovery!.FirstBusinessMs == null, "unauthenticated same-source packet is not first business"); }
            long idleDrops = 0;
            if (managed) {
                right.Filter = p => { if (p[4] == 6) { Interlocked.Increment(ref idleDrops); return false; } return true; };
                await Task.Delay(4100);
                check(idleDrops >= 2 && ra.Status().Single().Recovery!.StablePathConfirmedMs == null,
                    "real idle path with missing keepalive replies is not reported stable");
                right.Filter = null;
            }
            await Until(() => ra.Status().Single().Recovery!.StablePathConfirmedMs != null && rb.Status().Single().Recovery!.StablePathConfirmedMs != null, 22000);
            var idleProof = ra.Status().Single().Recovery!;
            check(idleProof.PathProbes >= 10 && idleProof.StablePathStartMs < idleProof.StablePathConfirmedMs &&
                idleProof.FirstBusinessMs == null && idleProof.StableBusinessConfirmedMs == null && idleProof.ProbePackets == 0 && aa.Incoming.Count == 0,
                "real ordinary keepalives establish StablePath without extra probes, inner business packets or QoS claims");
            long dropped = 0;
            if (managed) right.Filter = p => { if (p[4] == 6) { Interlocked.Increment(ref dropped); return false; } return true; };
            using var feeding = new CancellationTokenSource();
            var traffic = Task.Run(async () => {
                try { while (true) { aa.Outgoing.Add(packet(a.LocalIp, b.LocalIp)); ab.Outgoing.Add(packet(b.LocalIp, a.LocalIp)); await Task.Delay(100, feeding.Token); } }
                catch (OperationCanceledException) when (feeding.IsCancellationRequested) { }
            });
            try {
                await Until(() => ra.Status().Single().Recovery!.FirstBusinessMs != null && rb.Status().Single().Recovery!.FirstBusinessMs != null);
                long first = ra.Status().Single().Recovery!.FirstBusinessMs!.Value;
                if (managed) {
                    await Task.Delay(4100); var interrupted = ra.Status().Single().Recovery!;
                    check(dropped >= 5 && interrupted.StableBusinessConfirmedMs == null && interrupted.WindowRestarts > 0 && aa.Incoming.Count > 20,
                        "real authenticated IP continues but lost same-path probe replies forbid stable confirmation");
                    right.Filter = null;
                }
                await Until(() => ra.Status().Single().Recovery!.StableBusinessConfirmedMs != null && rb.Status().Single().Recovery!.StableBusinessConfirmedMs != null);
                var s = ra.Status().Single().Recovery!;
                check(s.FirstBusinessMs == first && s.StableBusinessConfirmedMs >= s.StableBusinessStartMs + 3000 && s.ConsecutiveProbes >= 10,
                    "formal router reports distinct timestamps only after actual bidirectional probes and accepted IP");
                if (managed) check(s.StableBusinessStartMs > first + 2000, "first success is preserved while stable start excludes the actual interruption");
                int sent = s.ProbePackets; await Task.Delay(650);
                check(ra.Status().Single().Recovery!.ProbePackets == sent, "completed recovery stops additional fast probes and leaves ordinary keepalive running");
                rows.Add(new { managed, receivedIpPackets = aa.Incoming.Count, suppressedProbeReplies = dropped, snapshot = s, idleSnapshot = idleProof, idleSuppressedReplies = idleDrops,
                    scope = "real loopback UDP + production MeshRouter/MeshLink; memory IP adapters; no native/Wintun/NAT" });
            } finally { feeding.Cancel(); await traffic; right.Filter = null; }
        }
        return rows.ToArray();
    }
}
