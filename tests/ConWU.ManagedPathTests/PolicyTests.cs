using System.Diagnostics;
using System.Text.Json;
using StreamLink.Core;

static class PolicyTests
{
    public static async Task Run(Action<bool, string> check)
    {
        void Reject(Action action, string why) {
            bool rejected = false; try { action(); } catch (FormatException) { rejected = true; }
            check(rejected, why);
        }
        var saved = JsonSerializer.Deserialize<DeviceProfile>("{\"Version\":2}")!;
        saved.Validate(); check(saved.PathSelection == "faketcp-only" && !saved.AllowUdpFallback, "missing policy fields default to fixed FakeTCP without automatic UDP fallback");
        var explicitOff = JsonSerializer.Deserialize<DeviceProfile>("{\"Version\":2,\"AllowUdpFallback\":false}")!;
        explicitOff.Validate(); check(!explicitOff.AllowUdpFallback,"explicit saved UDP refusal survives either edition's default");
        saved.AllowUdpFallback = true; saved.PathSelection = "faketcp-only";
        var restored = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(saved))!;
        restored.Validate(); check(!restored.Selection().Allows(TraversalProfile.UdpDirect), "persisted FakeTcpOnly overrides a previously enabled fallback checkbox");
        restored.TransportMode = "udp"; Reject(restored.Validate, "FakeTcpOnly rejects a contradictory UDP network configuration");
        restored.TransportMode = "faketcp"; restored.PathSelection = "auto-quality";
        Reject(restored.Validate, "AutoQuality cannot omit retained resources and explicit diagnostic consent");
        Reject(() => new PathSelection((PathPolicy)999).Validate(), "undefined enum cannot disable selection guards");
        new PathSelection(PathPolicy.AutoQuality,true).Validate();
        check(new PathSelection(PathPolicy.AutoQuality,true).Reject(TraversalProfile.UdpDirect,TraversalProfile.FakeTcpHttpSo,true)!=null,
            "AutoQuality enum alone cannot bypass healthy FakeTCP protection without a verified comparison vote");

        var a = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        foreach (var options in new[] { new PathSelection(), new PathSelection(PathPolicy.FakeTcpOnly, true), new PathSelection(PathPolicy.UdpOnly) }) {
            await using var router = new MeshRouter(a, new Adapter(), selection: options);
            var context = Context(a, b, router.BootId, Guid.NewGuid(), options.Policy==PathPolicy.UdpOnly?TraversalProfile.FakeTcpHttpSo:TraversalProfile.UdpDirect);
            using var resource = new Resource(); resource.Peer = resource.Local; var path = resource.Retain(context);
            bool denied = false;
            try { router.RegisterPath(2, path, context, 1, TimeSpan.FromSeconds(5), 1); }
            catch (IOException ex) { denied = ex.Message.Contains("策略"); }
            check(denied && resource.References == 2 && router.Paths(2).Length == 0, options.Policy + ": cold UDP cannot acquire router ownership without policy permission");
            await path.DisposeAsync();
        }
        // Real MeshLink/nomination packets on retained loopback sockets. FakeTCP
        // is a policy label in this fixture, not a native/NAT coverage claim.
        await using var ra = new MeshRouter(a, new Adapter(), selection: new(AllowUdpFallback: true));
        await using var rb = new MeshRouter(b, new Adapter(), selection: new(AllowUdpFallback: true));
        var originalContext = Context(a, b, ra.BootId, rb.BootId, TraversalProfile.FakeTcpHttpSo);
        var original = Pair(originalContext);
        Register(original, originalContext, 1);
        await Until(() => Active(ra, 2, original.Left) && Active(rb, 1, original.Right), "baseline policy path jointly selected");
        check(!ra.ReserveTraversal(2, TraversalProfile.FakeTcpHttpSo) && !ra.ReserveTraversal(2, TraversalProfile.UdpDirect),
            "background replacement reservation cannot displace healthy FakeTCP even with an allowed profile");
        original.A.Filter = original.B.Filter = p => p[4] != 6; // suppress only authenticated pong frames
        await Until(() => !ra.Status().Single().Connected && !rb.Status().Single().Connected, "both old-path round-trip proofs expire while resources stay owned", 15000);
        var nextContext = Context(a, b, ra.BootId, rb.BootId, TraversalProfile.UdpDirect); var next = Pair(nextContext);
        int suppressed = 0;
        next.B.Filter = p => {
            if (p[4] == 7 && rb.Paths(1).Any(s => s.PathId == next.Right.Identity.PathId && s.Stage == NominationStage.Confirming)) { Interlocked.Increment(ref suppressed); return false; }
            return true;
        };
        Register(next, nextContext, 2);
        await Until(() => suppressed > 0, "UDP reaches Confirm while the old path is unhealthy");
        original.A.Filter = original.B.Filter = null;
        await Until(() => ra.Status().Single().Connected && rb.Status().Single().Connected, "same FakeTCP resources recover before pending UDP confirmation");
        next.B.Filter = null;
        await Until(() => next.A.Closed && next.B.Closed, "policy recheck cancels UDP and converges on both routers without sending a stale Commit", 5000);
        check(Active(ra, 2, original.Left) && Active(rb, 1, original.Right) && !ra.Status().Single().Degraded && !rb.Status().Single().Degraded,
            "recovered healthy FakeTCP is retained at the actual switch boundary");

        async Task Until(Func<bool> condition, string why, int timeout = 4000) {
            var clock = Stopwatch.StartNew(); while (!condition()) { if (clock.ElapsedMilliseconds >= timeout) throw new TimeoutException(why); await Task.Delay(20); }
            check(true, why);
        }
        void Register((Resource A, Resource B, Reference Left, Reference Right) pair, TraversalAttemptContext c, long revision) {
            var remaining = TimeSpan.FromMilliseconds(c.Profile == TraversalProfile.UdpDirect ? TraversalLimits.UdpRoundMs : TraversalLimits.SoRoundMs);
            ra.RegisterPath(2, pair.Left, c, revision, remaining, 1);
            rb.RegisterPath(1, pair.Right, Reverse(c), revision, remaining, 1);
            pair.A.Dispose(); pair.B.Dispose();
        }
    }
    static bool Active(MeshRouter r, int slot, Reference p) => r.Paths(slot).Any(s => s.PathId == p.Identity.PathId && s.Active && s.Stage == NominationStage.Selected);
    static TraversalAttemptContext Context(MeshProfile a, MeshProfile b, Guid localBoot, Guid remoteBoot, TraversalProfile profile) =>
        new(a.Pair.Network, a.Self.Device, localBoot, b.Self.Device, remoteBoot, Guid.NewGuid(), Guid.NewGuid(), 1, Guid.NewGuid(), 1, profile, true, true, Guid.NewGuid());
    static TraversalAttemptContext Reverse(TraversalAttemptContext c) => c with { LocalNodeId = c.RemoteNodeId, RemoteNodeId = c.LocalNodeId,
        LocalBootId = c.RemoteBootId, RemoteBootId = c.LocalBootId, LocalCandidateId = c.RemoteCandidateId, RemoteCandidateId = c.LocalCandidateId, Nominator = false, ProtocolClient = false };
    static (Resource A, Resource B, Reference Left, Reference Right) Pair(TraversalAttemptContext c) {
        var a = new Resource(); var b = new Resource(); a.Peer = b.Local; b.Peer = a.Local;
        return (a, b, a.Retain(c), b.Retain(Reverse(c)));
    }
}
