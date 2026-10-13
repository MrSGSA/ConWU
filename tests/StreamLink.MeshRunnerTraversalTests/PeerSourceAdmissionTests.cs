using System.Net;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

static class PeerSourceAdmissionTests
{
    public static async Task Run(string binary, string root, Action<bool, string> check, CancellationToken token)
    {
        var mesh = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var peers = Enumerable.Range(0, 7).Select(_ => MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(mesh))).Self).ToArray();
        var config = new DeviceProfile { Mesh = mesh, TraversalMode = "tcp", TcpPeerReflexive = true, TcpStun = ["fixture.invalid:3478"] };
        var wire = new PeerSourceNatWire(0); await using var helper = new Reflector { MapForTest = wire.Reflect };
        int resolved = 0; var cacheTime = new CacheTime();
        await using var factory = new MeshCandidateFactory(config, binary, root, [TraversalProfile.FakeTcpHttpSo], captureBroker: true, wireControl: true, peerSourceNative: true) {
            ResolveTarget = (_, _, _) => { resolved++; return Task.FromResult(helper.Endpoint); }, RouteCheckForTest = (_, _, _) => { }, OpenCaptureForTest = (local, _) => wire.Open(0, local),
            EndpointTimeForTest = cacheTime
        };
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var remote = new MeshTraversalCandidate(Guid.NewGuid(), 1, "192.0.2.20:40000", null, now, now + 120, CandidatePurpose.SimultaneousOpen, PeerReflexive: true);
        async Task Reject(bool allowed, TraversalProfile profile, MeshTraversalCandidate offered, string why) {
            bool rejected = false; try { await using var r = await factory.GatherSourceAware(peers[0], profile, Guid.NewGuid(), false, offered, 1, false, allowed, token); } catch (IOException) { rejected = true; }
            check(rejected && resolved == 0 && helper.Accepted == 0 && wire.Ios.Length == 0, why);
        }
        await Reject(false, TraversalProfile.FakeTcpHttpSo, remote, "missing coordinator/bilateral source permission fails before DNS, helper or capture");
        await Reject(true, TraversalProfile.UdpDirect, remote, "source-aware remote request cannot switch into UDP gathering");
        await Reject(true, TraversalProfile.FakeTcpHttpSo, remote with { Endpoint = "[2001:db8::1]:40000" }, "IPv6 source permission fails before any gathering");
        await Reject(true, TraversalProfile.FakeTcpHttpSo, remote with { Prediction = new(Guid.NewGuid(), true, "") }, "source learning and prediction windows cannot share authorization");
        config.TcpPeerReflexive = false; await Reject(true, TraversalProfile.FakeTcpHttpSo, remote, "local opt-out refuses an otherwise signed source request before allocation"); config.TcpPeerReflexive = true;
        var resources = await Task.WhenAll(peers.Select(p => factory.GatherSourceAware(p, TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), false, null, 1, false, true, token)));
        try {
            check(helper.Accepted == 7 && helper.Requests == 7 && wire.Ios.Length == 7 &&
                resources.All(r => r.Candidate.PeerReflexive) && resources.Select(r => r.Candidate.Endpoint).Distinct().Count() == 7,
                "all seven authenticated peer identities get distinct real held TCP sources under the same reflection target");
            await using var same = await factory.GatherSourceAware(peers[0], TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), false, null, 1, false, true, token);
            check(same.Candidate.Endpoint == resources[0].Candidate.Endpoint && helper.Accepted == 7 && helper.Requests == 7,
                "a duplicate peer request reuses only its own partition and coalesces the recent query");
            cacheTime.Advance(2000);
            await using var fresh = await factory.GatherSourceAware(peers[0], TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), false, null, 1, false, true, token);
            check(fresh.Candidate.Endpoint == resources[0].Candidate.Endpoint && helper.Accepted == 7 && helper.Requests == 8 && wire.Ios.Length == 7,
                "at cache expiry this peer reobserves its own held source, without a new bind or another peer's partition");
        } finally { foreach (var resource in resources) await resource.DisposeAsync(); }
        await factory.DisposeAsync();
        check(wire.Ios.All(io => io.Closed), "partitioned source collection releases every helper/capture after candidate owners end");
    }
    // This test covers partition ownership and both sides of cache expiry;
    // seven real helper queries need not finish in two wall-clock seconds.
    // Only the pool's age is controlled. Socket I/O, UTC and timeouts stay real.
    sealed class CacheTime : TimeProvider
    {
        long milliseconds;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => milliseconds;
        public void Advance(int delta) => milliseconds += delta;
    }
}
