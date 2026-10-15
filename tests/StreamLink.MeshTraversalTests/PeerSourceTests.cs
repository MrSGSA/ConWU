using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

static class PeerSourceTests
{
    public static async Task Run(Action<bool, string> check)
    {
        void Reject(Action action, string why) { bool failed = false; try { action(); } catch (Exception e) when (e is FormatException or CryptographicException or ArgumentException) { failed = true; } check(failed, why); }
        var a = MeshIdentity.Create("https://example.com/", "", "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var ca = new MeshTraversalCapabilities(1, 1, Guid.NewGuid(), [TraversalProfile.FakeTcpHttpSo], TcpPeerReflexive: 1); var cb = ca with { BootId = Guid.NewGuid() };
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), sa = 0, sb = 0;
        var candidate = new MeshTraversalCandidate(Guid.NewGuid(), 1, "192.0.2.1:40000", "192.0.2.9:3478", now, now + 120,
            CandidatePurpose.SimultaneousOpen, PeerReflexive: true);
        await using var leader = MeshTraversalAttempt.Offer(a, b.Self, ca, cb, TraversalProfile.FakeTcpHttpSo, candidate, 1, () => ++sa);
        var offer = leader.Outbound!; MeshTraversalAttempt.ValidateOffer(b, a.Self, cb, ca, offer);
        check(true, "source-aware IPv4 Offer is covered by bilateral capabilities and the normal member signature");
        Reject(() => MeshTraversal.Verify(a.Pair.Network, a.Self, b.Self, offer with { Candidate = candidate with { PeerReflexive = false } }),
            "signature binds source-learning permission, not just address and port");
        Reject(() => MeshTraversalAttempt.ValidateOffer(b, a.Self, cb with { TcpPeerReflexive = 0 }, ca, offer), "local absent capability rejects source-aware Offer before allocation");
        Reject(() => MeshTraversalAttempt.ValidateOffer(b, a.Self, cb, ca with { TcpPeerReflexive = 0 }, offer), "remote absent capability rejects source-aware Offer before allocation");
        foreach (var invalid in new[] { candidate with { Endpoint = "[2001:db8::1]:40000", ObservationTarget = null },
            candidate with { Prediction = new(Guid.NewGuid(), true, "") } })
            Reject(() => MeshTraversal.Sign(a, offer with { Candidate = invalid }), "IPv6 and prediction windows cannot claim IPv4 source-learning permission");
        Reject(() => MeshTraversal.Sign(a, offer with { Profile = TraversalProfile.UdpDirect, Candidate = candidate with { Purpose = CandidatePurpose.UdpDirect } }), "TCP source learning cannot authorize a UDP candidate");
        Reject(() => MeshTraversal.ValidateCapabilities(ca with { TcpPeerReflexive = 2 }), "source capability rejects unknown versions");
        Reject(() => MeshTraversal.ValidateCapabilities(ca with { NativeAbi = 0, Profiles = [TraversalProfile.UdpDirect] }), "UDP-only metadata cannot advertise TCP source learning");
        check(!JsonSerializer.Serialize(ca with { TcpPeerReflexive = 0 }).Contains("TcpPeerReflexive") &&
            !JsonSerializer.Serialize(candidate with { PeerReflexive = false }).Contains("PeerReflexive"), "ordinary signing and old metadata omit inactive source extension fields");
        var ordinaryCaps = ca with { TcpPeerReflexive = 0 }; var ordinaryPeer = cb with { TcpPeerReflexive = 0 };
        await using var ordinary = MeshTraversalAttempt.Offer(a, b.Self, ordinaryCaps, ordinaryPeer, TraversalProfile.FakeTcpHttpSo, candidate with { PeerReflexive = false }, 2, () => ++sa);
        var ready = MeshTraversal.Sign(b, new(1, Guid.NewGuid(), b.Self.Slot, b.Self.Device, cb.BootId, a.Self.Slot, a.Self.Device, ca.BootId,
            ++sb, ordinary.AttemptId, ordinary.Outbound!.NominationRevision, ordinary.Outbound.ValidationNonce, TraversalProfile.FakeTcpHttpSo,
            a.Self.Slot, a.Self.Slot, candidate with { Id = Guid.NewGuid(), Endpoint = "192.0.2.2:41000" }, ordinary.Outbound.Candidate,
            MeshTraversalStage.Ready, now + 55, ""));
        Reject(() => ordinary.Receive(ready), "even a valid signed Ready cannot introduce source learning after an ordinary unnegotiated Offer");
        var profile = new DeviceProfile { TcpPeerReflexive = true, TraversalMode = "legacy" };
        Reject(profile.Validate, "explicit legacy mode cannot save a silently ineffective source-learning option");
        profile.TraversalMode = "tcp"; profile.Validate(); check(true, "explicit TCP mode accepts the opt-in configuration");
        check(!new DeviceProfile().TcpPeerReflexive, "existing and new profiles keep source learning disabled by default");
    }
}
