using StreamLink.Core;

namespace StreamLink.Service;

internal sealed partial class MeshTraversalManager
{
    readonly Dictionary<int, (Guid Path, long Since)> activeSince = [];
    readonly Dictionary<int, long> standbyNext = [];
    bool StandbyDue(int slot, TraversalProfile kind, MeshTraversalCapabilities? remote) =>
        discovery.SupportsStandbyPaths && Capabilities.StandbyPaths == 1 && remote is { StandbyPaths: 1 } &&
        remote.Profiles.Contains(kind) && Capabilities.Profiles.Contains(kind) && factory.SupportsStandbyProfile(kind) &&
        activeSince.TryGetValue(slot, out var active) && Environment.TickCount64 - active.Since >= TraversalLimits.UpgradeResidenceMs &&
        Environment.TickCount64 >= standbyNext.GetValueOrDefault(slot) && router.CanRetainStandby(slot, kind);
    TraversalProfile? StandbyProfile(int slot, MeshTraversalCapabilities remote)
    {
        // Prefer an independent protocol if allowed. This does not grant UDP
        // permission to displace a healthy FakeTCP, or approve a quality switch.
        var active = router.Paths(slot).FirstOrDefault(p => p.Active)?.Profile;
        TraversalProfile[] order = active == TraversalProfile.FakeTcpHttpSo
            ? [TraversalProfile.UdpDirect, TraversalProfile.FakeTcpHttpSo]
            : [TraversalProfile.FakeTcpHttpSo, TraversalProfile.UdpDirect];
        foreach (var kind in order) if (StandbyDue(slot, kind, remote)) return kind;
        return null;
    }
}
