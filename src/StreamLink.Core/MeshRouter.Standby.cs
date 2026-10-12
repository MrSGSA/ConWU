namespace StreamLink.Core;

public sealed record MeshStandbyStatus(Guid PathId, Guid ResourceId, TraversalProfile Profile, bool Ready,
    bool BidirectionalFresh, long RemainingMs, string Qualification = "QualityUnknown");

public sealed partial class MeshRouter
{
    static MeshStandbyStatus? StandbyStatus(Peer peer) => peer.Managed?.Candidate is {} path && path.Nomination.Stage == NominationStage.Standby
        ? new(path.Identity.PathId,path.Identity.LeaseId,path.Identity.Profile,path.Nomination.StandbyConfirmed,
            RoundTripFresh(path),Math.Max(0,(long)path.Nomination.TimeLeft.TotalMilliseconds)) : null;
    internal bool CanRetainStandby(int slot, TraversalProfile profile)
    {
        lock (gate) return peers.TryGetValue(slot, out var peer) && ManagedHealthy(peer) && Selection.Allows(profile) &&
            peer.Managed is { Candidate: null } managed && managed.Paths.Count == 1 &&
            managed.Active?.Nomination.Stage == NominationStage.Selected;
    }
    // Caller must supply policy/quality approval; retention is not approval.
    // No switch happens here: the in-path nominator/confirm/commit exchange
    // still determines promotion and can preserve/restore the old Active.
    internal bool ApproveStandbySelection(int slot, Guid pathId)
    {
        lock (gate) {
            if (!peers.TryGetValue(slot,out var peer) || peer.Managed?.Candidate is not {} path || path.Identity.PathId != pathId ||
                path.Closing || path.Transport.Failed || !RoundTripFresh(path) || !path.Nomination.StandbyConfirmed || path.Nomination.Stage != NominationStage.Standby)
                return false;
            if (Selection.Reject(path.Identity.Profile,peer.Managed.Active?.Identity.Profile,ManagedHealthy(peer)) != null) return false;
            path.Nomination.AllowStandbySelection();
            _ = path.Nomination.SelectStandby(); return true;
        }
    }
}
