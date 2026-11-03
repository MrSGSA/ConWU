namespace StreamLink.Core;

public sealed partial class MeshRouter
{
    // Reserve preparation, not the data plane. The peer can prepare SO before
    // our explicit-entry handshake arrives through its independent socket.
    public bool ReserveTraversal(int slot, TraversalProfile? replacement = null, bool standby = false)
    {
        lock (gate) {
            if (!peers.TryGetValue(slot, out var peer)) return false;
            if (standby) return replacement is {} kind && CanRetainStandby(slot, kind);
            // A healthy negotiated UDP path may keep transporting while one
            // FakeTCP candidate is prepared. No legacy ownership is displaced,
            // and retired references must converge before another candidate.
            if (Healthy(peer)) return replacement == TraversalProfile.FakeTcpHttpSo &&
                Selection.Allows(replacement.Value) && peer.Managed is { Candidate: null } managed &&
                managed.Paths.Count == 1 && managed.Active is { Identity.Profile: TraversalProfile.UdpDirect } active &&
                active.Nomination.Stage == NominationStage.Selected;
            if (peer.Managed != null) return peer.Managed.Paths.Count == 0;
            peer.TraversalReserved = true; return true;
        }
    }
    public bool ReleaseTraversalReservation(int slot)
    {
        lock (gate) {
            if (!peers.TryGetValue(slot, out var peer)) return true;
            if (peer.Managed?.Paths.Count > 0) return false;
            peer.TraversalReserved = false;
            peer.Managed = null; return true;
        }
    }
    // Only a fully qualified resource transfers the data plane to managed paths.
    public bool UsesManagedTransport(int slot)
    {
        lock(gate) return peers.TryGetValue(slot,out var peer)&&peer.Managed!=null;
    }
    public void DescribeTraversal(int slot, string name, string detail)
    {
        lock (gate) if (peers.TryGetValue(slot, out var peer)) { peer.Name = name; if (!Healthy(peer)) peer.Detail = detail; }
    }
}
