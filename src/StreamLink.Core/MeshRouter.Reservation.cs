namespace StreamLink.Core;

public sealed partial class MeshRouter
{
    // A runner must stop its obsolete legacy client when taking this reservation.
    // A healthy legacy path is never displaced to make room for an experiment.
    public bool ReserveTraversal(int slot)
    {
        lock (gate) {
            if (!peers.TryGetValue(slot, out var peer) || Healthy(peer)) return false;
            if (peer.Managed != null) return peer.Managed.Paths.Count == 0;
            peer.Active = null; peer.Candidate = null; peer.Probes.Clear(); peer.Retired.Clear();
            peer.Managed = new(); return true;
        }
    }
    public bool ReleaseTraversalReservation(int slot)
    {
        lock (gate) {
            if (!peers.TryGetValue(slot, out var peer)) return true;
            if (peer.Managed?.Paths.Count > 0) return false;
            peer.Managed = null; return true;
        }
    }
    public void DescribeTraversal(int slot, string name, string detail)
    {
        lock (gate) if (peers.TryGetValue(slot, out var peer)) { peer.Name = name; if (!Healthy(peer)) peer.Detail = detail; }
    }
}
