using System.Security.Cryptography;

namespace StreamLink.Core;

public sealed partial class MeshRouter
{
    void TickRecovery(Peer peer, long now)
    {
        var active = peer.Managed?.Active;
        bool owned = peer.Managed == null ? peer.Active != null && peer.LegacyPathId != Guid.Empty
            : active is { Closing: false, ProofAt: not 0 };
        if (owned) peer.Recovery.Select(active?.Identity.PathId ?? peer.LegacyPathId, now);
        peer.Recovery.Health(owned && Healthy(peer), now);
        peer.Recovery.Tick(now);
        if (!owned || !peer.Recovery.ProbeDue(now)) return;
        long nonce = BitConverter.ToInt64(RandomNumberGenerator.GetBytes(8));
        byte[]? ping = peer.Link.ProbePath(nonce);
        bool sent = ping != null && (active != null
            ? AdmitMaintenance(active, ping.Length) && SendManaged(ping, active)
            : TraversalResources.Shared.TrySend(ping.Length, maintenance: true) && Send(ping, peer.Active));
        // A wire-aware native path charges its injected frame, including these
        // probes, to the existing machine maintenance budget. Queuing alone is
        // never counted as a completed check; a dropped frame later times out.
        if (sent) peer.Recovery.ProbeSent(nonce, now); else peer.Recovery.ProbeDeferred();
    }
}
