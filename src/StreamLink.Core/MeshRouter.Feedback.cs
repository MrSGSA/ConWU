namespace StreamLink.Core;

public sealed partial class MeshRouter
{
    // Product scheduling only, never an alternate wire/admission allowance.
    // The ordinary heartbeat cursor provides a fair turn to each peer.
    double feedbackTokens = 2;
    long feedbackAt = Environment.TickCount64;
    bool SendFeedback(Peer peer, ManagedPath path, byte[] body, long now)
    {
        feedbackTokens = Math.Min(2, feedbackTokens + Math.Max(0, now - feedbackAt) * .008); feedbackAt = now;
        if (feedbackTokens < 1) return false;
        byte[]? packet = peer.Link.Control(body);
        if (packet == null || !AdmitMaintenance(path, packet.Length)) return false;
        feedbackTokens--; return SendManaged(packet, path);
    }
}
