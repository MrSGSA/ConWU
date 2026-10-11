using System.Net;

namespace StreamLink.Core;

// Convert only same-owner native SYN evidence. Kernel helper observations,
// ambiguity, mixed probes and unknown interfaces are deliberately not promoted.
// The existing one-shot observer doesn't measure background allocations, so it
// cannot by itself satisfy the predictor's interference qualification gate.
public static class TcpPredictionEvidence
{
    public static PortAllocationWindow[] Windows(IReadOnlyList<TcpShapeObservation> observations)
    {
        if (observations.Count is < 2 or > 4) return [];
        var good = observations.Where(o => o != null && o.State == "SynObserved" && o.Protocol == "TCP" &&
            o.TransportProfile == "udp2raw-http-c4995ea-syn" && o.Confidence == "IssTargetWindowOnly" &&
            o.CaptureOwnerId != Guid.Empty && o.ResourceId != Guid.Empty && o.NetworkGeneration != Guid.Empty &&
            o.InterfaceId is { Length: >= 1 and <= 128 } && o.InterfaceId != "Unknown" && o.ObservedAt != null &&
            o.ObservedAt > 0 && o.ObservedAt <= 253402300799999 && o.ObservedAt <= o.ProbeWindowEndsAt && o.ProbeWindowEndsAt <= o.Expires &&
            IPEndPoint.TryParse(o.Local, out _) && IPEndPoint.TryParse(o.Target, out _) && o.Mapped != null && IPEndPoint.TryParse(o.Mapped, out _)).OrderBy(o => o.ObservedAt).ToArray();
        if (good.Length < 2) return [];
        var first = good[0];
        if (good.Any(o => o.ResourceId != first.ResourceId || o.CaptureOwnerId != first.CaptureOwnerId || o.NetworkGeneration != first.NetworkGeneration ||
            o.Local != first.Local || o.InterfaceId != first.InterfaceId || o.ProbeWindowEndsAt != first.ProbeWindowEndsAt) ||
            good.Select(o => o.ProbeId).Distinct().Count() != good.Length || good.Select(o => o.Target).Distinct().Count() != good.Length) return [];
        var scope = new PortPredictionScope(first.NetworkGeneration, first.InterfaceId, IPEndPoint.Parse(first.Local).Address.ToString(), TraversalProfile.FakeTcpHttpSo);
        PortAllocationSample Sample(TcpShapeObservation o) => new(o.ResourceId, o.ProbeId, o.Local, o.Target, o.Mapped!,
            DateTimeOffset.FromUnixTimeMilliseconds(o.ObservedAt!.Value), true, PortAllocationEvidence.NativeSynObserved, o.CaptureOwnerId, o.LocalProbeStartedAt);
        // One eight-second ticket is ONE window even when it has four targets.
        // Counting its overlapping pairs separately would inflate independence.
        return [new(first.ProbeId, scope, Sample(good[0]), Sample(good[1]), 0)];
    }
}
