namespace StreamLink.Core;

// Device-local policy, shared by candidate advertisement, admission and the
// final router switch. Reachability/MTU qualification is not load evidence.
public sealed record PathSelection(PathPolicy Policy = PathPolicy.PreferFakeTcp, bool AllowUdpFallback = false)
{
    public void Validate()
    {
        if (!Enum.IsDefined(Policy)) throw new FormatException("选路策略无效");
    }
    public bool Allows(TraversalProfile profile) => profile switch {
        TraversalProfile.LegacyExplicit or TraversalProfile.FakeTcpHttpSo => Policy != PathPolicy.UdpOnly,
        TraversalProfile.UdpDirect => Policy == PathPolicy.UdpOnly || Policy != PathPolicy.FakeTcpOnly && AllowUdpFallback,
        _ => false
    };
    public string? Reject(TraversalProfile candidate, TraversalProfile? active, bool activeHealthy, bool qualityApproved = false)
    {
        if (!Allows(candidate)) return "所选传输策略不允许该候选协议";
        if (candidate == TraversalProfile.UdpDirect && activeHealthy && active != TraversalProfile.UdpDirect &&
            !(Policy == PathPolicy.AutoQuality && qualityApproved))
            return "当前策略保留健康 FakeTCP 路径";
        return null;
    }
}
