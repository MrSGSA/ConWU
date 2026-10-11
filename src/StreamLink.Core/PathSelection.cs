namespace StreamLink.Core;

// Device-local policy, shared by candidate advertisement, admission and the
// final router switch. Reachability/MTU qualification is not load evidence.
public sealed record PathSelection(PathPolicy Policy = PathPolicy.PreferFakeTcp, bool AllowUdpFallback = false)
{
    public void Validate()
    {
        if (!Enum.IsDefined(Policy)) throw new FormatException("选路策略无效");
        // Do not let the reserved enum silently disable PreferFakeTcp's guard.
        // Enable only once directional load evidence and joint standby selection
        // are wired through the production lifecycle, not from idle RTT alone.
        if (Policy == PathPolicy.AutoQuality) throw new FormatException("自动质量选路尚未完成负载证据与备用路径接入，暂不可启用");
    }
    public bool Allows(TraversalProfile profile) => profile switch {
        TraversalProfile.LegacyExplicit or TraversalProfile.FakeTcpHttpSo => true,
        TraversalProfile.UdpDirect => Policy == PathPolicy.PreferFakeTcp && AllowUdpFallback,
        _ => false
    };
    public string? Reject(TraversalProfile candidate, TraversalProfile? active, bool activeHealthy)
    {
        if (!Allows(candidate)) return "策略禁止 UDP 降级或候选类型无效";
        if (candidate == TraversalProfile.UdpDirect && activeHealthy && active != TraversalProfile.UdpDirect)
            return "当前策略保留健康 FakeTCP 路径";
        return null;
    }
}
