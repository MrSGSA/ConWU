using System.Net;

namespace StreamLink.Core;

public sealed record NatObservation(Guid SocketId, Guid NetworkGeneration, string Protocol,
    IPEndPoint Local, IPEndPoint Target, IPEndPoint Mapped, DateTimeOffset ObservedAt, long ProbeStartedAt = 0);
public sealed record NatAssessment(string Mapping, string Filtering, string Reason);

// Observations are scoped to a socket, route generation and time window. This
// is evidence for ordering attempts, never a promise about another destination.
public static class NatObservations
{
    public static NatAssessment Assess(IReadOnlyList<NatObservation> observations, DateTimeOffset now)
    {
        NatAssessment Unknown(string reason) => new("unknown", "unknown", reason);
        if (observations.Count < 3) return Unknown("至少需要两个目标 IP，其中一个 IP 的两个端口的近期观测");
        var first = observations[0];
        if (observations.Any(o => o.SocketId != first.SocketId || o.NetworkGeneration != first.NetworkGeneration ||
            o.Protocol != first.Protocol || !o.Local.Equals(first.Local) || now - o.ObservedAt > TimeSpan.FromSeconds(60) || o.ObservedAt > now))
            return Unknown("不能混合不同 socket、协议、出口代次或过期观测");
        if (observations.Select(o => o.Mapped.Address).Distinct().Count() != 1)
            return Unknown("观察到多个公网 IP，不能套用单一端口分配模型");
        if (observations.GroupBy(o => o.Target).Any(g => g.Select(o => o.Mapped).Distinct().Count() > 1))
            return Unknown("同一目标的映射发生变化，需要重新观察");
        var unique = observations.DistinctBy(o => o.Target).ToArray();
        if (unique.Select(o => o.Target.Address).Distinct().Count() < 2 ||
            !unique.GroupBy(o => o.Target.Address).Any(g => g.Select(o => o.Target.Port).Distinct().Count() >= 2))
            return Unknown("目标拓扑不足以区分地址相关和地址端口相关映射");
        if (unique.GroupBy(o => o.Target.Address).Any(g => g.Select(o => o.Mapped).Distinct().Count() > 1))
            return new("observed-apdm", "unknown", "同目标 IP 的不同端口出现不同映射；仅代表本次观测");
        return unique.Select(o => o.Mapped).Distinct().Count() == 1
            ? new("observed-eim", "unknown", "这些目标上的映射相同；过滤行为未测试")
            : new("observed-adm", "unknown", "不同目标 IP 的映射不同，同 IP 的两个端口映射相同；过滤行为未测试");
    }
}
