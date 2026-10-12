using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// Hard.Targets authorizes guesses ONLY on Hard.Endpoint's IP. Stable reports
// limited evidence for its fixed source; ordinary signatures omit this DTO.
public sealed record UdpExplorationCandidate(bool Stable, Guid EvidenceId, string EvidenceKind, long EvidenceObservedAt, string Targets, string PeerScope);
public static class MeshUdpExploration
{
    public static string FormatPorts(int[] values) => string.Join(',', values.Order().Select(p => p.ToString(CultureInfo.InvariantCulture)));
    public static int[] Ports(string value)
    {
        if (value == null || value.Length is < 1 or > 1535) throw new FormatException("UDP 探索端口集合无效");
        var parts = value.Split(',');
        if (parts.Length is < 1 or > 256) throw new FormatException("UDP 探索最多授权 256 个端口");
        var result = new int[parts.Length];
        for (int i = 0; i < parts.Length; i++)
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out result[i]) || result[i] is < 1024 or > 65535 ||
                parts[i] != result[i].ToString(CultureInfo.InvariantCulture) || i > 0 && result[i] <= result[i - 1]) throw new FormatException("UDP 探索端口需唯一、有序且使用标准十进制");
        return result;
    }
    public static void Validate(MeshTraversalCandidate candidate, TraversalProfile profile)
    {
        if (candidate.Exploration is not {} e) return;
        if (profile != TraversalProfile.UdpDirect || candidate.Prediction != null || candidate.PeerReflexive || candidate.Purpose != CandidatePurpose.UdpDirect ||
            IPEndPoint.Parse(candidate.Endpoint).AddressFamily != AddressFamily.InterNetwork || candidate.Version != 1 || e.Targets == null || e.PeerScope == null)
            throw new FormatException("UDP 探索仅允许独立 IPv4 UDP 候选");
        if (!e.Stable) {
            if (e.EvidenceId != Guid.Empty || e.EvidenceKind != "" || e.EvidenceObservedAt != 0 || e.PeerScope != "") throw new FormatException("严格侧不能伪报稳定证据");
            _ = Ports(e.Targets); return;
        }
        if (e.EvidenceId == Guid.Empty || e.EvidenceObservedAt <= 0 || e.EvidenceObservedAt > candidate.ObservedAt || e.EvidenceKind is not ("public-local" or "peer-ports"))
            throw new FormatException("UDP 稳定证据类型、时间或身份无效");
        if (e.EvidenceKind == "public-local") {
            if (e.Targets != "" || e.PeerScope != "") throw new FormatException("原生公网证据不能包含另一种端口观察范围");
        } else {
            _ = Ports(e.Targets);
            if (!IPAddress.TryParse(e.PeerScope, out var scope) || scope.AddressFamily != AddressFamily.InterNetwork || scope.ToString() != e.PeerScope)
                throw new FormatException("UDP 稳定观察的对端范围无效");
        }
    }
    public static void Pair(MeshTraversalCandidate a, MeshTraversalCandidate b)
    {
        if (a.Exploration is not {} x || b.Exploration is not {} y || x.Stable == y.Stable) throw new FormatException("UDP 探索需双方采用扩展且恰好一端有稳定证据");
        var stable = x.Stable ? a : b; var hard = x.Stable ? b : a;
        if (stable.Exploration!.EvidenceKind == "peer-ports" && (stable.Exploration.PeerScope != IPEndPoint.Parse(hard.Endpoint).Address.ToString() ||
            stable.Exploration.Targets != hard.Exploration!.Targets)) throw new FormatException("UDP 稳定观察不覆盖授权对端端口集合");
    }
}
