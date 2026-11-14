using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// No local lease/socket ID is published. Empty Ports reserves one source and
// a qualified local model; it does not advertise an actual usable peer tuple.
public sealed record TcpPredictionCandidate(Guid ModelId, bool StableModel, string Ports);
public static class MeshTcpPrediction
{
    public static bool Reserved(MeshTraversalCandidate? c) => c?.Prediction?.Ports == "";
    public static bool Final(MeshTraversalCandidate? c) => c?.Prediction is { Ports.Length: > 0 };
    public static int[] Ports(TcpPredictionCandidate p)
    {
        if (p.Ports is null || p.Ports.Length > 47) throw new FormatException("预测端口窗口无效");
        if (p.Ports.Length == 0) return [];
        var parts = p.Ports.Split(',');
        if (parts.Length is < 1 or > TraversalLimits.PredictionPorts || p.StableModel && parts.Length != 1) throw new FormatException("预测端口数量无效");
        var ports = new int[parts.Length];
        for (int i = 0; i < parts.Length; i++) {
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out ports[i]) || ports[i] is < 1024 or > 65535 ||
                parts[i] != ports[i].ToString(CultureInfo.InvariantCulture) || i > 0 && ports[i] <= ports[i - 1]) throw new FormatException("预测端口必须有序、唯一且使用标准十进制");
        }
        return ports;
    }
    public static void Validate(MeshTraversalCandidate c, TraversalProfile profile)
    {
        if (c.Prediction is not {} p) return;
        if (profile != TraversalProfile.FakeTcpHttpSo || c.Purpose != CandidatePurpose.SimultaneousOpen ||
            p.ModelId == Guid.Empty || !IPEndPoint.TryParse(c.Endpoint, out var endpoint) || endpoint.AddressFamily != AddressFamily.InterNetwork ||
            c.Version is < 1 or > 2) throw new FormatException("TCP 预测候选的协议、模型或代次无效");
        var ports = Ports(p);
        // Metadata must survive the handshake (and tolerated clock skew).
        // It is NOT evidence of a fresh prediction: only the owning endpoint's
        // monotonic, <=2s TryClaim authorizes the first actual SYN.
        if (ports.Length == 0 ? c.Version != 1 : c.Version != 2 || ports[0] != endpoint.Port || c.Expires > c.ObservedAt + TraversalLimits.SoRoundMs / 1000)
            throw new FormatException("预测候选的预约或短期端口窗口无效");
    }
    public static bool Upgrades(MeshTraversalCandidate reservation, MeshTraversalCandidate final) => Reserved(reservation) && Final(final) &&
        final.Id == reservation.Id && final.Version == 2 && final.Prediction!.ModelId == reservation.Prediction!.ModelId &&
        final.Prediction.StableModel == reservation.Prediction.StableModel && final.ObservedAt >= reservation.ObservedAt &&
        IPEndPoint.Parse(final.Endpoint).Address.Equals(IPEndPoint.Parse(reservation.Endpoint).Address);
    public static bool SameReservation(MeshTraversalCandidate a, MeshTraversalCandidate b) =>
        a == b || Reserved(a) && Upgrades(a, b) || Reserved(b) && Upgrades(b, a);
    public static void ValidateStage(MeshTraversalMessage m)
    {
        bool prediction = m.Candidate?.Prediction != null || m.PeerCandidate?.Prediction != null;
        if (m.Stage == MeshTraversalStage.Cancel) return;
        if (m.Stage is MeshTraversalStage.Reserved or MeshTraversalStage.Measure or MeshTraversalStage.Measured && !prediction)
            throw new FormatException("新阶段仅用于已协商的 TCP 预测");
        if (!prediction) return;
        if (m.Candidate?.Prediction == null || m.PeerCandidate != null && m.PeerCandidate.Prediction == null ||
            m.PeerCandidate != null && !m.Candidate.Prediction.StableModel && !m.PeerCandidate.Prediction!.StableModel)
            throw new FormatException("预测需双方采用同一扩展且至少一侧具有稳定映射模型");
        bool valid = m.Stage switch {
            MeshTraversalStage.Offer => Reserved(m.Candidate),
            MeshTraversalStage.Reserved or MeshTraversalStage.Measure => Reserved(m.Candidate) && Reserved(m.PeerCandidate),
            MeshTraversalStage.Measured => Final(m.Candidate),
            MeshTraversalStage.Ready or MeshTraversalStage.Start or MeshTraversalStage.Selected => Final(m.Candidate) && Final(m.PeerCandidate),
            _ => false
        };
        if (!valid) throw new FormatException("预测阶段与候选版本不匹配");
    }
    public static IPEndPoint[] Endpoints(MeshTraversalCandidate candidate)
    {
        Validate(candidate, TraversalProfile.FakeTcpHttpSo);
        if (!Final(candidate)) throw new IOException("预约不是可发送的 TCP 候选");
        var address = IPEndPoint.Parse(candidate.Endpoint).Address;
        return Ports(candidate.Prediction!).Select(p => new IPEndPoint(address, p)).ToArray();
    }
}
