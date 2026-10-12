using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace StreamLink.Core;

public sealed record MeshTraversalCapabilities(int Version, int NativeAbi, Guid BootId, TraversalProfile[] Profiles,
    int BackgroundUpgrade = 0, int UdpIpv6 = 0, int FakeTcpIpv6 = 0,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] int TcpPrediction = 0,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] int TcpPeerReflexive = 0,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] int UdpExploration = 0,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] int QualityFeedback = 0,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] int StandbyPaths = 0,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] int PathDiagnostics = 0,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] int DiagnosticMbps = 0);
public enum MeshTraversalStage { Offer = 1, Ready = 2, Start = 3, Cancel = 4, Selected = 5, Reserved = 6, Measure = 7, Measured = 8, Standby = 9 }
// Public observations only. Local lease/attachment IDs and socket handles never
// leave the endpoint. Both TCP and UDP retain their own profile and observations.
public sealed record MeshTraversalCandidate(Guid Id, long Version, string Endpoint, string? ObservationTarget,
    long ObservedAt, long Expires, CandidatePurpose Purpose,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] TcpPredictionCandidate? Prediction = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool PeerReflexive = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] UdpExplorationCandidate? Exploration = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool Standby = false);
public sealed record MeshTraversalMessage(int Version, Guid MessageId, int FromSlot, string FromDevice, Guid FromBoot,
    int ToSlot, string ToDevice, Guid ToBoot, long Sequence, Guid AttemptId, long NominationRevision,
    Guid ValidationNonce, TraversalProfile Profile, int ProtocolClientSlot, int NominatorSlot,
    MeshTraversalCandidate? Candidate, MeshTraversalCandidate? PeerCandidate, MeshTraversalStage Stage, long Expires, string Signature);
public sealed record MeshTraversalBatch(MeshTraversalMessage[] Messages);

public static class MeshTraversal
{
    public const int Version = 1, MaxBatch = 7, MaxInbox = 14, MaxSeconds = 60, PublishSeconds = 55;
    public const int MaxWatchBytes = 131072;
    static byte[] Signed(string network, MeshTraversalMessage m) => JsonSerializer.SerializeToUtf8Bytes(new {
        domain = "streamlink-traversal-state-v1", network, m.Version, m.MessageId, m.FromSlot, m.FromDevice, m.FromBoot,
        m.ToSlot, m.ToDevice, m.ToBoot, m.Sequence, m.AttemptId, m.NominationRevision, m.ValidationNonce,
        m.Profile, m.ProtocolClientSlot, m.NominatorSlot, m.Candidate, m.PeerCandidate, m.Stage, m.Expires });
    public static byte[] Fingerprint(string network, MeshTraversalMessage m) => SHA256.HashData(Signed(network, m));
    public static void ValidateCapabilities(MeshTraversalCapabilities? c)
    {
        if (c == null) return;
        if (c.Version != Version || c.NativeAbi is < 0 or > TraversalLimits.NativeAbi || c.BackgroundUpgrade is < 0 or > 1 || c.UdpIpv6 is < 0 or > 1 || c.FakeTcpIpv6 is < 0 or > 1 || c.TcpPrediction is < 0 or > 1 || c.TcpPeerReflexive is < 0 or > 1 || c.UdpExploration is < 0 or > 1 || c.QualityFeedback is < 0 or > 1 || c.StandbyPaths is < 0 or > 1 || c.PathDiagnostics is < 0 or > 1 ||
            c.PathDiagnostics == 0 && c.DiagnosticMbps != 0 || c.PathDiagnostics == 1 && (c.StandbyPaths != 1 || c.DiagnosticMbps is < 1 or > 50) || c.BootId == Guid.Empty ||
            c.Profiles is not { Length: >= 1 and <= 2 } || c.Profiles.Distinct().Count() != c.Profiles.Length ||
            c.UdpIpv6 == 1 && !c.Profiles.Contains(TraversalProfile.UdpDirect) ||
            c.FakeTcpIpv6 == 1 && !c.Profiles.Contains(TraversalProfile.FakeTcpHttpSo) ||
            c.TcpPrediction == 1 && !c.Profiles.Contains(TraversalProfile.FakeTcpHttpSo) ||
            c.TcpPeerReflexive == 1 && !c.Profiles.Contains(TraversalProfile.FakeTcpHttpSo) ||
            c.UdpExploration == 1 && !c.Profiles.Contains(TraversalProfile.UdpDirect) ||
            c.Profiles.Any(p => p is not (TraversalProfile.FakeTcpHttpSo or TraversalProfile.UdpDirect)) ||
            c.Profiles.Contains(TraversalProfile.FakeTcpHttpSo) && c.NativeAbi != TraversalLimits.NativeAbi)
            throw new FormatException("打洞能力或启动代次无效");
    }
    static void ValidateCandidate(MeshTraversalCandidate? c, TraversalProfile profile, long now, bool fresh)
    {
        if (c == null) return;
        bool Endpoint(string? value) => value is { Length: >= 3 and <= 64 } && IPEndPoint.TryParse(value, out var ep) && ep.Port > 0 &&
            (ep.AddressFamily == AddressFamily.InterNetwork && !ep.Address.Equals(IPAddress.Any) &&
             !ep.Address.Equals(IPAddress.Broadcast) && ep.Address.GetAddressBytes()[0] < 224 ||
             Ipv6Direct.UnscopedUnicast(ep.Address));
        if (c.Id == Guid.Empty || c.Version <= 0 || !Endpoint(c.Endpoint) || c.ObservationTarget != null && !Endpoint(c.ObservationTarget) ||
            c.ObservationTarget != null && IPEndPoint.Parse(c.Endpoint).AddressFamily != IPEndPoint.Parse(c.ObservationTarget).AddressFamily ||
            c.ObservedAt <= 0 || c.ObservedAt > now + 5 || c.Expires > c.ObservedAt + 180 || c.Expires < c.ObservedAt ||
            fresh && (c.ObservedAt < now - 180 || c.Expires <= now) ||
            c.Purpose != CandidatePurpose.Host && c.Purpose != (profile == TraversalProfile.UdpDirect ? CandidatePurpose.UdpDirect : CandidatePurpose.SimultaneousOpen))
            throw new FormatException("候选观察、协议或有效期无效");
        MeshTcpPrediction.Validate(c, profile);
        MeshUdpExploration.Validate(c, profile);
        if (c.Standby && (c.Prediction != null || c.PeerReflexive || c.Exploration != null)) throw new FormatException("备用候选不能复用高成本预测或来源学习授权");
        if (c.PeerReflexive && (profile != TraversalProfile.FakeTcpHttpSo || c.Prediction != null || IPEndPoint.Parse(c.Endpoint).AddressFamily != AddressFamily.InterNetwork))
            throw new FormatException("TCP 来源学习只允许独立 IPv4 SO 候选");
    }
    public static void ValidateShape(MeshTraversalMessage m, long? observedUnixSeconds = null)
    {
        long now = observedUnixSeconds ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (m.Version != Version || m.MessageId == Guid.Empty || m.FromSlot is < 1 or > 254 || m.ToSlot is < 1 or > 254 || m.FromSlot == m.ToSlot ||
            !Guid.TryParseExact(m.FromDevice, "N", out _) || !Guid.TryParseExact(m.ToDevice, "N", out _) || m.FromDevice == m.ToDevice ||
            m.FromBoot == Guid.Empty || m.ToBoot == Guid.Empty || m.Sequence <= 0 || m.AttemptId == Guid.Empty || m.NominationRevision <= 0 ||
            m.ValidationNonce == Guid.Empty || m.Profile is not (TraversalProfile.FakeTcpHttpSo or TraversalProfile.UdpDirect) ||
            m.ProtocolClientSlot != m.FromSlot && m.ProtocolClientSlot != m.ToSlot || m.NominatorSlot != m.FromSlot && m.NominatorSlot != m.ToSlot ||
            !Enum.IsDefined(m.Stage) || m.Expires <= now || m.Expires > now + MaxSeconds || m.Signature is null || m.Signature.Length > 256)
            throw new FormatException("打洞控制身份、阶段或有效期无效");
        if (m.Stage != MeshTraversalStage.Cancel && m.Candidate == null ||
            m.Stage is MeshTraversalStage.Ready or MeshTraversalStage.Start or MeshTraversalStage.Selected or MeshTraversalStage.Reserved or MeshTraversalStage.Measure or MeshTraversalStage.Measured or MeshTraversalStage.Standby && m.PeerCandidate == null ||
            m.Stage == MeshTraversalStage.Offer && m.PeerCandidate != null ||
            m.Candidate != null && m.PeerCandidate != null && m.Candidate.Id == m.PeerCandidate.Id)
            throw new FormatException("该阶段的候选对不完整");
        // Active authorization is distinct from candidate TTL. Selected only
        // reports an already authenticated path; it cannot prepare/promote one.
        bool fresh = m.Stage is not (MeshTraversalStage.Selected or MeshTraversalStage.Standby);
        ValidateCandidate(m.Candidate, m.Profile, now, fresh);
        ValidateCandidate(m.PeerCandidate, m.Profile, now, fresh);
        if (m.Candidate != null && m.PeerCandidate != null && m.Candidate.Standby != m.PeerCandidate.Standby ||
            m.Stage == MeshTraversalStage.Standby && m.Candidate?.Standby != true)
            throw new FormatException("备用阶段或候选对授权不一致");
        MeshTcpPrediction.ValidateStage(m);
        if (m.Candidate?.Exploration != null && m.PeerCandidate != null || m.PeerCandidate?.Exploration != null && m.Candidate != null)
            MeshUdpExploration.Pair(m.Candidate!, m.PeerCandidate!);
        if (m.Candidate != null && m.PeerCandidate != null && IPEndPoint.Parse(m.Candidate.Endpoint).AddressFamily != IPEndPoint.Parse(m.PeerCandidate.Endpoint).AddressFamily)
            throw new FormatException("候选对地址族不匹配");
    }
    public static MeshTraversalMessage Sign(MeshProfile local, MeshTraversalMessage message)
    {
        ValidateShape(message);
        if (message.FromSlot != local.Self.Slot || message.FromDevice != local.Self.Device ||
            local.Directory?.Members.Any(p => p.Slot == message.ToSlot && p.Device == message.ToDevice) != true)
            throw new CryptographicException("不能代其他成员发布打洞状态");
        return message with { Signature = MeshIdentity.Sign(local.SigningPrivate, Signed(local.Pair.Network, message)) };
    }
    public static void Verify(string network, MeshMember sender, MeshMember receiver, MeshTraversalMessage m)
    {
        ValidateShape(m);
        if (sender.Slot != m.FromSlot || sender.Device != m.FromDevice || receiver.Slot != m.ToSlot || receiver.Device != m.ToDevice ||
            !MeshIdentity.Verify(sender.SigningKey, Signed(network, m), m.Signature))
            throw new CryptographicException("打洞状态签名无效");
    }
    public static TraversalAttemptContext Context(string network, MeshTraversalMessage m, bool sender)
    {
        ValidateShape(m);
        if (m.Candidate == null || m.PeerCandidate == null) throw new InvalidOperationException("Offer 尚未形成完整候选对");
        return sender
            ? new(network, m.FromDevice, m.FromBoot, m.ToDevice, m.ToBoot, m.AttemptId, m.Candidate.Id, m.Candidate.Version,
                m.PeerCandidate.Id, m.PeerCandidate.Version, m.Profile, m.ProtocolClientSlot == m.FromSlot, m.NominatorSlot == m.FromSlot, m.ValidationNonce, m.Candidate.Exploration != null, m.Candidate.Standby)
            : new(network, m.ToDevice, m.ToBoot, m.FromDevice, m.FromBoot, m.AttemptId, m.PeerCandidate.Id, m.PeerCandidate.Version,
                m.Candidate.Id, m.Candidate.Version, m.Profile, m.ProtocolClientSlot == m.ToSlot, m.NominatorSlot == m.ToSlot, m.ValidationNonce, m.Candidate.Exploration != null, m.Candidate.Standby);
    }
}

public interface IMeshTraversalDiscovery
{
    Guid BootId { get; }
    bool SupportsTraversal { get; }
    bool SupportsUdpIpv6 => false;
    bool SupportsFakeTcpIpv6 => false;
    bool SupportsTcpPrediction => false;
    bool SupportsTcpPeerReflexive => false;
    bool SupportsUdpExploration => false;
    bool SupportsQualityFeedback => false;
    bool SupportsStandbyPaths => false;
    bool SupportsPathDiagnostics => false;
    Task PublishTraversal(MeshTraversalMessage[] messages, CancellationToken token);
}
