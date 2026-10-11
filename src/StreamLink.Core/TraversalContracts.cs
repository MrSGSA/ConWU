using System.Net;

namespace StreamLink.Core;

// Versioned control semantics. Local handles/resource references are deliberately
// separate from candidate announcements and are never serialized to Discovery.
public enum TraversalProfile { LegacyExplicit = 1, FakeTcpHttpSo = 2, UdpDirect = 3 }
public enum CandidatePurpose { ExplicitIngress = 1, SimultaneousOpen = 2, UdpDirect = 3, Host = 4 }
public enum TraversalFailure
{
    None, EndpointBusy, AttachUnauthorized, AttachStale, DriverUnavailable,
    CaptureConflict, CaptureNotReady, HelperQueryUnusable, HelperClosed,
    PeerTimeout, SynStateRejected, OuterHandshakeFailed, PathAuthFailed,
    MtuInsufficient, CandidateStale, BudgetExhausted, QualityInsufficient,
    NoDirectPathWithinBudget, EnvironmentUnavailable
}
public enum PathPolicy { PreferFakeTcp, FakeTcpOnly, AutoQuality }
public enum PathQualification { Reachable, Authenticated, MtuQualified, QualityObserved, Selected }

public sealed record TraversalCandidate(Guid CandidateId, long Version, TraversalProfile Profile,
    CandidatePurpose Purpose, IPEndPoint Endpoint, IPEndPoint? ObservationTarget,
    DateTimeOffset ObservedAt, DateTimeOffset ExpiresAt);

public sealed record TraversalAttemptContext(string NetworkId, string LocalNodeId, Guid LocalBootId,
    string RemoteNodeId, Guid RemoteBootId, Guid AttemptId, Guid LocalCandidateId,
    long LocalCandidateVersion, Guid RemoteCandidateId, long RemoteCandidateVersion,
    TraversalProfile Profile, bool ProtocolClient, bool Nominator, Guid ValidationNonce);

public sealed record ValidatedPathIdentity(Guid PathId, Guid AttemptId, Guid LeaseId,
    Guid? AttachId, Guid NetworkGeneration, IPEndPoint ActualLocal,
    IPEndPoint ActualRemote, TraversalProfile Profile, PathQualification Qualification);

// Single source for engineering budgets (not RFC defaults). All intervals below
// use monotonic local elapsed time; UTC is only for advertised observation age.
public static class TraversalLimits
{
    public const int NativeAbi = 1, CandidateVersion = 1;
    public const int UdpResources = 8, TcpResources = 8, ExperimentalResources = 40;
    public const int LightPeers = 2, HeavyPeers = 1, ControlPps = 60, ControlBurst = 8;
    public const int ControlBytesPerSecond = 65536, MaintenancePps = 24;
    public const int RoundPackets = 120, CompletionReserve = 24, RoundBytes = 65536;
    public const int UdpRoundMs = 6000, SoRoundMs = 8000, PairOpportunityMs = 60000;
    public const int UpgradeResidenceMs = 30000, UpgradeCooldownMs = 60000;
    public const int LongPollHoldSeconds = 25, LongPollTimeoutSeconds = 35;
    public const int EventQueueSize = 128, GlobalWaiters = 64;
    public const int InnerMtu = 1280, MeshOverhead = 64, UdpRequiredPayload = InnerMtu + MeshOverhead;
}
