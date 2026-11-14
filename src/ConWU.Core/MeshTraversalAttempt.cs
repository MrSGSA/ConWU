using System.Security.Cryptography;
using System.Diagnostics;

namespace StreamLink.Core;

public interface IPreparedMeshPath : IAsyncDisposable
{
    TraversalAttemptContext Context { get; }
    bool Armed { get; }
    TimeSpan RemainingAttemptTime { get; }
    Task<IMeshDatagramPath> Activate(CancellationToken token);
}
// Local, read-only execution evidence. This must not wrap or replace the
// prepared object: reference identity controls transfer of the winning owner.
public interface ITraversalCheckEvidence { TraversalCheckSnapshot CheckEvidence { get; } }
public sealed record TraversalCheckSnapshot(Guid AttemptId,TraversalProfile Profile,bool ActivationRequested,bool Started,
    long SendAttempts,long SendsCompleted,string EvidenceLevel,NativePathDiagnostics? Native=null)
{
    public bool Executed=>ActivationRequested&&Started&&SendsCompleted>0;
}
public enum MeshAttemptPhase { Offering, Preparing, Ready, Starting, Selected, Cancelled, Reserving, AwaitMeasure, Measuring, AwaitMeasured, AwaitReady, Standby }

// Production peer handshake. The runner owns gathering/admission; this object
// binds an authenticated Offer/Ready/Start to one prepared local resource and
// transfers the winning reference to the actual Router. HTTPS Selected is only
// reconciliation evidence; promotion always requires the in-path nomination.
public sealed partial class MeshTraversalAttempt : IAsyncDisposable
{
    readonly object gate = new();
    readonly MeshProfile local;
    readonly MeshMember peer;
    readonly Guid localBoot, remoteBoot, attempt, nonce;
    readonly TraversalProfile profile;
    readonly bool leader;
    readonly bool sourceNegotiated;
    readonly bool explorationNegotiated;
    readonly bool qualityNegotiated;
    readonly bool standbyNegotiated;
    readonly int diagnosticMbps;
    readonly bool autoQualityNegotiated;
    readonly int diagnosticTiming;
    public int DiagnosticTimingNegotiated=>diagnosticTiming;
    public bool QualityFeedbackNegotiated => qualityNegotiated;
    public bool StandbyNegotiated => standbyNegotiated;
    public int DiagnosticMbpsNegotiated=>diagnosticMbps;
    public bool AutoQualityNegotiated => autoQualityNegotiated;
    readonly long revision;
    readonly Func<long> nextSequence;
    MeshTraversalCandidate localCandidate;
    readonly MeshTraversalCandidate localReservation;
    MeshTraversalCandidate? remoteReservation;
    bool remotePrepared;
    long predictionBegan;
    public bool Predicting => localReservation.Prediction != null;
    public bool Exploring => localReservation.Exploration != null;
    public long PredictionBegan { get { lock (gate) return predictionBegan; } }
    public TimeSpan PredictionRemaining { get { lock (gate) return predictionBegan == 0 ? TimeSpan.Zero : TimeSpan.FromMilliseconds(TraversalLimits.SoRoundMs) - Stopwatch.GetElapsedTime(predictionBegan); } }
    public MeshTraversalCandidate? RemoteCandidate { get { lock (gate) return remoteCandidate; } }
    readonly CancellationTokenSource stop = new();
    MeshTraversalCandidate? remoteCandidate;
    IPreparedMeshPath? prepared;
    MeshRouter? router;
    IMeshDatagramPath? transport;
    Task? activation, closing;
    bool transferred, disposed;
    long remoteSequence;
    MeshAttemptPhase phase;
    MeshTraversalMessage? outbound;
    public Guid AttemptId => attempt;
    public MeshAttemptPhase Phase { get { lock (gate) return phase; } }
    public MeshTraversalMessage? Outbound { get { lock (gate) return outbound; } }
    public TraversalAttemptContext Context { get { lock (gate) {
        if (remoteCandidate == null) throw new InvalidOperationException("候选对尚未齐备");
        return new(local.Pair.Network, local.Self.Device, localBoot, peer.Device, remoteBoot, attempt, localCandidate.Id, localCandidate.Version,
            remoteCandidate.Id, remoteCandidate.Version, profile, leader, leader, nonce, Exploring, standbyNegotiated);
    } } }
    MeshTraversalAttempt(MeshProfile local, MeshMember peer, Guid localBoot, Guid remoteBoot, TraversalProfile profile,
        MeshTraversalCandidate candidate, Guid attempt, Guid nonce, long revision, Func<long> sequence, bool sourceNegotiated, bool explorationNegotiated, bool qualityNegotiated, bool standbyNegotiated,int diagnosticMbps,bool autoQualityNegotiated,bool timingNegotiated)
    {
        this.local = local; this.peer = peer; this.localBoot = localBoot; this.remoteBoot = remoteBoot; this.profile = profile;
        localReservation = localCandidate = candidate; this.attempt = attempt; this.nonce = nonce; this.revision = revision; nextSequence = sequence;
        leader = local.Self.Slot < peer.Slot;
        this.sourceNegotiated = sourceNegotiated;
        this.explorationNegotiated = explorationNegotiated;
        this.qualityNegotiated = qualityNegotiated;
        this.standbyNegotiated = standbyNegotiated;
        this.diagnosticMbps=diagnosticMbps;
        this.autoQualityNegotiated=autoQualityNegotiated && diagnosticMbps > 0;
        diagnosticTiming=timingNegotiated&&diagnosticMbps>0?1:0;
    }
    static void Membership(MeshProfile local, MeshMember peer, MeshTraversalCapabilities mine, MeshTraversalCapabilities theirs, TraversalProfile profile)
    {
        MeshTraversal.ValidateCapabilities(mine); MeshTraversal.ValidateCapabilities(theirs);
        if (local.Directory?.Members.Contains(peer) != true || peer.Slot == local.Self.Slot || !mine.Profiles.Contains(profile) || !theirs.Profiles.Contains(profile))
            throw new CryptographicException("成员或双方协商能力不匹配");
    }
    public static MeshTraversalAttempt Offer(MeshProfile local, MeshMember peer, MeshTraversalCapabilities mine,
        MeshTraversalCapabilities theirs, TraversalProfile profile, MeshTraversalCandidate candidate, long revision, Func<long> sequence,
        Guid? attemptId = null, bool coordinatorQuality = false, bool coordinatorStandby = false,bool coordinatorDiagnostics=false,bool coordinatorAutoQuality=false,bool coordinatorTiming=false)
    {
        Membership(local, peer, mine, theirs, profile);
        RequireFamily(candidate, mine, theirs, profile);
        if (candidate.Standby && !coordinatorStandby) throw new CryptographicException("协调服务未授权备用路径协商");
        if (local.Self.Slot >= peer.Slot) throw new InvalidOperationException("由较小成员编号统一发起本轮，避免交叉 Offer");
        var result = new MeshTraversalAttempt(local, peer, mine.BootId, theirs.BootId, profile, candidate, attemptId ?? Guid.NewGuid(), Guid.NewGuid(), revision, sequence,
            mine.TcpPeerReflexive == 1 && theirs.TcpPeerReflexive == 1, mine.UdpExploration == 1 && theirs.UdpExploration == 1,
            coordinatorQuality && mine.QualityFeedback == 1 && theirs.QualityFeedback == 1, candidate.Standby,
            candidate.Standby&&coordinatorDiagnostics&&mine.PathDiagnostics==1&&theirs.PathDiagnostics==1&&mine.DiagnosticMbps==theirs.DiagnosticMbps?mine.DiagnosticMbps:0,
            coordinatorAutoQuality&&mine.AutoQuality==1&&theirs.AutoQuality==1,
            coordinatorTiming&&mine.DiagnosticTiming==1&&theirs.DiagnosticTiming==1);
        try { result.phase = MeshAttemptPhase.Offering; result.outbound = result.Message(MeshTraversalStage.Offer); return result; }
        catch { result.stop.Dispose(); throw; }
    }
    // Invoke before allocating the responder's endpoint or native capture.
    public static void ValidateOffer(MeshProfile local, MeshMember peer, MeshTraversalCapabilities mine,
        MeshTraversalCapabilities theirs, MeshTraversalMessage offer, bool coordinatorStandby = false)
    {
        Membership(local, peer, mine, theirs, offer.Profile); MeshTraversal.Verify(local.Pair.Network, peer, local.Self, offer);
        if (offer.Stage != MeshTraversalStage.Offer || peer.Slot >= local.Self.Slot || offer.FromBoot != theirs.BootId || offer.ToBoot != mine.BootId ||
            offer.ProtocolClientSlot != peer.Slot || offer.NominatorSlot != peer.Slot)
            throw new CryptographicException("过期启动代次或非授权 Offer 角色");
        RequireFamily(offer.Candidate!, mine, theirs, offer.Profile);
        if (offer.Candidate!.Standby && !coordinatorStandby) throw new CryptographicException("协调服务未授权备用路径 Offer");
    }
    static void RequireFamily(MeshTraversalCandidate candidate, MeshTraversalCapabilities mine, MeshTraversalCapabilities theirs, TraversalProfile profile)
    {
        if (candidate.Prediction != null && (mine.TcpPrediction != 1 || theirs.TcpPrediction != 1)) throw new CryptographicException("双方尚未协商 TCP 预测能力");
        if (candidate.PeerReflexive && (mine.TcpPeerReflexive != 1 || theirs.TcpPeerReflexive != 1)) throw new CryptographicException("双方尚未协商 TCP 来源学习能力");
        if (candidate.Exploration != null && (mine.UdpExploration != 1 || theirs.UdpExploration != 1)) throw new CryptographicException("双方尚未协商 UDP 探索能力");
        if (candidate.Standby && (mine.StandbyPaths != 1 || theirs.StandbyPaths != 1)) throw new CryptographicException("双方尚未协商备用路径能力");
        if (System.Net.IPEndPoint.Parse(candidate.Endpoint).AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
            (profile == TraversalProfile.UdpDirect ? mine.UdpIpv6 != 1 || theirs.UdpIpv6 != 1 : mine.FakeTcpIpv6 != 1 || theirs.FakeTcpIpv6 != 1))
            throw new CryptographicException("双方尚未协商该承载的原生 IPv6 能力");
    }
    public static MeshTraversalAttempt Answer(MeshProfile local, MeshMember peer, MeshTraversalCapabilities mine,
        MeshTraversalCapabilities theirs, MeshTraversalMessage offer, MeshTraversalCandidate candidate, Func<long> sequence, bool coordinatorQuality = false, bool coordinatorStandby = false,bool coordinatorDiagnostics=false,bool coordinatorAutoQuality=false,bool coordinatorTiming=false)
    {
        ValidateOffer(local, peer, mine, theirs, offer, coordinatorStandby);
        RequireFamily(candidate, mine, theirs, offer.Profile);
        if ((candidate.Prediction != null) != (offer.Candidate!.Prediction != null)) throw new CryptographicException("不能把预约替换为普通候选");
        if (candidate.Standby != offer.Candidate.Standby) throw new CryptographicException("不能把备用候选替换为普通自动提名");
        var result = new MeshTraversalAttempt(local, peer, mine.BootId, theirs.BootId, offer.Profile, candidate, offer.AttemptId, offer.ValidationNonce, offer.NominationRevision, sequence,
            mine.TcpPeerReflexive == 1 && theirs.TcpPeerReflexive == 1, mine.UdpExploration == 1 && theirs.UdpExploration == 1,
            coordinatorQuality && mine.QualityFeedback == 1 && theirs.QualityFeedback == 1, candidate.Standby,
            candidate.Standby&&coordinatorDiagnostics&&mine.PathDiagnostics==1&&theirs.PathDiagnostics==1&&mine.DiagnosticMbps==theirs.DiagnosticMbps?mine.DiagnosticMbps:0,
            coordinatorAutoQuality&&mine.AutoQuality==1&&theirs.AutoQuality==1,
            coordinatorTiming&&mine.DiagnosticTiming==1&&theirs.DiagnosticTiming==1);
        try {
            result.remoteReservation = result.remoteCandidate = offer.Candidate; result.remoteSequence = offer.Sequence;
            result.phase = result.Predicting ? MeshAttemptPhase.Reserving : MeshAttemptPhase.Preparing;
            _ = result.Message(result.Predicting ? MeshTraversalStage.Reserved : MeshTraversalStage.Ready); // validate but do not publish before resource readiness
            return result;
        } catch { result.stop.Dispose(); throw; }
    }
    MeshTraversalMessage Message(MeshTraversalStage stage)
    {
        int initiator = Math.Min(local.Self.Slot, peer.Slot);
        return MeshTraversal.Sign(local, new(MeshTraversal.Version, Guid.NewGuid(), local.Self.Slot, local.Self.Device, localBoot,
            peer.Slot, peer.Device, remoteBoot, nextSequence(), attempt, revision, nonce, profile, initiator, initiator,
            stage == MeshTraversalStage.Cancel ? null : localCandidate, stage == MeshTraversalStage.Cancel ? null : remoteCandidate,
            stage, DateTimeOffset.UtcNow.AddSeconds(MeshTraversal.PublishSeconds).ToUnixTimeSeconds(), ""));
    }
    public bool Receive(MeshTraversalMessage message)
    {
        lock (gate) {
            if (disposed || phase == MeshAttemptPhase.Cancelled) return false;
            MeshTraversal.Verify(local.Pair.Network, peer, local.Self, message);
            if (message.FromBoot != remoteBoot || message.ToBoot != localBoot || message.AttemptId != attempt || message.NominationRevision != revision ||
                message.ValidationNonce != nonce || message.Profile != profile || message.ProtocolClientSlot != Math.Min(local.Self.Slot, peer.Slot) ||
                message.NominatorSlot != Math.Min(local.Self.Slot, peer.Slot)) throw new CryptographicException("消息不属于当前授权候选对");
            if (message.Sequence <= remoteSequence) return false;
            if (!sourceNegotiated && (message.Candidate?.PeerReflexive == true || message.PeerCandidate?.PeerReflexive == true))
                throw new CryptographicException("本轮未协商 TCP 来源学习，拒绝后续消息扩大范围");
            if (!explorationNegotiated && (message.Candidate?.Exploration != null || message.PeerCandidate?.Exploration != null))
                throw new CryptographicException("本轮未协商 UDP 探索，拒绝后续消息扩大范围");
            if (message.Stage == MeshTraversalStage.Cancel) { remoteSequence = message.Sequence; CancelLocked(); return true; }
            if (Predicting && ReceivePrediction(message)) { remoteSequence = message.Sequence; return true; }
            if (message.PeerCandidate != localCandidate || message.Candidate == null || remoteCandidate != null && message.Candidate != remoteCandidate)
                throw new CryptographicException("同一候选版本的地址或观察内容发生变化");
            if (leader && message.Stage == MeshTraversalStage.Ready && phase == MeshAttemptPhase.Offering) {
                remoteCandidate = message.Candidate; remotePrepared = true; phase = MeshAttemptPhase.Preparing; remoteSequence = message.Sequence; return true;
            }
            if (!leader && message.Stage == MeshTraversalStage.Start && phase == MeshAttemptPhase.Ready) {
                phase = MeshAttemptPhase.Starting; remoteSequence = message.Sequence; return true;
            }
            // Duplicate refreshed Ready/Start never allocates or starts another
            // resource. A control-plane Selected never promotes a data path.
            if (message.Stage is MeshTraversalStage.Ready or MeshTraversalStage.Start or MeshTraversalStage.Selected or MeshTraversalStage.Standby) remoteSequence = message.Sequence;
            return false;
        }
    }
    public void Prepared(IPreparedMeshPath path)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (phase != MeshAttemptPhase.Preparing || prepared != null || !path.Armed ||
                !PathNomination.ContextDigest(Context).AsSpan().SequenceEqual(PathNomination.ContextDigest(path.Context)))
                throw new IOException("捕获或接收资源未就绪，不能发布 Ready/Start");
            // Validate/sign before taking ownership; caller keeps it on failure.
            if (Predicting && (predictionBegan == 0 || PredictionRemaining <= TimeSpan.Zero)) throw new IOException("预测整轮期限已结束");
            var next = leader && !remotePrepared ? outbound : Message(leader ? MeshTraversalStage.Start : MeshTraversalStage.Ready);
            prepared = path; outbound = next; phase = leader ? remotePrepared ? MeshAttemptPhase.Starting : MeshAttemptPhase.AwaitReady : MeshAttemptPhase.Ready;
        }
    }
    // Caller dispatches the leader's Start message before invoking this method.
    // Exactly one activation/registration even with repeated Start delivery.
    public Task ActivateAndRegister(MeshRouter target, CancellationToken token)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (phase != MeshAttemptPhase.Starting || prepared == null || target.BootId != localBoot) throw new InvalidOperationException("本轮未获得 Start 或路由器代次不匹配");
            return activation ??= Activate(target, token);
        }
    }
    async Task Activate(MeshRouter target, CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
        try {
            var path = await prepared!.Activate(linked.Token);
            lock (gate) {
                transport = path;
                if (disposed || phase == MeshAttemptPhase.Cancelled) throw new OperationCanceledException();
                target.RegisterPath(peer.Slot, path, Context, revision, prepared.RemainingAttemptTime, MeshTraversal.Version, qualityNegotiated ? 1 : 0, standbyNegotiated ? 1 : 0,diagnosticMbps,autoQualityNegotiated?1:0,diagnosticTiming);
                router = target; transferred = true;
            }
        } catch { lock (gate) if (!disposed) CancelLocked(); throw; }
    }
    public void ObserveRouter()
    {
        lock (gate) {
            if (disposed || !transferred || phase == MeshAttemptPhase.Cancelled) return;
            var status = router!.Paths(peer.Slot).FirstOrDefault(p => p.PathId == transport!.Identity.PathId);
            if (status == null || status.Stage == NominationStage.Cancelled) { CancelLocked(); return; }
            if (standbyNegotiated && phase == MeshAttemptPhase.Starting && status.StandbyReady) {
                outbound = Message(MeshTraversalStage.Standby); phase = MeshAttemptPhase.Standby;
            }
            if (phase != MeshAttemptPhase.Selected && status.Stage == NominationStage.Selected && status.Active) {
                outbound = Message(MeshTraversalStage.Selected); phase = MeshAttemptPhase.Selected;
            }
        }
    }
    public void Cancel() { lock (gate) if (!disposed) CancelLocked(); }
    void CancelLocked()
    {
        if (phase == MeshAttemptPhase.Cancelled) return;
        phase = MeshAttemptPhase.Cancelled; stop.Cancel();
        try { outbound = Message(MeshTraversalStage.Cancel); }
        catch (CryptographicException) { outbound = null; } // revoked member cannot be messaged
        finally { if (transferred) router!.CancelPath(peer.Slot, transport!.Identity.PathId); }
    }
    public ValueTask DisposeAsync()
    {
        lock (gate) { if (closing != null) return new(closing); disposed = true; closing = Close(); return new(closing); }
    }
    async Task Close()
    {
        stop.Cancel();
        try {
            if (activation != null) try { await activation; } catch { }
            // Ending the Attempt MUST NOT close a reference already transferred
            // to Active. Explicit Cancel is a separate operation on that path.
            if (!transferred) {
                if (transport != null && !ReferenceEquals(transport, prepared)) await transport.DisposeAsync();
                if (prepared != null) await prepared.DisposeAsync();
            }
            else if (prepared != null && !ReferenceEquals(transport, prepared)) {
                // UDP returns a separate retained path. Retire the preparation
                // owner while that path keeps the same winning socket alive.
                await prepared.DisposeAsync();
            }
        } finally { stop.Dispose(); }
    }
}
