namespace StreamLink.Core;

public sealed partial class MeshRouter
{
    bool QualityEvidence(Peer peer, ManagedPath candidate, long now)
    {
        var m = peer.Managed!;
        if (m.Diagnostic is not { Finished: true, Cancelled: false } session || m.DiagnosticActive is not {} active ||
            !ReferenceEquals(m.DiagnosticStandby, candidate) || !ReferenceEquals(m.Candidate, candidate) || candidate.Closing || candidate.Transport.Failed ||
            !candidate.Nomination.StandbyConfirmed || !RoundTripFresh(candidate) || m.DiagnosticLocalEpoch != peer.Link.SendEpoch || m.DiagnosticPeerEpoch != peer.Link.ReceiveEpoch ||
            m.Active != null && !ReferenceEquals(m.Active, active) && !ReferenceEquals(m.Active, candidate)) {
            if (m.Quality is {} old) m.Quality = old with { CandidateQualified = false, StableBenefit = false, Result = "QualityUnknown", Reason = "ResourcesOrEpochChanged" };
            return false;
        }
        m.Quality = PathQualityEvaluator.Assess(session.Status(), active.Identity, candidate.Identity, now);
        return m.Quality.CandidateQualified;
    }
    static bool QualityOriginalHealthy(Peer peer) => peer.Link.Connected && peer.Managed?.DiagnosticActive is {} original &&
        !original.Closing && !original.Transport.Failed && original.Nomination.Stage != NominationStage.Cancelled &&
        original.LastReceive != 0 && System.Diagnostics.Stopwatch.GetElapsedTime(original.LastReceive).TotalSeconds < 12 && RoundTripFresh(original);
    bool QualityAuthorized(Peer peer, ManagedPath candidate, long now) => candidate.AutoQuality && Selection.Policy == PathPolicy.AutoQuality &&
        QualityEvidence(peer, candidate, now) && peer.Managed!.Agreement?.Authorized(now) == true &&
        (peer.Managed.Quality?.StableBenefit == true || !QualityOriginalHealthy(peer) || peer.Managed.Agreement.PeerHardFailure);
    bool QualityControl(Peer peer, ManagedPath path, byte[] payload, long now)
    {
        if (!PathQualityAgreement.IsControl(payload)) return false;
        if (!path.AutoQuality || !QualityEvidence(peer, path, now)) return true;
        EnsureQualityAgreement(peer, path, now);
        _ = peer.Managed!.Agreement?.Receive(payload, now);
        TickQuality(peer, now); return true;
    }
    void EnsureQualityAgreement(Peer peer, ManagedPath path, long now)
    {
        var m = peer.Managed!;
        if (m.Agreement == null && m.Quality is {} q && path.Context != null)
            m.Agreement = new(q.SessionId, q.TargetMbps, PathNomination.ContextDigest(path.Context), q.EvidenceDigest, now);
    }
    void TickQuality(Peer peer, long now)
    {
        var m = peer.Managed!;
        if (m.Active is { AutoQuality: true } selected && selected.Nomination.PeerAdopted &&
            m.DiagnosticLocalEpoch == peer.Link.SendEpoch && m.DiagnosticPeerEpoch == peer.Link.ReceiveEpoch &&
            m.Quality?.CandidatePathId == selected.Identity.PathId && m.Diagnostic is { Finished: true, Cancelled: false } done &&
            m.DiagnosticActive is {} old && ReferenceEquals(m.DiagnosticStandby, selected)) {
            var assessment = PathQualityEvaluator.Assess(done.Status(),old.Identity,selected.Identity,now);
            m.Quality = assessment.CandidateQualified ? assessment with { Result = "QualitySelectedDiagnostic", Reason = "SelectedFromQualifiedComparison" } : assessment;
            return;
        }
        if (m.Candidate is not {} candidate) {
            if (m.Quality is {} q) m.Quality = q with { CandidateQualified = false, StableBenefit = false, Result = "QualityUnknown", Reason = "CandidateNoLongerRetained" };
            return;
        }
        if (!QualityEvidence(peer,candidate,now)) return;
        if (!candidate.AutoQuality || Selection.Policy != PathPolicy.AutoQuality) return;
        // Hold an equally good path without starting an approval deadline. A
        // later genuine hard failure can still use fresh qualified evidence.
        // A provisional Candidate becoming Active is not itself an old-path
        // hard failure. Keep the recovery claim tied to the original resource.
        bool hardFailure = !QualityOriginalHealthy(peer);
        if (m.Agreement == null && !hardFailure && m.Quality?.StableBenefit != true) return;
        EnsureQualityAgreement(peer, candidate, now);
        var agreement = m.Agreement!;
        bool recovery = hardFailure || agreement.PeerHardFailure;
        bool residence = m.DiagnosticActive != null && now - m.DiagnosticActive.ProofAt >= TraversalLimits.UpgradeResidenceMs;
        if (recovery || m.Quality?.StableBenefit == true && residence && now >= m.NextQualitySelection)
            agreement.Approve(now, hardFailure);
        if (agreement.Tick(now) is {} frame) _ = SendFeedback(peer, candidate, frame, now);
        if (!agreement.Authorized(now)) return;
        if (candidate.Nomination.Stage == NominationStage.Standby && agreement.BeginSelection(now)) {
            candidate.Nomination.AllowStandbySelection(); _ = candidate.Nomination.SelectStandby();
        } else if (candidate.Nomination.Stage is NominationStage.Nominating or NominationStage.Confirming or NominationStage.Committing)
            _ = agreement.BeginSelection(now);
    }
    internal bool CanRecoverQualifiedStandby(int slot)
    {
        lock (gate) return peers.TryGetValue(slot, out var peer) && peer.Managed?.Candidate is { AutoQuality: true } path &&
            QualityEvidence(peer, path, Environment.TickCount64) && (peer.Managed.Agreement?.Open(Environment.TickCount64) != false ||
                peer.Managed.Agreement?.Authorized(Environment.TickCount64) == true);
    }
}
