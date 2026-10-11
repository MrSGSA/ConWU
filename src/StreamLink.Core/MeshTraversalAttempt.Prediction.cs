using System.Diagnostics;
using System.Security.Cryptography;

namespace StreamLink.Core;

public sealed partial class MeshTraversalAttempt
{
    public void Reserved(bool sourceCaptureReady)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (!Predicting || leader || phase != MeshAttemptPhase.Reserving || !sourceCaptureReady)
                throw new IOException("预测源端点尚未持有或捕获未就绪");
            outbound = Message(MeshTraversalStage.Reserved); phase = MeshAttemptPhase.AwaitMeasure;
        }
    }
    // Leader calls after publishing Measure; follower calls on receiving it.
    // This clock includes measurement, child preparation, shape, authentication
    // and nomination. Replayed control messages cannot restart it.
    public void BeginMeasurement()
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (!Predicting || phase != MeshAttemptPhase.AwaitMeasure) throw new IOException("本轮未协商预测观察启动");
            if (predictionBegan == 0) predictionBegan = Stopwatch.GetTimestamp();
            phase = MeshAttemptPhase.Measuring;
        }
    }
    public void Measured(MeshTraversalCandidate candidate)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (!Predicting || phase != MeshAttemptPhase.Measuring || PredictionRemaining <= TimeSpan.Zero ||
                !MeshTcpPrediction.Upgrades(localReservation, candidate)) throw new IOException("观察不属于本轮持续持有的预约资源");
            var prior = localCandidate; localCandidate = candidate;
            try { outbound = Message(MeshTraversalStage.Measured); }
            catch { localCandidate = prior; throw; }
            phase = MeshTcpPrediction.Final(remoteCandidate) ? MeshAttemptPhase.Preparing : MeshAttemptPhase.AwaitMeasured;
        }
    }
    bool ReceivePrediction(MeshTraversalMessage m)
    {
        void Reject() => throw new CryptographicException("预测控制不属于已预约的模型、候选或阶段");
        if (m.Stage == MeshTraversalStage.Reserved) {
            if (!leader || m.PeerCandidate != localReservation || !MeshTcpPrediction.Reserved(m.Candidate)) Reject();
            if (remoteReservation != null && remoteReservation != m.Candidate) Reject();
            if (phase == MeshAttemptPhase.Offering) {
                remoteReservation = remoteCandidate = m.Candidate;
                outbound = Message(MeshTraversalStage.Measure); phase = MeshAttemptPhase.AwaitMeasure;
            }
            return true;
        }
        if (m.Stage == MeshTraversalStage.Measure) {
            if (leader || m.Candidate != remoteReservation || m.PeerCandidate != localReservation) Reject();
            if (phase == MeshAttemptPhase.AwaitMeasure) BeginMeasurement();
            return true;
        }
        if (m.Stage == MeshTraversalStage.Measured) {
            if (remoteReservation == null || m.Candidate == null || !MeshTcpPrediction.Upgrades(remoteReservation, m.Candidate) ||
                m.PeerCandidate != localReservation && m.PeerCandidate != localCandidate ||
                MeshTcpPrediction.Final(remoteCandidate) && remoteCandidate != m.Candidate) Reject();
            remoteCandidate = m.Candidate;
            if (MeshTcpPrediction.Final(localCandidate) && phase is MeshAttemptPhase.Measuring or MeshAttemptPhase.AwaitMeasured)
                phase = MeshAttemptPhase.Preparing;
            return true;
        }
        if (m.Stage == MeshTraversalStage.Ready && leader) {
            if (!MeshTcpPrediction.Final(localCandidate) || m.PeerCandidate != localCandidate || remoteReservation == null || m.Candidate == null ||
                !MeshTcpPrediction.Upgrades(remoteReservation, m.Candidate) || MeshTcpPrediction.Final(remoteCandidate) && remoteCandidate != m.Candidate) Reject();
            remoteCandidate = m.Candidate; remotePrepared = true;
            if (phase is MeshAttemptPhase.Measuring or MeshAttemptPhase.AwaitMeasured or MeshAttemptPhase.Preparing or MeshAttemptPhase.AwaitReady) {
                if (prepared == null) phase = MeshAttemptPhase.Preparing;
                else { outbound = Message(MeshTraversalStage.Start); phase = MeshAttemptPhase.Starting; }
            }
            return true;
        }
        return false;
    }
}
