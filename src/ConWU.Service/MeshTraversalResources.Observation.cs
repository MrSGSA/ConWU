using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

internal sealed partial class MeshCandidateFactory
{
    readonly object observationGate = new();
    readonly CancellationTokenSource observationStop = new();
    ITcpObservationControl? observer;
    MeshRequestBudget? observationBudget;
    Action<string>? observationLog;
    Task observationTask = Task.CompletedTask;
    readonly HashSet<Guid> observedResources = [];
    readonly List<PortAllocationWindow> predictionWindows = [];
    public void ConfigureObservation(ITcpObservationControl control, MeshRequestBudget budget, Action<string> log)
    { lock (observationGate) { observer = control; observationBudget = budget; observationLog = log; } }
    void ObserveInBackground(TcpCaptureOwner owner, MeshMember peer)
    {
        lock (observationGate) {
            if (options.TcpPortCalibration) { StartCalibration(owner.Lease.Local.Address, owner.Lease.Reflector, peer); return; }
            // At most one running probe, eight source resources per service
            // lifetime. No retries/fan-out per peer; diagnostic failure cannot
            // delay Gather, reset STUN or replace a healthy data path.
            if (!options.TcpSynObservation || observer == null || observationBudget == null || observationStop.IsCancellationRequested ||
                !observationTask.IsCompleted || observedResources.Count >= 8 || !observedResources.Add(owner.Lease.Id)) return;
            TcpEndpointLease.Reference held;
            try { held = owner.Lease.AcquireAttempt(generation); }
            catch (InvalidOperationException) { return; }
            observationTask = Task.Run(async () => {
                using (held) try {
                    var epoch = operationEpoch.Value!;
                    using var heldEpoch = HoldEpoch(epoch);
                    using var epochStop = CancellationTokenSource.CreateLinkedTokenSource(observationStop.Token, epoch.Stop.Token);
                    var results = await TcpShapeProbe.Run(owner, observer, () => observationBudget.Take(),
                        ep => CheckRoute(ep, owner.Lease.Local.Address), epochStop.Token);
                    RequireEpoch(epoch);
                    Directory.CreateDirectory(root);
                    await File.WriteAllTextAsync(Path.Combine(root, "tcp-syn-observations-" + owner.Lease.Id.ToString("N") + ".json"),
                        JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }), observationStop.Token);
                    // This is evidence collection, not an enabled candidate
                    // strategy. The one-shot observer lacks the required fresh
                    // anchor/interference experiment for production prediction.
                    PortPredictionAssessment qualification; int count;
                    lock (networkGate) { RequireEpoch(epoch); predictionWindows.AddRange(TcpPredictionEvidence.Windows(results)); count=predictionWindows.Count; _ = NatPortPrediction.Fit(predictionWindows, out qualification); }
                    SaveEpochReport(epoch, "tcp-port-prediction-qualification.json", JsonSerializer.Serialize(new {
                        networkGeneration=epoch.Id, independentWindows = count, qualification,
                        candidateEnabled = false, reason = "fresh-anchor-and-authenticated-candidate-integration-pending"
                    }, new JsonSerializerOptions { WriteIndented = true }));
                    observationLog?.Invoke($"TCP SYN 独立观察：{results.Count(r => r.State == "SynObserved")}/{results.Length} 抵达；握手、业务及过滤仍未测试");
                    observationLog?.Invoke($"TCP 端口预测保持关闭：独立窗口 {predictionWindows.Count}/{NatPortPrediction.MinimumWindows}；{qualification.Reason}");
                } catch (OperationCanceledException) when (observationStop.IsCancellationRequested) { }
                catch (Exception ex) when (ex is IOException or InvalidOperationException or System.Net.Sockets.SocketException or System.Net.Http.HttpRequestException or OperationCanceledException or ArgumentException or FormatException or JsonException) {
                    observationLog?.Invoke("TCP 独立观察保持 Unknown：" + ex.GetType().Name);
                }
            });
        }
    }
    async Task StopObservation()
    {
        Task pending;
        lock (observationGate) { observationStop.Cancel(); pending = observationTask; }
        try { await Task.WhenAll(pending, calibrationTask); }
        finally { CalibratedTcpModel?.Invalidate(); }
    }
}
