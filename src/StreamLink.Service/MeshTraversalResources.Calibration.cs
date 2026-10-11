using System.Diagnostics;
using System.Net;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

internal sealed partial class MeshCandidateFactory
{
    static readonly SemaphoreSlim calibrationAdmission = new(1, 1);
    Task calibrationTask = Task.CompletedTask;
    bool calibrationStarted;
    int calibrationBusy = 1;
    int calibrationPeerSlot;
    long calibrationRegistered, calibrationInterrupted;
    internal TimeSpan? CalibrationIntervalForTest { get; init; }
    internal Task CalibrationCompletion => calibrationTask;
    internal NatPortPrediction? CalibratedTcpModel { get; private set; }
    // Called with existing Router status, not an extra path/throughput probe.
    internal void SetCalibrationBusy(bool value) => Volatile.Write(ref calibrationBusy, value ? 1 : 0);
    internal void UpdateCalibrationStatus(MeshPeerStatus[] statuses, bool ready)
    {
        var target = statuses.FirstOrDefault(p => p.Slot == Volatile.Read(ref calibrationPeerSlot));
        SetCalibrationBusy(!ready || target == null || target.Connected);
    }

    // Caller holds observationGate. At most one completed fit per generation;
    // interrupted collections never produce or retest a qualified model.
    void StartCalibration(IPAddress source, IPEndPoint reflector, int peerSlot)
    {
        if (calibrationStarted || !options.TcpSynObservation || observer == null || observationBudget == null || observationStop.IsCancellationRequested ||
            peerSlot == calibrationPeerSlot && Volatile.Read(ref calibrationBusy) != 0) return;
        calibrationStarted = true;
        Volatile.Write(ref calibrationPeerSlot, peerSlot);
        SetCalibrationBusy(true); // wait for a Router status for this target
        calibrationTask = Task.Run(async () => {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(observationStop.Token);
            deadline.CancelAfter(TraversalLimits.CalibrationDeadlineMs); var token = deadline.Token;
            var windows = new List<PortAllocationWindow>(); var raw = new List<TcpShapeObservation[]>();
            var sourceTuples = new HashSet<string>(); bool admitted = false;
            string state = "Collecting", reason = "independent-native-windows";
            PortPredictionAssessment? qualification = null;
            try {
                while (Volatile.Read(ref calibrationBusy) != 0 || calibrationInterrupted != 0 &&
                    Stopwatch.GetElapsedTime(calibrationInterrupted).TotalMilliseconds < TraversalLimits.CalibrationInterruptedCooldownMs) await Task.Delay(100, token);
                await calibrationAdmission.WaitAsync(token); admitted = true;
                if (Volatile.Read(ref calibrationBusy) != 0) throw new OperationCanceledException("Target connected while calibration queued");
                for (int i = 0; i < TraversalLimits.PredictionWindows; i++) {
                    // Default spacing preserves the server's 2/member/60s
                    // retained-ticket quota. Never hold a socket while waiting.
                    var interval = CalibrationIntervalForTest ?? TimeSpan.FromMilliseconds(TraversalLimits.CalibrationWindowIntervalMs);
                    while (calibrationRegistered != 0 && Stopwatch.GetElapsedTime(calibrationRegistered) < interval) {
                        if (Volatile.Read(ref calibrationBusy) != 0) throw new OperationCanceledException("Target connected between calibration windows");
                        await Task.Delay(100, token);
                    }
                    if (Volatile.Read(ref calibrationBusy) != 0) throw new OperationCanceledException("Target connected before calibration window");
                    token.ThrowIfCancellationRequested(); CheckRoute(reflector, source);
                    using var opening = CancellationTokenSource.CreateLinkedTokenSource(token); opening.CancelAfter(3500);
                    using var lease = await TcpEndpointLease.Open(new(source, 0), reflector, generation, opening.Token);
                    if (!sourceTuples.Add(lease.Local.ToString())) throw new IOException("校准源端点被复用，无法证明新分配窗口");
                    await using var capture = new TcpCaptureOwner(lease, generation,
                        (local, helper) => OpenCaptureForTest?.Invoke(local, helper) ?? new WinDivertEndpointIo(Path.Combine(Path.GetDirectoryName(binary)!, "WinDivert.dll"), local, helper), pacer);
                    await capture.Ready;
                    using var reference = lease.AcquireAttempt(generation);
                    while (!TraversalResources.Shared.TrySend(20, maintenance: true)) await Task.Delay(25, token);
                    await reference.Observe(token); // verified helper kept alive throughout this window
                    bool interference = i % 3 == 1;
                    using var windowStop = CancellationTokenSource.CreateLinkedTokenSource(token);
                    // Interrupt an in-flight window as soon as an authenticated
                    // business path returns; abandoned samples cannot train.
                    using var monitorStop = CancellationTokenSource.CreateLinkedTokenSource(token);
                    var monitor = Task.Run(async () => {
                        try { while (true) { await Task.Delay(100, monitorStop.Token); if (Volatile.Read(ref calibrationBusy) != 0) { windowStop.Cancel(); return; } } }
                        catch (OperationCanceledException) when (monitorStop.IsCancellationRequested) { }
                    });
                    try {
                        var result = await TcpShapeProbe.RunCalibration(capture, observer, () => observationBudget.Take(),
                            ep => CheckRoute(ep, source), interference, windowStop.Token,
                            registrationConfirmed: () => calibrationRegistered = Stopwatch.GetTimestamp());
                        var window = TcpPredictionEvidence.CalibrationWindow(result, interference);
                        raw.Add(result);
                        if (window == null) throw new IOException("独立观察或背景探测证据不足");
                        if (windows.Count != 0 && (window.Scope != windows[0].Scope || window.Before.Target != windows[0].Before.Target || window.After.Target != windows[0].After.Target))
                            throw new IOException("出口或校准主目标变化，不能混合窗口拟合模型");
                        windows.Add(window);
                    } finally { monitorStop.Cancel(); await monitor; }
                    observationLog?.Invoke($"TCP 端口校准 {windows.Count}/{TraversalLimits.PredictionWindows}；附加探测已观察={interference}，尚未启用预测路径");
                }
                token.ThrowIfCancellationRequested();
                if (Volatile.Read(ref calibrationBusy) != 0) throw new OperationCanceledException("Business path became available");
                CalibratedTcpModel = NatPortPrediction.Fit(windows, out qualification);
                state = qualification.State; reason = qualification.Reason;
            } catch (OperationCanceledException) {
                state = observationStop.IsCancellationRequested ? "Cancelled" : Volatile.Read(ref calibrationBusy) != 0 ? "BusinessPathAvailable" : "BudgetExhausted";
                reason = "calibration-ended-without-publishing-predicted-candidates";
            } catch (Exception ex) when (ex is IOException or InvalidOperationException or System.Net.Sockets.SocketException or System.Net.Http.HttpRequestException or ArgumentException or FormatException or JsonException) {
                state = "PredictionNotSupported"; reason = ex.Message;
            } finally {
                if (admitted) calibrationAdmission.Release();
                try {
                    Directory.CreateDirectory(root);
                    await File.WriteAllTextAsync(Path.Combine(root, "tcp-port-calibration.json"), JsonSerializer.Serialize(new {
                        state, reason, windows, raw, qualification, candidateEnabled = false,
                        backgroundEvidence = "observed extra native SYN destination, NOT confirmed allocation count",
                        scope = "actual independent local sources; no peer handshake or reachability proof"
                    }, new JsonSerializerOptions { WriteIndented = true }));
                } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { observationLog?.Invoke("TCP 校准记录保存失败：" + ex.GetType().Name); }
                observationLog?.Invoke($"TCP 端口校准结束：{state}；已记录 {windows.Count} 个独立窗口，预测路径保持关闭");
                if (state == "BusinessPathAvailable") lock (observationGate) { calibrationInterrupted = Stopwatch.GetTimestamp(); calibrationStarted = false; }
            }
        });
    }
}
