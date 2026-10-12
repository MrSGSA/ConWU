using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Service;

internal sealed partial class MeshCandidateFactory
{
    internal Guid GenerationForTest => generation;
    internal void SetPredictionModelForTest(NatPortPrediction model) {
        if (model.Scope.NetworkGeneration != generation) throw new ArgumentException("Model generation differs");
        CalibratedTcpModel = model;
    }
    public async Task<IMeshCandidateResource> GatherCoordinated(MeshMember peer, TraversalProfile profile, Guid attempt, bool allowIpv6,
        MeshTraversalCandidate? remote, int round, bool predictionAllowed, CancellationToken token)
    {
        bool requested = remote?.Prediction != null;
        if (requested && (!predictionAllowed || !SupportsTcpPrediction || profile != TraversalProfile.FakeTcpHttpSo))
            throw new IOException("预测协商能力未获双方和协调服务授权");
        // Ordinary attempts precede inferred prediction. A normal remote Offer
        // can never be silently answered with a different candidate strategy.
        if (requested || remote == null && round >= 2 && predictionAllowed && SupportsTcpPrediction && CalibratedTcpModel != null) {
            if (CalibratedTcpModel == null || observer == null || observationBudget == null) throw new IOException("PredictionNotSupported：尚无本出口合格模型");
            if (remote?.Prediction is { StableModel: false } && !CalibratedTcpModel.StableModel) throw new IOException("PredictionNotSupported：双方模型均不稳定");
            return await GatherPrediction(peer, CalibratedTcpModel, token);
        }
        return await GatherForPeer(peer, profile, attempt, allowIpv6, remote == null ? null : IPEndPoint.Parse(remote.Endpoint), round, token);
    }
    async Task<IMeshCandidateResource> GatherPrediction(MeshMember peer, NatPortPrediction model, CancellationToken token)
    {
        // Same heavy-operation slot as calibration, not a separate allowance
        // multiplied by the number of peers. Never hold a new socket in queue.
        var admission = await Enhancements.Enter(EnhancementScope(peer), TraversalEnhancementKind.TcpPrediction, token);
        TcpEndpointLease? lease = null; TcpCaptureOwner? capture = null;
        var background = observationBudget!.HoldBackground();
        try {
            // Refill before holding a new source; this does not precharge,
            // refund or bypass the shared HTTP token bucket.
            while (!observationBudget.Available(8)) await Task.Delay(100, token);
            var source = IPAddress.Parse(model.Scope.SourceAddress);
            if (model.Scope.NetworkGeneration != generation) throw new IOException("PredictionInvalidated：出口代次不符");
            var helper = await OpenPredictionHelper(source, token);
            lease = helper.Lease; capture = helper.Capture;
            while (!observationBudget.Take(priority: true)) await Task.Delay(100, token);
            var catalog = await observer!.TcpObservation("catalog", Guid.Empty, null, token);
            if (catalog.Version != 1 || catalog.FreshWindowMs != TcpObserverProtocol.FreshWindowMs) throw new IOException("ObserverUnavailable：服务不支持短窗观察");
            TcpObserverProtocol.ValidatePoints(catalog.Points);
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            // Hint port belongs only to the reservation. Measure replaces it
            // using native evidence from THIS still-held source before Prepare.
            var hint = new IPEndPoint(IPAddress.Parse(model.PublicAddress), helper.Observation.Public.Port); CheckRoute(hint, source);
            var candidate = new MeshTraversalCandidate(Guid.NewGuid(), 1, hint.ToString(), helper.Target.ToString(), now, now + 120,
                CandidatePurpose.SimultaneousOpen, new(model.Assessment.ModelId, model.StableModel, ""));
            return new PredictionResource(this, peer, candidate, lease, capture, model, catalog, admission, background);
        } catch {
            try { if (capture != null) await capture.DisposeAsync(); }
            finally { lease?.Dispose(); background.Dispose(); admission.Dispose(); } throw;
        }
    }
    async Task<(TcpEndpointLease Lease, TcpCaptureOwner Capture, IPEndPoint Target, StunResult Observation)>
        OpenPredictionHelper(IPAddress source, CancellationToken token)
    {
        // Reflection failures are not failures of the calibrated port model.
        // Try the same bounded configured list as ordinary candidate gathering,
        // but never reuse an ambiguous helper transaction or its failed source.
        using var preparation = CancellationTokenSource.CreateLinkedTokenSource(token);
        preparation.CancelAfter(TraversalLimits.PredictionHelperPrepareMs);
        Exception? last = null;
        foreach (string name in options.OrderedTcp().Distinct(StringComparer.OrdinalIgnoreCase).Take(3)) {
            TcpEndpointLease? lease = null; TcpCaptureOwner? capture = null; bool transferred = false, reflection = true;
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(preparation.Token); limit.CancelAfter(3500);
            try {
                var target = await ResolveTarget(name, AddressFamily.InterNetwork, limit.Token); CheckRoute(target, source);
                lease = await TcpEndpointLease.Open(new(source, 0), target, generation, limit.Token);
                reflection = false; // driver/capture setup faults cannot be fixed by another STUN server
                capture = new(lease, generation, (local, helper) => OpenCaptureForTest?.Invoke(local, helper) ??
                    new WinDivertEndpointIo(Path.Combine(Path.GetDirectoryName(binary)!, "WinDivert.dll"), local, helper), pacer);
                await capture.Ready.WaitAsync(limit.Token);
                reflection = true;
                using var query = lease.AcquireAttempt(generation);
                while (!TraversalResources.Shared.TrySend(20, maintenance: true)) await Task.Delay(25, limit.Token);
                var observed = await query.Observe(limit.Token);
                limit.Token.ThrowIfCancellationRequested();
                transferred = true; return (lease, capture, target, observed);
            } catch (Exception ex) when (reflection && !token.IsCancellationRequested && ex is IOException or SocketException or OperationCanceledException or ArgumentException) {
                last = ex; observationLog?.Invoke($"TCP 预测反射准备失败：{name}，{ex.GetType().Name}；在本轮剩余准备时间内尝试下一项");
            } finally {
                if (!transferred) try { if (capture != null) await capture.DisposeAsync(); }
                    finally { lease?.Dispose(); }
            }
            if (preparation.IsCancellationRequested) break;
        }
        token.ThrowIfCancellationRequested();
        throw new IOException("HelperQueryUnusable：本轮配置的 TCP 反射服务器未产生可用源端点", last);
    }
    sealed class PredictionResource(MeshCandidateFactory factory, MeshMember peer, MeshTraversalCandidate reservation,
        TcpEndpointLease lease, TcpCaptureOwner capture, NatPortPrediction model, TcpObserverReply catalog, TraversalEnhancementScheduler.Lease heavyAdmission, IDisposable background) : IMeshCandidateResource
    {
        MeshTraversalCandidate candidate = reservation;
        readonly MeshTraversalCandidate reserved = reservation;
        readonly TraversalControlRound round = new(TraversalResources.Shared);
        PortForecast? forecast;
        long began;
        bool measuring, prepared, finished;
        int disposed, admission = 1;
        public MeshTraversalCandidate Candidate => candidate;
        public bool PredictionReady => !lease.Closed && !capture.Failed && capture.Ready.IsCompletedSuccessfully;
        public bool PredictionControlReady(int requests) => factory.observationBudget!.Available(requests);
        public async Task<MeshTraversalCandidate> MeasurePrediction(long started, CancellationToken token)
        {
            if (measuring || disposed != 0 || !PredictionReady || started <= 0) throw new IOException("预测源资源未就绪或已使用");
            measuring = true; began = started;
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(token);
            var left = TimeSpan.FromMilliseconds(TraversalLimits.SoRoundMs) - Stopwatch.GetElapsedTime(started);
            if (left <= TimeSpan.Zero) throw new IOException("预测整轮已过期"); limit.CancelAfter(left);
            var observations = await TcpShapeProbe.RunFresh(capture, factory.observer!, () => factory.observationBudget!.Take(priority: true),
                ep => factory.CheckRoute(ep, lease.Local.Address), limit.Token, destinations: model.StableModel ? 2 : 1, preparedCatalog: catalog, controlRound: round);
            if (observations.Length != (model.StableModel ? 2 : 1) || observations.Any(o => o.State != "SynObserved" || o.ResourceId != lease.Id || o.CaptureOwnerId != capture.OwnerId ||
                o.NetworkGeneration != model.Scope.NetworkGeneration || o.InterfaceId != model.Scope.InterfaceId || o.Local != lease.Local.ToString() || o.Mapped == null || o.ObservedAt == null) ||
                model.StableModel && observations.Select(o => o.Mapped).Distinct().Count() != 1) throw new IOException("PredictionNotSupported：新鲜原生观察不支持已声明模型");
            var anchor = observations.OrderBy(o => o.LocalProbeStartedAt).Last();
            factory.observationLog?.Invoke($"TCP 预测新观察：源年龄 {Stopwatch.GetElapsedTime(anchor.LocalProbeStartedAt).TotalMilliseconds:F0} ms；整轮已用 {Stopwatch.GetElapsedTime(began).TotalMilliseconds:F0} ms");
            var sample = new PortAllocationSample(lease.Id, anchor.ProbeId, anchor.Local, anchor.Target, anchor.Mapped!,
                DateTimeOffset.FromUnixTimeMilliseconds(anchor.ObservedAt!.Value), true, PortAllocationEvidence.NativeSynObserved, capture.OwnerId, anchor.LocalProbeStartedAt);
            if (!model.TryForecast(model.Scope, sample, () => disposed == 0 && !lease.Closed && !capture.Failed, true, out forecast, out string reason))
                throw new IOException(reason);
            var ports = forecast!.Ports.Order().ToArray(); long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (model.StableModel && (ports.Length != 1 || ports[0] != IPEndPoint.Parse(anchor.Mapped!).Port))
                throw new IOException("PredictionNotSupported：新鲜映射不再符合稳定模型的预测端点");
            candidate = reserved with { Version = 2, Endpoint = new IPEndPoint(IPAddress.Parse(forecast.Address), ports[0]).ToString(),
                ObservationTarget = anchor.Target, ObservedAt = now, Expires = now + TraversalLimits.SoRoundMs / 1000,
                Prediction = reserved.Prediction! with { Ports = string.Join(',', ports) } };
            MeshTcpPrediction.Validate(candidate, TraversalProfile.FakeTcpHttpSo);
            return candidate;
        }
        public Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context, IPEndPoint remote, CancellationToken token) =>
            throw new IOException("预测窗口需要完整的签名远端候选");
        public async Task<IPreparedMeshPath> PrepareCandidate(TraversalAttemptContext context, MeshTraversalCandidate remote, CancellationToken token)
        {
            if (prepared || forecast == null || disposed != 0 || context.LocalCandidateId != candidate.Id || context.LocalCandidateVersion != 2 ||
                context.RemoteCandidateId != remote.Id || context.RemoteCandidateVersion != 2 || !model.StableModel && remote.Prediction?.StableModel != true)
                throw new IOException("预测上下文或单稳定端前提不匹配");
            var endpoints = MeshTcpPrediction.Endpoints(remote);
            foreach (var endpoint in endpoints) factory.CheckRoute(endpoint, lease.Local.Address);
            byte[] shared = MeshIdentity.SharedKey(factory.options.Mesh!, peer);
            try {
                var path = await NativePortWindow.Prepare(factory.binary, factory.root, capture, context, endpoints, shared,
                    () => {
                        bool accepted = model.TryClaim(forecast.Id);
                        factory.observationLog?.Invoke($"TCP 预测首次发包授权：{accepted}；整轮已用 {Stopwatch.GetElapsedTime(began).TotalMilliseconds:F0} ms");
                        return accepted;
                    }, token, roundStartedAt: began, controlRound: round);
                prepared = true; return path;
            } finally { CryptographicOperations.ZeroMemory(shared); }
        }
        public void FinishPrediction(PredictionOutcome outcome)
        {
            if (finished) return; finished = true; background.Dispose();
            if (forecast != null) model.Finish(forecast.Id, outcome);
            factory.observationLog?.Invoke($"TCP 预测结束：{outcome}；观察与握手共 {round.Packets}/{TraversalLimits.RoundPackets} 包，{round.Bytes}/{TraversalLimits.RoundBytes} 字节");
            if (outcome == PredictionOutcome.PathAuthenticated && Interlocked.Exchange(ref admission, 0) != 0) heavyAdmission.Dispose();
        }
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            FinishPrediction(PredictionOutcome.Cancelled);
            // Capture retirement keeps selected child session references alive;
            // its completion is owned by those children, not this Attempt.
            try { await capture.DisposeAsync(); }
            finally { lease.Dispose(); if (Interlocked.Exchange(ref admission, 0) != 0) heavyAdmission.Dispose(); }
        }
    }
}
