using System.Net;
using System.Net.NetworkInformation;
using StreamLink.Core;

namespace StreamLink.Service;

internal sealed partial class MeshCandidateFactory
{
    sealed class NetworkEpoch
    {
        public readonly Guid Id = Guid.NewGuid();
        public readonly CancellationTokenSource Stop = new();
        public int Users;
        public readonly HashSet<string> Targets = [];
        public int Operations;
        public readonly TaskCompletionSource OperationsDrained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
    readonly object networkGate = new();
    readonly AsyncLocal<NetworkEpoch?> operationEpoch = new();
    NetworkEpoch networkEpoch = new();
    readonly List<NetworkEpoch> retiredEpochs = [];
    readonly List<Task> retiredPools = [];
    readonly List<(Task Closed, IDisposable Reference)> pathEpochs = [];
    readonly Dictionary<string, (IPEndPoint Target, string Snapshot)> routeScopes = [];
    long nextRouteCheck, notificationAt;
    int notifications;
    bool watching, networkDisposed;
    internal Func<IPEndPoint, string>? NetworkRouteForTest { get; init; }
    internal Func<long> NetworkClock { get; init; } = () => Environment.TickCount64;
    Guid generation { get { lock (networkGate) return (operationEpoch.Value ?? networkEpoch).Id; } }
    Guid CurrentGeneration { get { lock (networkGate) return networkEpoch.Id; } }
    string RouteSnapshot(IPEndPoint target) => NetworkRouteForTest?.Invoke(target) ?? EgressRouteSnapshot.Capture(target);
    void TrackRoute(IPEndPoint target)
    {
        if (RouteCheckForTest != null && NetworkRouteForTest == null) return;
        string key = target.Address.ToString(), snapshot = RouteSnapshot(target);
        if (snapshot.StartsWith("Unavailable:", StringComparison.Ordinal)) throw new IOException("EnvironmentUnavailable：无法核实候选的实际出口");
        lock (networkGate) {
            if (networkDisposed) return;
            var epoch = operationEpoch.Value ?? networkEpoch;
            RequireEpoch(epoch);
            if (!routeScopes.ContainsKey(key) && routeScopes.Count >= 64) throw new IOException("BudgetExhausted：出口观察目标上限为 64");
            epoch.Targets.Add(key);
            if (routeScopes.TryGetValue(key, out var previous) && previous.Snapshot != snapshot) {
                NotifyNetworkChanged();
                throw new IOException("CandidateStale：收发准备期间实际出口已变化");
            }
            if (!routeScopes.ContainsKey(key))
                routeScopes.Add(key, (new(target.Address, target.Port), snapshot));
            if (!watching && NetworkRouteForTest == null) {
                watching = true;
                NetworkChange.NetworkAddressChanged += AddressChanged;
                NetworkChange.NetworkAvailabilityChanged += AvailabilityChanged;
            }
        }
    }
    void AddressChanged(object? sender, EventArgs e) => NotifyNetworkChanged();
    void AvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e) => NotifyNetworkChanged();
    internal void NotifyNetworkChanged() { Interlocked.Exchange(ref notificationAt, NetworkClock()); Interlocked.Exchange(ref notifications, 1); }
    void RequireEpoch(NetworkEpoch epoch)
    {
        lock (networkGate) if (networkDisposed || !ReferenceEquals(epoch, networkEpoch) || epoch.Stop.IsCancellationRequested)
            throw new IOException("CandidateStale：实际出口代次已变化");
    }
    IDisposable HoldEpoch(NetworkEpoch epoch)
    {
        lock (networkGate) { RequireEpoch(epoch); epoch.Users++; return new EpochReference(this, epoch); }
    }
    sealed class EpochReference(MeshCandidateFactory owner, NetworkEpoch epoch) : IDisposable
    {
        int disposed;
        public void Dispose() {
            if (Interlocked.Exchange(ref disposed, 1) == 0) lock (owner.networkGate) {
                epoch.Users--;
            }
        }
    }
    void PruneNetworkScopes()
    {
        lock (networkGate) {
            if (networkDisposed) return;
            foreach (var path in pathEpochs.Where(p => p.Closed.IsCompletedSuccessfully).ToArray()) {
                path.Reference.Dispose(); pathEpochs.Remove(path);
            }
            foreach (var epoch in retiredEpochs.Where(e => e.Users == 0).ToArray()) {
                epoch.Stop.Dispose(); retiredEpochs.Remove(epoch);
            }
            var used = networkEpoch.Targets.Concat(retiredEpochs.SelectMany(e => e.Targets)).ToHashSet();
            foreach (string key in routeScopes.Keys.Where(k => !used.Contains(k)).ToArray()) routeScopes.Remove(key);
        }
    }
    void RetainEpochForPath(NetworkEpoch epoch, IMeshDatagramPath path)
    {
        if (path is not IPathResourceLifetime lifetime) throw new IOException("Path resource lifetime is required for a managed network epoch");
        lock (networkGate) pathEpochs.Add((lifetime.ResourceReleased, HoldEpoch(epoch)));
    }
    void VerifyEpochRoutes(NetworkEpoch epoch)
    {
        (IPEndPoint Target,string Snapshot)[] routes;
        lock (networkGate) { RequireEpoch(epoch); routes = epoch.Targets.Where(routeScopes.ContainsKey).Select(k => routeScopes[k]).ToArray(); }
        if (routes.Any(r => RouteSnapshot(r.Target) != r.Snapshot)) {
            NotifyNetworkChanged();
            throw new IOException("CandidateStale：首个握手发送前实际出口已变化");
        }
    }
    void SaveEpochReport(NetworkEpoch epoch, string name, string json)
    {
        // Final metadata commit is serialized with epoch retirement. A stale
        // task keeps its historical evidence instead of overwriting current
        // qualification. This bounded file operation is never per packet.
        lock (networkGate) {
            if (!ReferenceEquals(epoch, networkEpoch)) name = Path.GetFileNameWithoutExtension(name) + "-" + epoch.Id.ToString("N") + ".json";
            File.WriteAllText(Path.Combine(root, name), json);
        }
    }
    async Task<T> InEpoch<T>(NetworkEpoch epoch, Func<CancellationToken, Task<T>> action, CancellationToken token)
    {
        IDisposable held;
        lock (networkGate) { held = HoldEpoch(epoch); epoch.Operations++; }
        using var reference = held;
        var previous = operationEpoch.Value; operationEpoch.Value = epoch;
        try {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, epoch.Stop.Token);
            return await action(linked.Token);
        }
        finally {
            operationEpoch.Value = previous;
            lock (networkGate) if (--epoch.Operations == 0 && epoch.Stop.IsCancellationRequested) epoch.OperationsDrained.TrySetResult();
        }
    }
    async Task<IMeshCandidateResource> GatherCurrent(Func<CancellationToken, Task<IMeshCandidateResource>> gather, CancellationToken token)
    {
        NetworkEpoch epoch; lock (networkGate) epoch = operationEpoch.Value ?? networkEpoch;
        var resource = await InEpoch(epoch, gather, token);
        try { RequireEpoch(epoch); return resource is EpochResource ? resource : new EpochResource(this, epoch, resource); }
        catch { await resource.DisposeAsync(); throw; }
    }
    // Called only by the Runner scheduler. A notification is a reason to read
    // actual routes, never proof that a healthy path must be destroyed.
    public bool PollNetworkChange()
    {
        long now = NetworkClock();
        if (Volatile.Read(ref notifications) != 0 && now - Volatile.Read(ref notificationAt) < 250) return false;
        if (Volatile.Read(ref notifications) == 0 && now < nextRouteCheck) return false;
        Interlocked.Exchange(ref notifications, 0); nextRouteCheck = now + 5000;
        PruneNetworkScopes();
        KeyValuePair<string, (IPEndPoint Target, string Snapshot)>[] routes;
        lock (networkGate) { if (networkDisposed) return false; routes = routeScopes.ToArray(); }
        var updated = routes.Select(r => (r.Key, r.Value.Target, Previous: r.Value.Snapshot, Snapshot: RouteSnapshot(r.Value.Target))).ToArray();
        if (!updated.Any(r => r.Snapshot != r.Previous)) return false;
        NetworkEpoch old;
        lock (poolGate) {
            lock (networkGate) {
                old = networkEpoch; retiredEpochs.Add(old); networkEpoch = new();
                foreach (var route in updated) routeScopes[route.Key] = (route.Target, route.Snapshot);
            }
            retiredPools.RemoveAll(t => t.IsCompletedSuccessfully);
            if (pool != null) { retiredPools.Add(pool.DisposeAsync().AsTask()); pool = null; }
            udpMethods.Clear();
        }
        old.Stop.Cancel();
        lock (networkGate) if (old.Operations == 0) old.OperationsDrained.TrySetResult();
        lock (observationGate) {
            CalibratedTcpModel?.Invalidate(); CalibratedTcpModel = null;
            predictionWindows.Clear(); observedResources.Clear(); calibrationStarted = false;
        }
        diagnostic?.Invoke($"NetworkScopeChanged old={old.Id:N} new={CurrentGeneration:N}；旧观察与未完成候选失效，已认证业务按实际健康保留");
        return true;
    }
    NetworkEpoch[] BeginNetworkClose()
    {
        NetworkEpoch[] epochs;
        lock (networkGate) {
            networkDisposed = true;
            if (watching) { NetworkChange.NetworkAddressChanged -= AddressChanged; NetworkChange.NetworkAvailabilityChanged -= AvailabilityChanged; watching = false; }
            epochs = [networkEpoch, .. retiredEpochs];
        }
        foreach (var epoch in epochs) epoch.Stop.Cancel();
        lock (networkGate) foreach (var epoch in epochs) if (epoch.Operations == 0) epoch.OperationsDrained.TrySetResult();
        return epochs;
    }
    async Task CloseNetworkScopes()
    {
        var epochs = BeginNetworkClose();
        try {
            await Task.WhenAll(retiredPools);
            await Task.WhenAll(pathEpochs.Select(p => p.Closed));
            lock (networkGate) foreach (var path in pathEpochs.Where(p => p.Closed.IsCompletedSuccessfully).ToArray()) {
                path.Reference.Dispose(); pathEpochs.Remove(path);
            }
            // Cancel/join actual I/O. A dormant borrowed Candidate is caller
            // owned and may be disposed after Factory.Dispose completes; it
            // must not make parent shutdown wait on a circular ownership order.
            await Task.WhenAll(epochs.Select(e => e.OperationsDrained.Task));
        }
        finally {
            lock (networkGate) foreach (var path in pathEpochs.Where(p => p.Closed.IsCompletedSuccessfully).ToArray()) {
                path.Reference.Dispose(); pathEpochs.Remove(path);
            }
            foreach (var epoch in epochs) epoch.Stop.Dispose();
        }
    }
    sealed class EpochResource(MeshCandidateFactory owner, NetworkEpoch epoch, IMeshCandidateResource inner) : IMeshCandidateResource
    {
        public void AuthorizeUdpWitness(MeshTraversalCandidate remote) { owner.RequireEpoch(epoch); inner.AuthorizeUdpWitness(remote); }
        readonly IDisposable reference = owner.HoldEpoch(epoch);
        int disposed;
        public MeshTraversalCandidate Candidate { get { owner.RequireEpoch(epoch); return inner.Candidate; } }
        public bool PredictionReady => epoch.Id == owner.CurrentGeneration && inner.PredictionReady;
        public TimeSpan ExplorationRemaining => epoch.Id == owner.CurrentGeneration ? inner.ExplorationRemaining : TimeSpan.Zero;
        public object? ExplorationStats => inner.ExplorationStats;
        public bool PredictionControlReady(int requests) => epoch.Id == owner.CurrentGeneration && inner.PredictionControlReady(requests);
        public async Task<MeshTraversalCandidate> MeasurePrediction(long started, CancellationToken token)
        {
            var candidate = await owner.InEpoch(epoch, ct => inner.MeasurePrediction(started, ct), token);
            owner.RequireEpoch(epoch); return candidate;
        }
        public void FinishPrediction(PredictionOutcome outcome) => inner.FinishPrediction(outcome);
        public Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context, IPEndPoint remote, CancellationToken token)
            => PrepareScoped(ct => inner.Prepare(context, remote, ct), token);
        public Task<IPreparedMeshPath> PrepareCandidate(TraversalAttemptContext context, MeshTraversalCandidate remote, CancellationToken token)
            => PrepareScoped(ct => inner.PrepareCandidate(context, remote, ct), token);
        async Task<IPreparedMeshPath> PrepareScoped(Func<CancellationToken, Task<IPreparedMeshPath>> prepare, CancellationToken token)
        {
            var prepared = await owner.InEpoch(epoch, prepare, token);
            try { owner.RequireEpoch(epoch); return new EpochPrepared(owner, epoch, prepared); }
            catch { await prepared.DisposeAsync(); throw; }
        }
        public async ValueTask DisposeAsync() { if (Interlocked.Exchange(ref disposed, 1) != 0) return; try { await inner.DisposeAsync(); } finally { reference.Dispose(); } }
    }
    sealed class EpochPrepared(MeshCandidateFactory owner, NetworkEpoch epoch, IPreparedMeshPath inner) : IPreparedMeshPath, ITraversalCheckEvidence
    {
        readonly IDisposable reference = owner.HoldEpoch(epoch);
        int disposed, nativeTransferred;
        readonly object gate = new();
        Task<IMeshDatagramPath>? activation;
        public TraversalAttemptContext Context => inner.Context;
        public TraversalCheckSnapshot CheckEvidence=>inner is ITraversalCheckEvidence evidence?evidence.CheckEvidence:
            new(inner.Context.AttemptId,inner.Context.Profile,activation!=null,false,0,0,"NoExecutionEvidence");
        public bool Armed => epoch.Id == owner.CurrentGeneration && inner.Armed;
        public TimeSpan RemainingAttemptTime => epoch.Id == owner.CurrentGeneration ? inner.RemainingAttemptTime : TimeSpan.Zero;
        public Task<IMeshDatagramPath> Activate(CancellationToken token)
        {
            lock (gate) { ObjectDisposedException.ThrowIf(disposed != 0, this); owner.RequireEpoch(epoch); return activation ??= ActivateCore(token); }
        }
        async Task<IMeshDatagramPath> ActivateCore(CancellationToken token)
        {
            owner.VerifyEpochRoutes(epoch);
            var path = await owner.InEpoch(epoch, inner.Activate, token);
            try {
                owner.RequireEpoch(epoch);
                owner.RetainEpochForPath(epoch, path);
                // NativeDatagramPath is BOTH preparation and the winning path.
                // Wrapping preparation must not turn Attempt.Dispose into a
                // second owner which closes Router's transferred Active path.
                if (ReferenceEquals(path, inner)) Volatile.Write(ref nativeTransferred, 1);
                return path;
            }
            catch { await path.DisposeAsync(); throw; }
        }
        public async ValueTask DisposeAsync() {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            try { if (Volatile.Read(ref nativeTransferred) == 0) await inner.DisposeAsync(); }
            finally { reference.Dispose(); }
        }
    }
}
