using System.Net;
using System.Security.Cryptography;

namespace StreamLink.Core;

// Internal mechanism until authenticated product negotiation and a real
// stable-endpoint evidence provider are integrated. Nothing calls this from
// default collection; an ordinary STUN response does not authorize exploration.
internal sealed class UdpProbabilityPreparation : IPreparedMeshPath
{
    readonly object gate = new();
    readonly UdpProbeGroup group;
    readonly UdpTraversal[] nodes;
    readonly IDisposable expansion;
    readonly TraversalEnhancementScheduler.Lease admission;
    readonly Guid generation;
    readonly IPEndPoint? fixedPeer;
    readonly CancellationTokenSource stop = new();
    Task<IMeshDatagramPath>? activation;
    Task<NatObservation[]>? observation;
    Task? closing;
    int references = 1;
    bool disposed;
    public TraversalAttemptContext Context { get; }
    public bool Armed { get { lock (gate) return !disposed && group.Remaining > TimeSpan.Zero && !group.Exhausted && nodes.Any(n => n.ReceiveReady); } }
    public TimeSpan RemainingAttemptTime => group.Started == 0 ? TimeSpan.Zero : TimeSpan.FromMilliseconds(Math.Min(Context.UdpExploration ? UdpProbeGroup.DurationMs : TraversalLimits.UdpRoundMs,
        UdpProbeGroup.DurationMs - System.Diagnostics.Stopwatch.GetElapsedTime(group.Started).TotalMilliseconds));
    public Guid[] SocketIds => nodes.Select(n => n.SocketId).ToArray();
    public object Statistics => group.Snapshot();
    public Task<NatObservation[]> Observe(IPEndPoint reflector, CancellationToken token)
    {
        lock (gate) {
            if (disposed || activation != null || observation is { IsCompleted: false }) throw new IOException("探索已启动、正在观察或已退役，不能增加观察");
            group.Begin(); return observation = ObserveCore(reflector, token);
        }
    }
    async Task<NatObservation[]> ObserveCore(IPEndPoint reflector, CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
        // The test/collector may observe every held source; this does not claim
        // any STUN mapping equals its later peer-dependent public mapping.
        return await Task.WhenAll(nodes.Select(n => n.Observe(reflector, linked.Token)));
    }
    public UdpProbabilityPreparation(TraversalResources machine, TraversalAttemptContext context, Guid generation,
        byte[] key, bool stable, IPAddress peer, IPEndPoint? fixedPeer, int[] targetPorts,
        int sourcesRequested, Func<int, ITraversalSocket> open)
        : this(machine, context, generation, key, stable, peer, fixedPeer, targetPorts, sourcesRequested, open, null) { }
    // The product collector can wait fairly without pre-opening sources, then
    // transfer this exact grant to the preparation (never acquire it twice).
    internal static async Task<UdpProbabilityPreparation> Create(TraversalResources machine, TraversalAttemptContext context, Guid generation,
        byte[] key, bool stable, IPAddress peer, IPEndPoint? fixedPeer, int[] targetPorts,
        int sourcesRequested, Func<int, ITraversalSocket> open, CancellationToken token)
    {
        var admitted = await machine.Enhancements.Enter(new(context.NetworkId, context.LocalNodeId, context.RemoteNodeId, generation),
            TraversalEnhancementKind.UdpExploration, token);
        UdpProbabilityPreparation? prepared = null;
        try {
            token.ThrowIfCancellationRequested();
            prepared = new(machine, context, generation, key, stable, peer, fixedPeer, targetPorts, sourcesRequested, open, admitted);
            token.ThrowIfCancellationRequested(); return prepared;
        } catch {
            if (prepared != null) await prepared.DisposeAsync(); else admitted.Dispose();
            throw;
        }
    }
    internal static async Task<UdpProbabilityPreparation> CreateForSeed(UdpExplorationSeed seed, TraversalAttemptContext context, Guid generation,
        byte[] key, bool stable, IPAddress peer, IPEndPoint? fixedPeer, int[] targetPorts, int sourcesRequested,
        Func<int, ITraversalSocket> open, CancellationToken token, Func<bool>? stillEligible = null, bool constrainStablePorts = false)
    {
        if (!context.UdpExploration || seed.Remaining <= TimeSpan.Zero) throw new IOException("UDP 探索未获上下文授权或种子已过期");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(seed.Remaining);
        var machine = seed.Round.Machine;
        var admitted = await machine.Enhancements.Enter(new(context.NetworkId, context.LocalNodeId, context.RemoteNodeId, generation),
            TraversalEnhancementKind.UdpExploration, deadline.Token);
        UdpProbabilityPreparation? prepared = null;
        try {
            deadline.Token.ThrowIfCancellationRequested();
            if (stillEligible != null && !stillEligible()) throw new IOException("UDP 探索目标已有健康路径，取消高成本准备");
            prepared = new(machine, context, generation, key, stable, peer, fixedPeer, targetPorts, sourcesRequested, open, admitted, seed, constrainStablePorts);
            deadline.Token.ThrowIfCancellationRequested(); return prepared;
        } catch { if (prepared != null) await prepared.DisposeAsync(); else admitted.Dispose(); throw; }
    }
    UdpProbabilityPreparation(TraversalResources machine, TraversalAttemptContext context, Guid generation,
        byte[] key, bool stable, IPAddress peer, IPEndPoint? fixedPeer, int[] targetPorts,
        int sourcesRequested, Func<int, ITraversalSocket> open, TraversalEnhancementScheduler.Lease? admitted, UdpExplorationSeed? seed = null, bool constrainStablePorts = false)
    {
        _ = PathNomination.ContextDigest(context);
        if (context.Profile != TraversalProfile.UdpDirect || generation == Guid.Empty || key.Length != 32 || sourcesRequested is < 1 or > 32 || stable && sourcesRequested != 1)
            throw new ArgumentException("探索上下文或源数量无效");
        Context = context; this.generation = generation; this.fixedPeer = fixedPeer == null ? null : new(fixedPeer.Address, fixedPeer.Port);
        group = new(machine, stable, peer, this.fixedPeer, targetPorts, seed?.Round, constrainStablePorts) { RequestedSources = sourcesRequested };
        try { admission = admitted ?? machine.Enhancements.TryEnter(new(context.NetworkId, context.LocalNodeId, context.RemoteNodeId, generation),
            TraversalEnhancementKind.UdpExploration) ?? throw new IOException("BudgetExhausted：TCP/UDP 增强任务正在占用全机名额"); }
        catch { group.Dispose(); stop.Dispose(); throw; }
        try { expansion = machine.BeginUdpExploration(); }
        catch { admission.Dispose(); group.Dispose(); stop.Dispose(); throw; }
        var created = new List<UdpTraversal>();
        try {
            if (seed != null) created.Add(seed.Owner);
            for (int i = created.Count; i < sourcesRequested; i++) {
                IDisposable quota;
                try { quota = machine.Acquire(); }
                catch (IOException) when (created.Count > 0) { break; }
                created.Add(UdpTraversal.OpenGrouped(index => {
                    var next = open(index);
                    if (created.Any(n => n.SocketId == next.Id || n.Local.Equals(next.Local))) { next.Dispose(); throw new IOException("探索源不能重复同一资源或本地端点"); }
                    return next;
                }, i, quota, machine, group, context, generation, key));
            }
            if (seed != null) { seed.Transfer(group, context, generation, key); group.BeginFrom(seed.Began); }
            nodes = created.ToArray();
        } catch {
            // No Punch was started and no retained path exists here.
            foreach (var node in created) node.DisposeAsync().AsTask().GetAwaiter().GetResult();
            expansion.Dispose(); admission.Dispose(); group.Dispose(); stop.Dispose(); throw;
        }
    }
    public Task<IMeshDatagramPath> Activate(CancellationToken token)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (observation is { IsCompleted: false }) throw new IOException("先等待当前同资源观察结束");
            return activation ??= Open(token);
        }
    }
    async Task<IMeshDatagramPath> Open(CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
        group.Begin();
        var pending = nodes.Select(n => (Node: n, Work: n.Punch(fixedPeer == null ? [] : [fixedPeer],
            new(UdpProbeGroup.DurationMs, UdpProbeGroup.PacketLimit), linked.Token))).ToList();
        var all = pending.Select(p => p.Work).ToArray();
        UdpTraversal? winner = null;
        Exception? lastFailure = null;
        try {
            while (pending.Count > 0) {
                var completed = await Task.WhenAny(pending.Select(p => p.Work));
                var item = pending.Single(p => p.Work == completed); pending.Remove(item);
                PunchResult result;
                try { result = await completed; }
                catch (Exception ex) { lastFailure = ex; linked.Token.ThrowIfCancellationRequested(); continue; }
                if (!result.Success) continue;
                winner = item.Node; break;
            }
        } finally {
            linked.Cancel();
            try { await Task.WhenAll(all); } catch (Exception ex) { lastFailure ??= ex; }
        }
        token.ThrowIfCancellationRequested(); stop.Token.ThrowIfCancellationRequested();
        if (winner == null) {
            if (group.PeerProbed) admission.Failed();
            throw new IOException($"NoDirectPathWithinBudget：{(group.Exhausted ? "BudgetExhausted" : group.Remaining <= TimeSpan.Zero ? "DeadlineExpired" : "NoVerifiedPair")}；本次有界 UDP 探索未完成共同选择与 PMTU", lastFailure);
        }
        foreach (var node in nodes.Where(n => !ReferenceEquals(n, winner))) await node.DisposeAsync();
        var path = winner.RetainPath(generation, Guid.NewGuid());
        lock (gate) references++;
        return new PathReference(this, path);
    }
    void Release() { lock (gate) if (--references == 0) group.Dispose(); }
    public ValueTask DisposeAsync()
    {
        lock (gate) { if (closing != null) return new(closing); disposed = true; closing = Close(); return new(closing); }
    }
    async Task Close()
    {
        stop.Cancel();
        try {
            if (observation != null) try { await observation; } catch { }
            if (activation != null) try { await activation; } catch { }
            foreach (var node in nodes) await node.DisposeAsync();
        } finally { expansion.Dispose(); admission.Dispose(); stop.Dispose(); Release(); }
    }
    sealed class PathReference(UdpProbabilityPreparation owner, IMeshDatagramPath path) : IMeshDatagramPath, ITraversalControlledPath,IPathResourceLifetime
    {
        int disposed;
        readonly TaskCompletionSource resourceReleased = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task ResourceReleased => resourceReleased.Task;
        public ValidatedPathIdentity Identity => path.Identity;
        public bool Failed => path.Failed;
        public TraversalControlRound ControlRound => ((ITraversalControlledPath)path).ControlRound;
        public bool TrySend(ReadOnlySpan<byte> data) => path.TrySend(data);
        public ValueTask<ReadOnlyMemory<byte>> Receive(CancellationToken token) => path.Receive(token);
        public async ValueTask DisposeAsync() {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            try { try { await path.DisposeAsync(); } finally { owner.Release(); } resourceReleased.TrySetResult(); }
            catch (Exception ex) { resourceReleased.TrySetException(ex); throw; }
        }
    }
}

public sealed partial class UdpTraversal
{
    internal static UdpTraversal OpenGrouped(Func<int, ITraversalSocket> open, int index, IDisposable quota,
        TraversalResources machine, UdpProbeGroup group, TraversalAttemptContext context, Guid generation, byte[] key)
    {
        ITraversalSocket? socket = null;
        UdpTraversal? node = null;
        byte[]? scopedKey = null;
        try {
            socket = open(index);
            if (socket.Local.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || !socket.DontFragment)
                throw new IOException("概率探索需要同一 IPv4 资源与 DF 支持");
            scopedKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, key, 32, PathNomination.ContextDigest(context), "streamlink-udp-exploration-v1"u8.ToArray());
            node = new UdpTraversal(socket, generation, context.AttemptId, context.ProtocolClient ? 1 : 2,
                context.ProtocolClient ? 2 : 1, scopedKey, machine, quota);
            node.group = group; group.Register(node.probeSource); return node;
        } catch {
            if (node != null) node.DisposeAsync().AsTask().GetAwaiter().GetResult();
            else { socket?.Dispose(); quota.Dispose(); }
            throw;
        } finally { if (scopedKey != null) CryptographicOperations.ZeroMemory(scopedKey); }
    }
}
