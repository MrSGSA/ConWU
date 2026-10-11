using System.Net;

namespace StreamLink.Core;

public sealed partial class UdpTraversal
{
    bool preparedAttached;
    // Transfers the original owner reference to a preparation adapter. Its
    // Activate returns a separate retained path; disposing this adapter retires
    // only the owner and never the router's winning socket reference.
    public IPreparedMeshPath PreparePath(TraversalAttemptContext context, Guid expectedGeneration, IPEndPoint remote)
    {
        _ = PathNomination.ContextDigest(context);
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed != 0 || resourceClosed, this);
            if (preparedAttached || pathAttached || payloadReaders != 0 || started != 0 || receiving.IsCompleted ||
                context.Profile != TraversalProfile.UdpDirect || context.AttemptId != new Guid(attempt) || generation != expectedGeneration || !ValidEndpoint(remote) || !GatewayEligible)
                throw new IOException("UDP 准备资源不属于当前轮次，或接收者已被占用");
            var result = new PreparedUdp(this, context, expectedGeneration, new(remote.Address, remote.Port));
            preparedAttached = true; return result;
        }
    }
    sealed class PreparedUdp(UdpTraversal owner, TraversalAttemptContext context, Guid generation, IPEndPoint remote) : IPreparedMeshPath
    {
        readonly object gate = new();
        readonly CancellationTokenSource stop = new();
        Task<IMeshDatagramPath>? activation;
        Task? closing;
        bool disposed;
        public TraversalAttemptContext Context => context;
        public bool Armed { get { lock (owner.gate) return !Volatile.Read(ref disposed) && owner.disposed == 0 && !owner.resourceClosed && !owner.receiving.IsCompleted && owner.GatewayEligible; } }
        public TimeSpan RemainingAttemptTime => owner.RemainingAttemptTime;
        public Task<IMeshDatagramPath> Activate(CancellationToken token)
        {
            lock (gate) {
                ObjectDisposedException.ThrowIf(disposed, this);
                return activation ??= Open(token);
            }
        }
        async Task<IMeshDatagramPath> Open(CancellationToken token)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
            if (!Armed) throw new IOException("UDP socket 或网关候选已失效，不能启动旧轮次");
            var result = await owner.Punch([remote], new(DurationMs: TraversalLimits.UdpRoundMs), linked.Token);
            if (!result.Success) throw new IOException($"UDP 连通检查失败：{result.Failure}; socket={owner.SocketId:N}; attempt={context.AttemptId:N}; local={owner.Local}; peer={remote}; sent={result.SentPackets}; authenticated={result.AuthenticatedPackets}; learned={result.LearnedCandidates}; elapsedMs={result.ElapsedMs:F0}");
            linked.Token.ThrowIfCancellationRequested();
            return owner.RetainPath(generation, Guid.NewGuid());
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
                await owner.DisposeAsync();
            } finally { stop.Dispose(); }
        }
    }
}
