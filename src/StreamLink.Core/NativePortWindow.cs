using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace StreamLink.Core;

// Prepared adapter for one authenticated remote IPv4/port window. This is NOT
// a NAT strategy: the caller must negotiate the exact guesses and establish
// the stable-side precondition. It cannot turn arbitrary forecasts into peers.
[SupportedOSPlatform("windows")]
public sealed class NativePortWindow : IPreparedMeshPath
{
    readonly object gate = new();
    readonly NativeAttemptGroup group;
    readonly List<NativeDatagramPath> paths = [];
    readonly CancellationTokenSource stop = new();
    Task<IMeshDatagramPath>? activation;
    Task? closing;
    NativeDatagramPath? transferred;
    bool disposed;
    public TraversalAttemptContext Context { get; }
    public bool Armed => !Volatile.Read(ref disposed) && paths.Count != 0 && paths.All(p => p.Armed);
    public TimeSpan RemainingAttemptTime => group.Remaining;
    public TraversalControlRound ControlRound => group.ControlRound;
    public bool Claimed => group.Claimed;
    public IReadOnlyList<NativePathDiagnostics> Diagnostics => paths.Select(p => p.Diagnostics).ToArray();
    NativePortWindow(TraversalAttemptContext context, TraversalResources resources, Func<bool> claim, long roundStartedAt, TraversalControlRound? controlRound)
    { Context = context; group = new(resources, claim, roundStartedAt, controlRound); }

    public static async Task<NativePortWindow> Prepare(string executable, string root, TcpCaptureOwner owner,
        TraversalAttemptContext context, IReadOnlyList<IPEndPoint> authorizedEndpoints, byte[] sharedKey,
        Func<bool> claimFirstProbe, CancellationToken token, TraversalResources? resources = null, long roundStartedAt = 0, TraversalControlRound? controlRound = null)
    {
        // Snapshot mutable endpoints before any asynchronous work. A caller
        // cannot change the authorization or introduce a second IP afterwards.
        var peers = authorizedEndpoints.Select(p => p == null ? null : new IPEndPoint(p.Address, p.Port)).ToArray();
        if (peers.Length is < 1 or > TraversalLimits.PredictionPorts || peers.Any(p => p == null || p.AddressFamily != AddressFamily.InterNetwork ||
            p.Port is < 1024 or > 65535 || p.Address.GetAddressBytes()[0] is 0 or >= 224 || p.Address.Equals(IPAddress.Broadcast)) ||
            peers.Select(p => p!.Address).Distinct().Count() != 1 || peers.Distinct().Count() != peers.Length ||
            owner.Lease.Local.AddressFamily != AddressFamily.InterNetwork || context.Profile != TraversalProfile.FakeTcpHttpSo)
            throw new ArgumentException("One authorized IPv4 address and one to eight distinct ports are required");
        var result = new NativePortWindow(context, resources ?? TraversalResources.Shared, claimFirstProbe, roundStartedAt, controlRound);
        using var preparing = CancellationTokenSource.CreateLinkedTokenSource(token);
        async Task<NativeDatagramPath> PrepareOne(IPEndPoint peer) {
            try {
                preparing.Token.ThrowIfCancellationRequested();
                return await NativeDatagramPath.Prepare(executable, root, owner.Lease, owner.Lease.NetworkGeneration,
                    context, peer, sharedKey, preparing.Token, captureOwner: owner, countWireControl: true, group: result.group);
            } catch { preparing.Cancel(); throw; }
        }
        // Bounded by the already validated <=8 tuples. Prepare concurrently to
        // preserve the caller's short forecast lifetime; never start a SYN here.
        var pending = peers.Select(peer => PrepareOne(peer!)).ToArray();
        try {
            result.paths.AddRange(await Task.WhenAll(pending));
            return result;
        } catch {
            // WhenAll has joined every preparation, including ones which won a
            // cancellation race. Their workers still need explicit disposal.
            result.paths.AddRange(pending.Where(p => p.IsCompletedSuccessfully).Select(p => p.Result));
            await result.DisposeAsync(); throw;
        }
    }
    public Task<IMeshDatagramPath> Activate(CancellationToken token)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (activation != null) return activation;
            if (!Armed) throw new IOException("Port-window capture is not ready");
            return activation ??= ActivateCore(token);
        }
    }
    async Task<IMeshDatagramPath> ActivateCore(CancellationToken token)
    {
        using var attempts = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
        group.Join(Stopwatch.GetTimestamp());
        if (RemainingAttemptTime <= TimeSpan.Zero) throw new IOException("PredictionRoundExpired");
        attempts.CancelAfter(RemainingAttemptTime);
        var pending = paths.Select(p => p.Activate(attempts.Token)).ToList();
        var all = pending.ToArray(); NativeDatagramPath? winner = null;
        try {
            while (pending.Count != 0) {
                var completed = await Task.WhenAny(pending.Cast<Task>().Append(group.Rejected));
                if (ReferenceEquals(completed, group.Rejected)) throw new IOException("PredictionClaimRejected");
                var next = (Task<IMeshDatagramPath>)completed; pending.Remove(next);
                try { winner = (NativeDatagramPath)await next; break; }
                catch when (!token.IsCancellationRequested && !stop.IsCancellationRequested) { }
            }
            if (winner == null) throw new IOException(group.ClaimRejected ? "PredictionClaimRejected" : "NoDirectPathWithinBudget");
        } finally {
            attempts.Cancel();
            try { await Task.WhenAll(all); } catch { }
            // A qualified winner is not yet Router-selected. Join every loser
            // before returning so later selection cannot exempt its traffic.
            try { await Task.WhenAll(paths.Where(p => !ReferenceEquals(p, winner)).Select(p => p.DisposeAsync().AsTask())); }
            catch { if (winner != null) await winner.DisposeAsync(); throw; }
        }
        lock (gate) {
            if (!disposed && !token.IsCancellationRequested && !stop.IsCancellationRequested && RemainingAttemptTime > TimeSpan.Zero) {
                transferred = winner; return winner;
            }
        }
        await winner.DisposeAsync(); throw new OperationCanceledException("Port-window attempt ended before ownership transfer", token);
    }
    public ValueTask DisposeAsync()
    {
        lock (gate) {
            if (closing != null) return new(closing);
            disposed = true; stop.Cancel(); return new(closing = Close());
        }
    }
    async Task Close()
    {
        if (activation != null) try { await activation; } catch { }
        try { await Task.WhenAll(paths.Where(p => !ReferenceEquals(p, transferred)).Select(p => p.DisposeAsync().AsTask())); }
        finally { stop.Dispose(); }
    }
}
