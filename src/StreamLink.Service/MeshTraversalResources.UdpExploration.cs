using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Service;

internal sealed partial class MeshCandidateFactory
{
    internal TraversalResources? ExplorationBudgetForTest { get; init; }
    internal Func<IPEndPoint, ITraversalSocket>? OpenExplorationSocketForTest { get; init; }
    internal Func<UdpTraversal, Guid, NatObservation[], MeshTraversalCandidate?, UdpStableSourceEvidence?>? ExplorationEvidenceForTest { get; init; }
    internal Func<IPEndPoint, int[]>? ExplorationTargetsForTest { get; init; }
    public bool SupportsUdpExploration => options.UdpExploration && options.TraversalMode == "tcp-udp" &&
        options.Selection().Allows(TraversalProfile.UdpDirect) && Profiles.Contains(TraversalProfile.UdpDirect);
    public Task<IMeshCandidateResource> GatherEnhanced(MeshMember peer, TraversalProfile profile, Guid attempt, bool allowIpv6,
        MeshTraversalCandidate? remote, int round, bool predictionAllowed, bool peerSourceAllowed, bool explorationAllowed, Func<bool> stillEligible, CancellationToken token) =>
        GatherCurrent(ct => GatherEnhancedCurrent(peer,profile,attempt,allowIpv6,remote,round,predictionAllowed,peerSourceAllowed,explorationAllowed,stillEligible,ct),token);
    Task<IMeshCandidateResource> GatherEnhancedCurrent(MeshMember peer, TraversalProfile profile, Guid attempt, bool allowIpv6,
        MeshTraversalCandidate? remote, int round, bool predictionAllowed, bool peerSourceAllowed, bool explorationAllowed, Func<bool> stillEligible, CancellationToken token)
    {
        if (remote?.Exploration != null && (!explorationAllowed || !SupportsUdpExploration || profile != TraversalProfile.UdpDirect ||
            remote.Prediction != null || remote.PeerReflexive || IPEndPoint.Parse(remote.Endpoint).AddressFamily != AddressFamily.InterNetwork))
            throw new IOException("UDP 探索未获双方、服务与本机策略授权");
        if (remote?.Exploration != null && RouteCheckForTest == null && !PortControlRoute.GlobalV4(IPEndPoint.Parse(remote.Endpoint).Address))
            throw new IOException("UDP 探索只能使用已认证对端声明的公网 IPv4");
        if (remote?.Exploration != null || remote == null && round >= 2 && explorationAllowed && SupportsUdpExploration && profile == TraversalProfile.UdpDirect) {
            if (!stillEligible()) throw new IOException("UDP 探索目标已有健康路径");
            return GatherExploration(peer, attempt, remote, stillEligible, token);
        }
        return GatherSourceAware(peer, profile, attempt, allowIpv6, remote, round, predictionAllowed, peerSourceAllowed, token);
    }
    ITraversalSocket OpenExplorationSocket(IPEndPoint local, string fairness)
    {
        ITraversalSocket socket = OpenExplorationSocketForTest?.Invoke(local) ?? new TraversalSocket(local);
        if (pacer != null) socket = new PacedTraversalSocket(socket, pacer, fairness);
        return socket;
    }
    static bool PhysicalPublic(IPEndPoint local) => PortControlRoute.GlobalV4(local.Address) &&
        NetworkInterface.GetAllNetworkInterfaces().Any(n => Ipv6Direct.Physical(n) && n.OperationalStatus == OperationalStatus.Up &&
            n.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(local.Address)));
    static int[] GuessUdpPorts(IPEndPoint hint)
    {
        var values = new HashSet<int>();
        // This is a bounded guess order, not a fitted port prediction or a
        // claim that a NAT allocator uses adjacent ports.
        for (int i = -16; i <= 16; i++) if (hint.Port + i is >= 1024 and <= 65535) values.Add(hint.Port + i);
        while (values.Count < 256) values.Add(RandomNumberGenerator.GetInt32(1024, 65536));
        return values.Order().ToArray();
    }
    async Task<IMeshCandidateResource> GatherExploration(MeshMember peer, Guid attempt, MeshTraversalCandidate? remote, Func<bool> stillEligible, CancellationToken token)
    {
        UdpExplorationSeed? seed = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(UdpProbeGroup.DurationMs);
        var machine = ExplorationBudgetForTest ?? TraversalResources.Shared;
        var observations = new List<NatObservation>(); IPEndPoint? target = null;
        try {
            Exception? last = null;
            foreach (var name in options.UdpStun.Distinct().Take(3)) {
                using var resolve = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token); resolve.CancelAfter(1500);
                try { var resolved = await ResolveTarget(name, AddressFamily.InterNetwork, resolve.Token); CheckRoute(resolved); target = resolved; break; }
                catch (Exception ex) when (!deadline.IsCancellationRequested && ex is IOException or SocketException or OperationCanceledException or ArgumentException) { last = ex; }
            }
            if (target == null) throw new IOException("UDP 探索无法解析独立候选观察目标", last);
            byte[] shared = MeshIdentity.SharedKey(options.Mesh!, peer);
            UdpTraversal node;
            try { node = UdpTraversal.CreateUsing(() => OpenExplorationSocket(new(Stun.LocalAddress(target), 0), peer.Device), generation, attempt,
                options.Mesh!.Self.Slot, peer.Slot, shared, machine); }
            finally { CryptographicOperations.ZeroMemory(shared); }
            try { seed = new(node, machine); } catch { await node.DisposeAsync(); throw; }
            observations.Add(await node.Observe(target, deadline.Token));
            var mapped = observations[0].Mapped;
            if (RouteCheckForTest == null && !PortControlRoute.GlobalV4(mapped.Address)) throw new IOException("UDP 探索观察未得到可使用的公网 IPv4");
            CheckRoute(mapped);
            UdpStableSourceEvidence? proof = null;
            if (remote?.Exploration?.Stable != true && mapped.Equals(node.Local) && PhysicalPublic(node.Local)) {
                foreach (var name in options.UdpStun.Distinct().Take(4)) {
                    using var fast = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token); fast.CancelAfter(1000);
                    try {
                        var other = await ResolveTarget(name, AddressFamily.InterNetwork, fast.Token);
                        if (observations.Any(o => o.Target.Address.Equals(other.Address))) continue;
                        CheckRoute(other, node.Local.Address); observations.Add(await node.Observe(other, fast.Token));
                        proof = UdpStableSourceEvidence.PublicLocal(node, generation, observations.ToArray(), PhysicalPublic(node.Local)); break;
                    } catch (Exception ex) when (!deadline.IsCancellationRequested && ex is IOException or SocketException or OperationCanceledException or ArgumentException) { }
                }
            }
            // Only injected test providers can attest an external mapping table;
            // production never infers peer-port stability from unrelated STUN.
            if (remote?.Exploration?.Stable != true && ExplorationEvidenceForTest != null)
                proof = ExplorationEvidenceForTest(node, generation, observations.ToArray(), remote);
            if (remote?.Exploration is { Stable: false } && proof == null) throw new IOException("UdpStableEndpointUnavailable：双方没有合格稳定源证据");
            bool stable = remote?.Exploration?.Stable != true && proof != null;
            var targets = stable ? [] : ExplorationTargetsForTest?.Invoke(mapped) ?? GuessUdpPorts(mapped);
            if (!stable) _ = MeshUdpExploration.Ports(MeshUdpExploration.FormatPorts(targets));
            long observed = observations.Min(o => o.ObservedAt.ToUnixTimeSeconds());
            var description = stable ? proof!.Description : new UdpExplorationCandidate(false, Guid.Empty, "", 0, MeshUdpExploration.FormatPorts(targets), "");
            var candidate = new MeshTraversalCandidate(Guid.NewGuid(), 1, mapped.ToString(), target.ToString(), observed, observed + 12,
                CandidatePurpose.UdpDirect, Exploration: description);
            MeshUdpExploration.Validate(candidate, TraversalProfile.UdpDirect);
            if (seed.Remaining <= TimeSpan.Zero || !stillEligible()) throw new IOException("UDP 探索种子已过期或已有健康路径");
            var result = new ExplorationResource(this, peer, candidate, seed, proof, stillEligible); seed = null; return result;
        } finally { if (seed != null) await seed.DisposeAsync(); }
    }
    sealed class ExplorationResource(MeshCandidateFactory owner, MeshMember peer, MeshTraversalCandidate candidate, UdpExplorationSeed seed,
        UdpStableSourceEvidence? proof, Func<bool> stillEligible) : IMeshCandidateResource
    {
        bool prepared;
        UdpProbabilityPreparation? exploration;
        public MeshTraversalCandidate Candidate => candidate;
        public TimeSpan ExplorationRemaining => seed.Remaining;
        public object? ExplorationStats => exploration?.Statistics;
        public Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context, IPEndPoint remote, CancellationToken token) =>
            throw new IOException("UDP 探索必须使用完整双方签名候选");
        public async Task<IPreparedMeshPath> PrepareCandidate(TraversalAttemptContext context, MeshTraversalCandidate remote, CancellationToken token)
        {
            if (prepared || !context.UdpExploration || !stillEligible()) throw new IOException("UDP 探索资源已接入、未授权或目标已健康");
            MeshUdpExploration.Validate(remote, TraversalProfile.UdpDirect); MeshUdpExploration.Pair(candidate, remote);
            var local = seed.Owner.Local; var remoteEndpoint = IPEndPoint.Parse(remote.Endpoint); owner.CheckRoute(remoteEndpoint, local.Address);
            if (owner.RouteCheckForTest == null && !PortControlRoute.GlobalV4(remoteEndpoint.Address)) throw new IOException("UDP 探索拒绝非公网对端地址");
            bool stable = candidate.Exploration!.Stable;
            int[] targets = stable ? MeshUdpExploration.Ports(remote.Exploration!.Targets) : [];
            if (stable) (proof ?? throw new IOException("UDP 稳定证据缺失")).Require(seed.Owner, owner.generation, IPEndPoint.Parse(candidate.Endpoint), remoteEndpoint.Address, targets);
            byte[] shared = MeshIdentity.SharedKey(owner.options.Mesh!, peer);
            try {
                var result = await UdpProbabilityPreparation.CreateForSeed(seed, context, owner.generation, shared, stable, remoteEndpoint.Address,
                    stable ? null : remoteEndpoint, targets, stable ? 1 : 32, _ => owner.OpenExplorationSocket(new(local.Address, 0), peer.Device), token, stillEligible, proof?.Kind == "peer-ports");
                try {
                    owner.observationLog?.Invoke($"UDP 探索资源就绪：{(stable ? "稳定端" : "严格端")}；实际 {result.SocketIds.Length}/{(stable ? 1 : 32)} 源；共同期限剩余 {result.RemainingAttemptTime.TotalMilliseconds:F0} ms；外部映射确认数 Unknown");
                    exploration = result; prepared = true; return result;
                } catch { await result.DisposeAsync(); throw; }
            } finally { CryptographicOperations.ZeroMemory(shared); }
        }
        public ValueTask DisposeAsync() => seed.DisposeAsync();
    }
}
