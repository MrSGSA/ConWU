using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// Local proof binds the continuously held resource. Public metadata exposes
// only a random proof ID and its limited scope, never the SocketResourceId.
internal sealed class UdpStableSourceEvidence
{
    readonly Guid socket, generation;
    readonly IPEndPoint local, mapped;
    readonly string ports, peer;
    public Guid Id { get; } = Guid.NewGuid();
    public string Kind { get; }
    public long ObservedAt { get; }
    UdpStableSourceEvidence(UdpTraversal owner, Guid generation, IPEndPoint mapped, string kind, long observedAt, string peer = "", string ports = "")
    {
        socket = owner.SocketId; this.generation = generation; local = Copy(owner.Local); this.mapped = Copy(mapped);
        Kind = kind; ObservedAt = observedAt; this.peer = peer; this.ports = ports;
    }
    static IPEndPoint Copy(IPEndPoint endpoint) => new(IPAddress.Parse(endpoint.Address.ToString()), endpoint.Port);
    static void Validate(UdpTraversal owner, Guid generation, NatObservation[] observations)
    {
        if (generation == Guid.Empty || !owner.ReceiveReady || observations.Length == 0 || observations.Length > 256 ||
            owner.Local.AddressFamily != AddressFamily.InterNetwork || observations.Any(o => o.SocketId != owner.SocketId || o.NetworkGeneration != generation ||
                o.Protocol != "udp" || !o.Local.Equals(owner.Local) || o.Target.AddressFamily != AddressFamily.InterNetwork || o.Mapped.AddressFamily != AddressFamily.InterNetwork ||
                o.ObservedAt > DateTimeOffset.UtcNow || DateTimeOffset.UtcNow - o.ObservedAt > TimeSpan.FromMilliseconds(UdpProbeGroup.DurationMs)) ||
            observations.Select(o => o.Mapped).Distinct().Count() != 1)
            throw new IOException("UDP 稳定证据不能混合源资源、协议、代次、过期或变化映射");
    }
    public static UdpStableSourceEvidence PublicLocal(UdpTraversal owner, Guid generation, NatObservation[] observations, bool physicalPublicSource)
    {
        Validate(owner, generation, observations);
        if (!physicalPublicSource || !PortControlRoute.GlobalV4(owner.Local.Address) || !observations.All(o => o.Mapped.Equals(owner.Local)) ||
            observations.Select(o => o.Target.Address).Distinct().Count() < 2)
            throw new IOException("UDP 稳定入口缺少物理公网源与独立目标的同端点观察");
        return new(owner, generation, owner.Local, "public-local", observations.Min(o => o.ObservedAt.ToUnixTimeSeconds()));
    }
    // A peer-specific provider must have observed EVERY authorized target port
    // from this source. Unrelated public STUN targets cannot authorize it.
    public static UdpStableSourceEvidence PeerPorts(UdpTraversal owner, Guid generation, IPAddress peer, int[] targetPorts, NatObservation[] observations)
    {
        Validate(owner, generation, observations);
        string ports = MeshUdpExploration.FormatPorts(targetPorts);
        if (peer.AddressFamily != AddressFamily.InterNetwork || observations.Any(o => !o.Target.Address.Equals(peer)) ||
            !observations.Select(o => o.Target.Port).Distinct().Order().SequenceEqual(targetPorts.Order()))
            throw new IOException("UDP 稳定观察必须覆盖本次对端 IP 的完整授权端口集合");
        return new(owner, generation, observations[0].Mapped, "peer-ports", observations.Min(o => o.ObservedAt.ToUnixTimeSeconds()), peer.ToString(), ports);
    }
    public UdpExplorationCandidate Description => new(true, Id, Kind, ObservedAt, ports, peer);
    public static UdpStableSourceEvidence Empirical(UdpTraversal owner, Guid generation, NatObservation[] training, NatObservation[] holdout, bool explicitlyEnabled)
    {
        Validate(owner, generation, training.Concat(holdout).ToArray());
        var result = UdpEmpiricalEvidenceProvider.Evaluate(owner, generation, training, holdout, explicitlyEnabled);
        if (!result.ExperimentalAdmission) throw new IOException("UdpStableEndpointUnavailable: " + result.Reason);
        return new(owner, generation, training[0].Mapped, "empirical-eim-v1", training.Min(o => o.ObservedAt.ToUnixTimeSeconds()));
    }
    public void Require(UdpTraversal owner, Guid expectedGeneration, IPEndPoint advertised, IPAddress peerAddress, int[] targets)
    {
        if (owner.SocketId != socket || expectedGeneration != generation || !owner.Local.Equals(local) || !advertised.Equals(mapped) || !owner.ReceiveReady ||
            Kind == "peer-ports" && (peer != peerAddress.ToString() || ports != MeshUdpExploration.FormatPorts(targets)))
            throw new IOException("UDP 稳定证据不属于实际持有资源或本轮目标集合");
    }
}
