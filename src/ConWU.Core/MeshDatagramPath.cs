namespace StreamLink.Core;

// Completion means the path has joined its I/O and released its own resource
// references. A failed close stays observable and is not ownership proof.
public interface IPathResourceLifetime { Task ResourceReleased { get; } }

// A retained resource reference transferred to MeshRouter on successful
// registration. Exactly one Receive consumer; disposal must release only this
// reference, not the owning attempt or another peer's reference.
public interface IMeshDatagramPath : IAsyncDisposable
{
    ValidatedPathIdentity Identity { get; }
    bool Failed { get; }
    // Bounded/non-blocking enqueue. The implementation owns a copy on success.
    bool TrySend(ReadOnlySpan<byte> datagram);
    ValueTask<ReadOnlyMemory<byte>> Receive(CancellationToken token);
}

public sealed record MeshPathStatus(Guid PathId, Guid ResourceId, Guid AttemptId, TraversalProfile Profile,
    NominationStage Stage, bool Active, bool Retired, int ControlPackets, int ControlBytes, string Failure,
    bool BidirectionalFresh = false, double? RoundTripMs = null)
{
    public NativeWireStats? WireControl { get; init; }
    public DatagramQueueStats? SendQueue { get; init; }
    public PathTrafficSnapshot? Traffic { get; init; }
    public PathDeliverySnapshot? Delivery { get; init; }
    public PathKeepaliveSnapshot? Keepalive { get; init; }
    public bool StandbyReady { get; init; }
}
