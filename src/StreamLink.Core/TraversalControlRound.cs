namespace StreamLink.Core;

// Shared by traversal checks and the nominated adapter: obtaining a Path
// reference does not grant another 120 packets or another byte allowance.
public sealed class TraversalControlRound(TraversalResources machine, int maximumPackets = TraversalLimits.RoundPackets)
{
    readonly object gate = new();
    int packets, bytes;
    public int Packets { get { lock (gate) return packets; } }
    public int Bytes { get { lock (gate) return bytes; } }
    public bool TryMaintenance(int length) => machine.TrySend(length, maintenance: true);
    public bool TrySend(int length, bool completion)
    {
        if (length is < 1 or > TraversalLimits.RoundBytes) return false;
        lock (gate) {
            int reserved = Math.Min(TraversalLimits.CompletionReserve, maximumPackets / 4);
            if (packets >= maximumPackets - (completion ? 0 : reserved) || bytes + length > TraversalLimits.RoundBytes || !machine.TrySend(length)) return false;
            packets++; bytes += length; return true;
        }
    }
}
public interface ITraversalControlledPath
{
    TraversalControlRound ControlRound { get; }
}
