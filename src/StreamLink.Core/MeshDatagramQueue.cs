using System.Threading.Channels;

namespace StreamLink.Core;

public sealed record MeshDatagramQueueSnapshot(int QueuedPackets, long OfferedPackets, long DequeuedPackets,
    long DataRejected, long ControlRejected, long DiscardedOnClose)
{
    public bool Conserved => OfferedPackets == DequeuedPackets + DataRejected + ControlRejected + DiscardedOnClose + QueuedPackets;
}

// Keep the existing 128-packet bound, reserving 16 positions for MeshLink
// control. FIFO is preserved: classifying the clear header is admission only,
// never authentication or a change to the peer's sequence/replay domain.
internal sealed class MeshDatagramQueue
{
    const int Capacity = 128, ControlReserve = 16;
    readonly object gate = new();
    readonly Channel<byte[]> packets = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(Capacity) {
        SingleReader = true, AllowSynchronousContinuations = false
    });
    int queued, data;
    long offered, dequeued, dataRejected, controlRejected, discarded;
    bool completed;

    static bool Control(ReadOnlySpan<byte> packet) => packet.Length >= MeshLink.Overhead && packet.StartsWith("SLM4"u8) &&
        (packet[4] is 1 or 2 or 3 && packet.Length == MeshLink.Overhead ||
         packet[4] is 5 or 6 && packet.Length == MeshLink.Overhead + 8 ||
         packet[4] == 7 && packet.Length is >= MeshLink.Overhead + 1 and <= MeshLink.Overhead + 256);

    public bool TryWrite(ReadOnlySpan<byte> packet)
    {
        bool control = Control(packet);
        lock (gate) {
            offered++;
            if (completed || queued >= Capacity || !control && data >= Capacity-ControlReserve) {
                if (control) controlRejected++; else dataRejected++;
                return false;
            }
            if (!packets.Writer.TryWrite(packet.ToArray())) throw new InvalidOperationException("Mesh datagram queue accounting diverged");
            queued++; if (!control) data++;
            return true;
        }
    }
    public async ValueTask<byte[]> Read(CancellationToken token)
    {
        var packet = await packets.Reader.ReadAsync(token);
        lock (gate) { queued--; if (!Control(packet)) data--; dequeued++; }
        return packet;
    }
    public MeshDatagramQueueSnapshot Snapshot()
    {
        lock (gate) return new(queued, offered, dequeued, dataRejected, controlRejected, discarded);
    }
    public void Complete() { lock (gate) { completed = true; packets.Writer.TryComplete(); } }
    // After the sole consumer has joined; no packet can leak into a new path.
    public void Discard()
    {
        lock (gate) {
            completed = true; packets.Writer.TryComplete();
            while (packets.Reader.TryRead(out var packet)) { queued--; if (!Control(packet)) data--; discarded++; }
        }
    }
}
