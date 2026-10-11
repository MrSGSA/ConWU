using System.Diagnostics;

namespace StreamLink.Core;

// Local broker metadata, never added to the public FakeTCP/HTTP packet.
public enum NativeWireKind { Handshake = 0, Maintenance = 1, Business = 2, Completion = 3 }
public sealed record NativeWireStats(long HandshakePackets, long HandshakeBytes, long MaintenancePackets,
    long MaintenanceBytes, long BusinessPackets, long BusinessBytes, long Denied, bool Selected);

// The public-IP frame is charged at its final injection point. Upper-layer
// bridge/nomination enqueue attempts must not charge the same packet again.
public sealed class NativeWireBudget(TraversalControlRound round)
{
    readonly object gate = new();
    long started, handshakePackets, handshakeBytes, maintenancePackets, maintenanceBytes, businessPackets, businessBytes, denied;
    bool selected;
    public void Start(long timestamp)
    {
        lock (gate) {
            if (timestamp <= 0 || started != 0 && started != timestamp) throw new InvalidOperationException("Wire round cannot restart its deadline");
            started = timestamp;
        }
    }
    public void Select() { lock (gate) { if (started == 0) throw new InvalidOperationException("Wire round has not started"); selected = true; } }
    public NativeWireStats Snapshot() { lock (gate) return new(handshakePackets, handshakeBytes, maintenancePackets, maintenanceBytes, businessPackets, businessBytes, denied, selected); }
    public bool Admit(NativeWireKind kind, int bytes)
    {
        if (!Enum.IsDefined(kind) || bytes is < 40 or > 65535) throw new ArgumentException("Invalid native wire frame metadata");
        lock (gate) {
            // Before authenticated joint nomination, even a Business label is
            // only an attempt packet and cannot bypass the shared round budget.
            if (!selected) {
                if (started == 0 || Stopwatch.GetElapsedTime(started).TotalMilliseconds >= TraversalLimits.SoRoundMs ||
                    !round.TrySend(bytes, kind is NativeWireKind.Completion or NativeWireKind.Maintenance)) { denied++; return false; }
                handshakePackets++; handshakeBytes += bytes; return true;
            }
            if (kind == NativeWireKind.Business) { businessPackets++; businessBytes += bytes; return true; }
            if (!round.TryMaintenance(bytes)) { denied++; return false; }
            maintenancePackets++; maintenanceBytes += bytes; return true;
        }
    }
}

public interface IWireControlPath
{
    bool CountsWireControl { get; }
    NativeWireStats? WireControl { get; }
    void SelectWireBudget();
}
