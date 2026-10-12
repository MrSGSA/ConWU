using System.Diagnostics;

namespace StreamLink.Core;

// Local broker metadata, never added to the public FakeTCP/HTTP packet.
public enum NativeWireKind { Handshake = 0, Maintenance = 1, Business = 2, Completion = 3, Diagnostic = 4 }
public sealed record NativeWireStats(long HandshakePackets, long HandshakeBytes, long MaintenancePackets,
    long MaintenanceBytes, long BusinessPackets, long BusinessBytes, long Denied, bool Selected, bool Standby = false,
    long DiagnosticPackets = 0, long DiagnosticBytes = 0);

// The public-IP frame is charged at its final injection point. Upper-layer
// bridge/nomination enqueue attempts must not charge the same packet again.
public sealed class NativeWireBudget(TraversalControlRound round, NativeAttemptGroup? group = null, bool diagnosticNative = false, Guid pathId = default)
{
    readonly object gate = new();
    long started, handshakePackets, handshakeBytes, maintenancePackets, maintenanceBytes, businessPackets, businessBytes, denied;
    bool selected;
    long standbyAt;
    long diagnosticPackets,diagnosticBytes;
    PathDiagnosticAllowance? diagnostic;
    bool DiagnosticPathLive=>started!=0&&(selected||standbyAt!=0&&Stopwatch.GetElapsedTime(standbyAt).TotalMilliseconds<StandbyNomination.HoldMs);
    internal bool DiagnosticActive{get{lock(gate)return diagnosticNative&&DiagnosticPathLive&&diagnostic?.Active==true;}}
    internal double DiagnosticDelay(int bytes){lock(gate)return diagnosticNative&&DiagnosticPathLive&&diagnostic!=null?diagnostic.DelaySeconds(bytes):0;}
    internal void GrantDiagnostic(PathDiagnosticAllowance allowance){lock(gate){
        if(!diagnosticNative||!DiagnosticPathLive||pathId==Guid.Empty||allowance.PathId!=pathId||!allowance.Active||diagnostic?.Active==true)
            throw new InvalidOperationException("Diagnostic requires a capable, authenticated exact path and a new bounded window");
        diagnostic=allowance;
    }}
    public void HoldStandby() { lock (gate) {
        if (started == 0 || selected || group != null || standbyAt == 0 && Stopwatch.GetElapsedTime(started).TotalMilliseconds >= TraversalLimits.SoRoundMs)
            throw new InvalidOperationException("Only an authenticated independent round can enter standby within its original deadline");
        if (standbyAt == 0) standbyAt = Stopwatch.GetTimestamp();
    } }
    public long Start(long timestamp)
    {
        lock (gate) {
            if (group != null && !ReferenceEquals(round, group.ControlRound)) throw new InvalidOperationException("A tuple must use its group's control allowance");
            if (timestamp <= 0 || started != 0 && started != timestamp) throw new InvalidOperationException("Wire round cannot restart its deadline");
            started = group?.Join(timestamp) ?? timestamp;
            return started;
        }
    }
    public void Select() { lock (gate) { if (started == 0 || group != null && !group.Claimed) throw new InvalidOperationException("Wire round has not started or acquired its first-probe permit"); selected = true; } }
    public NativeWireStats Snapshot() { lock (gate) return new(handshakePackets, handshakeBytes, maintenancePackets, maintenanceBytes, businessPackets, businessBytes, denied, selected, standbyAt != 0 && !selected,diagnosticPackets,diagnosticBytes); }
    public bool Admit(NativeWireKind kind, int bytes)
    {
        if (!Enum.IsDefined(kind) || bytes is < 40 or > 65535) throw new ArgumentException("Invalid native wire frame metadata");
        lock (gate) {
            if(kind==NativeWireKind.Diagnostic){
                if(!diagnosticNative||!DiagnosticPathLive||diagnostic==null||!diagnostic.Admit(bytes)){denied++;return false;}
                diagnosticPackets++;diagnosticBytes+=bytes;return true;
            }
            if (!selected && standbyAt != 0) {
                if (kind == NativeWireKind.Business || Stopwatch.GetElapsedTime(standbyAt).TotalMilliseconds >= StandbyNomination.HoldMs + StandbyNomination.SelectMs ||
                    !round.TryMaintenance(bytes)) { denied++; return false; }
                maintenancePackets++; maintenanceBytes += bytes; return true;
            }
            // Before authenticated joint nomination, even a Business label is
            // only an attempt packet and cannot bypass the shared round budget.
            if (!selected) {
                if (started == 0 || Stopwatch.GetElapsedTime(started).TotalMilliseconds >= TraversalLimits.SoRoundMs ||
                    !round.TrySend(bytes, kind is NativeWireKind.Completion or NativeWireKind.Maintenance) || group != null && !group.Claim()) { denied++; return false; }
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
    void HoldStandbyWireBudget() => throw new NotSupportedException("Native standby budget not supported");
}
