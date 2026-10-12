using System.Diagnostics;

namespace StreamLink.Core;

public sealed record LegacyTransportResource(Guid ResourceId, string Mode, bool Server, string Listener,
    string Target, Guid HelperResourceId, int ProcessId, string State, bool RetirementRequested)
{
    public LegacyWireReport? Wire { get; init; }
}
public sealed record LegacyTransportUsage(int OpenResources, int Limit, int PeakResources, long Created,
    LegacyTransportResource[] Resources)
{
    public int ActiveReportedResources { get; init; }
    public int ActiveUnreportedResources { get; init; }
    public long ActiveKnownInjectionPackets { get; init; }
    public long ActiveKnownInjectionBytes { get; init; }
    public string Scope => "Compatibility native resources with optional successful-injection counters; missing snapshots, peer kernel overhead and physical delivery remain unknown";
    public bool CompleteWireAudit => false;
}

// A legacy listener multiplexes peers; each of seven other members can retain
// Active + Candidate clients. This explicit compatibility allowance is distinct
// from the managed eight-source TCP pool, not secretly charged as eight sockets.
public sealed class LegacyTransportLedger
{
    public static LegacyTransportLedger Shared { get; } = new();
    public const int CompatibilityLimit = 1 + 2 * (MeshIdentity.MaxMembers - 1);
    readonly object gate = new();
    readonly Dictionary<Guid, Handle> resources = [];
    readonly Queue<LegacyTransportResource> history = [];
    int peak; long created;
    internal Handle Acquire(string mode, bool server, string listener, string target, Guid helper)
    {
        lock (gate) {
            Reap();
            if(resources.Count>=CompatibilityLimit)throw new IOException("BudgetExhausted: compatibility native transport allowance is full");
            var h=new Handle(this,new(Guid.NewGuid(),mode,server,listener,target,helper,0,"Prepared",false));
            resources.Add(h.Value.ResourceId,h);created++;peak=Math.Max(peak,resources.Count);return h;
        }
    }
    void Reap()
    {
        foreach(var h in resources.Values.Where(h=>h.Value.RetirementRequested).ToArray())if(h.Gone())h.Complete();
    }
    public LegacyTransportUsage Snapshot(){lock(gate){Reap();
        var reports=resources.Values.Select(h=>h.Value.Wire).Where(w=>w!=null).ToArray();
        return new(resources.Count,CompatibilityLimit,peak,created,resources.Values.Select(h=>h.Value).Concat(history.TakeLast(4)).ToArray()){
            ActiveReportedResources=reports.Length,ActiveUnreportedResources=resources.Count-reports.Length,
            ActiveKnownInjectionPackets=reports.Sum(w=>w!.HandshakePackets+w.MaintenancePackets+w.BusinessPackets+w.CompletionPackets+w.DiagnosticPackets),
            ActiveKnownInjectionBytes=reports.Sum(w=>w!.HandshakeBytes+w.MaintenanceBytes+w.BusinessBytes+w.CompletionBytes+w.DiagnosticBytes)
        };
    }}
    internal sealed class Handle(LegacyTransportLedger owner,LegacyTransportResource value):IDisposable
    {
        internal LegacyTransportResource Value=value;
        long processStart;
        bool completed;
        internal Guid ResourceId=>Value.ResourceId;
        internal void WireLine(string line)
        {
            if(!LegacyWireReport.TryParse(line,Value.ResourceId,out var next))return;
            lock(owner.gate){
                if(completed||Value.Wire is{}old&&(next!.Sequence<=old.Sequence||
                    old.FirstObservedSource!="Unknown"&&next.FirstObservedSource!=old.FirstObservedSource||
                    old.Counters().Zip(next.Counters()).Any(p=>p.First>p.Second)))return;
                Value=Value with{Wire=next};
            }
        }
        internal void Started(Process child){lock(owner.gate){
            if(completed)throw new ObjectDisposedException(nameof(Handle));
            Value=Value with{ProcessId=child.Id,State="IdentityPending"};
            processStart=child.StartTime.ToUniversalTime().Ticks;Value=Value with{State="Running"};
        }}
        internal bool Gone()
        {
            if(Value.ProcessId==0)return true;
            try{using var p=Process.GetProcessById(Value.ProcessId);return p.HasExited||processStart!=0&&p.StartTime.ToUniversalTime().Ticks!=processStart;}
            catch(ArgumentException){return true;}
            catch(InvalidOperationException){return true;}
            catch(System.ComponentModel.Win32Exception){return false;} // unknown is still reserved
        }
        internal void Complete()
        {
            if(completed)return;completed=true;Value=Value with{State="Closed",RetirementRequested=true};
            owner.resources.Remove(Value.ResourceId);owner.history.Enqueue(Value);while(owner.history.Count>64)owner.history.Dequeue();
        }
        public void Dispose(){lock(owner.gate){if(completed)return;Value=Value with{State="Retiring",RetirementRequested=true};if(Gone())Complete();}}
    }
}
