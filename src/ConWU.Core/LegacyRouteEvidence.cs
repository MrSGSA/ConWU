using System.Net;
using System.Diagnostics;
using System.Threading.Channels;

namespace StreamLink.Core;
public sealed record LegacyRouteReport(Guid Generation,ulong CaptureEpoch,EgressRouteWitness[] Witnesses,long StaleRejected,long Unavailable,bool Enforced)
{
    public int PendingObservations { get; init; }
    public long ObservationQueueRejected { get; init; }
    public long Observations { get; init; }
    public long MaximumObservationMs { get; init; }
}

// Only enforced egress needs synchronous route preparation. Advisory OS queries
// must never consume the native control packet's 250ms lifetime or IPC deadline.
// Actual packet sources remain authoritative in both modes.
internal sealed class LegacyRouteEvidence(Guid generation,bool enforced,Func<IPEndPoint,IPEndPoint,Guid,ulong,EgressRouteWitness>? observer=null) : IDisposable
{
    readonly object gate=new();
    sealed class Entry { internal EgressRouteWitness? Witness; internal long At; internal bool Pending; }
    readonly Dictionary<(IPEndPoint Source,IPEndPoint Target),Entry> records=[];
    readonly Func<IPEndPoint,IPEndPoint,Guid,ulong,EgressRouteWitness> observe=observer??EgressRouteSnapshot.Bound;
    ulong epoch;long stale,unavailable,queueRejected,observations,maximumObservationMs;bool disposed;
    // One process-wide worker and at most 32 queued queries, including retired
    // owners. An unresponsive OS query cannot spawn more workers on reconnect.
    sealed record Work(LegacyRouteEvidence Owner,ulong Epoch,IPEndPoint Source,IPEndPoint Target,Entry Record);
    static readonly Channel<Work> work=Channel.CreateBounded<Work>(new BoundedChannelOptions(32){SingleReader=true,FullMode=BoundedChannelFullMode.Wait});
    static readonly Task worker=Task.Run(async()=>{
        await foreach(var item in work.Reader.ReadAllAsync()){
            lock(item.Owner.gate)if(item.Owner.disposed||item.Owner.epoch!=item.Epoch)continue;
            item.Owner.Observe(item.Epoch,item.Source,item.Target,item.Record);
        }
    });
    internal LegacyRouteReport Snapshot(){lock(gate)return new(generation,epoch,records.Values.Where(r=>r.Witness!=null).Select(r=>r.Witness!).Take(8).ToArray(),stale,unavailable,enforced){
        PendingObservations=records.Values.Count(r=>r.Pending),ObservationQueueRejected=queueRejected,Observations=observations,MaximumObservationMs=maximumObservationMs};}
    internal bool Prepare(ulong capture,IPEndPoint source,IPEndPoint target,out EgressRouteWitness? witness)
    {
        witness=null;
        Entry record;
        lock(gate){
            if(disposed)return false;
            if(capture<epoch){stale++;return false;}
            if(capture>epoch){epoch=capture;records.Clear();}
            if(!records.TryGetValue((source,target),out record!)){
                if(records.Count>=32){unavailable++;return !enforced;}
                records[(source,target)]=record=new();
            }
            if(record.Witness!=null&&Environment.TickCount64-record.At<1000){witness=record.Witness;return !enforced||witness.Ready;}
            if(!enforced){
                if(!record.Pending){
                    record.Pending=true;
                    if(!work.Writer.TryWrite(new(this,capture,source,target,record))){record.Pending=false;queueRejected++;}
                }
                return true;
            }
        }
        witness=Observe(capture,source,target,record);
        return witness?.Ready==true;
    }
    EgressRouteWitness? Observe(ulong capture,IPEndPoint source,IPEndPoint target,Entry record)
    {
        long began=Stopwatch.GetTimestamp();EgressRouteWitness next;
        try{next=observe(source,target,generation,capture);}
        catch(Exception ex){next=new(generation,capture,source.ToString(),target.ToString(),0,0,"Unknown","Unknown","Unavailable",ex.GetType().Name);}
        lock(gate){
            if(disposed)return null;
            observations++;maximumObservationMs=Math.Max(maximumObservationMs,(long)Stopwatch.GetElapsedTime(began).TotalMilliseconds);
            if(capture!=epoch){stale++;return null;}
            if(!next.Ready)unavailable++;
            record.Witness=next;record.At=Environment.TickCount64;record.Pending=false;return next;
        }
    }
    internal bool Use(ulong capture,IPEndPoint source,IPEndPoint target,out EgressRouteWitness? witness)
    {
        witness=null;lock(gate){
            if(disposed||capture!=epoch||!records.TryGetValue((source,target),out var record)||record.Witness==null){stale++;return false;}
        }return Prepare(capture,source,target,out witness);
    }
    public void Dispose(){lock(gate){disposed=true;records.Clear();}}
}
