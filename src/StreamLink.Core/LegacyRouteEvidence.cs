using System.Net;

namespace StreamLink.Core;
public sealed record LegacyRouteReport(Guid Generation,ulong CaptureEpoch,EgressRouteWitness[] Witnesses,long StaleRejected,long Unavailable,bool Enforced);

// A synchronous prepare precedes the native control permit. The packet's actual
// source is authoritative; the local UDP bridge endpoint is never a substitute.
internal sealed class LegacyRouteEvidence(Guid generation,bool enforced,Func<IPEndPoint,IPEndPoint,Guid,ulong,EgressRouteWitness>? observer=null)
{
    readonly object gate=new();
    readonly Dictionary<(IPEndPoint Source,IPEndPoint Target),(EgressRouteWitness Witness,long At)> records=[];
    readonly Func<IPEndPoint,IPEndPoint,Guid,ulong,EgressRouteWitness> observe=observer??EgressRouteSnapshot.Bound;
    ulong epoch;long stale,unavailable;
    internal LegacyRouteReport Snapshot(){lock(gate)return new(generation,epoch,records.Values.Select(r=>r.Witness).Take(8).ToArray(),stale,unavailable,enforced);}
    internal bool Prepare(ulong capture,IPEndPoint source,IPEndPoint target,out EgressRouteWitness? witness)
    {
        witness=null;
        lock(gate){
            if(capture<epoch){stale++;return false;}
            if(capture>epoch){epoch=capture;records.Clear();}
            if(records.TryGetValue((source,target),out var saved)&&Environment.TickCount64-saved.At<1000){witness=saved.Witness;return !enforced||witness.Ready;}
        }
        var next=observe(source,target,generation,capture);
        lock(gate){
            if(capture!=epoch){stale++;return false;}
            if(records.Count>=32&&!records.ContainsKey((source,target))){unavailable++;return !enforced;}
            if(!next.Ready)unavailable++;records[(source,target)]=(next,Environment.TickCount64);witness=next;return !enforced||next.Ready;
        }
    }
    internal bool Use(ulong capture,IPEndPoint source,IPEndPoint target,out EgressRouteWitness? witness)
    {
        witness=null;lock(gate){
            if(capture!=epoch||!records.ContainsKey((source,target))){stale++;return false;}
        }return Prepare(capture,source,target,out witness);
    }
}
