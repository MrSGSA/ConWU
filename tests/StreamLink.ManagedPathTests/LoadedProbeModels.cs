using StreamLink.Core;

static class LoadedProbeModels
{
    public static object Run(Action<bool,string> check)
    {
        var rows = new List<object>();
        foreach (string mode in new[] { "correct", "wrong-leg", "baseline", "unmarked", "denied" }) {
            var clock = new Clock(); Guid id = Guid.NewGuid(), path = Guid.NewGuid(); byte[] scope = new byte[32];
            using var permit = new PathDiagnosticResources(clock).TryBegin(id)!;
            var messages = new List<PathDiagnosticMessage>(); int probes = 0;
            var completion = new TaskCompletionSource<PathDiagnosticSendResult>(); PathDiagnosticSession? session = null;
            var identity = new ValidatedPathIdentity(path, Guid.NewGuid(), Guid.NewGuid(), null, Guid.NewGuid(),
                new(System.Net.IPAddress.Loopback,41000),new(System.Net.IPAddress.Loopback,41001),TraversalProfile.UdpDirect,PathQualification.MtuQualified);
            var target = new PathDiagnosticTarget(identity,new Wire(),_=>true,p=>p,()=>0,null,leg=>{
                probes++;
                if(mode=="denied")return false;
                session!.RoundTrip(path,10,mode=="baseline"?leg:-1,mode=="correct"?leg:mode=="wrong-leg"?leg+1:-1);
                return true;
            });
            using(session=new(scope,true,1,2,1,permit,_=>target,body=>{
                if(PathDiagnosticControl.TryParse(body,scope,1,out var parsed))messages.Add(parsed!);return true;
            },()=>true,clock,(_,_,_,_,_)=>completion.Task)){
                session.Receive(new(PathDiagnosticStep.Ready,id,0,1),clock.Ms);
                session.Receive(new(PathDiagnosticStep.Prepared,id,0,1),clock.Ms);
                clock.Ms=500;session.Tick(clock.Ms);
                check(session.LoadedLeg(path)==0&&session.LoadedLeg(Guid.NewGuid())==-1,mode+": timing ownership binds to the actual source path and current leg");
                for(int i=0;i<10;i++){clock.Ms+=500;session.Tick(clock.Ms);}
                check(probes<=10&&probes==(mode=="correct"?4:10),mode+": loaded probes have a fixed attempt count and stop after sufficient returned samples");
                completion.SetResult(new(20,0,5000,1,"Completed",0,0));session.Tick(clock.Ms);clock.Ms+=500;session.Tick(clock.Ms);
                var summary=messages.Last(m=>m.Step==PathDiagnosticStep.End).Source!;
                check(summary.RttSamples==(mode=="correct"?4:0),mode+": wrong leg, idle baseline, unmarked or denied timing never qualifies as loaded evidence");
                int before=probes;clock.Ms+=500;session.Tick(clock.Ms);
                check(session.LoadedLeg(path)==-1&&probes==before,mode+": draining and control reconciliation cannot add synthetic loaded probes");
                rows.Add(new{mode,probes,samples=summary.RttSamples});
            }
        }
        return new{rows,scope="deterministic diagnostic timing/phase model; no socket, driver, network capacity or deadline delivery claim"};
    }
    sealed class Clock:TimeProvider {public long Ms;public override long TimestampFrequency=>1000;public override long GetTimestamp()=>Ms;}
    sealed class Wire:IPathDiagnosticWire {public bool SupportsDiagnosticWire=>true;public void GrantDiagnosticWire(PathDiagnosticAllowance allowance){}}
}
