using StreamLink.Core;
using System.Net;

static class RelativeSessionModels
{
    public static object Run(Action<bool,string> check)
    {
        int cases=0;
        foreach(string mode in new[]{"good","duplicate","ordinary-pongs","wrong-path","wrong-leg","no-pongs"})for(int round=0;round<30;round++){
            var clock=new Clock();Guid id=Guid.NewGuid();byte[] scope=new byte[32];
            var pa=new PathDiagnosticResources().TryBegin(id)!;var pb=new PathDiagnosticResources().TryBegin(id)!;
            var queue=new Queue<(bool A,byte[] Body)>();PathDiagnosticSession? a=null,b=null;int sourceCalls=0,probes=0;
            var ia=Enumerable.Range(0,2).Select(_=>Identity()).ToArray();var ib=Enumerable.Range(0,2).Select(_=>Identity()).ToArray();
            PathDiagnosticTarget Target(bool ownA,int index)=>new((ownA?ia:ib)[index],new Wire(),
                packet=>{(ownA?b:a)!.Data((ownA?ib:ia)[index].PathId,packet);return true;},p=>p,()=>0,
                leg=>{probes++;var receiver=ownA?a:b;Guid path=mode=="wrong-path"?Guid.NewGuid():(ownA?ia:ib)[index].PathId;
                    if(mode!="no-pongs")receiver!.RoundTrip(path,100,mode=="ordinary-pongs"?-1:mode=="wrong-leg"?leg+1:leg);return true;});
            bool Control(bool ownA,byte[] packet){queue.Enqueue((ownA,packet));if(mode=="duplicate")queue.Enqueue((ownA,(byte[])packet.Clone()));return true;}
            Task<PathDiagnosticSendResult> Source(PathDiagnosticAllowance allowance,double rate,int duration,Func<int,int,bool> send,CancellationToken token){
                sourceCalls++;for(int i=0;i<20;i++)send(i,i*10);return Task.FromResult(new PathDiagnosticSendResult(20,0,5000,0,"Completed",0,0));}
            using(a=new(scope,true,1,2,1,pa,i=>Target(true,i),p=>Control(true,p),()=>true,clock,Source,timingVersion:1))
            using(b=new(scope,false,2,1,1,pb,i=>Target(false,i),p=>Control(false,p),()=>true,clock,Source,timingVersion:1)){
                for(int tick=0;tick<1000&&!a.Finished;tick++){
                    a.Tick(clock.Ms);b.Tick(clock.Ms);int n=0;
                    while(queue.TryDequeue(out var m)){
                        if(++n>100)throw new Exception("control storm");
                        if(PathDiagnosticControl.TryParse(m.Body,scope,1,out var parsed,1))(m.A?b:a).Receive(parsed!,clock.Ms);
                    }
                    clock.Ms+=100;
                }
                for(int tick=0;tick<15;tick++){a.Tick(clock.Ms);b.Tick(clock.Ms);while(queue.TryDequeue(out var m)){
                    if(PathDiagnosticControl.TryParse(m.Body,scope,1,out var parsed,1))(m.A?b:a).Receive(parsed!,clock.Ms);}clock.Ms+=100;}
                bool good=mode is"good"or"duplicate";
                check(good?a.Status().State=="Done"&&b.Status().State=="Done":a.Cancelled&&b.Cancelled,mode+": timing-v2 peers jointly complete or cancel within the common deadline");
                check(good?sourceCalls==12:sourceCalls==0,"only current path/leg baseline pongs authorize load; old/ordinary replies cannot grant a source window");
                if(good)check(a.Status().TimingVersion==1&&a.Status().Windows.All(w=>w.Source.IdleRttSamples is>=4 and<=8&&w.Source.IdleRttP95Ms==100&&w.Source.IdleAgeMs<30000)&&
                    a.Status().Windows.Select(w=>w.Source).SequenceEqual(b.Status().Windows.Select(w=>w.Source)),"baseline samples and age agree between authenticated source/receipt records in all twelve windows");
                check(probes<=32&&!pa.Active&&!pb.Active,"baseline probes and final permits stay bounded even with duplicate controls");cases++;
            }
        }
        return new{cases,scope="deterministic control/nonce-label/path/leg models with synthetic RTTs; no measured route or throughput"};
    }
    static ValidatedPathIdentity Identity()=>new(Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),null,Guid.NewGuid(),new(IPAddress.Loopback,40001),new(IPAddress.Loopback,40002),TraversalProfile.UdpDirect,PathQualification.MtuQualified);
    sealed class Clock:TimeProvider{public long Ms;public override long TimestampFrequency=>1000;public override long GetTimestamp()=>Ms;}
    sealed class Wire:IPathDiagnosticWire{public bool SupportsDiagnosticWire=>true;public void GrantDiagnosticWire(PathDiagnosticAllowance allowance){}}
}
