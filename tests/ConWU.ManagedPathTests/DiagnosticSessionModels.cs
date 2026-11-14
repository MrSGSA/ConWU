using System.Security.Cryptography;
using StreamLink.Core;

static class DiagnosticSessionModels
{
    public static object Run(Action<bool,string> check)
    {
        int cases=0;
        foreach(string mode in new[]{"normal","lose-ready","lose-prepare","lose-prepared","lose-start","lose-end","lose-report","lose-ack","lose-done","lose-completed","duplicate","busy","cancel"})for(int round=0;round<30;round++){
            var clock=new Clock();Guid id=Guid.NewGuid();byte[] scope=RandomNumberGenerator.GetBytes(32);
            using var permitA=new PathDiagnosticResources(clock).TryBegin(id)!;using var permitB=new PathDiagnosticResources(clock).TryBegin(id)!;
            var queue=new Queue<(bool A,byte[] Body)>();bool dropped=false,busy=false;int sources=0;
            bool Control(bool fromA,byte[] body){
                var step=(PathDiagnosticStep)body[5];bool drop=!dropped&&(mode=="lose-prepare"&&step==PathDiagnosticStep.Prepare||mode=="lose-ready"&&step==PathDiagnosticStep.Ready||
                    mode=="lose-prepared"&&step==PathDiagnosticStep.Prepared||mode=="lose-start"&&step==PathDiagnosticStep.Start||mode=="lose-end"&&step==PathDiagnosticStep.End||
                    mode=="lose-report"&&step==PathDiagnosticStep.Report||mode=="lose-ack"&&step==PathDiagnosticStep.Ack||mode=="lose-done"&&step==PathDiagnosticStep.Done||
                    mode=="lose-completed"&&step==PathDiagnosticStep.Completed);
                if(drop){dropped=true;return true;}queue.Enqueue((fromA,body));if(mode=="duplicate")queue.Enqueue((fromA,(byte[])body.Clone()));return true;
            }
            PathDiagnosticSession? a=null,b=null;
            var identitiesA=Enumerable.Range(0,2).Select(_=>Identity()).ToArray();var identitiesB=Enumerable.Range(0,2).Select(_=>Identity()).ToArray();
            PathDiagnosticTarget Target(bool localA,int index)=>new((localA?identitiesA:identitiesB)[index],new Wire(),
                payload=>{(localA?b:a)!.Data((localA?identitiesB:identitiesA)[index].PathId,payload);return true;},p=>p,()=>0);
            Task<PathDiagnosticSendResult> Source(PathDiagnosticAllowance allowance,double rate,int duration,Func<int,int,bool> send,CancellationToken token){
                sources++;for(int i=0;i<20;i++)send(i,i*10);return Task.FromResult(new PathDiagnosticSendResult(20,0,5000,0,"Completed",0,0));
            }
            using(a=new(scope,true,1,2,1,permitA,i=>Target(true,i),body=>Control(true,body),()=>!busy,clock,Source))
            using(b=new(scope,false,2,1,1,permitB,i=>Target(false,i),body=>Control(false,body),()=>!busy,clock,Source)){
                for(int tick=0;tick<1000&&!a.Finished;tick++){
                    if(mode=="busy"&&sources>0)busy=true;if(mode=="cancel"&&sources>0)a.Cancel("model cancellation");
                    a.Tick(clock.Ms);b.Tick(clock.Ms);int bounded=0;
                    while(queue.TryDequeue(out var message)){
                        if(++bounded>100)throw new Exception("diagnostic control response storm");
                        if(PathDiagnosticControl.TryParse(message.Body,scope,1,out var parsed))(message.A?b:a).Receive(parsed!,clock.Ms);
                    }
                    clock.Ms+=100;
                }
                // Send bounded cancellation/completion reconciliation after local end.
                for(int n=0;n<15;n++){a.Tick(clock.Ms);b.Tick(clock.Ms);while(queue.TryDequeue(out var m)){
                    if(PathDiagnosticControl.TryParse(m.Body,scope,1,out var parsed))(m.A?b:a).Receive(parsed!,clock.Ms);}clock.Ms+=100;}
                bool negative=mode is"busy"or"cancel";
                check(negative?a.Cancelled&&b.Cancelled:a.Status().State=="Done"&&b.Status().State=="Done",mode+": model endpoints converge or cancel inside common deadline");
                check(negative?sources<=1:sources==12,"duplicate/late control cannot create another source task or skip a directional window");
                if(!negative)check(a.Status().Windows.Length==12&&b.Status().Windows.Length==12&&a.Status().Windows.All(w=>w.Receipt.ReceivedPackets==20),
                    "both model peers retain one immutable receipt per active/standby direction, including implicit acknowledgment");
                check(!permitA.Active&&!permitB.Active,"completion/cancellation releases both machine diagnostic permits");cases++;
            }
        }
        return new{cases,scope="deterministic protocol/control/receipt models with instant synthetic source results; no sockets, native I/O or capacity proof"};
    }
    static ValidatedPathIdentity Identity()=>new(Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),null,Guid.NewGuid(),
        new(System.Net.IPAddress.Loopback,40001),new(System.Net.IPAddress.Loopback,40002),TraversalProfile.UdpDirect,PathQualification.MtuQualified);
    sealed class Wire:IPathDiagnosticWire{public bool SupportsDiagnosticWire=>true;public void GrantDiagnosticWire(PathDiagnosticAllowance allowance){}}
    sealed class Clock:TimeProvider{public long Ms;public override long TimestampFrequency=>1000;public override long GetTimestamp()=>Ms;}
}
