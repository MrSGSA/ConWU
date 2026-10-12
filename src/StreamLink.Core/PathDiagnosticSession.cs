namespace StreamLink.Core;

public sealed record PathDiagnosticWindow(Guid SessionId,int Leg,int SourceSlot,Guid PathId,Guid ResourceId,Guid NetworkGeneration,
    int TargetMbps,PathDiagnosticSummaryView Source,PathDiagnosticReceipt Receipt,long ObservedMs);
public sealed record PathDiagnosticSummaryView(int Accepted,int Rejected,double ElapsedMs,long AdmittedPackets,long AdmittedBytes,
    long WireDenied,int LoadedRttSamples,double? LoadedRttP95Ms,string Result);
public sealed record PathDiagnosticSessionStatus(Guid SessionId,string State,int Leg,int TargetMbps,string Failure,
    PathDiagnosticCost Cost,PathDiagnosticWindow[] Windows);
internal sealed record PathDiagnosticTarget(ValidatedPathIdentity Identity,IPathDiagnosticWire Wire,Func<byte[],bool> Send,
    Func<byte[],byte[]?> Encode,Func<long> Denied);

// Serialized by the Router gate, with one existing receiver. One source worker
// invokes the callback under that same gate; no second socket or reader exists.
internal sealed class PathDiagnosticSession:IDisposable
{
    enum Phase{WaitReady,WaitPrepared,WaitStart,Sending,Draining,Receiving,Settling,WaitReport,WaitAck,WaitCompleted,Done,Cancelled}
    readonly byte[] scope;
    readonly bool leader;
    readonly int own,remote,target;
    readonly Func<int,PathDiagnosticTarget> getTarget;
    readonly Func<byte[],bool> control;
    readonly Func<bool> healthy;
    readonly PathDiagnosticPermit permit;
    readonly Func<long> clockNow;
    readonly Func<PathDiagnosticAllowance,double,int,Func<int,int,bool>,CancellationToken,Task<PathDiagnosticSendResult>> source;
    readonly CancellationTokenSource stop=new();
    readonly List<PathDiagnosticWindow> windows=[];
    readonly List<double> rtts=[];
    readonly long began;
    Phase phase;
    int leg,controls,cleanupSends;
    long stageAt,sendAt,completedAt,settleAt,beforeDenied;
    bool pendingStart,disposed;
    string failure="";
    PathDiagnosticMessage? outgoing;
    PathDiagnosticAllowance? allowance;
    PathDiagnosticReceiver? receiver;
    Task<PathDiagnosticSendResult>? sending;
    PathDiagnosticSummary? summary;
    PathDiagnosticCost? before;
    PathDiagnosticReceipt? report;
    PathDiagnosticTarget? current;
    public Guid SessionId=>permit.SessionId;
    public bool Finished=>phase is Phase.Done or Phase.Cancelled;
    public bool Cancelled=>phase==Phase.Cancelled;
    public int Leg=>leg;
    public bool IsLocalSource=>(leg<6)==leader;
    public int TargetIndex=>leg%6<3?0:1;
    public PathDiagnosticSessionStatus Status()=>new(SessionId,phase.ToString(),leg,target,failure,permit.Snapshot(),windows.ToArray());
    public PathDiagnosticSession(byte[] scope,bool leader,int own,int remote,int target,PathDiagnosticPermit permit,
        Func<int,PathDiagnosticTarget> getTarget,Func<byte[],bool> control,Func<bool> healthy,TimeProvider? clockForTest=null,
        Func<PathDiagnosticAllowance,double,int,Func<int,int,bool>,CancellationToken,Task<PathDiagnosticSendResult>>? sourceForTest=null)
    {
        if(scope.Length!=32||target is<1 or>50||own==remote)throw new ArgumentException("Invalid diagnostic session");
        this.scope=scope.ToArray();this.leader=leader;this.own=own;this.remote=remote;this.target=target;this.permit=permit;
        this.getTarget=getTarget;this.control=control;this.healthy=healthy;phase=leader?Phase.WaitReady:Phase.WaitStart;
        clockNow=clockForTest==null?()=>Environment.TickCount64:()=>(long)(clockForTest.GetTimestamp()*1000d/clockForTest.TimestampFrequency);
        source=sourceForTest??PathDiagnosticSender.Send;began=clockNow();
        Set(leader?PathDiagnosticStep.Begin:PathDiagnosticStep.Ready);stageAt=began;
    }
    PathDiagnosticMessage Message(PathDiagnosticStep step,PathDiagnosticSummary? s=null,PathDiagnosticReceipt? r=null)=>new(step,SessionId,leg,target,s,r);
    void Set(PathDiagnosticStep step,PathDiagnosticSummary? s=null,PathDiagnosticReceipt? r=null){outgoing=Message(step,s,r);sendAt=0;}
    void Prepare(int next)
    {
        if(allowance!=null){allowance.Dispose();allowance=null;}leg=next;current=getTarget(TargetIndex);rtts.Clear();summary=null;report=null;receiver=null;sending=null;
        if(!IsLocalSource)receiver=new(SessionId,leg);stageAt=clockNow();
    }
    void Source()
    {
        if(sending!=null||current==null||!IsLocalSource)return;
        before=permit.Snapshot();beforeDenied=current.Denied();allowance=permit.Open(current.Identity.PathId,(int)Math.Ceiling(target*1.4),5500);
        current.Wire.GrantDiagnosticWire(allowance);var path=current;int round=leg;
        sending=source(allowance,target*1.05,5000,(index,elapsed)=>{
            byte[]? encoded=path.Encode(PathDiagnosticFrames.Encode(SessionId,round,index,elapsed));return encoded!=null&&path.Send(encoded);
        },stop.Token);phase=Phase.Sending;
    }
    public void Tick(long now)
    {
        if(disposed)return;
        if(!Finished&&(!healthy()||!permit.Active||now-began>=PathDiagnosticPermit.SessionMs||now-stageAt>=12000))Cancel("ResourcesOrDeadline");
        if(phase==Phase.Sending&&sending!.IsCompleted){
            try{_ = sending.GetAwaiter().GetResult();phase=Phase.Draining;completedAt=now;}catch(Exception){Cancel("SourceFailed");}
        }
        if(phase==Phase.Draining&&now-completedAt>=500){
            var sent=sending!.GetAwaiter().GetResult();var cost=permit.Snapshot();double? p95=rtts.Count==0?null:rtts.Order().ElementAt((int)Math.Ceiling(rtts.Count*.95)-1);
            summary=new(sent.AcceptedPackets,sent.RejectedOffers,(long)(sent.ElapsedMs*1000),cost.WirePackets-before!.WirePackets,cost.WireBytes-before.WireBytes,
                Math.Max(0,current!.Denied()-beforeDenied),rtts.Count,p95,sent.Result=="Completed"?1:sent.Result=="Cancelled"?2:3);
            allowance!.Dispose();phase=Phase.WaitReport;Set(PathDiagnosticStep.End,summary);
        }
        if(phase==Phase.Settling&&now-settleAt>=1000){
            int settled=(int)Math.Min(8000,now-settleAt);report=receiver!.Finish(summary!.Accepted,settled);phase=Phase.WaitAck;
            Set(PathDiagnosticStep.Report,r:report);
        }
        if(Finished&&cleanupSends>=3)outgoing=null;
        if(outgoing!=null&&now-sendAt>=500&&controls<256){
            if(control(PathDiagnosticControl.Encode(outgoing,scope))){controls++;if(Finished)cleanupSends++;sendAt=now;if(pendingStart){pendingStart=false;Source();}}
        }
    }
    public bool Receive(PathDiagnosticMessage m,long now)
    {
        if(disposed||m.Session!=SessionId||m.TargetMbps!=target)return false;
        if(m.Step==PathDiagnosticStep.Cancel){Cancel("PeerCancelled");return true;}
        if(Finished){if(phase==Phase.Done&&m.Step==PathDiagnosticStep.Done&&controls<256){cleanupSends=0;Set(PathDiagnosticStep.Completed);}return true;}
        if(!healthy()||!permit.Active){Cancel("ResourcesUnavailable");return true;}
        if(leader&&m.Step==PathDiagnosticStep.Ready&&phase==Phase.WaitReady){Prepare(0);phase=Phase.WaitPrepared;Set(PathDiagnosticStep.Prepare);return true;}
        if(!leader&&m.Step==PathDiagnosticStep.Prepare){
            if(m.Leg==leg&&phase==Phase.WaitStart&&current!=null){Set(PathDiagnosticStep.Prepared);return true;}
            if(m.Leg==leg&&current==null||m.Leg==leg+1&&phase is Phase.WaitAck or Phase.WaitStart){
                if(m.Leg==leg+1&&phase==Phase.WaitAck)Record(now); // next Prepare is an implicit receipt acknowledgment
                Prepare(m.Leg);phase=Phase.WaitStart;Set(PathDiagnosticStep.Prepared);return true;
            }
        }
        if(m.Leg!=leg)return false;
        if(leader&&m.Step==PathDiagnosticStep.Prepared&&phase==Phase.WaitPrepared){
            Set(PathDiagnosticStep.Start);if(IsLocalSource)pendingStart=true;else phase=Phase.Receiving;return true;
        }
        if(!leader&&m.Step==PathDiagnosticStep.Start&&phase==Phase.WaitStart){
            outgoing=null;if(IsLocalSource)Source();else phase=Phase.Receiving;return true;
        }
        if(!IsLocalSource&&m.Step==PathDiagnosticStep.End&&phase is Phase.Receiving or Phase.WaitStart){
            summary=m.Source!;settleAt=now;phase=Phase.Settling;outgoing=null;return true;
        }
        if(!IsLocalSource&&m.Step==PathDiagnosticStep.End&&phase==Phase.WaitAck){Set(PathDiagnosticStep.Report,r:report);return true;}
        if(IsLocalSource&&m.Step==PathDiagnosticStep.Report&&phase==Phase.WaitReport){
            if(m.Receipt!.ExpectedPackets!=summary!.Accepted){Cancel("ReceiptMismatch");return true;}
            report=m.Receipt;Record(now);Set(PathDiagnosticStep.Ack);phase=Phase.WaitStart;
            if(leader)Next(now);return true;
        }
        if(!IsLocalSource&&m.Step==PathDiagnosticStep.Ack&&phase==Phase.WaitAck){Record(now);phase=Phase.WaitStart;outgoing=null;if(leader)Next(now);return true;}
        if(!leader&&m.Step==PathDiagnosticStep.Done&&leg==11&&phase==Phase.WaitStart){phase=Phase.Done;permit.Dispose();Set(PathDiagnosticStep.Completed);return true;}
        if(leader&&m.Step==PathDiagnosticStep.Completed&&phase==Phase.WaitCompleted){phase=Phase.Done;permit.Dispose();outgoing=null;return true;}
        return false;
    }
    void Record(long now)
    {
        if(windows.Any(w=>w.Leg==leg))return;var s=summary!;
        windows.Add(new(SessionId,leg,IsLocalSource?own:remote,current!.Identity.PathId,current.Identity.LeaseId,current.Identity.NetworkGeneration,target,
            new(s.Accepted,s.Rejected,s.ElapsedMicroseconds/1000d,s.AdmittedPackets,s.AdmittedBytes,s.WireDenied,s.RttSamples,s.LoadedRttP95,
                s.Result==1?"Completed":s.Result==2?"Cancelled":"AllowanceEnded"),report!,now));
    }
    void Next(long now)
    {
        if(leg==11){phase=Phase.WaitCompleted;stageAt=now;Set(PathDiagnosticStep.Done);return;}
        Prepare(leg+1);phase=Phase.WaitPrepared;Set(PathDiagnosticStep.Prepare);
    }
    public void Data(Guid path,ReadOnlySpan<byte> payload)
    {
        if(!Finished&&(!healthy()||!permit.Active)){Cancel("DataBoundary");return;}
        if(!Finished&&!IsLocalSource&&current?.Identity.PathId==path&&phase is Phase.WaitStart or Phase.Receiving or Phase.Settling)
            receiver?.Record(payload);
    }
    public void RoundTrip(Guid path,double milliseconds)
    {
        if(IsLocalSource&&current?.Identity.PathId==path&&phase==Phase.Sending&&rtts.Count<32&&double.IsFinite(milliseconds)&&milliseconds is>=0 and<12000)rtts.Add(milliseconds);
    }
    public void Cancel(string reason)
    {
        if(Finished)return;failure=reason;phase=Phase.Cancelled;pendingStart=false;stop.Cancel();allowance?.Dispose();permit.Dispose();Set(PathDiagnosticStep.Cancel);
    }
    public Task Join()=>sending??Task.CompletedTask;
    public void Dispose(){if(disposed)return;Cancel("Disposed");disposed=true;if(sending==null||sending.IsCompleted)stop.Dispose();else _=sending.ContinueWith(_=>stop.Dispose(),TaskScheduler.Default);}
}
