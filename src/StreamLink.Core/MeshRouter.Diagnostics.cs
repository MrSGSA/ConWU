namespace StreamLink.Core;

public sealed partial class MeshRouter
{
    readonly PathDiagnosticResources diagnosticResources=new();
    readonly HashSet<Task> diagnosticTasks=[];
    bool DiagnosticIdle(long now,int horizon)=>!peers.Values.Any(p=>p.Managed?.Active?.Traffic.BusyWithin(now,horizon)==true);
    bool DiagnosticPair(Peer peer,ManagedPath active,ManagedPath standby)=>peer.Managed is{}managed&&ReferenceEquals(managed.Active,active)&&
        ReferenceEquals(managed.Candidate,standby)&&!active.Closing&&!standby.Closing&&!active.Transport.Failed&&!standby.Transport.Failed&&
        active.Nomination.Stage==NominationStage.Selected&&standby.Nomination.StandbyConfirmed&&standby.Nomination.Stage==NominationStage.Standby&&
        standby.DiagnosticMbps>0&&active.Transport is IPathDiagnosticWire{SupportsDiagnosticWire:true}&&standby.Transport is IPathDiagnosticWire{SupportsDiagnosticWire:true}&&
        RoundTripFresh(active)&&RoundTripFresh(standby);
    PathDiagnosticSession? OpenDiagnostic(Peer peer,ManagedPath active,ManagedPath standby,Guid id)
    {
        if(!DiagnosticPair(peer,active,standby)||!DiagnosticIdle(Environment.TickCount64,10000))return null;
        var permit=diagnosticResources.TryBegin(id);if(permit==null)return null;
        try{
            Guid localEpoch=peer.Link.SendEpoch;Guid? peerEpoch=peer.Link.ReceiveEpoch;
            var managed=peer.Managed!;
            managed.DiagnosticActive=active;managed.DiagnosticStandby=standby;
            managed.DiagnosticLocalEpoch=localEpoch;managed.DiagnosticPeerEpoch=peerEpoch;
            managed.Quality=null;managed.Agreement=null;
            bool Valid()=>DiagnosticPair(peer,active,standby)&&peer.Link.SendEpoch==localEpoch&&peer.Link.ReceiveEpoch==peerEpoch;
            PathDiagnosticTarget Target(int i){var path=i==0?active:standby;return new(path.Identity,(IPathDiagnosticWire)path.Transport,
                packet=>{lock(gate)return Valid()&&DiagnosticIdle(Environment.TickCount64,1000)&&SendManaged(packet,path);},
                body=>{lock(gate)return Valid()&&DiagnosticIdle(Environment.TickCount64,1000)?peer.Link.Diagnostic(body):null;},
                ()=>path.Transport is IWireControlPath wire?wire.WireControl?.Denied??0:
                    (path.Transport as IMeshSendDiagnostics)?.SendQueue.Accounting.Failed.Packets??0);}
            return new(PathNomination.ContextDigest(standby.Context!),standby.Context!.Nominator,profile.Self.Slot,peer.Member.Slot,standby.DiagnosticMbps,permit,Target,
                body=>SendFeedback(peer,standby,body,Environment.TickCount64),
                ()=>Valid()&&DiagnosticIdle(Environment.TickCount64,1000));
        }catch{permit.Dispose();throw;}
    }
    bool DiagnosticControl(Peer peer,ManagedPath path,byte[] payload,long now)
    {
        if(!PathDiagnosticControl.IsControl(payload))return false;
        var managed=peer.Managed;
        if(managed?.Candidate is not{}standby||!ReferenceEquals(standby,path)||standby.DiagnosticMbps==0||standby.Context==null)return true;
        if(!PathDiagnosticControl.TryParse(payload,PathNomination.ContextDigest(standby.Context),standby.DiagnosticMbps,out var message))return true;
        if(managed.Diagnostic==null&&message!.Step==PathDiagnosticStep.Begin&&managed.Active is{}active&&!standby.Context.Nominator&&now>=managed.NextDiagnostic&&
            managed.DiagnosticAttempt!=standby.Identity.AttemptId){
            managed.Diagnostic=OpenDiagnostic(peer,active,standby,message.Session);
            if(managed.Diagnostic!=null){managed.DiagnosticAttempt=standby.Identity.AttemptId;managed.NextDiagnostic=now+300000;}
        }
        if(managed.Diagnostic is{}session){
            try{session.Receive(message!,now);}catch(Exception ex)when(ex is IOException or ArgumentException or InvalidOperationException){session.Cancel("ControlBoundary:"+ex.GetType().Name);}
            TrackDiagnostic(session);
        }
        return true;
    }
    void TickDiagnostic(Peer peer,long now)
    {
        var managed=peer.Managed!;
        if(managed.Diagnostic is{Finished:true}old&&managed.Candidate is{}next&&next.Identity.AttemptId!=managed.DiagnosticAttempt){
            old.Dispose();managed.Diagnostic=null;
        }
        if(managed.Diagnostic==null&&managed.Candidate is{DiagnosticMbps:>0,Context:{}c}standby&&c.Nominator&&managed.Active is{}active&&
            standby.StandbyAt!=0&&now-standby.StandbyAt>=1000&&now>=managed.NextDiagnostic&&managed.DiagnosticAttempt!=standby.Identity.AttemptId){
            managed.Diagnostic=OpenDiagnostic(peer,active,standby,Guid.NewGuid());
            if(managed.Diagnostic!=null){managed.DiagnosticAttempt=standby.Identity.AttemptId;managed.NextDiagnostic=now+300000;}
        }
        if(managed.Diagnostic is{}session){
            try{session.Tick(now);}catch(Exception ex)when(ex is IOException or ArgumentException or InvalidOperationException){session.Cancel("TickBoundary:"+ex.GetType().Name);}
            TrackDiagnostic(session);
        }
    }
    void TrackDiagnostic(PathDiagnosticSession session)
    {
        var task=session.Join();if(!task.IsCompleted)diagnosticTasks.Add(task);diagnosticTasks.RemoveWhere(t=>t.IsCompleted);
    }
}
