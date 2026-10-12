using System.Diagnostics;
using StreamLink.Core;

static class StandbyTests
{
    public static async Task<object> Run(Action<bool,string> check,Func<string,string,byte[]> packet)
    {
        Models(check);
        var a=MeshIdentity.Create("https://example.com/","","faketcp");var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;
        var aa=new Adapter();var ab=new Adapter();await using var ra=new MeshRouter(a,aa,selection:new(AllowUdpFallback:true));await using var rb=new MeshRouter(b,ab,selection:new(AllowUdpFallback:true));
        TraversalAttemptContext Context(bool standby)=>new(a.Pair.Network,a.Self.Device,ra.BootId,b.Self.Device,rb.BootId,Guid.NewGuid(),Guid.NewGuid(),1,
            Guid.NewGuid(),1,TraversalProfile.UdpDirect,true,true,Guid.NewGuid(),Standby:standby);
        static TraversalAttemptContext Reverse(TraversalAttemptContext c)=>c with{LocalNodeId=c.RemoteNodeId,LocalBootId=c.RemoteBootId,RemoteNodeId=c.LocalNodeId,
            RemoteBootId=c.LocalBootId,LocalCandidateId=c.RemoteCandidateId,RemoteCandidateId=c.LocalCandidateId,ProtocolClient=false,Nominator=false};
        async Task Until(Func<bool> ready,int ms=6000){var clock=Stopwatch.StartNew();while(!ready()){if(clock.ElapsedMilliseconds>ms)throw new Exception("standby router timeout");await Task.Delay(10);}}
        using var firstA=new Resource();using var firstB=new Resource();firstA.Peer=firstB.Local;firstB.Peer=firstA.Local;
        var firstContext=Context(false);var fa=firstA.Retain(firstContext);var fb=firstB.Retain(Reverse(firstContext));
        ra.RegisterPath(2,fa,firstContext,1,TimeSpan.FromSeconds(6),1);rb.RegisterPath(1,fb,Reverse(firstContext),1,TimeSpan.FromSeconds(6),1);
        firstA.Dispose();firstB.Dispose();await Until(()=>ra.Status().Single().Connected&&rb.Status().Single().Connected);
        using var otherA=new Resource();using var otherB=new Resource();otherA.Peer=otherB.Local;otherB.Peer=otherA.Local;
        var c=Context(true);var ca=otherA.Retain(c);var cb=otherB.Retain(Reverse(c));
        ra.RegisterPath(2,ca,c,2,TimeSpan.FromSeconds(6),1,negotiatedStandbyVersion:1);rb.RegisterPath(1,cb,Reverse(c),2,TimeSpan.FromSeconds(6),1,negotiatedStandbyVersion:1);
        otherA.Dispose();otherB.Dispose();await Until(()=>ra.Paths(2).Any(p=>p.PathId==ca.Identity.PathId&&p.StandbyReady)&&rb.Paths(1).Any(p=>p.PathId==cb.Identity.PathId&&p.StandbyReady));
        check(ra.Paths(2).Single(p=>p.Active).PathId==fa.Identity.PathId&&rb.Paths(1).Single(p=>p.Active).PathId==fb.Identity.PathId,
            "authenticated standby does not nominate itself or replace either healthy Active");
        await Task.Delay(8200);
        aa.Outgoing.Add(packet(a.LocalIp,b.LocalIp));await Until(()=>ab.Incoming.Count==1);
        check(firstA.Data==1&&otherA.Data==0&&ra.Paths(2).Any(p=>p.StandbyReady&&p.BidirectionalFresh)&&!otherA.Closed,
            "after the original handshake deadline, retained standby stays fresh and original path alone delivers complete business");
        check(rb.ApproveStandbySelection(1,cb.Identity.PathId)&&ra.ApproveStandbySelection(2,ca.Identity.PathId),"both local approvals still require the path-bound commit exchange");
        await Until(()=>ra.Paths(2).Any(p=>p.PathId==ca.Identity.PathId&&p.Active&&p.Stage==NominationStage.Selected)&&
            rb.Paths(1).Any(p=>p.PathId==cb.Identity.PathId&&p.Active&&p.Stage==NominationStage.Selected));
        aa.Outgoing.Add(packet(a.LocalIp,b.LocalIp));await Until(()=>ab.Incoming.Count==2);
        check(firstA.Data==1&&otherA.Data==1,"later common selection uses the existing retained resource without recreating a socket");
        ra.CancelPath(2,ca.Identity.PathId);await Until(()=>ra.Paths(2).Any(p=>p.PathId==fa.Identity.PathId&&p.Active));
        await Until(()=>rb.Paths(1).Any(p=>p.PathId==fb.Identity.PathId&&p.Active));
        check(!firstA.Closed&&!firstB.Closed,"selection cancellation restores the exact previous Active owners");
        await Until(()=>ra.Paths(2).Length==1&&rb.Paths(1).Length==1);
        using var lateA=new Resource();using var lateB=new Resource();lateA.Peer=lateB.Local;lateB.Peer=lateA.Local;
        var lateContext=Context(true);var la=new RefuseHold(lateA.Retain(lateContext));var lb=new RefuseHold(lateB.Retain(Reverse(lateContext)));
        ra.RegisterPath(2,la,lateContext,3,TimeSpan.FromSeconds(6),1,negotiatedStandbyVersion:1);
        rb.RegisterPath(1,lb,Reverse(lateContext),3,TimeSpan.FromSeconds(6),1,negotiatedStandbyVersion:1);
        lateA.Dispose();lateB.Dispose();
        await Until(()=>ra.Paths(2).Any(p=>p.Failure=="standby-wire-deadline")||rb.Paths(1).Any(p=>p.Failure=="standby-wire-deadline"));
        await Until(()=>ra.Paths(2).Length==1&&rb.Paths(1).Length==1);
        aa.Outgoing.Add(packet(a.LocalIp,b.LocalIp));await Until(()=>ab.Incoming.Count==3);
        check(!ra.Completion.IsCompleted&&!rb.Completion.IsCompleted&&ra.Paths(2).Single(p=>p.Active).PathId==fa.Identity.PathId,
            "expired native hold authorization cancels only candidate and cannot fault the runner or working Active");
        await ra.DisposeAsync();await rb.DisposeAsync();check(firstA.Closed&&firstB.Closed&&otherA.Closed&&otherB.Closed,"standby and rollback release every actual reference on shutdown");
        return new{scope="real UDP loopback/Router/MeshLink with retained resources, no Wintun/native TCP/WAN"};
    }
    static void Models(Action<bool,string> check)
    {
        Perturbations(check);
        var clock=new Clock();var c=new TraversalAttemptContext("network","a",Guid.NewGuid(),"b",Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),1,Guid.NewGuid(),1,
            TraversalProfile.UdpDirect,true,true,Guid.NewGuid(),Standby:true);
        var r=c with{LocalNodeId=c.RemoteNodeId,LocalBootId=c.RemoteBootId,RemoteNodeId=c.LocalNodeId,RemoteBootId=c.LocalBootId,
            LocalCandidateId=c.RemoteCandidateId,RemoteCandidateId=c.LocalCandidateId,ProtocolClient=false,Nominator=false};
        Guid pa=Guid.NewGuid(),pb=Guid.NewGuid();var a=new PathNomination(c,pa,1,TimeSpan.FromSeconds(6),true,clock);var b=new PathNomination(r,pb,1,TimeSpan.FromSeconds(6),true,clock);
        void Deliver(byte[][] messages,bool fromA){var queue=new Queue<(byte[] P,bool A)>(messages.Select(p=>(p,fromA)));int limit=0;
            while(queue.TryDequeue(out var item)){if(++limit>100)throw new Exception("standby response loop");foreach(var reply in (item.A?b:a).Receive(item.A?pb:pa,item.P))queue.Enqueue((reply,!item.A));}}
        void Drive(int ms){for(int end=clock.Ms+ms;clock.Ms<end;clock.Ms+=100){Deliver(a.Tick(),true);Deliver(b.Tick(),false);}}
        Drive(1000);check(a.StandbyConfirmed&&b.StandbyConfirmed&&a.Stage==NominationStage.Standby&&b.Stage==NominationStage.Standby,
            "mutual path authentication enters retained standby before the original bounded deadline");
        Drive(30000);check(!a.SwitchRequested&&!b.SwitchRequested&&a.TimeLeft.TotalSeconds>80,"standby lifetime is a distinct retention phase and never restarts TCP/authentication");
        check(!a.SelectStandby(),"retention alone cannot authorize a selection");a.AllowStandbySelection();check(a.SelectStandby(),"authorized nominator starts one new application selection deadline");
        Drive(500);check(!a.SwitchRequested&&!b.SwitchRequested,"one-sided approval cannot switch either endpoint");b.AllowStandbySelection();Drive(1000);
        check(a.Stage==NominationStage.Selected&&b.Stage==NominationStage.Selected,"fresh selection token and existing authenticated challenges converge");
        a.Cancel();Deliver(a.Tick(),true);check(a.Stage==NominationStage.Cancelled&&b.Stage==NominationStage.Cancelled,"authenticated cancellation cannot leave the standby selection resurrectable");
        var expired=new PathNomination(c,Guid.NewGuid(),2,TimeSpan.FromSeconds(6),true,clock);clock.Ms+=6001;_ = expired.Tick();
        check(expired.Stage==NominationStage.Cancelled&&!expired.StandbyConfirmed,"missing standby authentication cannot borrow the long retention lifetime");
        var budget=new NativeWireBudget(new(new TraversalResources()));budget.Start(Stopwatch.GetTimestamp());budget.HoldStandby();
        check(!budget.Admit(NativeWireKind.Business,1400)&&budget.Admit(NativeWireKind.Maintenance,80)&&budget.Snapshot() is{Standby:true,Selected:false,BusinessPackets:0},
            "native hold uses maintenance budget and cannot authorize a business-labelled raw frame");
        budget.Select();check(budget.Admit(NativeWireKind.Business,1400)&&budget.Snapshot() is{Selected:true,Standby:false},"joint selection changes the wire phase without a new TCP state");
        var tooLate=new NativeWireBudget(new(new TraversalResources()));tooLate.Start(Stopwatch.GetTimestamp()-9*Stopwatch.Frequency);bool rejected=false;
        try{tooLate.HoldStandby();}catch(InvalidOperationException){rejected=true;}check(rejected,"expired unauthenticated native round cannot be revived as standby");
    }
    static void Perturbations(Action<bool,string> check)
    {
        foreach(string mode in new[]{"normal","lose-ready","lose-confirm","lose-commit","lose-final-ack","all-confirm-lost","retain-expiry"})
        for(int round=0;round<30;round++){
            var clock=new Clock();var c=new TraversalAttemptContext("network","a",Guid.NewGuid(),"b",Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),1,Guid.NewGuid(),1,
                TraversalProfile.UdpDirect,true,true,Guid.NewGuid(),Standby:true);
            var r=c with{LocalNodeId=c.RemoteNodeId,LocalBootId=c.RemoteBootId,RemoteNodeId=c.LocalNodeId,RemoteBootId=c.LocalBootId,
                LocalCandidateId=c.RemoteCandidateId,RemoteCandidateId=c.LocalCandidateId,ProtocolClient=false,Nominator=false};
            Guid pa=Guid.NewGuid(),pb=Guid.NewGuid();var a=new PathNomination(c,pa,round+1,TimeSpan.FromSeconds(6),true,clock);
            var b=new PathNomination(r,pb,round+1,TimeSpan.FromSeconds(6),true,clock);bool dropped=false;
            void Send(byte[][] packets,bool fromA){var queue=new Queue<(byte[] Packet,bool FromA)>(packets.Select(p=>(p,fromA)));int cap=0;
                while(queue.TryDequeue(out var item)){
                    if(++cap>100)throw new Exception("standby response storm");byte kind=item.Packet[4];
                    bool drop=mode=="all-confirm-lost"&&kind==4 || !dropped&&(mode=="lose-ready"&&kind==8||mode=="lose-confirm"&&kind==4||mode=="lose-commit"&&kind==5||mode=="lose-final-ack"&&kind==6);
                    if(drop){dropped=true;continue;}
                    foreach(var reply in (item.FromA?b:a).Receive(item.FromA?pb:pa,item.Packet))queue.Enqueue((reply,!item.FromA));
                }
            }
            void Drive(int milliseconds){for(int end=clock.Ms+milliseconds;clock.Ms<end;clock.Ms+=100){Send(a.Tick(),true);Send(b.Tick(),false);}}
            Drive(2000);check(a.StandbyConfirmed&&b.StandbyConfirmed,$"standby {mode}/{round}: repeated authentication reaches mutually retained state within the original deadline");
            if(mode=="retain-expiry"){
                Drive(121000);check(a.Stage==NominationStage.Cancelled&&b.Stage==NominationStage.Cancelled,"retention keepalives cannot extend the fixed 120-second deadline");continue;
            }
            Drive(30000);check(!a.SwitchRequested&&!b.SwitchRequested,"standby keepalives do not implicitly approve selection");
            a.AllowStandbySelection();b.AllowStandbySelection();check(a.SelectStandby(),"selection starts from the same held resource");Drive(9000);
            check(mode=="all-confirm-lost"?a.Stage==NominationStage.Cancelled&&b.Stage==NominationStage.Cancelled:a.Stage==NominationStage.Selected&&b.Stage==NominationStage.Selected,
                mode+": bounded retransmission converges or cancels both endpoints without a new TCP handshake");
            var old=a.Tick();a.Cancel();Send(old,true);check(a.Stage==NominationStage.Cancelled,"late completion cannot resurrect a locally cancelled selection");
        }
    }
    sealed class RefuseHold(IMeshDatagramPath inner):IMeshDatagramPath,IWireControlPath
    {
        public ValidatedPathIdentity Identity=>inner.Identity;public bool Failed=>inner.Failed;
        public bool CountsWireControl=>true;public NativeWireStats? WireControl=>null;
        public void HoldStandbyWireBudget()=>throw new InvalidOperationException("simulated wire deadline already ended");
        public void SelectWireBudget()=>throw new Exception("unapproved standby cannot select");
        public bool TrySend(ReadOnlySpan<byte> p)=>inner.TrySend(p);
        public ValueTask<ReadOnlyMemory<byte>> Receive(CancellationToken t)=>inner.Receive(t);
        public ValueTask DisposeAsync()=>inner.DisposeAsync();
    }
    sealed class Clock:TimeProvider{public int Ms;public override long TimestampFrequency=>1000;public override long GetTimestamp()=>Ms;}
}
