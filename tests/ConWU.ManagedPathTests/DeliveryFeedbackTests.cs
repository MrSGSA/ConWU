using System.Buffers.Binary;
using System.Diagnostics;
using StreamLink.Core;

static class DeliveryFeedbackTests
{
    public static void Models(Action<bool,string> check)
    {
        var c=new TraversalAttemptContext("network","left",Guid.NewGuid(),"right",Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),1,Guid.NewGuid(),1,
            TraversalProfile.UdpDirect,true,true,Guid.NewGuid());
        var reverse=c with{LocalNodeId=c.RemoteNodeId,LocalBootId=c.RemoteBootId,RemoteNodeId=c.LocalNodeId,RemoteBootId=c.LocalBootId,
            LocalCandidateId=c.RemoteCandidateId,RemoteCandidateId=c.LocalCandidateId,ProtocolClient=false,Nominator=false};
        foreach(string scenario in new[]{"complete","partial","overflow","timeout","duplicate","bad-count","bad-scope","bad-epoch","late-reset","sleep"}){
            var a=new PathDeliveryFeedback(c);var b=new PathDeliveryFeedback(reverse);Guid epoch=Guid.NewGuid();
            for(ulong seq=10;seq<30;seq++){a.Send(epoch,seq,1280,0);if(scenario!="partial"||seq%2==0)b.Receive(epoch,seq,1280);}
            if(scenario=="overflow")for(ulong seq=30;seq<PathDeliveryFeedback.HistorySize+40;seq++)b.Receive(epoch,seq,1280);
            byte[]? query=null,reply=null;a.Tick(scenario=="sleep"?10000:2000,p=>{query=p.ToArray();return true;});
            if(scenario=="sleep"){check(query==null&&a.Snapshot().Reports.Single().Result=="ObservationDiscontinuous","sleep gap cannot create a fresh normal delivery interval");continue;}
            if(scenario=="timeout"){a.Tick(10000,_=>true);check(a.Snapshot().Reports.Single().PeerDeliveredPackets==null&&a.Snapshot().Reports.Single().Result=="FeedbackTimeout",
                "no peer response remains unknown and is never converted to total packet loss");continue;}
            var changed=query!.ToArray();if(scenario=="bad-scope")changed[8]^=1;
            if(scenario=="bad-epoch")Guid.NewGuid().TryWriteBytes(changed.AsSpan(56));
            if(scenario=="late-reset")b.Reset();
            b.Control(changed,epoch,2000);b.Tick(2999,p=>{reply=p;return true;});
            check(reply==null,"peer waits the bounded settling interval before taking a delivery snapshot: "+scenario);
            b.Tick(3000,p=>{reply=p.ToArray();return true;});
            if(scenario.StartsWith("bad-")&&scenario!="bad-count"){
                check(reply==null&&b.Snapshot().InvalidControls==1,"wrong scope/epoch cannot allocate a reply: "+scenario);continue;}
            if(scenario=="bad-count")BinaryPrimitives.WriteInt64BigEndian(reply!.AsSpan(88),21);
            a.Control(reply!,Guid.NewGuid(),3100);
            if(scenario=="bad-count"){check(a.Snapshot().Reports.Length==0&&a.Snapshot().InvalidControls==1,"over-report cannot commit false received data");continue;}
            var report=a.Snapshot().Reports.Single();
            check(scenario is "overflow" or "late-reset"?report.PeerDeliveredPackets==null&&report.Result=="ReceiverHistoryIncomplete":
                report.PeerDeliveredPackets==(scenario=="partial"?10:20)&&report.PeerDeliveredBytes==(scenario=="partial"?12800:25600),
                "range report distinguishes exact local delivery from unknown history: "+scenario);
            if(scenario=="duplicate"){
                a.Control(reply!,Guid.NewGuid(),3200);b.Control(query!,epoch,3200);
                check(a.Snapshot().Reports.Length==1&&a.Snapshot().InvalidControls==0&&b.Snapshot().ReceiverRequests==1,"duplicate request/report is idempotent and does not reset settling or counts");
                int resend=0;b.Tick(3500,_=>{resend++;return true;});b.Tick(5500,_=>{resend++;return true;});
                check(resend==1,"only a repeated query retries the cached report; idle receiver does not send unsolicited repeats");
            }
            a.Reset();check(a.Snapshot().Reports.Length==0&&a.Snapshot().WaitingReports==0,"retiring a path clears completed and pending evidence: "+scenario);
        }
        var capped=new PathDeliveryFeedback(c);Guid e=Guid.NewGuid();
        for(ulong seq=1;seq<50000;seq++)capped.Receive(e,seq,1280);
        check(capped.Snapshot().RetainedReceiveRecords==PathDeliveryFeedback.HistorySize,"receive metadata stays at the exact bounded history size under sustained input");
    }
    public static async Task<object[]> Run(Action<bool,string> check,Func<string,string,byte[]> packet)
    {
        Models(check);var rows=new List<object>();
        foreach(string mode in new[]{"ordinary","partial","feedback-loss"})rows.Add(await Router(mode,check,packet));return rows.ToArray();
    }
    static async Task<object> Router(string mode,Action<bool,string> check,Func<string,string,byte[]> packet)
    {
        var a=MeshIdentity.Create("https://example.com/","","faketcp");var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;
        var aa=new Adapter();var ab=new Adapter();await using var ra=new MeshRouter(a,aa);await using var rb=new MeshRouter(b,ab);
        using var left=new Resource();using var right=new Resource();left.Peer=right.Local;right.Peer=left.Local;
        var c=new TraversalAttemptContext(a.Pair.Network,a.Self.Device,ra.BootId,b.Self.Device,rb.BootId,Guid.NewGuid(),Guid.NewGuid(),1,Guid.NewGuid(),1,
            TraversalProfile.FakeTcpHttpSo,true,true,Guid.NewGuid());
        var r=c with{LocalNodeId=c.RemoteNodeId,LocalBootId=c.RemoteBootId,RemoteNodeId=c.LocalNodeId,RemoteBootId=c.LocalBootId,
            LocalCandidateId=c.RemoteCandidateId,RemoteCandidateId=c.LocalCandidateId,ProtocolClient=false,Nominator=false};
        var pa=left.Retain(c);var pb=right.Retain(r);int permission=mode=="ordinary"?0:1;
        ra.RegisterPath(2,pa,c,1,TimeSpan.FromSeconds(8),1,permission);rb.RegisterPath(1,pb,r,1,TimeSpan.FromSeconds(8),1,permission);
        left.Dispose();right.Dispose();
        async Task Until(Func<bool> ready,int ms=14000){var clock=Stopwatch.StartNew();while(!ready()){if(clock.ElapsedMilliseconds>ms)throw new Exception("feedback Router timeout");await Task.Delay(10);}}
        await Until(()=>ra.Status().Single().Connected&&rb.Status().Single().Connected);
        int data=0;left.Filter=p=>p[4]!=4||mode!="partial"||Interlocked.Increment(ref data)%2==0;
        if(mode=="feedback-loss")right.Filter=p=>p[4]!=7;
        for(int i=0;i<20;i++)aa.Outgoing.Add(packet(a.LocalIp,b.LocalIp));
        await Until(()=>ra.Status().Single().SentBytes==25600&&ab.Incoming.Count==(mode=="partial"?10:20));
        for(int i=0;i<7;i++)ab.Outgoing.Add(packet(b.LocalIp,a.LocalIp));await Until(()=>aa.Incoming.Count==7);
        if(permission==0){await Task.Delay(3500);check(ra.Status().Single().Delivery==null&&rb.Status().Single().Delivery==null,
            "ordinary product path creates no delivery history, control query or experiment result");}
        else{
            await Until(()=>ra.Status().Single().Delivery!.Reports.Length>0);
            var report=ra.Status().Single().Delivery!.Reports.Single();
            check(mode=="partial"?report.PeerDeliveredPackets==10&&report.AcceptedPackets==20&&report.DeficitAtReceiptPercent==50:
                report.PeerDeliveredPackets==null&&report.Result=="FeedbackTimeout","real encrypted path carries precise receiver delivery or explicit missing-feedback result: "+mode);
            check(ra.Status().Single().Connected&&rb.Status().Single().Connected&&ra.Status().Single().Traffic!.Qualification=="QualityUnknown",
                "delivery diagnostics never switch paths, create QualityObserved qualification or tear down healthy business");
        }
        var result=new{mode,left=ra.Status().Single().Delivery,right=rb.Status().Single().Delivery,scope="real Windows UDP loopback/Router/MeshLink AEAD, synthetic loss, no FakeTCP/Wintun/WAN"};
        await ra.DisposeAsync();await rb.DisposeAsync();check(left.Closed&&right.Closed&&aa.Disposed&&ab.Disposed,"feedback holds no extra socket or transport reference: "+mode);return result;
    }
}
