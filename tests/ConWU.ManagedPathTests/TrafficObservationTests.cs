using System.Diagnostics;
using System.Net;
using StreamLink.Core;

static class TrafficObservationTests
{
    public static async Task<object> Run(Action<bool,string> check,Func<string,string,byte[]> packet)
    {
        Model(check);
        var a=MeshIdentity.Create("https://example.com/","","faketcp");var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;
        var aa=new Adapter();var ab=new Adapter();await using var ra=new MeshRouter(a,aa);await using var rb=new MeshRouter(b,ab);
        using var left=new Resource();using var right=new Resource();left.Peer=right.Local;right.Peer=left.Local;
        var context=new TraversalAttemptContext(a.Pair.Network,a.Self.Device,ra.BootId,b.Self.Device,rb.BootId,Guid.NewGuid(),
            Guid.NewGuid(),1,Guid.NewGuid(),1,TraversalProfile.FakeTcpHttpSo,true,true,Guid.NewGuid());
        var reverse=context with{LocalNodeId=context.RemoteNodeId,LocalBootId=context.RemoteBootId,RemoteNodeId=context.LocalNodeId,
            RemoteBootId=context.LocalBootId,LocalCandidateId=context.RemoteCandidateId,RemoteCandidateId=context.LocalCandidateId,ProtocolClient=false,Nominator=false};
        var pa=left.Retain(context);var pb=right.Retain(reverse);
        ra.RegisterPath(2,pa,context,1,TimeSpan.FromSeconds(8),1);rb.RegisterPath(1,pb,reverse,1,TimeSpan.FromSeconds(8),1);
        left.Dispose();right.Dispose();
        async Task Until(Func<bool> ready,int milliseconds=6000){var clock=Stopwatch.StartNew();while(!ready()){if(clock.ElapsedMilliseconds>milliseconds)throw new Exception("traffic observation timeout");await Task.Delay(10);}}
        await Until(()=>ra.Status().Single().Connected&&rb.Status().Single().Connected);
        int sent=0;left.Filter=p=>p[4]!=4||Interlocked.Increment(ref sent)%2==0;
        for(int i=0;i<20;i++)aa.Outgoing.Add(packet(a.LocalIp,b.LocalIp));
        await Until(()=>ra.Status().Single().SentBytes==25600&&ab.Incoming.Count==10);
        for(int i=0;i<7;i++)ab.Outgoing.Add(packet(b.LocalIp,a.LocalIp));
        await Until(()=>aa.Incoming.Count==7);
        await Until(()=>ra.Status().Single().Traffic!.Windows.Any(w=>w.Complete)&&rb.Status().Single().Traffic!.Windows.Any(w=>w.Complete),7000);
        var at=ra.Status().Single().Traffic!;var bt=rb.Status().Single().Traffic!;
        var aw=at.Windows.Single(w=>w.AcceptedSendBytes>0);var bw=bt.Windows.Single(w=>w.DeliveredReceiveBytes>0);
        check(aw.AcceptedSendPackets==20&&aw.AcceptedSendBytes==25600&&bw.DeliveredReceivePackets==10&&bw.DeliveredReceiveBytes==12800,
            "real Router separates accepted outbound bytes from actual authenticated inbound delivery under deliberate datagram loss");
        check(aw.DeliveredReceivePackets==7&&bw.AcceptedSendPackets==7&&aw.ActivityRtt.Samples+aw.IdleRtt.Samples>0,
            "directional windows contain actual reverse business and matched same-path RTT samples");
        check(at.PathId==pa.Identity.PathId&&at.ResourceId==left.Id&&at.NetworkGeneration==pa.Identity.NetworkGeneration&&at.SendEpoch!=null&&at.ReceiveEpoch!=null,
            "formal member traffic observation identifies retained path, generation and actual AEAD epochs");
        check(at.Qualification=="QualityUnknown"&&at.SendLossPercent==null&&at.PeerDeliveredSendBytes==null&&at.OneWayDelayMs==null,
            "known local enqueue and deliberately lost peer packets never invent remote loss, delivery or one-way evidence");
        ra.CancelPath(2,pa.Identity.PathId);await Until(()=>ra.Paths(2).All(p=>!p.Active));
        check(ra.Status().Single().Traffic==null,"retiring the actual path removes its observation from active member status");
        await ra.DisposeAsync();await rb.DisposeAsync();
        check(left.Closed&&right.Closed&&aa.Disposed&&ab.Disposed,"observation never takes a new socket or resource reference on shutdown");
        return new{at,bt,scope="real Windows UDP loopback/Router/MeshLink; explicit packet-loss fixture, no native FakeTCP/Wintun/WAN"};
    }
    static void Model(Action<bool,string> check)
    {
        var identity=new ValidatedPathIdentity(Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),null,Guid.NewGuid(),new(IPAddress.Loopback,1),new(IPAddress.Loopback,2),TraversalProfile.UdpDirect,PathQualification.MtuQualified);
        var observed=new PathTrafficObservation(identity);observed.Send(1280,true,0);
        check(observed.Snapshot(0).Current==null,"unselected resources cannot manufacture traffic windows");
        observed.Start(0);observed.RoundTrip(16,100);observed.Send(1280,true,200);observed.Send(1280,false,201);observed.Receive(1280,202);
        for(int i=0;i<40;i++)observed.RoundTrip(5+i,300+i);observed.RoundTrip(double.NaN,500);observed.RoundTrip(-1,500);observed.Tick(5000);
        var w=observed.Snapshot(5000).Windows.Single();
        check(w.Complete&&w.Seconds==5&&w.AcceptedSendBytes==1280&&w.DeliveredReceiveBytes==1280&&w.SendRejectedPackets==1,
            "window uses actual interval, accepted send, local delivery and distinct rejection");
        check(w.IdleRtt.Samples==1&&w.IdleRtt.P95Ms==16&&w.ActivityRtt.Samples==32&&w.ActivityRtt.DiscardedSamples==8&&w.ActivityRtt.P95Ms==35,
            "bounded same-path RTT observations separate recent activity from idle samples and report discarded observations");
        observed.Send(1280,true,5001);observed.Tick(17000);
        check(!observed.Snapshot(17000).Windows.Last().Complete&&observed.Snapshot(17000).Windows.Length==2,
            "sleep-sized gap preserves actual duration and cannot fabricate three successful five-second windows");
        for(int t=22000;t<=37000;t+=5000)observed.Tick(t);
        check(observed.Snapshot(37000).Windows.Length==3,"history remains bounded across long idle operation");
        observed.Epoch(true,Guid.NewGuid(),37001);observed.Send(1280,true,37002);observed.Epoch(true,Guid.NewGuid(),37003);
        check(observed.Snapshot(37003).Windows.Length==0&&observed.Snapshot(37003).Current!.AcceptedSendBytes==0,
            "new cryptographic epoch invalidates prior comparison windows without changing the retained transport");
        observed.Suspend("Replaced",38000);observed.Receive(1280,38001);
        check(observed.Snapshot(38001).State=="Replaced"&&observed.Snapshot(38001).Current==null,"retired path cannot reopen a business measurement through late traffic");
        observed.Start(39000);check(observed.Snapshot(39000).Windows.Length==0,"rollback starts fresh evidence rather than reusing retired history");
        observed.Send(1280,true,43999);observed.Tick(44000);observed.RoundTrip(12,44001);
        check(observed.Snapshot(44001).Current!.ActivityRtt.Samples==1,"continuous activity across a window boundary is not mislabeled idle");
        observed.RoundTrip(10,45002,activityAtSend:true);observed.Send(1280,true,45003);observed.RoundTrip(8,45004,activityAtSend:false);
        check(observed.Snapshot(45004).Current!.ActivityRtt.Samples==2&&observed.Snapshot(45004).Current!.IdleRtt.Samples==1,
            "actual probe-send activity determines RTT classification even if business starts or stops while the pong is in flight");
    }
}
