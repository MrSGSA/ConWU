using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.EndpointPoc;

static class NativeDiagnosticTests
{
    public static async Task<object> Run(string binary,string root,Action<bool,string> check,CancellationToken token,bool load=false)
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(load?60000:20000);token=timeout.Token;
        await using var reflector=new Reflector();Guid generation=Guid.NewGuid(),attempt=Guid.NewGuid();
        using var a=await TcpEndpointLease.Open(new(IPAddress.Loopback,0),reflector.Endpoint,generation,token);
        using var b=await TcpEndpointLease.Open(new(IPAddress.Loopback,0),reflector.Endpoint,generation,token);
        var wire=new NativeIpv6RunnerTests.Wire(false);using var pacer=new EgressPacer(load?70:10);
        await using var ownerA=new TcpCaptureOwner(a,generation,(local,_)=>wire.Open(local),pacer);
        await using var ownerB=new TcpCaptureOwner(b,generation,(local,_)=>wire.Open(local),pacer);
        await Task.WhenAll(ownerA.Ready,ownerB.Ready).WaitAsync(token);
        byte[] key=RandomNumberGenerator.GetBytes(32);
        var c=new TraversalAttemptContext("network","a",Guid.NewGuid(),"b",Guid.NewGuid(),attempt,Guid.NewGuid(),1,Guid.NewGuid(),1,
            TraversalProfile.FakeTcpHttpSo,true,true,Guid.NewGuid(),Standby:true);
        var r=c with{LocalNodeId=c.RemoteNodeId,LocalBootId=c.RemoteBootId,RemoteNodeId=c.LocalNodeId,RemoteBootId=c.LocalBootId,
            LocalCandidateId=c.RemoteCandidateId,RemoteCandidateId=c.LocalCandidateId,ProtocolClient=false,Nominator=false};
        await using var pa=await NativeDatagramPath.Prepare(binary,root,a,generation,c,b.Local,key,token,captureOwner:ownerA,countWireControl:true,diagnosticNative:true);
        await using var pb=await NativeDatagramPath.Prepare(binary,root,b,generation,r,a.Local,key,token,captureOwner:ownerB,countWireControl:true,diagnosticNative:true);
        await Task.WhenAll(pa.StartAndQualify(token),pb.StartAndQualify(token));pa.HoldStandbyWireBudget();pb.HoldStandbyWireBudget();
        using var linkA=new MeshLink(1,2,key);using var linkB=new MeshLink(2,1,key);CryptographicOperations.ZeroMemory(key);
        check(pa.TrySend(linkA.Hello()),"actual native retained path begins existing peer AEAD handshake");
        var reply=linkB.Receive((await pb.Receive(token)).Span);check(pb.TrySend(reply.Reply!),"actual C++ peer returns handshake response on the exact held tuple");
        reply=linkA.Receive((await pa.Receive(token)).Span);check(pa.TrySend(reply.Reply!),"native retains one shared peer epoch before diagnostics");
        _=linkB.Receive((await pb.Receive(token)).Span);
        var resources=new PathDiagnosticResources();using var permit=resources.TryBegin(Guid.NewGuid())!;
        byte[] sample=PathDiagnosticFrames.Encode(permit.SessionId,0,0,0);
        check(!pa.TrySend(linkA.Diagnostic(sample)!),"actual native bridge rejects diagnostic enqueue without an explicit allowance");
        if(load)return await Load(pa,pb,linkA,linkB,permit,wire,pacer,binary,check,token);
        using var window=permit.Open(pa.Identity.PathId,3,2500);((IPathDiagnosticWire)pa).GrantDiagnosticWire(window);
        var receiver=new PathDiagnosticReceiver(permit.SessionId,0);
        for(int i=0;i<20;i++){
            check(pa.TrySend(linkA.Diagnostic(PathDiagnosticFrames.Encode(permit.SessionId,0,i,i*8))!),"bounded native diagnostic queues without enabling standby business");
            var received=linkB.Receive((await pb.Receive(token)).Span);
            check(received.Authenticated&&received.Diagnostic!=null&&receiver.Record(received.Diagnostic),"actual udp2raw C++ profile carries authenticated diagnostic data with no delivery wait");
            await Task.Delay(8,token);
        }
        check(pa.WireControl is{DiagnosticPackets:20,BusinessPackets:0,Standby:true,Selected:false}&&permit.Snapshot().WireBytes==pa.WireControl.DiagnosticBytes,
            "new native metadata labels real final IP diagnostic frames separately from maintenance and ordinary business");
        window.Dispose();check(!pa.TrySend(linkA.Diagnostic(sample)!),"native diagnostic window cancellation cannot silently become selected business");
        pa.SelectWireBudget();pb.SelectWireBudget();
        check(pa.TrySend(linkA.Data(new byte[1280])!),"ending diagnostic leaves existing native business data profile available");
        check(linkB.Receive((await pb.Receive(token)).Span) is{Authenticated:true,Packet.Length:1280,Diagnostic:null},"ordinary native data remains independent of diagnostic report completion");
        return new{scope="actual C++/TCP helpers/authenticated pipes/UDP bridges and shared pacing; raw IP memory fixture, manual test grant; no formal Router policy or WinDivert/Wintun/WAN",
            nativeSha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(binary))),cost=permit.Snapshot(),receiver=receiver.Finish(20,1000),wire=pa.WireControl,pacing=pacer.Snapshot()};
    }
    static async Task<object> Load(NativeDatagramPath path,NativeDatagramPath peer,MeshLink sender,MeshLink receiver,PathDiagnosticPermit permit,
        NativeIpv6RunnerTests.Wire wire,EgressPacer pacer,string binary,Action<bool,string> check,CancellationToken token)
    {
        var rows=new List<object>();
        using var echoes=CancellationTokenSource.CreateLinkedTokenSource(token);
        var echoReader=Task.Run(async()=>{try{while(true)sender.Receive((await path.Receive(echoes.Token)).Span);}
            catch(OperationCanceledException)when(echoes.IsCancellationRequested){}},token);
        try{
        for(int leg=0;leg<3;leg++){
            using var window=permit.Open(path.Identity.PathId,65,5500);((IPathDiagnosticWire)path).GrantDiagnosticWire(window);
            var samples=new PathDiagnosticReceiver(permit.SessionId,leg);int accepted=0,rejected=0;
            var before=path.WireControl!;using var collecting=CancellationTokenSource.CreateLinkedTokenSource(token);
            var reading=Task.Run(async()=>{try{while(true){var got=receiver.Receive((await peer.Receive(collecting.Token)).Span);
                if(got.Reply!=null)peer.TrySend(got.Reply);
                if(got.Authenticated&&got.Diagnostic!=null)samples.Record(got.Diagnostic);}}
                catch(OperationCanceledException)when(collecting.IsCancellationRequested){}},token);
            var source=PathDiagnosticSender.Send(window,50,5000,(index,elapsed)=>path.TrySend(sender.Diagnostic(PathDiagnosticFrames.Encode(permit.SessionId,leg,index,elapsed))!),token);
            while(!source.IsCompleted){var ping=sender.ProbePath(System.Diagnostics.Stopwatch.GetTimestamp());if(ping!=null)path.TrySend(ping);await Task.Delay(500,token);}
            var sourceResult=await source;accepted=sourceResult.AcceptedPackets;rejected=sourceResult.RejectedOffers;
            await Task.Delay(1000,token);collecting.Cancel();await reading;
            var report=samples.Finish(accepted,1000);var after=path.WireControl!;
            check(accepted>0&&report.Result=="ReportedAtCutoff"&&after.DiagnosticPackets-before.DiagnosticPackets>0,
                "actual native loaded diagnostic leg has source offers, final wire admission and authenticated receiver evidence");
            check(after.BusinessPackets==0&&!after.Selected&&after.Standby,"loaded probe remains diagnostic-only on the retained native path");
            rows.Add(new{leg,accepted,rejected,offeredPayloadMbps=accepted*PathDiagnosticFrames.PayloadBytes*8d/5/1e6,
                receivedPayloadMbps=report.ReceivedPayloadBytes*8d/5/1e6,admittedIpPackets=after.DiagnosticPackets-before.DiagnosticPackets,
                admittedIpBytes=after.DiagnosticBytes-before.DiagnosticBytes,wireDenied=after.Denied-before.Denied,receipt=report,source=sourceResult});
        }
        return new{scope="three actual C++ paced diagnostic legs with manual test grant, raw IP memory fixture; no formal automatic policy, WinDivert/Wintun/WAN or real-time delivery guarantee",
            nativeSha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(binary))),rows,cost=permit.Snapshot(),wire=path.WireControl,pacing=pacer.Snapshot()};
        }finally{echoes.Cancel();await echoReader;}
    }
}
