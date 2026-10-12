using System.Security.Cryptography;
using StreamLink.Core;

static class DiagnosticBudgetTests
{
    public static object Run(Action<bool,string> check)
    {
        var clock=new Clock();var machine=new PathDiagnosticResources(clock);
        using var session=machine.TryBegin(Guid.NewGuid())!;
        check(machine.TryBegin(Guid.NewGuid())==null,"only one machine diagnostic session can own the extra measurement allowance");
        Guid path=Guid.NewGuid();using var window=session.Open(path,1,1000);
        var wire=new NativeWireBudget(new(new TraversalResources()),diagnosticNative:true,pathId:path);
        bool rejected=false;try{wire.GrantDiagnostic(window);}catch(InvalidOperationException){rejected=true;}
        check(rejected&&!wire.Admit(NativeWireKind.Diagnostic,1400),"native diagnostic cannot run before original authentication and explicit window grant");
        wire.Start(System.Diagnostics.Stopwatch.GetTimestamp());wire.HoldStandby();wire.GrantDiagnostic(window);
        check(wire.Admit(NativeWireKind.Diagnostic,1400)&&!wire.Admit(NativeWireKind.Business,1400)&&wire.Snapshot() is{DiagnosticPackets:1,BusinessPackets:0,Selected:false},
            "authenticated standby diagnostic is separately counted and does not grant ordinary business");
        check(!wire.Admit(NativeWireKind.Diagnostic,40)&&!wire.Admit(NativeWireKind.Diagnostic,1600),"diagnostic cannot masquerade as a small control or exceed the measured IP envelope");
        int burst=1;while(wire.Admit(NativeWireKind.Diagnostic,1400))burst++;
        check(burst==4,"final diagnostic allowance starts with four full datagrams, not an unlimited startup burst");
        clock.Ms+=100;check(wire.Admit(NativeWireKind.Diagnostic,1400),"final injection accrues only configured wire-rate credit");
        clock.Ms=1000;check(!wire.Admit(NativeWireKind.Diagnostic,1400)&&!window.Active,"original diagnostic window expires without being restarted by traffic");
        using var other=session.Open(Guid.NewGuid(),1,1000);rejected=false;
        try{wire.GrantDiagnostic(other);}catch(InvalidOperationException){rejected=true;}check(rejected,"another actual path's measurement ticket cannot authorize this tuple");
        var noCapability=new NativeWireBudget(new(new TraversalResources()),pathId:path);noCapability.Start(System.Diagnostics.Stopwatch.GetTimestamp());noCapability.Select();
        check(!noCapability.Admit(NativeWireKind.Diagnostic,1400),"even Selected ordinary business permission cannot grant diagnostic without native capability");
        other.Dispose();using var renewed=session.Open(path,1,1000);wire.GrantDiagnostic(renewed);session.Dispose();
        using var replacement=machine.TryBegin(Guid.NewGuid());
        check(!wire.Admit(NativeWireKind.Diagnostic,1400)&&replacement!=null,"session cancellation revokes all window references and releases machine admission");
        // Fixed whole-session time, not a new ninety seconds per retained path.
        var time=new Clock();var resources=new PathDiagnosticResources(time);using var expiring=resources.TryBegin(Guid.NewGuid())!;
        time.Ms=85000;rejected=false;try{expiring.Open(Guid.NewGuid(),1,10000);}catch(InvalidOperationException){rejected=true;}
        check(rejected,"a leg cannot borrow more time than the remaining common session deadline");time.Ms=90000;check(!expiring.Active,"common diagnostic lifetime is fixed across all windows");
        var volumeTime=new Clock();using var volume=new PathDiagnosticResources(volumeTime).TryBegin(Guid.NewGuid())!;
        for(int leg=0;leg<2;leg++){
            using var bounded=volume.Open(Guid.NewGuid(),100,15000);
            for(int ms=0;ms<15000;ms++){volumeTime.Ms=leg*15000+ms;for(int i=0;i<8;i++)bounded.Admit(1500);}
            volumeTime.Ms=(leg+1)*15000;
        }
        check(volume.Snapshot() is{WireBytes:<=PathDiagnosticPermit.MaximumBytes,Denied:>0},
            "multi-path windows share the fixed whole-session byte ceiling instead of multiplying it per path");
        byte[] key=RandomNumberGenerator.GetBytes(32);using var a=new MeshLink(1,2,key);using var b=new MeshLink(2,1,key);CryptographicOperations.ZeroMemory(key);
        var hello=b.Receive(a.Hello());var response=a.Receive(hello.Reply!);b.Receive(response.Reply!);
        byte[] payload=RandomNumberGenerator.GetBytes(1280),frame=a.Diagnostic(payload)!;var received=b.Receive(frame);
        check(received.Authenticated&&received.Diagnostic!.SequenceEqual(payload)&&received.Packet==null&&received.Control==null,
            "diagnostic has its own authenticated demultiplexed kind and cannot become application IP or nomination control");
        check(!b.Receive(frame).Authenticated,"diagnostic duplicates use the same logical-peer replay state");
        byte[] changed=a.Diagnostic(payload)!;changed[^1]^=1;check(!b.Receive(changed).Authenticated,"altered diagnostic cannot advance valid receipt evidence");
        var data=b.Receive(a.Data(new byte[1280])!);check(data.Authenticated&&data.Packet!.Length==1280&&data.Diagnostic==null,
            "diagnostic sequence allocation leaves subsequent ordinary application datagrams independently deliverable");
        var cost=session.Snapshot();check(cost.WirePackets==5&&cost.WireBytes==7000&&!cost.Active,"wire costs are local admitted IP frames, separate from remote receipt and quality");
        Receipt(check);
        return new{scope="deterministic budget/crypto/receipt model only; no actual C++ or socket measurement",wire=wire.Snapshot(),cost};
    }
    static void Receipt(Action<bool,string> check)
    {
        var clock=new Clock();Guid id=Guid.NewGuid();var receiver=new PathDiagnosticReceiver(id,0,clock);
        check(!receiver.Record(PathDiagnosticFrames.Encode(Guid.NewGuid(),0,0,0))&&!receiver.Record(PathDiagnosticFrames.Encode(id,1,0,0)),
            "authenticated payload still must belong to the approved exact diagnostic session and leg");
        check(receiver.Record(PathDiagnosticFrames.Encode(id,0,0,0)),"first diagnostic establishes only a relative arrival baseline");
        clock.Ms=50;check(receiver.Record(PathDiagnosticFrames.Encode(id,0,2,20)),"receipts accept an out-of-order gap without waiting or retransmission");
        clock.Ms=60;check(receiver.Record(PathDiagnosticFrames.Encode(id,0,1,10))&&!receiver.Record(PathDiagnosticFrames.Encode(id,0,1,10)),
            "sample identity deduplicates repeated content even across fresh AEAD frames");
        var report=receiver.Finish(5,1000);
        check(report is{Result:"ReportedAtCutoff",ReceivedPackets:3,DeficitAtCutoffPercent:40,Duplicates:1,Reordered:1,MaximumReorderDistance:1,LongestAbsentRun:2,RelativelyDelayedOver20Ms:2},
            "bounded cutoff reports gaps, duplicate/reorder distance and relative delay without pretending one-way timing");
        check(!receiver.Record(PathDiagnosticFrames.Encode(id,0,3,30))&&ReferenceEquals(report,receiver.Finish(5,1000)),
            "late data cannot rewrite a sealed diagnostic report");
        var bad=new PathDiagnosticReceiver(id,0,clock);bad.Record(PathDiagnosticFrames.Encode(id,0,5,0));
        check(bad.Finish(5,1000).Result=="InvalidSummary","receiver detects a source summary inconsistent with admitted sample indices");
        byte[] malformed=PathDiagnosticFrames.Encode(id,0,0,0);malformed[^1]=1;
        check(!new PathDiagnosticReceiver(id,0,clock).Record(malformed),"unexpected payload padding cannot allocate or alter a measurement");
        check(new PathDiagnosticReceiver(id,0,clock).Finish(0,1000) is{Result:"NoOfferedSamples",DeficitAtCutoffPercent:null},
            "unavailable sender evidence remains unknown instead of a false zero-loss quality result");
    }
    public static async Task<object> Socket(Action<bool,string> check)
    {
        using var limit=new CancellationTokenSource(TimeSpan.FromSeconds(12));var token=limit.Token;
        byte[] key=RandomNumberGenerator.GetBytes(32);Guid generation=Guid.NewGuid(),attempt=Guid.NewGuid();
        using var pacer=new EgressPacer(10);
        await using var a=UdpTraversal.Create(new(System.Net.IPAddress.Loopback,0),generation,attempt,1,2,key,pacer:pacer,fairnessKey:"a");
        await using var b=UdpTraversal.Create(new(System.Net.IPAddress.Loopback,0),generation,attempt,2,1,key,pacer:pacer,fairnessKey:"b");
        using var linkA=new MeshLink(1,2,key);using var linkB=new MeshLink(2,1,key);CryptographicOperations.ZeroMemory(key);
        var c=new TraversalAttemptContext("network","a",Guid.NewGuid(),"b",Guid.NewGuid(),attempt,Guid.NewGuid(),1,Guid.NewGuid(),1,
            TraversalProfile.UdpDirect,true,true,Guid.NewGuid());
        var r=c with{LocalNodeId=c.RemoteNodeId,LocalBootId=c.RemoteBootId,RemoteNodeId=c.LocalNodeId,RemoteBootId=c.LocalBootId,
            LocalCandidateId=c.RemoteCandidateId,RemoteCandidateId=c.LocalCandidateId,ProtocolClient=false,Nominator=false};
        await using var pa=a.PreparePath(c,generation,b.Local);await using var pb=b.PreparePath(r,generation,a.Local);
        var paths=await Task.WhenAll(pa.Activate(token),pb.Activate(token));await using var pathA=paths[0];await using var pathB=paths[1];
        check(pathA.TrySend(linkA.Hello()),"real UDP owner sends initial shared peer handshake");
        var response=linkB.Receive((await pathB.Receive(token)).Span);check(pathB.TrySend(response.Reply!),"real UDP peer sends authenticated handshake response");
        response=linkA.Receive((await pathA.Receive(token)).Span);check(pathA.TrySend(response.Reply!),"real UDP returns final shared epoch confirmation");
        _=linkB.Receive((await pathB.Receive(token)).Span);
        await pa.DisposeAsync();await pb.DisposeAsync();
        byte[] payload=PathDiagnosticFrames.Encode(Guid.NewGuid(),0,0,0);
        check(!pathA.TrySend(linkA.Diagnostic(payload)!),"actual paced UDP path refuses ungranted diagnostic before queueing");
        var machine=new PathDiagnosticResources();using var session=machine.TryBegin(Guid.NewGuid())!;
        using var window=session.Open(pathA.Identity.PathId,3,2000);((IPathDiagnosticWire)pathA).GrantDiagnosticWire(window);
        var receiver=new PathDiagnosticReceiver(session.SessionId,0);
        for(int i=0;i<20;i++){
            check(pathA.TrySend(linkA.Diagnostic(PathDiagnosticFrames.Encode(session.SessionId,0,i,i*6))!),"approved diagnostic queues on exact retained UDP socket");
            var incoming=linkB.Receive((await pathB.Receive(token)).Span);
            check(incoming.Authenticated&&incoming.Diagnostic!=null&&receiver.Record(incoming.Diagnostic),"real UDP diagnostic is authenticated and separately received");
            await Task.Delay(6,token);
        }
        check(pathA.Identity.LeaseId==a.SocketId&&!a.Closed&&session.Snapshot() is{WirePackets:20,WireBytes:27440},
            "prepared-owner disposal preserves same UDP socket; final shared egress charges IPv4 plus UDP bytes");
        window.Dispose();check(!pathA.TrySend(linkA.Diagnostic(payload)!),"window cancellation rejects new actual UDP diagnostic submissions");
        check(pathA.TrySend(linkA.Data(new byte[1280])!),"ending diagnostic leaves ordinary selected business available");
        check(linkB.Receive((await pathB.Receive(token)).Span) is{Authenticated:true,Packet.Length:1280,Diagnostic:null},"ordinary payload remains independent of measurement completion");
        return new{scope="real paced Windows UDP sockets and MeshLink; manually granted test window, no formal Router policy/native/WinDivert/Wintun or WAN",
            cost=session.Snapshot(),receipt=receiver.Finish(20,1000),pacing=pacer.Snapshot()};
    }
    sealed class Clock:TimeProvider{public int Ms;public override long TimestampFrequency=>1000;public override long GetTimestamp()=>Ms;}
}
