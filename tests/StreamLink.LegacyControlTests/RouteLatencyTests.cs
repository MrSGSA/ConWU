using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using StreamLink.Core;

static class RouteLatencyTests
{
    // Intentionally uses the old public/internal surface too: the same fixture
    // can run against the installed rc.2 Core DLL as a regression baseline.
    internal static async Task<object> Run(Action<bool,string> check,CancellationToken token)
    {
        using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
        var routes=new LegacyRouteEvidence(Guid.NewGuid(),false,(s,t,g,e)=>{
            entered.Set();release.Wait(token);return new(g,e,s.ToString(),t.ToString(),7,3,"Fixture","Fixture","Fixture","");
        });
        using var channel=new LegacyControlChannel(Guid.NewGuid(),true,0,new(new TraversalResources()),routes);
        channel.Start(Environment.ProcessId);
        using var peer=new NamedPipeClientStream(".",channel.Name,PipeDirection.InOut,PipeOptions.Asynchronous);
        await peer.ConnectAsync(token);
        var secret=Convert.FromHexString(channel.Authorization);await peer.WriteAsync(secret,token);await peer.ReadExactlyAsync(new byte[64],token);
        async Task<byte> Exchange(ulong sequence)
        {
            byte[] frame=new byte[56];BinaryPrimitives.WriteUInt64LittleEndian(frame,sequence);BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(8),1);
            frame[16]=(byte)NativeWireKind.Maintenance;frame[17]=6;frame[19]=1;BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(20),64);
            IPAddress.Parse("10.0.0.2").GetAddressBytes().CopyTo(frame,24);IPAddress.Parse("198.51.100.1").GetAddressBytes().CopyTo(frame,28);
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(32),41000);BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(34),443);
            BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(44),40);BinaryPrimitives.WriteInt64LittleEndian(frame.AsSpan(48),Environment.TickCount64);
            await peer.WriteAsync(frame,token);var reply=new byte[16];await peer.ReadExactlyAsync(reply,token);
            if(BinaryPrimitives.ReadUInt64LittleEndian(reply)!=sequence)throw new IOException("reply sequence mismatch");return reply[8];
        }
        Task<byte>? first=null;long maximumReplyMs=0;
        try{
            first=Exchange(1);check(entered.Wait(2000),"diagnostic route observer is actually blocked inside the OS-query fixture");
            var clock=Stopwatch.StartNew();
            check(await first.WaitAsync(TimeSpan.FromMilliseconds(500),token)==0,"a blocked diagnostic route does not delay the first control permit");
            for(ulong i=2;i<=16;i++){
                await Task.Delay(80,token);long began=Stopwatch.GetTimestamp();
                check(await Exchange(i).WaitAsync(TimeSpan.FromMilliseconds(500),token)==0,"live pipe accepts maintenance while route observation is blocked, request="+i);
                maximumReplyMs=Math.Max(maximumReplyMs,(long)Stopwatch.GetElapsedTime(began).TotalMilliseconds);
            }
            check(clock.ElapsedMilliseconds>=1000&&!channel.Failed&&!release.IsSet,"control channel stays responsive beyond the unchanged native IPC timeout");
            return new{scope="real Windows named pipe, blocked advisory observer; no driver or physical network",blockedMs=clock.ElapsedMilliseconds,maximumReplyMs};
        }finally{
            release.Set();if(first!=null)try{await first.WaitAsync(TimeSpan.FromSeconds(3),token);}catch(Exception){ }
            // Wait for the fixture observer before disposing its wait handles.
            for(int i=0;routes.Snapshot().Witnesses.Length==0&&i<200;i++)await Task.Delay(10,token);
        }
    }

    internal static async Task<object> Bounds(Action<bool,string> check,CancellationToken token)
    {
        using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
        var source=new IPEndPoint(IPAddress.Parse("10.0.0.2"),41000);var target=new IPEndPoint(IPAddress.Parse("198.51.100.1"),443);
        int calls=0;
        using var routes=new LegacyRouteEvidence(Guid.NewGuid(),false,(s,t,g,e)=>{
            Interlocked.Increment(ref calls);if(e==1){entered.Set();release.Wait(token);}
            return new(g,e,s.ToString(),t.ToString(),7,3,"Fixture","Fixture","Fixture","");
        });
        routes.Prepare(1,source,target,out _);check(entered.Wait(2000),"advisory observation runs independently of Prepare");
        try{
            for(int i=0;i<100;i++)routes.Prepare(1,source,target,out _);
            check(calls==1&&routes.Snapshot().PendingObservations==1,"repeated controls coalesce one in-flight diagnostic query");
            routes.Prepare(2,source,target,out _);
            check(!routes.Prepare(1,source,target,out _)&&!routes.Use(1,source,target,out _),"asynchronous diagnostics retain stale-epoch rejection");
        }finally{release.Set();}
        for(int i=0;routes.Snapshot().Witnesses.Length==0&&i<200;i++)await Task.Delay(10,token);
        var report=routes.Snapshot();
        check(report.CaptureEpoch==2&&report.Witnesses.Single().CaptureEpoch==2&&report.StaleRejected>=2,"old asynchronous result cannot publish into the new capture epoch");
        using var unavailable=new LegacyRouteEvidence(Guid.NewGuid(),false,(_,_,_,_)=>throw new IOException("fixture"));
        check(unavailable.Prepare(1,source,target,out _),"diagnostic observer failure cannot reject a valid control request");
        for(int i=0;unavailable.Snapshot().Unavailable==0&&i<200;i++)await Task.Delay(10,token);
        check(unavailable.Snapshot().Witnesses.Single().Failure==nameof(IOException),"background diagnostic failure remains observable without faulting the shared worker");
        routes.Dispose();check(!routes.Prepare(3,source,target,out _)&&routes.Snapshot().PendingObservations==0,"retired route owner accepts no further work");
        using var occupied=new ManualResetEventSlim();using var unblock=new ManualResetEventSlim();using var completed=new ManualResetEventSlim();
        using var busy=new LegacyRouteEvidence(Guid.NewGuid(),false,(s,t,g,e)=>{
            occupied.Set();try{unblock.Wait(token);return new(g,e,s.ToString(),t.ToString(),7,3,"Fixture","Fixture","Fixture","");}finally{completed.Set();}
        });
        using var crowd=new LegacyRouteEvidence(Guid.NewGuid(),false,(s,t,g,e)=>new(g,e,s.ToString(),t.ToString(),7,3,"Fixture","Fixture","Fixture",""));
        LegacyRouteReport bounded;
        try{
            busy.Prepare(1,source,target,out _);check(occupied.Wait(2000),"one shared diagnostic worker is held while queue bounds are exercised");
            for(int i=0;i<100;i++)busy.Prepare(1,new(source.Address,42000+i),target,out _);
            for(int i=0;i<100;i++)crowd.Prepare(1,new(source.Address,43000+i),target,out _);
            bounded=crowd.Snapshot();
            check(busy.Snapshot().PendingObservations<=32&&bounded.PendingObservations<=32&&bounded.ObservationQueueRejected>0,
                "per-owner tuple records and the process-wide observation queue stay bounded without blocking controls");
            busy.Dispose();crowd.Dispose();
        }finally{unblock.Set();check(completed.Wait(2000),"retired in-flight diagnostic query finishes without delaying transport disposal");}
        check(busy.Snapshot().Witnesses.Length==0&&crowd.Snapshot().PendingObservations==0,"retired observations cannot repopulate evidence or leave queued ownership");
        return new{report,bounded,scope="coalescing, epoch fencing, observer error, global queue bound and retirement"};
    }
}
