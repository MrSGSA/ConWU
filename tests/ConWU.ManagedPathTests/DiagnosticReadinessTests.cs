using System.Diagnostics;
using StreamLink.Core;

static class DiagnosticReadinessTests
{
    public static async Task<object> Run(Action<bool,string> check)
    {
        using var pacer=new EgressPacer(10);
        var resources=new PathDiagnosticResources();
        using var session=resources.TryBegin(Guid.NewGuid())!;
        using var allowance=session.Open(Guid.NewGuid(),1,2000);
        using var blocked=new ManualResetEventSlim();
        int sent=0;long otherAt=0;
        using var diagnostic=pacer.Register("diagnostic-peer",(packet,_)=>{
            bool admitted=allowance.Admit(packet.Length);if(admitted)Interlocked.Increment(ref sent);return admitted;});
        using var other=pacer.Register("ordinary-peer",(packet,_)=>{Interlocked.Exchange(ref otherAt,Stopwatch.GetTimestamp());return true;});
        double Ready(int bytes){double delay=allowance.DelaySeconds(bytes);if(delay>0)blocked.Set();return delay;}
        var clock=Stopwatch.StartNew();
        for(int i=0;i<12;i++)check(diagnostic.TrySendWhenReady(new byte[1400],1400,null,Ready),"bounded queue accepts a low-rate diagnostic burst under the original byte ceiling");
        check(blocked.Wait(1000),"final measurement rate produces a real scheduler readiness wait");
        long offered=Stopwatch.GetTimestamp();
        check(other.TrySend(new byte[64],64),"another peer can enter while diagnostic head is deferred");
        while(Volatile.Read(ref sent)!=12||Volatile.Read(ref otherAt)==0){
            if(clock.ElapsedMilliseconds>1500)throw new TimeoutException("deferred diagnostic did not finish");
            await Task.Delay(2);
        }
        var cost=session.Snapshot();
        check(cost is{WirePackets:12,WireBytes:16800,Denied:0},"all queued diagnostic frames are paced at their own final allowance instead of being miscounted as wire rejection");
        check(clock.ElapsedMilliseconds>=60&&Stopwatch.GetElapsedTime(offered,otherAt).TotalMilliseconds<50,
            "slow diagnostic readiness preserves other peer progress and cannot drain at the faster aggregate rate");
        var ledger=diagnostic.SendQueue.Accounting;
        check(ledger is{Conserved:true,Failed.Packets:0,Sent.Packets:12},"deferred readiness retains the same queue and terminal accounting");
        using var cancelled=resources.TryBegin(Guid.NewGuid());
        check(cancelled==null,"readiness waiting cannot create another machine diagnostic session");
        allowance.Dispose();
        int before=sent;
        check(diagnostic.TrySendWhenReady(new byte[1400],1400,null,Ready),"expired queued work uses the existing bounded termination path");
        var timeout=Stopwatch.StartNew();
        while(diagnostic.SendQueue.Accounting.Failed.Packets==0){
            if(timeout.ElapsedMilliseconds>1000)throw new TimeoutException("expired readiness stalled queue");await Task.Delay(2);
        }
        check(sent==before,"ticket expiry terminates without reauthorizing or injecting a diagnostic frame");
        return new{scope="real shared egress timer/queues and final diagnostic allowance; memory callbacks, no native/UDP/WAN",
            elapsedMs=clock.ElapsedMilliseconds,cost,queue=diagnostic.SendQueue};
    }
}
