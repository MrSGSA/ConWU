using System.Diagnostics;

namespace StreamLink.Core;

public sealed record PathDiagnosticSendResult(int AcceptedPackets,int RejectedOffers,double ElapsedMs,double OfferedPayloadMbps,string Result,
    long TimerWaits,double TimerWaitMs);

// Only schedules explicitly granted synthetic samples. It owns no socket or
// receiver; callback uses the existing peer AEAD and retained data path. The
// shared egress pacer still limits actual whole-IP sends and queue memory.
internal static class PathDiagnosticSender
{
    public static Task<PathDiagnosticSendResult> Send(PathDiagnosticAllowance allowance,double payloadMbps,int durationMs,
        Func<int,int,bool> send,CancellationToken token)
    {
        if(!double.IsFinite(payloadMbps)||payloadMbps is<.1 or>55||durationMs is<100 or>5000||!allowance.Active)
            throw new ArgumentException("Diagnostic sender requires a bounded granted window");
        var completion=new TaskCompletionSource<PathDiagnosticSendResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var worker=new Thread(()=>{
            try{
                using var wake=new AutoResetEvent(false);using var cancelled=token.Register(()=>wake.Set());using var timer=new EgressPacer.PreciseTimer();
                var clock=Stopwatch.StartNew();int accepted=0,rejected=0;long waits=0;double waiting=0;
                double rate=payloadMbps*1e6/8/PathDiagnosticFrames.PayloadBytes,credit=0,lastCredit=0;
                while(clock.Elapsed.TotalMilliseconds<durationMs&&allowance.Active&&!token.IsCancellationRequested){
                    double elapsed=clock.Elapsed.TotalSeconds;
                    // A delayed wake cannot replay every missed deadline into
                    // a fast outer pacer. Retain at most the final gate's
                    // bounded jitter envelope (four frames at low rates).
                    credit=Math.Min(allowance.MaximumSourceCredit,credit+Math.Max(0,elapsed-lastCredit)*rate);lastCredit=elapsed;
                    int count=Math.Min(8,(int)credit);bool backpressure=false;
                    for(int i=0;i<count;i++){
                        if(!allowance.Active||token.IsCancellationRequested||clock.Elapsed.TotalMilliseconds>=durationMs)break;
                        if(send(accepted,(int)clock.Elapsed.TotalMilliseconds)){accepted++;credit--;}
                        else{rejected++;backpressure=true;break;}
                    }
                    // The next sample, or a short wait after bounded queue
                    // rejection. Never spin through repeated rejected offers.
                    double wait=backpressure ? .001 : Math.Clamp((1-credit)/rate,.0001,.001);
                    long before=Stopwatch.GetTimestamp();timer.Wait(wake,wait);waits++;waiting+=Stopwatch.GetElapsedTime(before).TotalMilliseconds;
                }
                string result=token.IsCancellationRequested?"Cancelled":!allowance.Active?"AllowanceEnded":"Completed";
                completion.TrySetResult(new(accepted,rejected,clock.Elapsed.TotalMilliseconds,
                    accepted*PathDiagnosticFrames.PayloadBytes*8d/Math.Max(.001,clock.Elapsed.TotalSeconds)/1e6,result,waits,waiting));
            }catch(Exception ex){completion.TrySetException(ex);}
        }){IsBackground=true,Name="StreamLink diagnostic source",Priority=ThreadPriority.Normal};
        worker.Start();return completion.Task;
    }
}
