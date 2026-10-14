using StreamLink.ResearchAdapters;
using System.Text.Json;

int checks=0;
void Check(bool ok,string reason){if(!ok)throw new Exception(reason);checks++;}
for(int round=0;round<30;round++){
    using var readEntered=new ManualResetEventSlim();using var releaseRead=new ManualResetEventSlim();
    using var firstStop=new ManualResetEventSlim();using var cancel=new CancellationTokenSource();
    int closed=0;
    var adapter=new ResearchTunAdapter(_=>{readEntered.Set();releaseRead.Wait();return 0;},()=>firstStop.Set(),()=>Interlocked.Increment(ref closed));
    Task Start(Action action)=>Task.Factory.StartNew(action,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
    var read=Start(()=>{try{adapter.Read(new byte[1280],cancel.Token);}catch(OperationCanceledException){}});
    Task? dispose=null,callback=null;
    try{
        Check(readEntered.Wait(2000),"read entered injected native delegate");
        dispose=Start(adapter.Dispose);Check(firstStop.Wait(2000),"Dispose requested native stop before write-lock wait");
        Check(SpinWait.SpinUntil(()=>adapter.WaitingLifetimeWriters>0,2000),"writer is queued behind read");
        callback=Start(cancel.Cancel);
        Check(SpinWait.SpinUntil(()=>adapter.WaitingLifetimeReaders>0,2000),"cancellation callback waits behind writer");
        releaseRead.Set();
        // Old lock order needs the 5-second writer timeout to break the cycle.
        await Task.WhenAll(read,dispose,callback).WaitAsync(TimeSpan.FromSeconds(2));
        Check(closed==1,"close completed once without waiting for the 5-second timeout");
    }finally{
        releaseRead.Set();
        // No unbounded Dispose in failure cleanup. This process has no native
        // resource/driver; the test supervisor can terminate a stuck fixture.
        try{await Task.WhenAll(new[]{read,dispose,callback}.OfType<Task>()).WaitAsync(TimeSpan.FromSeconds(6));}catch{}
    }
}
Console.WriteLine(JsonSerializer.Serialize(new{status="Pass",checks,rounds=30,scope="Exact ResearchTunAdapter.Read/Stop/Dispose with managed delegates and controlled three-thread ordering; no DLL or SYS loaded"}));
