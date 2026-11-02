using System.Diagnostics;
using System.Text.Json;
using StreamLink.Core;

static class WintunReopenHarness
{
    public static async Task Run(string components,string output)
    {
        // A fresh random identity; no daily profile/service/adapter is touched.
        var mesh=MeshIdentity.Create("https://example.com/","","faketcp");
        var events=new List<object>();var clock=Stopwatch.StartNew();int round=0;bool completed=false;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        void Trace(string stage){lock(events)events.Add(new{round,stage,ms=clock.ElapsedMilliseconds});}
        try {
            for(round=1;round<=3;round++){
                using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(60));
                var adapter=await Task.Factory.StartNew(()=>new NativeAdapter(components,mesh.Pair.Network,1,Trace,timeout.Token,mesh.LocalIp),CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
                try {
                    bool rejected=false;try{using var duplicate=new NativeAdapter(components,mesh.Pair.Network,1,null,timeout.Token,mesh.LocalIp);}catch(IOException){rejected=true;}
                    if(!rejected)throw new Exception("Second live owner admitted");Trace("duplicate-owner-rejected");
                    using var readingStop=new CancellationTokenSource();
                    var reading=Task.Factory.StartNew(()=>{try{adapter.Read(new byte[2048],readingStop.Token);}catch(OperationCanceledException){}},CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
                    await Task.Delay(200);readingStop.Cancel();await reading.WaitAsync(TimeSpan.FromSeconds(5));Trace("read-joined");
                } finally {await Task.Factory.StartNew(adapter.Dispose,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);}
                Trace("close-joined");
            }
            completed=true;
        } finally {File.WriteAllText(output,JsonSerializer.Serialize(new{status=completed?"Pass":"Fail",identity=WintunIdentity.For(mesh.Pair.Network,1),rounds=3,events,scope="Isolated official Wintun read/cancel/close/reopen; no physical streaming claim"},new JsonSerializerOptions{WriteIndented=true}));}
    }
}
