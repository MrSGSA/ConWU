using System.Diagnostics;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using StreamLink.Core;

static class WintunReopenHarness
{
    public static async Task Run(string components,string output,bool diagnostic=false,bool fresh=false)
    {
        // A fresh random identity; no daily profile/service/adapter is touched.
        var mesh=MeshIdentity.Create("https://example.com/","","faketcp");
        var ownerNetwork=Guid.NewGuid().ToString("N");
        var events=new List<object>();var clock=Stopwatch.StartNew();int round=0;bool completed=false;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        using var logger=diagnostic?new OfficialLogger(components,output+".official.log"):null;
        void Trace(string stage){lock(events)events.Add(new{round,stage,ms=clock.ElapsedMilliseconds});}
        try {
            for(round=1;round<=3;round++){
                if(fresh&&round>1)mesh=MeshIdentity.Create("https://example.com/","","faketcp");
                using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(90));
                var adapter=await Task.Factory.StartNew(()=>new NativeAdapter(components,mesh.Pair.Network,round==3?2:1,Trace,timeout.Token,mesh.LocalIp,ownerNetwork:ownerNetwork),CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
                try {
                    bool rejected=false;try{using var duplicate=new NativeAdapter(components,mesh.Pair.Network,round==3?2:1,null,timeout.Token,mesh.LocalIp,ownerNetwork:ownerNetwork);}catch(IOException){rejected=true;}
                    if(!rejected)throw new Exception("Second live owner admitted");Trace("duplicate-owner-rejected");
                    using var readingStop=new CancellationTokenSource();
                    var reading=Task.Factory.StartNew(()=>{try{adapter.Read(new byte[2048],readingStop.Token);}catch(OperationCanceledException){}},CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
                    await Task.Delay(200);readingStop.Cancel();await reading.WaitAsync(TimeSpan.FromSeconds(5));Trace("read-joined");
                } finally {await Task.Factory.StartNew(adapter.Dispose,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);}
                Trace("close-joined");
                if(round==1){
                    var scope=WintunIdentity.For(ownerNetwork,1);var ids=WintunAdapterJournal.Read(scope).Select(i=>i.Guid).ToHashSet();
                    if(WindowsInterfaceInventory.Read().Any(r=>ids.Contains(r.Guid))){
                        using var cancelling=new CancellationTokenSource(TimeSpan.FromSeconds(20));bool cancelled=false;
                        var watch=Stopwatch.StartNew();
                        try{using var attempt=new NativeAdapter(components,mesh.Pair.Network,1,phase=>{Trace(phase);if(phase.StartsWith("previous-adapter-settle-wait/",StringComparison.Ordinal))cancelling.Cancel();},cancelling.Token,mesh.LocalIp,ownerNetwork:ownerNetwork);}
                        catch(OperationCanceledException)when(cancelling.IsCancellationRequested){cancelled=true;}
                        if(!cancelled||watch.Elapsed>TimeSpan.FromSeconds(15))throw new IOException("Settling cancellation did not promptly release ownership");
                        Trace("settle-cancellation-releases-ownership");
                    }
                }
            }
            for(round=4;round<=5;round++){
                if(round==5&&!fresh)mesh=MeshIdentity.Create("https://example.com/","","faketcp",mesh.LocalIp);
                if(fresh)mesh=MeshIdentity.Create("https://example.com/","","faketcp");
                var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
                if(Path.GetFileNameWithoutExtension(start.FileName).Equals("dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(typeof(WintunReopenHarness).Assembly.Location);
                foreach(var arg in new[]{"--wintun-reopen-owned-node",components,ownerNetwork,mesh.Pair.Network,mesh.LocalIp,output+".child-"+round+".json"})start.ArgumentList.Add(arg);
                using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();
                try{await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(90));}
                catch{if(!child.HasExited)child.Kill(true);throw;}
                if(child.ExitCode!=0)throw new IOException("Cross-process Wintun reopen failed: "+await stdout+await stderr);
                Trace("cross-process-open-close-joined");
            }
            completed=true;
        } finally {File.WriteAllText(output,JsonSerializer.Serialize(new{status=completed?"Pass":"Fail",network=mesh.Pair.Network,identity=WintunIdentity.For(ownerNetwork,1),rounds=3,crossProcessRounds=2,officialModulePinnedForDiagnostics=diagnostic,freshIdentityPerRound=fresh,lastRoundRecreatesNetworkAtSameIp=!fresh,events,scope="Isolated official Wintun read/cancel/close/reopen; settling cancellation; member-slot rotation; fresh-process reopen and network recreation at same IP; no physical streaming claim"},new JsonSerializerOptions{WriteIndented=true}));}
    }
    public static void Node(string components,string network,string ip,string output,string? ownerNetwork=null)
    {
        var stages=new List<string>();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(90));bool passed=false;
        try{
            using(var adapter=new NativeAdapter(components,network,1,stages.Add,timeout.Token,ip,ownerNetwork:ownerNetwork))stages.Add("opened");
            stages.Add("closed");passed=true;
        }finally{File.WriteAllText(output,JsonSerializer.Serialize(new{status=passed?"Pass":"Fail",stages}));}
    }
    sealed class OfficialLogger:IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]delegate void Log(int level,ulong timestamp,[MarshalAs(UnmanagedType.LPWStr)]string message);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]delegate void Set(IntPtr logger);
        readonly IntPtr library;readonly Set set;readonly Log log;int count;
        public OfficialLogger(string components,string output){
            string path=Path.GetFullPath(Path.Combine(components,"wintun.dll"));
            if(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))!="E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE")throw new IOException("Diagnostic driver hash mismatch");
            library=NativeLibrary.Load(path);set=Marshal.GetDelegateForFunctionPointer<Set>(NativeLibrary.GetExport(library,"WintunSetLogger"));
            var gate=new object();log=(level,_,message)=>{try{if(Interlocked.Increment(ref count)<=1000)lock(gate)File.AppendAllText(output,DateTimeOffset.UtcNow.ToString("o")+" "+level+" "+message+Environment.NewLine);}catch{}};
            set(Marshal.GetFunctionPointerForDelegate(log));
        }
        public void Dispose(){set(IntPtr.Zero);GC.KeepAlive(log);NativeLibrary.Free(library);}
    }
}
