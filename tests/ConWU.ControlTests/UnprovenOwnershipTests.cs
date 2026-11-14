using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

static class UnprovenOwnershipTests
{
    public static async Task Child(string output){
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var worker=new ControlWorker();worker.StartLocal();
        var flags=BindingFlags.Instance|BindingFlags.NonPublic;
        typeof(ControlWorker).GetField("resourceShutdownUnproven",flags)!.SetValue(worker,true);
        typeof(ControlWorker).GetField("running",flags)!.SetValue(worker,Task.CompletedTask);
        var stopped=await worker.Handle(new("stop"));
        bool failedStop=!stopped.Ok&&stopped.Operation is {Completed:true}&&stopped.Operation.Error.Length>0&&stopped.Status?.State=="资源退出未完成";
        bool localRefused=false;try{await worker.StopLocal();}catch(IOException){localRefused=true;}
        worker.Dispose();worker=null!;GC.Collect();GC.WaitForPendingFinalizers();GC.Collect();
        bool secondRefused=false;try{using var other=new ControlWorker();}catch(IOException){secondRefused=true;}
        File.WriteAllText(output,JsonSerializer.Serialize(new{status=failedStop&&localRefused&&secondRefused?"Pass":"Fail",failedStop,localRefused,secondRefused,
            lockFile=Path.Combine(ProfileStore.Root,"runtime.lock"),pid=Environment.ProcessId,scope="Injected unproven resource state; actual profile/file ownership, no native driver"}));
        if(!failedStop||!localRefused||!secondRefused)throw new IOException("Unproven resource ownership was released or stop falsely succeeded");
    }
    public static async Task Run(Action<bool,string> check){
        string result=Path.Combine(Path.GetTempPath(),"StreamLink-unproven-owner-"+Guid.NewGuid().ToString("N")+".json");
        string exe=Environment.ProcessPath??throw new IOException("Test executable missing");
        var start=new ProcessStartInfo(exe){UseShellExecute=false,CreateNoWindow=true};
        if(Path.GetFileNameWithoutExtension(exe)=="dotnet")start.ArgumentList.Add(typeof(UnprovenOwnershipTests).Assembly.Location);
        start.ArgumentList.Add("--unproven-owner-child");start.ArgumentList.Add(result);
        using var child=Process.Start(start)??throw new IOException("Own child did not start");
        using var timeout=new CancellationTokenSource(20000);
        try{await child.WaitForExitAsync(timeout.Token);}catch{if(!child.HasExited){child.Kill(true);await child.WaitForExitAsync(new CancellationTokenSource(5000).Token);}throw;}
        check(child.ExitCode==0,"unproven owner child keeps failed stop and denies second owner after Dispose/GC");
        using var d=JsonDocument.Parse(File.ReadAllText(result));check(d.RootElement.GetProperty("status").GetString()=="Pass","child JSON agrees with exit code");
        using var reopened=new FileStream(d.RootElement.GetProperty("lockFile").GetString()!,FileMode.Open,FileAccess.ReadWrite,FileShare.None);
        check(reopened.CanWrite,"process termination releases quarantined file ownership for a clean restart");
    }
}
