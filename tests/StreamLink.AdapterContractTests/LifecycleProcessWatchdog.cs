using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

static class LifecycleProcessWatchdog
{
    public sealed record Result(bool TimedOut,bool Reaped,int? ExitCode,int Pid,string Directory,string? Error);
    public static async Task<Result> Run(string directory,IEnumerable<string> arguments,TimeSpan timeout)
    {
        Directory.CreateDirectory(directory);
        string processPath=Environment.ProcessPath??throw new IOException("Missing host executable");
        var start=new ProcessStartInfo(processPath){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        if(Path.GetFileNameWithoutExtension(processPath).Equals("dotnet",StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        foreach(string argument in arguments)start.ArgumentList.Add(argument);
        using var child=Process.Start(start)??throw new IOException("Cannot start isolated lifecycle child");
        var stdout=Drain(child.StandardOutput,Path.Combine(directory,"stdout.log"));
        var stderr=Drain(child.StandardError,Path.Combine(directory,"stderr.log"));
        bool timedOut=false,reaped=false;string? error=null;int pid=child.Id;
        try{await child.WaitForExitAsync().WaitAsync(timeout);reaped=true;}
        catch(TimeoutException){
            timedOut=true;
            // Write evidence BEFORE killing only our own child process tree.
            var threads=new List<object>();
            try{foreach(ProcessThread thread in child.Threads){try{threads.Add(new{id=thread.Id,state=thread.ThreadState.ToString(),wait=thread.ThreadState==System.Diagnostics.ThreadState.Wait?thread.WaitReason.ToString():""});}catch(Exception ex){threads.Add(new{error=ex.Message});}finally{thread.Dispose();}}}catch(Exception ex){threads.Add(new{error=ex.Message});}
            try{File.WriteAllText(Path.Combine(directory,"watchdog-timeout.json"),JsonSerializer.Serialize(new{pid,timeoutMs=timeout.TotalMilliseconds,threads,nativeStacksCaptured=false,scope="Only the child started by this test; no foreign process, NIC or shared driver cleanup"},new JsonSerializerOptions{WriteIndented=true}));}
            catch(Exception ex){error="Timeout evidence write failed: "+ex.Message;} // still reap our child
            try{child.Kill(entireProcessTree:true);await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));reaped=true;}
            catch(Exception ex){error=(error??"")+" Could not reap isolated child: "+ex;}
        }
        try{await Task.WhenAll(stdout,stderr).WaitAsync(TimeSpan.FromSeconds(5));}
        catch(Exception ex){error=(error??"")+" Log drain failed: "+ex.Message;}
        return new(timedOut,reaped,reaped?child.ExitCode:null,pid,directory,error);
    }
    static async Task Drain(StreamReader source,string path)
    {
        using var target=new StreamWriter(path,false);char[] buffer=new char[4096];long written=0;int read;
        while((read=await source.ReadAsync(buffer))!=0){
            // Always drain pipes, even after reaching the artifact cap.
            int keep=(int)Math.Min(read,Math.Max(0,1024*1024-written));
            if(keep>0){await target.WriteAsync(buffer.AsMemory(0,keep));written+=keep;}
        }
    }
}
