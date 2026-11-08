using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace StreamLink.Core;

public sealed class ChildJob : IDisposable
{
    readonly IntPtr handle;
    sealed record Child(Process Process, Action CompleteOutput);
    readonly List<Child> children = [];
    readonly object lifecycle = new();
    bool disposed;
    AggregateException? disposalFailure;
    [StructLayout(LayoutKind.Sequential)] struct BasicLimits { public long PerProcess, PerJob; public uint Flags; public UIntPtr MinWorkingSet, MaxWorkingSet; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits { public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimits info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
    public ChildJob()
    {
        if(OperatingSystem.IsLinux())return;
        handle = CreateJobObject(IntPtr.Zero, null);
        var limits = new ExtendedLimits(); limits.Basic.Flags = 0x2000; // KILL_ON_JOB_CLOSE
        if (handle == IntPtr.Zero || !SetInformationJobObject(handle, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()))
        { if (handle != IntPtr.Zero) CloseHandle(handle); throw new IOException("无法建立子进程生命周期约束"); }
    }
    public Process Start(string exe, IEnumerable<string> args, string? logPath, IDictionary<string, string>? environment = null, IEnumerable<string>? secrets = null)
        => StartObserved(exe,args,logPath,environment,secrets,null);
    internal Process StartObserved(string exe, IEnumerable<string> args, string? logPath, IDictionary<string, string>? environment, IEnumerable<string>? secrets, Action<string>? observe)
    {
        lock(lifecycle) {
            ObjectDisposedException.ThrowIf(disposed,this);
            return StartOwned(exe,args,logPath,environment,secrets,observe);
        }
    }
    Process StartOwned(string exe, IEnumerable<string> args, string? logPath, IDictionary<string, string>? environment, IEnumerable<string>? secrets, Action<string>? observe)
    {
        var info = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(exe)!, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var key in info.Environment.Keys.Where(k => k.StartsWith("ET_", StringComparison.Ordinal) || k.StartsWith("STREAMLINK_", StringComparison.Ordinal)).ToArray()) info.Environment.Remove(key);
        foreach (var arg in args) info.ArgumentList.Add(arg);
        if (environment != null) foreach (var p in environment) info.Environment[p.Key] = p.Value;
        var process = new Process { StartInfo = info };
        string[] redactions = (secrets ?? []).Where(x => x.Length > 0).Distinct().OrderByDescending(x => x.Length).ToArray();
        var writer = logPath == null ? null : new StreamWriter(logPath, false) { AutoFlush = true };
        var sync = new object();
        var outputComplete = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int outputEnds=0;
        bool outputClosed=false;
        IOException? outputFailure=null;
        void CloseOutput(bool incomplete=false) { lock(sync) {
            if(outputClosed)return;
            outputClosed=true;
            try { if(incomplete)writer?.WriteLine("配套组件输出未在停止期限内结束，已关闭日志读取。"); }
            catch(IOException ex) { outputFailure??=ex; }
            finally { try { writer?.Dispose(); } catch(IOException ex) { outputFailure??=ex; } }
        } }
        void CompleteOutput() {
            // Timed Process.WaitForExit only waits for the OS process. Its EOF
            // callbacks may still own the log; do not cancel them by disposing
            // Process first, and do not wait without a deadline for inherited pipes.
            bool complete=outputComplete.Task.Wait(TimeSpan.FromSeconds(5));
            CloseOutput(!complete);
            lock(sync)if(outputFailure!=null)throw new IOException("配套组件日志未能完整关闭。",outputFailure);
        }
        void Record(object sender, DataReceivedEventArgs e) {
            // Process.Exited can arrive before buffered stdout/stderr. Keep the
            // writer until both EOF events so a fatal cause is not discarded.
            if(e.Data==null){lock(sync){if(!outputClosed&&++outputEnds==2){CloseOutput();outputComplete.TrySetResult();}}return;}
            lock(sync){if(outputClosed)return;}
            // Observers do not own the log lock: a slow observer must not
            // prevent the bounded shutdown path from closing its file handle.
            observe?.Invoke(e.Data);
            lock(sync) {
            if(outputClosed)return;
            try { string line = e.Data; foreach (string secret in redactions) line = line.Replace(secret, "[redacted]", StringComparison.Ordinal); writer?.WriteLine(line); }
            catch(Exception ex) when (ex is ObjectDisposedException or IOException) { }
        } }
        bool started=false;
        try {
            if (!process.Start()) throw new IOException("无法启动配套组件");
            started=true;
            if (OperatingSystem.IsWindows() && !AssignProcessToJobObject(handle, process.Handle)) throw new IOException("无法托管配套组件，已停止启动");
            process.OutputDataReceived += Record; process.ErrorDataReceived += Record;
            process.EnableRaisingEvents = true; // attachment owners also subscribe to Exited
            process.BeginOutputReadLine(); process.BeginErrorReadLine();
            children.Add(new(process,CompleteOutput));return process;
        } catch {
            try {
                if(started){try{if(!process.HasExited)process.Kill(true);process.WaitForExit(5000);}catch(InvalidOperationException){}}
            } finally { CloseOutput();process.Dispose(); }
            throw;
        }
    }
    public bool AnyExited { get { lock(lifecycle)return children.Any(p => p.Process.HasExited); } }
    public void Dispose()
    {
        lock(lifecycle) {
            // Concurrent callers must not return until the first shutdown has
            // released its files. EOF handlers and observers do not take this gate.
            if(disposed){if(disposalFailure!=null)throw disposalFailure;return;}
            disposed=true;var owned=children.ToArray();children.Clear();
            List<Exception> failures=[];
            bool killIndividually=!OperatingSystem.IsWindows();
            if(OperatingSystem.IsWindows()&&!CloseHandle(handle)) {
                failures.Add(new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError(),"无法关闭配套组件任务"));
                killIndividually=true;
            }
            if(killIndividually)foreach(var child in owned) {
            try{if(!child.Process.HasExited)child.Process.Kill(true);}
            catch(InvalidOperationException){}
            catch(Exception ex){failures.Add(ex);}
            }
            foreach (var child in owned) {
            try {
                if(!child.Process.WaitForExit(5000))failures.Add(new IOException("配套组件未在停止期限内退出"));
            } catch(InvalidOperationException) { }
            catch(Exception ex){failures.Add(ex);}
            finally {
                try { child.CompleteOutput(); }
                catch(Exception ex){failures.Add(ex);}
                finally { try{child.Process.Dispose();}catch(Exception ex){failures.Add(ex);} }
            }
            }
            if(failures.Count>0)throw disposalFailure=new AggregateException("配套组件未完全停止，请检查日志。",failures);
        }
    }
}

[SupportedOSPlatform("windows")]
public static class WindowsHost
{
    public static bool IsAdmin => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    public static void AddFirewall(string name, string localIp, string peerIp)
    {
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!;
        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;
        try
        {
            rule.Name = name; rule.Description = "ConWU 已配对的虚拟 IP，停止时移除";
            rule.Protocol = 256; rule.Direction = 1; rule.Action = 1; rule.Enabled = true;
            rule.Profiles = int.MaxValue; rule.LocalAddresses = localIp; rule.RemoteAddresses = peerIp;
            policy.Rules.Add(rule);
        }
        finally { Marshal.FinalReleaseComObject(rule); Marshal.FinalReleaseComObject(policy); }
    }
    public static void RemoveFirewall(string name)
    {
        if (!name.StartsWith("StreamLink-", StringComparison.Ordinal)) throw new ArgumentException("规则不属于本软件");
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!;
        try { policy.Rules.Remove(name); } finally { Marshal.FinalReleaseComObject(policy); }
    }
}
