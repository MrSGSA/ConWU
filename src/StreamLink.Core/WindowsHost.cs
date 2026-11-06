using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace StreamLink.Core;

public sealed class ChildJob : IDisposable
{
    readonly IntPtr handle;
    readonly List<Process> children = [];
    [StructLayout(LayoutKind.Sequential)] struct BasicLimits { public long PerProcess, PerJob; public uint Flags; public UIntPtr MinWorkingSet, MaxWorkingSet; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits { public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimits info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
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
        var info = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(exe)!, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var key in info.Environment.Keys.Where(k => k.StartsWith("ET_", StringComparison.Ordinal) || k.StartsWith("STREAMLINK_", StringComparison.Ordinal)).ToArray()) info.Environment.Remove(key);
        foreach (var arg in args) info.ArgumentList.Add(arg);
        if (environment != null) foreach (var p in environment) info.Environment[p.Key] = p.Value;
        var process = new Process { StartInfo = info };
        if (!process.Start()) throw new IOException("无法启动配套组件");
        if (OperatingSystem.IsWindows() && !AssignProcessToJobObject(handle, process.Handle)) { process.Kill(); process.Dispose(); throw new IOException("无法托管配套组件，已停止启动"); }
        children.Add(process);
        var writer = logPath == null ? null : new StreamWriter(logPath, false) { AutoFlush = true };
        string[] redactions = (secrets ?? []).Where(x => x.Length > 0).Distinct().OrderByDescending(x => x.Length).ToArray();
        var sync = new object();
        int outputEnds=0;
        void Record(object sender, DataReceivedEventArgs e) { lock(sync) {
            // Process.Exited can arrive before buffered stdout/stderr. Keep the
            // writer until both EOF events so a fatal cause is not discarded.
            if(e.Data==null){if(++outputEnds==2)writer?.Dispose();return;}
            observe?.Invoke(e.Data);
            try { string line = e.Data; foreach (string secret in redactions) line = line.Replace(secret, "[redacted]", StringComparison.Ordinal); writer?.WriteLine(line); }
            catch(Exception ex) when (ex is ObjectDisposedException or IOException) { }
        } }
        process.OutputDataReceived += Record; process.ErrorDataReceived += Record;
        process.EnableRaisingEvents = true; // attachment owners also subscribe to Exited
        process.BeginOutputReadLine(); process.BeginErrorReadLine(); return process;
    }
    public bool AnyExited => children.Any(p => p.HasExited);
    public void Dispose()
    {
        if(OperatingSystem.IsWindows())CloseHandle(handle);
        else foreach(var child in children)if(!child.HasExited){child.Kill();child.WaitForExit();}
        foreach (var p in children) { try { p.WaitForExit(5000); } catch { } p.Dispose(); }
        children.Clear();
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
            rule.Name = name; rule.Description = "StreamLink 已配对的虚拟 IP，停止时移除";
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
