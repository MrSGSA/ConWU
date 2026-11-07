using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink;

public static partial class ServiceInstaller
{
    // Must run under install.lock after SCM stop + old process exit. Holding the
    // same lease as ControlWorker also excludes a console/service restart.
    static void PrepareWintunUpgrade(ProfileStore store)
    {
        if (Installed) {
            using var service = new ServiceController(WindowsInstance.Name);
            if (service.Status != ServiceControllerStatus.Stopped) throw new IOException("原服务仍在运行，未清理 Wintun");
        }
        string path = Path.Combine(ProfileStore.Root, "runtime.lock");
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("运行所有权文件不能是链接");
        using var runtime = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        var profiles = (store.HasSavedProfile?new[]{("",store.LoadForMaintenance())}:Array.Empty<(string,DeviceProfile)>()).Concat(store.NetworksForMaintenance()).ToArray();
        string journal = Path.Combine(ProfileStore.Root, "wintun-upgrade.jsonl");
        if (File.Exists(journal) && (File.GetAttributes(journal) & FileAttributes.ReparsePoint) != 0) throw new IOException("网卡维护日志不能是链接");
        void Log(object value) => File.AppendAllText(journal, JsonSerializer.Serialize(new { timestamp = DateTimeOffset.UtcNow, instance = WindowsInstance.Name, value }) + Environment.NewLine);
        try {
            Log("旧服务已停止，独占运行锁已取得，开始更新清理");
            foreach(var (_,profile) in profiles){
                if(profile.AdapterBackend!=PacketAdapterBackend.OfficialWintun)continue;
                string owner=profile.AdapterScope.Length>0?profile.AdapterScope:profile.Device;
                var result = WintunMaintenance.PrepareUpgrade(Path.Combine(AppContext.BaseDirectory, "components"), profile.Mesh?.Pair.Network??owner, profile.Mesh?.Self.Slot??1, text => Log(text),ownerNetwork:owner);
                Log(result);
            }
        } catch (Exception ex) { Log(new { failed = true, error = ex.Message }); throw; }
    }
    public static object AdapterMaintenance(string action)
    {
        if(!WindowsHost.IsAdmin)throw new UnauthorizedAccessException("网卡维护需要管理员权限");
        if(action is not ("inspect" or "release"))throw new ArgumentException("网卡维护操作无效");
        bool stopped=true;if(Installed){using var service=new ServiceController(WindowsInstance.Name);stopped=service.Status==ServiceControllerStatus.Stopped;}
        var store=new ProfileStore();
        var scopes=(store.HasSavedProfile?new[]{("",store.LoadForMaintenance())}:Array.Empty<(string,DeviceProfile)>()).Concat(store.NetworksForMaintenance()).Select(row=>new{
            ConfigurationId=row.Item1,NetworkId=row.Item2.Mesh?.Pair.Network??"",OwnerScope=row.Item2.AdapterScope.Length>0?row.Item2.AdapterScope:row.Item2.Device,Slot=row.Item2.Mesh?.Self.Slot??1
        }).ToArray();
        if(action=="release")PrepareWintunUpgrade(store);
        return new{Schema=1,Instance=WindowsInstance.Name,DataRoot=ProfileStore.Root,ServiceStopped=stopped,Scopes=scopes,Released=action=="release",Error=""};
    }

    [StructLayout(LayoutKind.Sequential)] struct ServiceProcessStatus
    {
        public uint Type, State, Accepted, Win32Exit, SpecificExit, Checkpoint, WaitHint, ProcessId, Flags;
    }
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceProcessStatus status, int size, out int needed);
    static Process? CaptureServiceProcess(ServiceController service)
    {
        if (!QueryServiceStatusEx(service.ServiceHandle.DangerousGetHandle(), 0, out var status, Marshal.SizeOf<ServiceProcessStatus>(), out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (status.ProcessId == 0) return null;
        Process? process = null;
        try { process = Process.GetProcessById(checked((int)status.ProcessId)); _ = process.Handle; return process; }
        catch (ArgumentException) { process?.Dispose(); return null; } // already exited
        catch { process?.Dispose(); throw; }
    }
}
