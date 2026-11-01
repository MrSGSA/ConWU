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
        var profile = store.LoadForMaintenance();
        string journal = Path.Combine(ProfileStore.Root, "wintun-upgrade.jsonl");
        if (File.Exists(journal) && (File.GetAttributes(journal) & FileAttributes.ReparsePoint) != 0) throw new IOException("网卡维护日志不能是链接");
        void Log(object value) => File.AppendAllText(journal, JsonSerializer.Serialize(new { timestamp = DateTimeOffset.UtcNow, instance = WindowsInstance.Name, value }) + Environment.NewLine);
        if (profile.Mesh == null || profile.AdapterBackend != PacketAdapterBackend.OfficialWintun) { Log("没有属于本实例的官方 Wintun 网络，无需卸载"); return; }
        try {
            Log("旧服务已停止，独占运行锁已取得，开始更新清理");
            var result = WintunMaintenance.PrepareUpgrade(Path.Combine(AppContext.BaseDirectory, "components"), profile.Mesh.Pair.Network, profile.Mesh.Self.Slot, text => Log(text));
            Log(result);
        } catch (Exception ex) { Log(new { failed = true, error = ex.Message }); throw; }
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
