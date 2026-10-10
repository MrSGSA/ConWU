using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace StreamLink.Core;
[SupportedOSPlatform("windows")]
static class ControlServerIdentity
{
    [StructLayout(LayoutKind.Sequential)] struct Status { public uint Type, State, Accepted, Win32Exit, ServiceExit, Checkpoint, Hint, Pid, Flags; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool QueryServiceStatusEx(IntPtr service, int info, out Status status, int size, out int needed);
    [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
    public static void Verify(NamedPipeClientStream pipe)
    {
        IntPtr manager = OpenSCManager(null, null, 1), service = IntPtr.Zero;
        try
        {
            if (manager == IntPtr.Zero || (service = OpenService(manager, "StreamLink", 4)) == IntPtr.Zero || !QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<Status>(), out _) || status.State != 4 || !GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint pid) || pid == 0 || pid != status.Pid) throw new IOException("控制接口不是已注册的 StreamLink 服务，已拒绝发送配对信息");
        }
        finally { if (service != IntPtr.Zero) CloseServiceHandle(service); if (manager != IntPtr.Zero) CloseServiceHandle(manager); }
    }
}
