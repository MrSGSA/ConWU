using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace StreamLink.Core;

public static class StartupSettings
{
    public static UiDesktopStatus Read()
    {
        if(!OperatingSystem.IsWindows())return new(false,false,"NotInstalled");
        using var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+WindowsInstance.Name);
        return new(key!=null,key?.GetValue("Start") is int start && start==2,ControlServerIdentity.Availability());
    }
    // The service changes only its own startup type, with no user-supplied paths.
    public static void Set(bool enabled)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
        IntPtr manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            IntPtr service=OpenService(manager,WindowsInstance.Name,2);if(service==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
            try {if(!ChangeServiceConfig(service,uint.MaxValue,enabled?2u:3u,uint.MaxValue,null,null,IntPtr.Zero,null,null,null,null))throw new Win32Exception(Marshal.GetLastWin32Error());}
            finally{CloseServiceHandle(service);}
        }finally{CloseServiceHandle(manager);}
    }
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool ChangeServiceConfig(IntPtr service,uint type,uint start,uint error,string? binary,string? group,IntPtr tag,string? dependencies,string? account,string? password,string? display);
    [DllImport("advapi32.dll")]static extern bool CloseServiceHandle(IntPtr handle);
}
