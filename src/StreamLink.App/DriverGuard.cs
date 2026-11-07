using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink;

// An installer-only, process-owned foreign Wintun scope. The private stop
// file is the sole normal release signal; an abandoned installer leaves the
// process and exact ownership evidence available for inspection.
internal static class DriverGuard
{
    [DllImport("iphlpapi.dll")]static extern int ConvertInterfaceLuidToGuid(ref ulong luid,out Guid guid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    static void WriteReport(string path,object value)
    {
        string temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try{
            using(var file=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){JsonSerializer.Serialize(file,value);file.Flush(true);}
            File.Move(temporary,path,false);
        }finally{if(File.Exists(temporary))File.Delete(temporary);}
    }
    static void RequirePrivate(FileSystemSecurity acl)
    {
        string current=WindowsIdentity.GetCurrent().User?.Value??throw new UnauthorizedAccessException("无法确认当前用户");
        var permitted=new HashSet<string>(StringComparer.OrdinalIgnoreCase){current,"S-1-5-18","S-1-5-32-544"};
        if(!acl.AreAccessRulesProtected)throw new UnauthorizedAccessException("保护目录必须禁止继承权限");
        if(acl.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner||!permitted.Contains(owner.Value))
            throw new UnauthorizedAccessException("保护目录所有者不受信任");
        const FileSystemRights writes=FileSystemRights.WriteData|FileSystemRights.AppendData|FileSystemRights.CreateDirectories|
            FileSystemRights.WriteAttributes|FileSystemRights.WriteExtendedAttributes|FileSystemRights.Delete|
            FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
        foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow&&(rule.FileSystemRights&writes)!=0&&!permitted.Contains(((SecurityIdentifier)rule.IdentityReference).Value))
                throw new UnauthorizedAccessException("保护目录允许其他主体写入");
    }
    public static void Hold(string scope,string report,string stop)
    {
        if(!WindowsHost.IsAdmin)throw new UnauthorizedAccessException("保护网卡需要管理员权限");
        if(!Guid.TryParseExact(scope,"N",out var parsed)||parsed==Guid.Empty)throw new ArgumentException("保护 scope 无效");
        if(!Path.IsPathFullyQualified(report)||!Path.IsPathFullyQualified(stop))throw new ArgumentException("保护文件必须为绝对路径");
        report=Path.GetFullPath(report);stop=Path.GetFullPath(stop);string directory=Path.GetDirectoryName(report)!;
        if(!string.Equals(directory,Path.GetDirectoryName(stop),StringComparison.OrdinalIgnoreCase)||
            string.Equals(report,stop,StringComparison.OrdinalIgnoreCase)||string.Equals(report+".stopped",stop,StringComparison.OrdinalIgnoreCase)||!Directory.Exists(directory)||
            (File.GetAttributes(directory)&FileAttributes.ReparsePoint)!=0||File.Exists(report)||File.Exists(stop)||File.Exists(report+".stopped"))
            throw new IOException("保护文件目录或目标无效");
        // No FILE_SHARE_DELETE: the private evidence directory cannot be
        // renamed/replaced while a live guard is waiting for its stop signal.
        using var directoryLease=CreateFile(directory,0,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
        if(directoryLease.IsInvalid)throw new IOException("无法独占保护目录的重命名权",new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        RequirePrivate(new DirectoryInfo(directory).GetAccessControl());
        var process=Process.GetCurrentProcess();string started=process.StartTime.ToUniversalTime().ToString("O");
        try{
        using(var adapter=new NativeAdapter(Path.Combine(AppContext.BaseDirectory,"components"),scope,1)){
            ulong luid=adapter.InterfaceLuid??throw new IOException("保护网卡缺少 LUID");
            int error=ConvertInterfaceLuidToGuid(ref luid,out var adapterId);if(error!=0||adapterId==Guid.Empty)throw new IOException("保护网卡 GUID 不可用："+error);
            WriteReport(report,new{Status="Ready",Instance=WindowsInstance.Name,DataRoot=ProfileStore.Root,Scope=scope,InterfaceGuid=adapterId,ProcessId=Environment.ProcessId,StartedAt=started});
            while(true){
                try{
                    if(File.Exists(stop)&&(File.GetAttributes(directory)&FileAttributes.ReparsePoint)==0&&
                        (File.GetAttributes(stop)&FileAttributes.ReparsePoint)==0){
                        RequirePrivate(new DirectoryInfo(directory).GetAccessControl());
                        using var signal=new FileStream(stop,FileMode.Open,FileAccess.Read,FileShare.Read);
                        break;
                    }
                }catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException){}
                Thread.Sleep(250);
            }
        }
        WriteReport(report+".stopped",new{Status="Stopped",Scope=scope,ProcessId=Environment.ProcessId,StartedAt=started});
        }catch(Exception ex){
            try{if(!File.Exists(report))WriteReport(report,new{Status="Fail",Scope=scope,ProcessId=Environment.ProcessId,StartedAt=started,Error=ex.Message});}catch(IOException){}
            throw;
        }
    }
}
