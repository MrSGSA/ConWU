using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using StreamLink.Core;

namespace StreamLink;
public static class ServiceInstaller
{
    public static bool Installed { get { using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\StreamLink"); return key != null; } }
    static async Task Sc(params string[] args)
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        using var process = Process.Start(info)!; string stdout = await process.StandardOutput.ReadToEndAsync(); string stderr = await process.StandardError.ReadToEndAsync(); await process.WaitForExitAsync();
        if (process.ExitCode != 0) throw new IOException("服务管理失败：" + stdout + stderr);
    }
    public static async Task Install()
    {
        if (!WindowsHost.IsAdmin) throw new IOException("安装后台服务需要管理员权限");
        if (Installed) { try { await ServiceProtocol.Call(new("status")); return; } catch { await Sc("start", "StreamLink"); return; } }
        string parent = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "StreamLink");
        string destination = Path.Combine(parent, "0.2.0");
        foreach (string path in new[] { parent, destination })
        {
            if (Directory.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("安装目录不能是链接");
            Directory.CreateDirectory(path);
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid }) acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(acl);
        }
        string source = AppContext.BaseDirectory;
        foreach (string relative in new[] { "StreamLink.exe", "StreamLink.Service.exe", "StreamLink.Cli.exe", "discovery-defaults.json", "components/udp2raw-native.exe", "components/easytier-core.exe", "components/easytier-cli.exe", "components/WinDivert.dll", "components/WinDivert64.sys", "components/wintun.dll" })
        {
            string from = Path.Combine(source, relative), to = Path.Combine(destination, relative);
            if (!File.Exists(from)) throw new IOException("安装包不完整：" + relative);
            Directory.CreateDirectory(Path.GetDirectoryName(to)!);
            if ((File.GetAttributes(Path.GetDirectoryName(to)!) & FileAttributes.ReparsePoint) != 0 || (File.Exists(to) && (File.GetAttributes(to) & FileAttributes.ReparsePoint) != 0)) throw new IOException("安装目标不能是链接");
            if (!Path.GetFullPath(from).Equals(Path.GetFullPath(to), StringComparison.OrdinalIgnoreCase)) File.Copy(from, to, true);
        }
        await Sc("create", "StreamLink", "binPath=", "\"" + Path.Combine(destination, "StreamLink.Service.exe") + "\"", "start=", "auto", "DisplayName=", "StreamLink P2P Network");
        await Sc("description", "StreamLink", "原生 udp2raw P2P 组网，发现服务只交换元数据；关闭界面后继续运行。");
        await Sc("failure", "StreamLink", "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000");
        await Sc("start", "StreamLink");
    }
    public static async Task Uninstall()
    {
        if (!Installed) return;
        try { await ServiceProtocol.Call(new("stop")); } catch { }
        try { await Sc("stop", "StreamLink"); } catch { }
        // SCM keeps a deletion pending until a running service has stopped.
        await Sc("delete", "StreamLink");
    }
}
