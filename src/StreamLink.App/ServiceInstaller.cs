using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.Json;
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
        string source = AppContext.BaseDirectory;
        string manifest = Path.Combine(source, "manifest.json");
        if (!File.Exists(manifest)) throw new IOException("请从完整发布包运行；缺少安装文件清单");
        string parent = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "StreamLink");
        string bundleId = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(manifest)))[..10].ToLowerInvariant();
        string destination = Path.Combine(parent, "0.3.0-" + bundleId);
        await Task.Run(() => CopyBundle(source, destination, parent, manifest));
        bool existed = Installed;
        string? previous = null;
        if (existed) {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\StreamLink"); previous = key?.GetValue("ImagePath") as string;
            await StopRegistered();
        }
        try {
            await Sc(existed ? "config" : "create", "StreamLink", "binPath=", "\"" + Path.Combine(destination, "StreamLink.Service.exe") + "\"", "start=", "auto", "DisplayName=", "StreamLink P2P Network");
            await Sc("description", "StreamLink", "原生 udp2raw P2P 组网；协调服务只交换元数据，业务始终直连。");
            await Sc("failure", "StreamLink", "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000");
            await Sc("start", "StreamLink");
            await Task.Run(() => { using var service = new ServiceController("StreamLink"); service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30)); });
        } catch {
            if (previous != null) { try { await StopRegistered(); await Sc("config", "StreamLink", "binPath=", previous); await Sc("start", "StreamLink"); } catch { } }
            throw;
        }
    }
    static void CopyBundle(string source, string destination, string parent, string manifest)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(manifest));
        if (document.RootElement.GetProperty("version").GetString() != "0.3.0-preview") throw new IOException("发布清单版本不符");
        var files = document.RootElement.GetProperty("files").EnumerateArray().ToArray();
        foreach (var entry in files) {
            string relative = entry.GetProperty("path").GetString()!;
            string from = Path.GetFullPath(Path.Combine(source, relative));
            if (!from.StartsWith(Path.GetFullPath(source).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("安装清单路径无效");
            using var input = File.OpenRead(from);
            if (Convert.ToHexString(SHA256.HashData(input)) != entry.GetProperty("sha256").GetString()) throw new IOException("发布文件校验失败：" + relative);
        }
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
        foreach (var entry in files)
        {
            string relative = entry.GetProperty("path").GetString()!;
            string from = Path.Combine(source, relative), to = Path.Combine(destination, relative);
            if (!File.Exists(from)) throw new IOException("安装包不完整：" + relative);
            Directory.CreateDirectory(Path.GetDirectoryName(to)!);
            if ((File.GetAttributes(Path.GetDirectoryName(to)!) & FileAttributes.ReparsePoint) != 0 || (File.Exists(to) && (File.GetAttributes(to) & FileAttributes.ReparsePoint) != 0)) throw new IOException("安装目标不能是链接");
            if (!Path.GetFullPath(from).Equals(Path.GetFullPath(to), StringComparison.OrdinalIgnoreCase)) {
                bool equal = false; if (File.Exists(to)) { using var existing = File.OpenRead(to); equal = Convert.ToHexString(SHA256.HashData(existing)) == entry.GetProperty("sha256").GetString(); }
                if (!equal) File.Copy(from, to, true);
            }
            using var copied = File.OpenRead(to);
            if (Convert.ToHexString(SHA256.HashData(copied)) != entry.GetProperty("sha256").GetString()) throw new IOException("安装文件校验失败：" + relative);
        }
        string targetManifest = Path.Combine(destination, "manifest.json");
        if (!Path.GetFullPath(manifest).Equals(Path.GetFullPath(targetManifest), StringComparison.OrdinalIgnoreCase)) File.Copy(manifest, targetManifest, true);
    }
    static async Task StopRegistered()
    {
        if (!Installed) return;
        using var service = new ServiceController("StreamLink");
        if (service.Status == ServiceControllerStatus.Stopped) return;
        if (service.Status != ServiceControllerStatus.StopPending) await Sc("stop", "StreamLink");
        await Task.Run(() => service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(50)));
    }
    public static async Task StartIfNeeded()
    {
        using var service = new ServiceController("StreamLink");
        if (service.Status == ServiceControllerStatus.Stopped) await Sc("start", "StreamLink");
        await Task.Run(() => service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30)));
    }
    public static async Task Uninstall()
    {
        if (!Installed) return;
        try { await ServiceProtocol.Call(new("stop")); } catch { }
        await StopRegistered();
        await Sc("delete", "StreamLink");
    }
}
