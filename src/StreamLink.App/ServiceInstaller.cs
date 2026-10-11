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
        string bundleId = Convert.ToHexString(SHA256.HashData(ReadManifest(manifest)))[..10].ToLowerInvariant();
        string destination = Path.Combine(parent, DesktopVersion.Number + "-" + bundleId);
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
        source = Path.GetFullPath(source); destination = Path.GetFullPath(destination); parent = Path.GetFullPath(parent);
        if (!destination.StartsWith(parent.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("安装目标不在受管目录内");
        byte[] manifestBytes = ReadManifest(manifest);
        var files = ValidateBundle(source, manifestBytes);
        // Validate every destination ancestor before mutating any directory.
        EnsureNoLinks(parent, Path.GetRelativePath(parent, destination));
        foreach (var entry in files) EnsureNoLinks(destination, entry.Path);
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
            string relative = entry.Path;
            string from = Path.Combine(source, relative), to = Path.Combine(destination, relative);
            if (!File.Exists(from)) throw new IOException("安装包不完整：" + relative);
            Directory.CreateDirectory(Path.GetDirectoryName(to)!);
            if ((File.GetAttributes(Path.GetDirectoryName(to)!) & FileAttributes.ReparsePoint) != 0 || (File.Exists(to) && (File.GetAttributes(to) & FileAttributes.ReparsePoint) != 0)) throw new IOException("安装目标不能是链接");
            if (!Path.GetFullPath(from).Equals(Path.GetFullPath(to), StringComparison.OrdinalIgnoreCase)) {
                bool equal = false; if (File.Exists(to)) { using var existing = File.OpenRead(to); equal = Convert.ToHexString(SHA256.HashData(existing)) == entry.Hash; }
                if (!equal) File.Copy(from, to, true);
            }
            using var copied = File.OpenRead(to);
            if (Convert.ToHexString(SHA256.HashData(copied)) != entry.Hash) throw new IOException("安装文件校验失败：" + relative);
        }
        string targetManifest = Path.Combine(destination, "manifest.json");
        EnsureNoLinks(destination, "manifest.json");
        if (!Path.GetFullPath(manifest).Equals(Path.GetFullPath(targetManifest), StringComparison.OrdinalIgnoreCase)) File.WriteAllBytes(targetManifest, manifestBytes);
    }
    sealed record BundleFile(string Path, string Hash);
    public static int VerifyBundle(string source) => ValidateBundle(Path.GetFullPath(source), ReadManifest(Path.Combine(source, "manifest.json"))).Length;
    static byte[] ReadManifest(string path)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length is < 2 or > 4194304) throw new IOException("发布清单大小无效");
        byte[] bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes); return bytes;
    }
    static BundleFile[] ValidateBundle(string source, byte[] manifest)
    {
        if (manifest.Length is < 2 or > 4194304) throw new IOException("发布清单大小无效");
        ReadOnlyMemory<byte> json = manifest;
        if (manifest.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) json = json[3..];
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.GetProperty("version").GetString() != DesktopVersion.Release) throw new IOException("发布清单版本不符");
        var entries = document.RootElement.GetProperty("files");
        if (entries.GetArrayLength() is < 1 or > 4096) throw new IOException("发布文件数量无效");
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var files = new List<BundleFile>();
        foreach (var entry in entries.EnumerateArray()) {
            string relative = entry.GetProperty("path").GetString() ?? "";
            var parts = relative.Replace('/', '\\').Split('\\');
            if (Path.IsPathRooted(relative) || parts.Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith('.') || p.EndsWith(' ') || p.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                System.Text.RegularExpressions.Regex.IsMatch(p.Split('.')[0], @"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)))
                throw new IOException("安装清单路径无效");
            relative = Path.Combine(parts);
            if (relative.Equals("manifest.json", StringComparison.OrdinalIgnoreCase) || !paths.Add(relative)) throw new IOException("安装清单包含重复或保留路径");
            EnsureNoLinks(source, relative);
            string hash = entry.GetProperty("sha256").GetString() ?? "";
            if (hash.Length != 64 || hash.Any(c => !char.IsAsciiHexDigit(c))) throw new IOException("发布文件哈希无效");
            using var input = File.OpenRead(Path.Combine(source, relative));
            if (entry.TryGetProperty("length", out var size) && size.GetInt64() != input.Length || !Convert.ToHexString(SHA256.HashData(input)).Equals(hash, StringComparison.OrdinalIgnoreCase))
                throw new IOException("发布文件校验失败：" + relative);
            files.Add(new(relative, hash.ToUpperInvariant()));
        }
        return files.ToArray();
    }
    static void EnsureNoLinks(string root, string relative)
    {
        string at = root;
        foreach (var part in new[] { "" }.Concat(relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))) {
            at = Path.Combine(at, part);
            if ((File.Exists(at) || Directory.Exists(at)) && (File.GetAttributes(at) & FileAttributes.ReparsePoint) != 0) throw new IOException("安装路径不能经过链接");
        }
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
