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
    public static bool Installed { get { using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+WindowsInstance.Name); return key != null; } }
    static async Task Sc(params string[] args)
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        using var process = Process.Start(info)!; string stdout = await process.StandardOutput.ReadToEndAsync(); string stderr = await process.StandardError.ReadToEndAsync(); await process.WaitForExitAsync();
        if (process.ExitCode != 0) throw new IOException("服务管理失败：" + stdout + stderr);
    }
    public static async Task Install(string? confirmedUiAccount=null)
    {
        if (!WindowsHost.IsAdmin) throw new IOException("安装后台服务需要管理员权限");
        var profileStore=new StreamLink.Service.ProfileStore();
        // All installers for this protected profile serialize the authorization
        // and SCM transaction. No identity is inferred from the elevated token.
        string installLock=Path.Combine(StreamLink.Service.ProfileStore.Root,"install.lock");
        if(File.Exists(installLock)&&(File.GetAttributes(installLock)&FileAttributes.ReparsePoint)!=0)throw new IOException("安装锁不能是链接");
        using var installation=new FileStream(installLock,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
        string? previousUi=profileStore.UiUserSnapshot();
        string selectedUi=UiAuthorizationPolicy.SelectForInstall(previousUi,confirmedUiAccount==null?null:UiUserSelection.ResolveAccount(confirmedUiAccount));
        bool wroteUi=false;
        string source = AppContext.BaseDirectory;
        string manifest = Path.Combine(source, "manifest.json");
        if (!File.Exists(manifest)) throw new IOException("请从完整发布包运行；缺少安装文件清单");
        VerifyBundle(source);
        string parent = WindowsInstance.IsValidation ? WindowsInstance.InstallParent : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), PersonalFeature.InstanceName);
        string bundleId = Convert.ToHexString(SHA256.HashData(ReadManifest(manifest)))[..10].ToLowerInvariant();
        string destination = Path.Combine(parent, DesktopVersion.Number + "-" + bundleId);
        await Task.Run(() => CopyBundle(source, destination, parent, manifest));
        bool existed = Installed;
        string? previous = null;
        bool wasRunning=false;int previousStart=2;string previousDisplay="StreamLink P2P Network";object? previousFailure=null,previousDescription=null;
        if (existed) {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+WindowsInstance.Name); previous = key?.GetValue("ImagePath") as string;
            if(string.IsNullOrEmpty(previous))throw new IOException("原服务的 ImagePath 无效，未修改原服务");
            previousStart=(int?)key!.GetValue("Start")??2;previousDisplay=key.GetValue("DisplayName") as string??previousDisplay;
            previousFailure=key.GetValue("FailureActions");previousDescription=key.GetValue("Description");
            using var service=new ServiceController(WindowsInstance.Name);wasRunning=service.Status!=ServiceControllerStatus.Stopped;
        }
        await ServiceInstallTransaction.Execute(async()=>{
            if(existed)await StopRegistered();
            if(profileStore.UiUserSnapshot()!=previousUi)throw new IOException("安装期间UI授权已改变，拒绝覆盖");
            if(previousUi==null){
                profileStore.AuthorizeUiUser(selectedUi);wroteUi=true;
                profileStore.AuditUiAuthorization("install-explicit-grant",previousUi,selectedUi);
            }
            string command="\""+Path.Combine(destination,"StreamLink.Service.exe")+"\""+(WindowsInstance.IsValidation?" --validation-instance "+WindowsInstance.ValidationId:"");
            await Sc(existed ? "config" : "create", WindowsInstance.Name, "binPath=",command, "start=", "auto", "DisplayName=", "StreamLink P2P Network");
            await Sc("description", WindowsInstance.Name, "原生 udp2raw P2P 组网；协调服务只交换元数据，业务始终直连。");
            await Sc("failure", WindowsInstance.Name, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000");
            await Sc("start", WindowsInstance.Name);
            await WaitRunning();await WaitLocalReady(true);
        },()=>{
            if(wroteUi){
                if(profileStore.UiUserSnapshot()!=selectedUi)throw new IOException("UI授权已由其他管理操作改变，未覆盖其新值");
                profileStore.RestoreUiUser(previousUi);
                profileStore.AuditUiAuthorization("install-rollback",selectedUi,previousUi);
            }
            return Task.CompletedTask;
        },async()=>{
            await StopRegistered();
            if(previous!=null){
                await Sc("config",WindowsInstance.Name,"binPath=",previous,"start=",previousStart==2?"auto":previousStart==4?"disabled":"demand","DisplayName=",previousDisplay);
                using(var key=Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+WindowsInstance.Name,true)!) {
                    if(previousFailure!=null)key.SetValue("FailureActions",previousFailure);else key.DeleteValue("FailureActions",false);
                    if(previousDescription!=null)key.SetValue("Description",previousDescription);else key.DeleteValue("Description",false);
                }
                if(wasRunning){await Sc("start",WindowsInstance.Name);await WaitRunning();await WaitLocalReady(false);}
            }else if(Installed)await Sc("delete",WindowsInstance.Name);
        });
    }
    static Task WaitRunning()=>Task.Run(()=>{using var service=new ServiceController(WindowsInstance.Name);service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(30));});
    static async Task WaitLocalReady(bool candidate)
    {
        using var ready=new CancellationTokenSource(15000);
        while(true){
            ready.Token.ThrowIfCancellationRequested();
            try {var status=await ServiceProtocol.Call(new("status"),ready.Token);
                if(status.Ok&&(!candidate||status.ServiceReady&&status.ControlOperationsVersion==1&&status.Version==DesktopVersion.Number))return;
            }catch(Exception ex)when(!ready.IsCancellationRequested&&ex is IOException or System.TimeoutException){ }
            await Task.Delay(250,ready.Token);
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
    public static int VerifyBundle(string source)
    {
        source=Path.GetFullPath(source);byte[] bytes=ReadManifest(Path.Combine(source,"manifest.json"));var files=ValidateBundle(source,bytes);
        ReadOnlyMemory<byte> json=bytes;if(bytes.AsSpan().StartsWith(new byte[]{0xef,0xbb,0xbf}))json=json[3..];using var doc=JsonDocument.Parse(json);var manifest=doc.RootElement;
        if(!manifest.TryGetProperty("schemaVersion",out var schema)||schema.GetInt32()!=2||manifest.GetProperty("architecture").GetString()!="win-x64"||manifest.GetProperty("tunAbi").GetInt32()!=2||manifest.GetProperty("meshProtocol").GetInt32()!=4)throw new IOException("发布格式、架构或协议ABI不匹配");
        string[] required=["StreamLink.exe","StreamLink.dll","StreamLink.runtimeconfig.json","StreamLink.deps.json","StreamLink.Service.exe","StreamLink.Service.dll","StreamLink.Service.runtimeconfig.json","StreamLink.Service.deps.json","components/udp2raw-native.exe","components/streamlink-tun.dll","components/wintun.dll","components/WinDivert.dll","components/WinDivert64.sys"];
        var paths=files.Select(f=>f.Path.Replace('\\','/')).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if(required.Any(p=>!paths.Contains(p)))throw new IOException("发布包缺少必需运行文件");
        if(PersonalFeature.Enabled) {
            if(!manifest.TryGetProperty("personalContract",out var contract)||contract.GetString()!=PersonalFeature.Contract)throw new IOException("个人包契约不匹配");
            string[] personalRequired=["web/StreamLink.Web.exe","web/StreamLink.Web.dll","web/StreamLink.Web.runtimeconfig.json","web/wwwroot/index.html","web/wwwroot/app.js","web/wwwroot/style.css"];
            if(personalRequired.Any(p=>!paths.Contains(p)))throw new IOException("AQ-1 个人包缺少 WebUI 运行文件");
            if(paths.Any(p=>p.Contains("self-tun",StringComparison.OrdinalIgnoreCase)||p.EndsWith("StreamLink.ResearchAdapters.dll",StringComparison.OrdinalIgnoreCase)||p.Contains("easytier",StringComparison.OrdinalIgnoreCase)))throw new IOException("AQ-1 产品包不能包含自研驱动或旧组网组件");
        }
        foreach(string path in new[]{"StreamLink.exe","StreamLink.Service.exe","components/udp2raw-native.exe","components/streamlink-tun.dll","components/wintun.dll","components/WinDivert.dll","components/WinDivert64.sys"}){
            using var input=File.OpenRead(Path.Combine(source,path));var head=new byte[64];input.ReadExactly(head);
            int offset=System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(60));if(head[0]!='M'||head[1]!='Z'||offset<64||offset>input.Length-6)throw new IOException("运行组件PE头无效："+path);
            input.Position=offset;var pe=new byte[6];input.ReadExactly(pe);if(!pe.AsSpan(0,4).SequenceEqual(new byte[]{0x50,0x45,0,0})||System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(4))!=0x8664)throw new IOException("运行组件非x64："+path);
        }
        // Listed hashes prove integrity, never provenance. Candidate bundles
        // remain explicitly unsigned until a real publisher signature exists.
        if(!manifest.TryGetProperty("provenance",out var provenance)||provenance.GetProperty("publisherSignature").GetString() is not("UnsignedCandidate" or "VerifiedPublisher"))throw new IOException("发布来源证据缺失");
        if(provenance.GetProperty("publisherSignature").GetString()=="VerifiedPublisher")throw new IOException("发布者签名晋级尚未实现，拒绝自声明可信来源");
        return files.Length;
    }
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
        using var service = new ServiceController(WindowsInstance.Name);
        if (service.Status == ServiceControllerStatus.Stopped) return;
        if (service.Status != ServiceControllerStatus.StopPending) await Sc("stop", WindowsInstance.Name);
        await Task.Run(() => service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(50)));
    }
    public static async Task StartIfNeeded()
    {
        using var service = new ServiceController(WindowsInstance.Name);
        if (service.Status == ServiceControllerStatus.Stopped) await Sc("start", WindowsInstance.Name);
        await Task.Run(() => service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30)));
    }
    public static async Task Uninstall()
    {
        if (!Installed) return;
        try { await ServiceProtocol.Call(new("stop")); } catch { }
        await StopRegistered();
        await Sc("delete", WindowsInstance.Name);
    }
}
