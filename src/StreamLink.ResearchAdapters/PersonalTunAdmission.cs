using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using StreamLink.Core;

namespace StreamLink.ResearchAdapters;

public sealed record TunPackageMember(string Name, string Sha256);
public sealed record TunPackageIdentity(int SchemaVersion, string SourceCommit, string Architecture, int DescriptorAbi,
    int UserAbi, int Mtu, string HardwareId, string ServiceName, TunPackageMember[] Files);
public sealed record TunTargetApproval(int SchemaVersion, string MachineGuid, string PackageHash, string DeviceInstanceId,
    string Purpose, DateTimeOffset ExpiresUtc, string KernelEvidenceSha256);

// No arbitrary DLL/index/boolean entry point is exposed by the product factory.
// This token can only be created after protected files, signature, approval,
// actual PnP identity and loaded image have all been checked.
public sealed class PersonalTunAdmission
{
    public string Dll { get; }
    public uint InterfaceIndex { get; }
    public string DeviceInstance { get; }
    public string PackageHash { get; }
    public string DriverHash { get; }
    PersonalTunAdmission(string dll, uint index, string device, string package, string driver)
        => (Dll, InterfaceIndex, DeviceInstance, PackageHash, DriverHash) = (dll, index, device, package, driver);

    public static void ValidateIdentity(TunPackageIdentity value)
    {
        string[] names = ["StreamLinkTun.sys", "StreamLinkTun.inf", "StreamLinkTun.cat", "streamlink-tun-research.dll"];
        if (value is null || value.SchemaVersion != 1 || value.Architecture != "win-x64" || value.DescriptorAbi != 2 || value.UserAbi != 1 ||
            value.Mtu != MeshLink.Mtu || value.HardwareId != @"ROOT\StreamLinkTun" || value.ServiceName != "StreamLinkTun" ||
            !Hex(value.SourceCommit,40) || value.Files is null || value.Files.Any(x=>x is null) ||
            value.Files.Length != names.Length || !value.Files.Select(x => x.Name).ToHashSet(StringComparer.Ordinal).SetEquals(names) ||
            value.Files.Any(x => !Hex(x.Sha256,64)))
            throw new IOException("自研 TUN 包身份、固定文件清单或 ABI 无效");
    }

    public static void ValidateApproval(TunTargetApproval approval, string machineGuid, string packageHash, DateTimeOffset now)
    {
        if (approval is null || approval.SchemaVersion != 1 || string.IsNullOrWhiteSpace(machineGuid) || approval.MachineGuid != machineGuid || !Hex(packageHash,64) || approval.PackageHash != packageHash ||
            approval.Purpose != "personal-target-after-kernel-gate" || approval.ExpiresUtc <= now ||
            approval.ExpiresUtc > now.AddDays(90) || approval.DeviceInstanceId is null || !approval.DeviceInstanceId.StartsWith(@"ROOT\STREAMLINKTUN\", StringComparison.OrdinalIgnoreCase) ||
            approval.DeviceInstanceId.Length > 200 || approval.DeviceInstanceId.Any(char.IsControl) ||
            !Hex(approval.KernelEvidenceSha256,64))
            throw new IOException("自研 TUN 缺少本机、当前包、有效期及内核 Gate 对应的明确准入");
    }

    [SupportedOSPlatform("windows")]
    public static async Task<PersonalTunAdmission> Inspect(string packageRoot, string approvalRoot, CancellationToken token)
    {
        if (!PersonalFeature.Enabled || !WindowsHost.IsAdmin) throw new IOException("自研 TUN 需要个人功能包和合法管理员入口");
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string expectedParent = Path.Combine(programFiles, PersonalFeature.InstanceName);
        string package = Path.GetFullPath(packageRoot), approvals = Path.GetFullPath(approvalRoot);
        if (!package.StartsWith(expectedParent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new IOException("自研 TUN 只能从受保护的个人安装目录加载，请先安装完整包");
        ProtectedFile(package, expectedParent, directory: true);
        ProtectedFile(approvals, approvals, directory: true);
        string identityPath = Path.Combine(package, "package-identity.json");
        ProtectedFile(identityPath, expectedParent);
        var identity = JsonSerializer.Deserialize<TunPackageIdentity>(File.ReadAllText(identityPath)) ?? throw new IOException("自研包身份为空");
        ValidateIdentity(identity);
        foreach (var member in identity.Files) {
            string file = Path.Combine(package, member.Name); ProtectedFile(file, expectedParent);
            if (!Hash(file).Equals(member.Sha256, StringComparison.OrdinalIgnoreCase)) throw new IOException("自研 TUN 包文件与固定身份不匹配");
        }
        string packageHash = Hash(identityPath);
        string approvalPath = Path.Combine(approvals, "target-approval.json"), evidencePath = Path.Combine(approvals, "kernel-gate.json");
        ProtectedFile(approvalPath, approvals); ProtectedFile(evidencePath, approvals);
        var approval = JsonSerializer.Deserialize<TunTargetApproval>(File.ReadAllText(approvalPath)) ?? throw new IOException("本机 TUN 准入为空");
        string machine = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", null) as string ?? throw new IOException("无法核验本机身份");
        ValidateApproval(approval, machine, packageHash, DateTimeOffset.UtcNow);
        if (!Hash(evidencePath).Equals(approval.KernelEvidenceSha256, StringComparison.OrdinalIgnoreCase)) throw new IOException("内核 Gate 证据文件不匹配");
        using (var evidence = JsonDocument.Parse(File.ReadAllText(evidencePath))) {
            var e = evidence.RootElement;
            if (e.GetProperty("evidenceLevel").GetString() != "DriverKernelIO" || e.GetProperty("packageHash").GetString() != packageHash ||
                new[] { "kernelIo", "cancellation", "permissions", "cleanup", "verifier" }.Any(k => e.GetProperty(k).GetString() != "Pass"))
                throw new IOException("自研 TUN 未通过与当前包匹配的针对性内核 Gate；模型和构建结果不能替代");
        }
        string id64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(approval.DeviceInstanceId));
        string cat64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(Path.Combine(package, "StreamLinkTun.cat")));
        // Encoded strings carry data, not PowerShell code. Fixed read-only commands.
        string script = $$"""
            $ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
            $id=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{id64}}'))
            $cat=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{cat64}}'))
            $signature=Get-AuthenticodeSignature -LiteralPath $cat
            if($signature.Status -ne 'Valid'){throw 'Catalog signature is not trusted'}
            $device=@(Get-CimInstance Win32_PnPEntity -OperationTimeoutSec 5 | Where-Object PNPDeviceID -eq $id)
            $adapter=@(Get-CimInstance Win32_NetworkAdapter -OperationTimeoutSec 5 | Where-Object PNPDeviceID -eq $id)
            $driver=@(Get-CimInstance Win32_SystemDriver -OperationTimeoutSec 5 | Where-Object Name -eq 'StreamLinkTun')
            $signed=@(Get-CimInstance Win32_PnPSignedDriver -OperationTimeoutSec 5 | Where-Object DeviceID -eq $id)
            if($device.Count -ne 1 -or $adapter.Count -ne 1 -or $driver.Count -ne 1 -or $signed.Count -ne 1){throw 'Managed device identity is not unique'}
            if($device[0].Service -ne 'StreamLinkTun' -or $device[0].ConfigManagerErrorCode -ne 0 -or $driver[0].State -ne 'Running' -or -not $signed[0].IsSigned){throw 'Approved driver is not actually loaded and signed'}
            $image=$driver[0].PathName
            if($image.StartsWith('\SystemRoot\')){$image=Join-Path $env:WINDIR $image.Substring(12)}
            if($image.StartsWith('\??\')){$image=$image.Substring(4)}
            [ordered]@{device=$id;index=[uint32]$adapter[0].InterfaceIndex;image=$image;catalogTrusted=$true}|ConvertTo-Json -Compress
            """;
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe")) {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new IOException("无法启动只读驱动身份核查");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(30000);
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(), stderr = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync(deadline.Token); }
        catch { try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { } throw; }
        if (process.ExitCode != 0) throw new IOException("自研 TUN 签名、设备或实际加载核查失败；未打开设备或修改网络");
        using var result = JsonDocument.Parse(await stdout);
        _ = await stderr;
        uint index = result.RootElement.GetProperty("index").GetUInt32();
        string image = result.RootElement.GetProperty("image").GetString()!;
        if (index == 0 || !Path.IsPathFullyQualified(image) || image.StartsWith(@"\\") || (File.GetAttributes(image) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("实际自研驱动路径或接口无效");
        string driverHash = identity.Files.Single(x => x.Name == "StreamLinkTun.sys").Sha256;
        if (!Hash(image).Equals(driverHash, StringComparison.OrdinalIgnoreCase)) throw new IOException("已加载设备的驱动文件与批准包不匹配");
        return new(Path.Combine(package, "streamlink-tun-research.dll"), index, approval.DeviceInstanceId, packageHash, driverHash);
    }

    public static string Hash(string file) { using var input = File.OpenRead(file); return Convert.ToHexString(SHA256.HashData(input)); }
    static bool Hex(string? value,int length)=>value?.Length==length && value.All(char.IsAsciiHexDigit);

    [SupportedOSPlatform("windows")]
    static void ProtectedFile(string path, string anchor, bool directory = false)
    {
        string full = Path.GetFullPath(path), root = Path.GetFullPath(anchor);
        if (full.StartsWith(@"\\") || (!full.Equals(root, StringComparison.OrdinalIgnoreCase) && !full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
            throw new IOException("自研 TUN 文件必须位于固定本地保护目录");
        string[] writers = ["S-1-5-18", "S-1-5-32-544"];
        string at = full;
        while (true) {
            bool isDirectory = at != full || directory;
            if ((File.GetAttributes(at) & FileAttributes.ReparsePoint) != 0) throw new IOException("自研 TUN 装载路径不能含重解析点");
            FileSystemSecurity acl = isDirectory ? new DirectoryInfo(at).GetAccessControl() : new FileInfo(at).GetAccessControl();
            if (acl.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !writers.Contains(owner.Value)) throw new IOException("自研 TUN 文件所有者不受信任");
            const FileSystemRights write = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & write) != 0 && !writers.Contains(rule.IdentityReference.Value))
                    throw new IOException("自研 TUN 装载文件可被非管理主体替换");
            if (at.Equals(root, StringComparison.OrdinalIgnoreCase)) break;
            at = Path.GetDirectoryName(at) ?? throw new IOException("保护目录边界无效");
        }
    }
}
