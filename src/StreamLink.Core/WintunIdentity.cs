using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace StreamLink.Core;

// One process owns an adapter identity, including the interval spent in PnP
// creation/close. A file lease survives thread changes and is released by the
// OS on process exit. Never delete these files: that would split ownership.
[SupportedOSPlatform("windows")]
public sealed record WintunIdentity(Guid Guid, string Name)
{
    public string DeviceId => @"SWD\WINTUN\" + Guid.ToString("B").ToUpperInvariant();
    public static WintunIdentity For(string network, int slot)
    {
        if (network.Length != 32 || network.Any(c => !char.IsAsciiHexDigit(c)) || slot is < 1 or > 254)
            throw new ArgumentException("Wintun 网络身份无效");
        return new(new Guid(SHA256.HashData(Encoding.ASCII.GetBytes($"streamlink-wintun-v4/{network}/{slot}")).AsSpan(0, 16)), $"StreamLink-{network[..8]}-{slot}");
    }

    public FileStream Acquire()
    {
        if (!WindowsHost.IsAdmin) throw new UnauthorizedAccessException("管理 Wintun 需要管理员权限");
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "StreamLink-Wintun");
        if (Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Wintun 所有权目录不能是链接");
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(root).Create(acl);
        new DirectoryInfo(root).SetAccessControl(acl);
        string path = Path.Combine(root, Guid.ToString("N") + ".lock");
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Wintun 所有权文件不能是链接");
        try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException ex) { throw new IOException("此 Wintun 网卡仍由其他实例持有；未接管或卸载，请等待原实例退出", ex); }
    }
}
