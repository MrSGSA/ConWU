using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed class ProfileStore
{
    public static string Root => Environment.GetEnvironmentVariable("STREAMLINK_PROFILE_ROOT") is { Length: > 0 } testRoot ? Path.GetFullPath(testRoot) : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "StreamLink");
    readonly string file;
    public ProfileStore()
    {
        if (Directory.Exists(Root) && (File.GetAttributes(Root) & FileAttributes.ReparsePoint) != 0) throw new IOException("配置目录不能是链接");
        Directory.CreateDirectory(Root);
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(Root).SetAccessControl(acl); file = Path.Combine(Root, "profile.dpapi");
    }
    public DeviceProfile Load()
    {
        if (!File.Exists(file)) return new();
        var profile = JsonSerializer.Deserialize<DeviceProfile>(ProtectedData.Unprotect(File.ReadAllBytes(file), "StreamLink-profile-v2"u8.ToArray(), DataProtectionScope.LocalMachine)) ?? throw new IOException("配置为空"); profile.Validate(); return profile;
    }
    public void Save(DeviceProfile profile)
    {
        profile.Validate();
        File.WriteAllBytes(file + ".tmp", ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(profile), "StreamLink-profile-v2"u8.ToArray(), DataProtectionScope.LocalMachine)); File.Move(file + ".tmp", file, true);
    }
}
