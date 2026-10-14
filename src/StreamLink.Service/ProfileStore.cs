using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed class ProfileStore
{
    public void AuthorizeUiUser(string value)
    {
        var sid=new SecurityIdentifier(value);if(!sid.IsAccountSid())throw new IOException("必须授权单一用户SID");
        string target=Path.Combine(Root,"ui-user.sid");if(File.Exists(target)&&(File.GetAttributes(target)&FileAttributes.ReparsePoint)!=0)throw new IOException("UI授权文件不能是链接");
        string temporary=Path.Combine(Root,"ui-user-"+Guid.NewGuid().ToString("N")+".tmp");
        try{
            using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){
                var bytes=System.Text.Encoding.UTF8.GetBytes(sid.Value);stream.Write(bytes);stream.Flush(true);
            }
            File.Move(temporary,target,true);
        }finally{if(File.Exists(temporary))File.Delete(temporary);}
    }
    public void AuditUiAuthorization(string action,string? before,string? after)
    {
        string path=Path.Combine(Root,"ui-authorization.jsonl");
        if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("授权审计文件不能是链接");
        string record=JsonSerializer.Serialize(new{timestamp=DateTimeOffset.UtcNow,action,before,after,actor=WindowsIdentity.GetCurrent().User?.Value});
        File.AppendAllText(path,record+Environment.NewLine);
    }

    internal string? AuthorizedUiUser()
    {
        string path=Path.Combine(Root,"ui-user.sid");if(!File.Exists(path))return null;if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("UI授权文件不能是链接");
        var text=File.ReadAllText(path).Trim();if(text.Length>128)throw new IOException("UI授权文件无效");var sid=new SecurityIdentifier(text);return sid.IsAccountSid()?sid.Value:throw new IOException("UI授权SID无效");
    }
    public string? UiUserSnapshot()=>AuthorizedUiUser();
    public void RestoreUiUser(string? previous){if(previous!=null){AuthorizeUiUser(previous);return;}string path=Path.Combine(Root,"ui-user.sid");if(File.Exists(path)){if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("UI授权文件不能是链接");File.Delete(path);}}
    public static string Root => WindowsInstance.IsValidation ? WindowsInstance.ProfileRoot : Environment.GetEnvironmentVariable("STREAMLINK_PROFILE_ROOT") is { Length: > 0 } testRoot ? Path.GetFullPath(testRoot) : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "StreamLink");
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
        if(File.Exists(file)){
            var previous=Load();
            if(previous.Mesh?.Directory is{} known&&profile.Mesh is{} next&&previous.Mesh.Pair.Network==next.Pair.Network&&previous.Mesh.OwnerKey==next.OwnerKey){
                if(next.Directory==null)next.Directory=known;
                MeshIdentity.ValidateDirectory(next.Directory,next.Pair.Network,next.OwnerKey,known.Revision);
                if(next.Directory.Revision==known.Revision&&next.Directory.Signature!=known.Signature)throw new IOException("同一授权revision内容冲突，不能回退撤销记录");
            }
        }
        File.WriteAllBytes(file + ".tmp", ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(profile), "StreamLink-profile-v2"u8.ToArray(), DataProtectionScope.LocalMachine)); File.Move(file + ".tmp", file, true);
    }
    public void BackupLegacy(DeviceProfile profile)
    {
        if (profile.Pair == null || profile.Mesh != null) return;
        profile.Validate();
        string backup = Path.Combine(Root, "profile-before-native-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8] + ".dpapi");
        File.WriteAllBytes(backup, ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(profile), "StreamLink-profile-v2"u8.ToArray(), DataProtectionScope.LocalMachine));
    }
}
