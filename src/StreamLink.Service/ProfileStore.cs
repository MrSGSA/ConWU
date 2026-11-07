using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed class ProfileStore
{
    readonly ProfileStore? deviceStore;
    readonly object persistenceGate;
    public string DirectoryPath {get;}
    internal Action<DeviceProfile>? ValidateNetworkProfile {get;set;}
    internal void WritePrivate<T>(string name,T value)
    {
        if(Path.GetFileName(name)!=name)throw new ArgumentException("备份名称无效");
        string path=Path.Combine(DirectoryPath,name),temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("受保护记录不能是链接");
        byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(value);
        if(OperatingSystem.IsLinux()){LinuxPlatform.PrivateWrite(path,bytes);return;}
        try{
            bytes=ProtectedData.Protect(bytes,"ConWU-private-document-v1"u8.ToArray(),DataProtectionScope.LocalMachine);
            using(var output=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){output.Write(bytes);output.Flush(true);}
            File.Move(temporary,path,true);
        }finally{if(File.Exists(temporary))File.Delete(temporary);}
    }
    internal T? ReadPrivate<T>(string name)
    {
        if(Path.GetFileName(name)!=name)throw new ArgumentException("备份名称无效");
        string path=Path.Combine(DirectoryPath,name);if(!File.Exists(path))return default;
        if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0||new FileInfo(path).Length>4_194_304)throw new IOException("受保护记录无效");
        byte[] bytes=File.ReadAllBytes(path);if(!OperatingSystem.IsLinux())bytes=ProtectedData.Unprotect(bytes,"ConWU-private-document-v1"u8.ToArray(),DataProtectionScope.LocalMachine);
        return JsonSerializer.Deserialize<T>(bytes)??throw new IOException("受保护记录为空");
    }
    internal void DeletePrivate(string name)
    {
        if(Path.GetFileName(name)!=name)throw new ArgumentException("记录名称无效");
        string path=Path.Combine(DirectoryPath,name);if(File.Exists(path)){if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("受保护记录不能是链接");File.Delete(path);}
    }
    public void AuthorizeUiUser(string value)
    {
        if(OperatingSystem.IsLinux()){if(value!=LinuxPlatform.UserIdentity)throw new IOException("Linux 控制仅授权后台所属用户");return;}
        var sid=new SecurityIdentifier(value);if(!sid.IsAccountSid())throw new IOException("必须授权单一用户SID");
        string target=Path.Combine(DirectoryPath,"ui-user.sid");if(File.Exists(target)&&(File.GetAttributes(target)&FileAttributes.ReparsePoint)!=0)throw new IOException("UI授权文件不能是链接");
        string temporary=Path.Combine(DirectoryPath,"ui-user-"+Guid.NewGuid().ToString("N")+".tmp");
        try{
            using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){
                var bytes=System.Text.Encoding.UTF8.GetBytes(sid.Value);stream.Write(bytes);stream.Flush(true);
            }
            File.Move(temporary,target,true);
        }finally{if(File.Exists(temporary))File.Delete(temporary);}
    }
    public void AuditUiAuthorization(string action,string? before,string? after)
    {
        string path=Path.Combine(DirectoryPath,"ui-authorization.jsonl");
        if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("授权审计文件不能是链接");
        string record=JsonSerializer.Serialize(new{timestamp=DateTimeOffset.UtcNow,action,before,after,actor=WindowsIdentity.GetCurrent().User?.Value});
        File.AppendAllText(path,record+Environment.NewLine);
    }

    internal string? AuthorizedUiUser()
    {
        if(deviceStore!=null)return deviceStore.AuthorizedUiUser();
        if(OperatingSystem.IsLinux())return LinuxPlatform.UserIdentity;
        string path=Path.Combine(DirectoryPath,"ui-user.sid");if(!File.Exists(path))return null;if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("UI授权文件不能是链接");
        var text=File.ReadAllText(path).Trim();if(text.Length>128)throw new IOException("UI授权文件无效");var sid=new SecurityIdentifier(text);return sid.IsAccountSid()?sid.Value:throw new IOException("UI授权SID无效");
    }
    public string? UiUserSnapshot()=>AuthorizedUiUser();
    public void RestoreUiUser(string? previous){if(previous!=null){AuthorizeUiUser(previous);return;}string path=Path.Combine(DirectoryPath,"ui-user.sid");if(File.Exists(path)){if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("UI授权文件不能是链接");File.Delete(path);}}
    public static string Root => WindowsInstance.IsValidation ? WindowsInstance.ProfileRoot : Environment.GetEnvironmentVariable("STREAMLINK_PROFILE_ROOT") is { Length: > 0 } testRoot ? Path.GetFullPath(testRoot) : OperatingSystem.IsLinux()?"/var/lib/streamlink":PersonalFeature.DataRoot;
    readonly string file;
    public bool HasSavedProfile=>File.Exists(file);
    public ProfileStore():this(Root){}
    internal ProfileStore(string directory,ProfileStore? device=null)
    {
        DirectoryPath=Path.GetFullPath(directory);deviceStore=device;persistenceGate=device?.persistenceGate??new();
        if (Directory.Exists(DirectoryPath) && (File.GetAttributes(DirectoryPath) & FileAttributes.ReparsePoint) != 0) throw new IOException("配置目录不能是链接");
        if(OperatingSystem.IsLinux()){LinuxPlatform.PrivateDirectory(DirectoryPath);file=Path.Combine(DirectoryPath,"profile.json");return;}
        Directory.CreateDirectory(DirectoryPath);
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(DirectoryPath).SetAccessControl(acl); file = Path.Combine(DirectoryPath, "profile.dpapi");
    }
    public DeviceProfile Load()
    {
        if (!File.Exists(file)) return new();
        var profile = JsonSerializer.Deserialize<DeviceProfile>(ReadProtected()) ?? throw new IOException("配置为空");
        HydrateShared(profile);
        bool migrated=PersonalFeature.Enabled && profile.MigrateAutomaticTransport();
        profile.Validate();
        if(PersonalFeature.Enabled) profile.RequireFixedTransport();
        if(migrated) {
            File.Copy(file, Path.Combine(DirectoryPath, "profile-before-fixed-transport-" + Guid.NewGuid().ToString("N") + ".dpapi"), false);
            Write(profile);
        }
        return profile;
    }
    // Maintenance identifies only the protected instance's signed mesh profile.
    // It must not migrate/save settings while the installation may roll back.
    public DeviceProfile LoadForMaintenance()
    {
        if (!File.Exists(file)) return new();
        if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new IOException("配置文件不能是链接");
        var profile = JsonSerializer.Deserialize<DeviceProfile>(ReadProtected()) ?? throw new IOException("配置为空");
        HydrateShared(profile);profile.Validate(); return profile;
    }
    public IReadOnlyList<(string ConfigurationId,DeviceProfile Profile)> NetworksForMaintenance()
    {
        var result=new List<(string,DeviceProfile)>();string folder=Path.Combine(DirectoryPath,"networks");
        if(!Directory.Exists(folder))return result;
        if((File.GetAttributes(folder)&FileAttributes.ReparsePoint)!=0)throw new IOException("网络配置目录不能是链接");
        foreach(string path in Directory.EnumerateDirectories(folder)){
            string id=Path.GetFileName(path);if(!Guid.TryParseExact(id,"N",out _))continue;
            if(result.Count>=1024)throw new IOException("网络维护记录过多，请检查数据目录");
            var network=new ProfileStore(path,this);if(network.HasSavedProfile)result.Add((id,network.LoadForMaintenance()));
        }
        return result;
    }
    public void Save(DeviceProfile profile)
    {
        lock(persistenceGate)SaveProfile(profile);
    }
    void SaveProfile(DeviceProfile profile)
    {
        ValidateNetworkProfile?.Invoke(profile);
        profile.Validate();
        if(PersonalFeature.Enabled) profile.RequireFixedTransport();
        if(File.Exists(file)){
            var previous=Load();
            if(previous.Mesh?.Directory is{} known&&profile.Mesh is{} next&&previous.Mesh.Pair.Network==next.Pair.Network&&previous.Mesh.OwnerKey==next.OwnerKey){
                if(next.Directory==null)next.Directory=known;
                MeshIdentity.ValidateDirectory(next.Directory,next.Pair.Network,next.OwnerKey,known.Revision);
                if(next.Directory.Revision==known.Revision&&next.Directory.Signature!=known.Signature)throw new IOException("同一授权revision内容冲突，不能回退撤销记录");
            }
        }
        Write(profile);
    }
    byte[] ReadProtected() {
        if((File.GetAttributes(file)&FileAttributes.ReparsePoint)!=0)throw new IOException("配置文件不能是链接");
        return OperatingSystem.IsLinux()?File.ReadAllBytes(file):ProtectedData.Unprotect(File.ReadAllBytes(file), "StreamLink-profile-v2"u8.ToArray(), DataProtectionScope.LocalMachine);
    }
    void Write(DeviceProfile profile)
    {
        var saved=ProfileChanges.Copy(profile);
        if(deviceStore!=null){saved.CloudflareDdnsToken="";saved.NodeSigningPrivate="";saved.Ddns=saved.Ddns with{Publish=false};}
        if(OperatingSystem.IsLinux()){LinuxPlatform.PrivateWrite(file,JsonSerializer.SerializeToUtf8Bytes(saved));return;}
        File.WriteAllBytes(file + ".tmp", ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(saved), "StreamLink-profile-v2"u8.ToArray(), DataProtectionScope.LocalMachine)); File.Move(file + ".tmp", file, true);
    }
    void HydrateShared(DeviceProfile profile)
    {
        if(deviceStore==null)return;
        var device=deviceStore.Load();profile.Device=device.Device;profile.DeviceName=device.DeviceName;
        profile.NodeSigningPrivate=device.NodeSigningPrivate;
        profile.LogLevel=device.LogLevel;profile.AutoStart=device.AutoStart;profile.Coordinator=new();
        profile.Ddns=device.Ddns;profile.CloudflareDdnsToken=device.CloudflareDdnsToken;
        if(profile.SavedNetworkSettings is {} saved)profile.SavedNetworkSettings=saved with{Coordinator=new(),Ddns=device.Ddns};
    }
    public void BackupLegacy(DeviceProfile profile)
    {
        if (profile.Pair == null || profile.Mesh != null) return;
        profile.Validate();
        string backup = Path.Combine(DirectoryPath, "profile-before-native-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8] + ".dpapi");
        if(OperatingSystem.IsLinux()){LinuxPlatform.PrivateWrite(backup,JsonSerializer.SerializeToUtf8Bytes(profile));return;}
        File.WriteAllBytes(backup, ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(profile), "StreamLink-profile-v2"u8.ToArray(), DataProtectionScope.LocalMachine));
    }
    public string BackupNetwork(DeviceProfile profile)
    {
        profile.Validate();
        if(profile.Mesh==null&&profile.Pair==null)throw new IOException("当前没有可备份的网络");
        string backup=Path.Combine(DirectoryPath,"profile-before-local-exit-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N")+(OperatingSystem.IsLinux()?".json":".dpapi"));
        var saved=ProfileChanges.Copy(profile);if(deviceStore!=null){saved.NodeSigningPrivate="";saved.CloudflareDdnsToken="";saved.Ddns=saved.Ddns with{Publish=false};}
        byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(saved);
        if(OperatingSystem.IsLinux())LinuxPlatform.PrivateWrite(backup,bytes);
        else File.WriteAllBytes(backup,ProtectedData.Protect(bytes,"StreamLink-profile-v2"u8.ToArray(),DataProtectionScope.LocalMachine));
        return backup;
    }
    public void BackupResearchProfile()
    {
        if (!File.Exists(file)) return;
        File.Copy(file, Path.Combine(DirectoryPath, "profile-before-aq1-" + Guid.NewGuid().ToString("N") + ".dpapi"), false);
    }
}
