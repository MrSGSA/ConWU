using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Web;

// Stored separately from device/network settings and never returned via UI IPC.
public sealed record RemoteAdminConfig(string Origin,string Salt,string PasswordHash,int Iterations)
{
    const int Work=600000;
    public static string FilePath(string root)=>Path.Combine(root,"remote-admin.json");
    public static RemoteAdminConfig Create(string origin,string password)
    {
        if(!Uri.TryCreate(origin,UriKind.Absolute,out var uri)||uri.Scheme!=Uri.UriSchemeHttps||uri.UserInfo.Length!=0||uri.AbsolutePath!="/"||uri.Query.Length!=0||uri.Fragment.Length!=0||uri.IsLoopback||uri.HostNameType==UriHostNameType.Unknown)
            throw new ArgumentException("远程管理地址必须是 HTTPS 域名来源，不含路径、用户名或查询");
        if(password.Length is <16 or >256||password.Any(char.IsControl))throw new ArgumentException("远程管理密码需为 16–256 个非控制字符");
        byte[] salt=RandomNumberGenerator.GetBytes(32);byte[] hash=Rfc2898DeriveBytes.Pbkdf2(password,salt,Work,HashAlgorithmName.SHA256,32);
        return new(uri.GetLeftPart(UriPartial.Authority),Convert.ToBase64String(salt),Convert.ToBase64String(hash),Work);
    }
    public bool Verify(string password)
    {
        if(password.Length>256||Iterations!=Work)return false;
        try {byte[] salt=Convert.FromBase64String(Salt),expected=Convert.FromBase64String(PasswordHash);if(salt.Length!=32||expected.Length!=32)return false;byte[] actual=Rfc2898DeriveBytes.Pbkdf2(password,salt,Iterations,HashAlgorithmName.SHA256,32);return CryptographicOperations.FixedTimeEquals(actual,expected);}
        catch(FormatException){return false;}
    }
    public void Save(string root){if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException();LinuxPlatform.PrivateDirectory(root);LinuxPlatform.PrivateWrite(FilePath(root),JsonSerializer.SerializeToUtf8Bytes(this));}
    public static RemoteAdminConfig? Load(string root)
    {
        string path=FilePath(root);if(!File.Exists(path))return null;
        if(new FileInfo(path).Length>4096||(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0||(File.GetUnixFileMode(path)&(UnixFileMode.GroupRead|UnixFileMode.GroupWrite|UnixFileMode.GroupExecute|UnixFileMode.OtherRead|UnixFileMode.OtherWrite|UnixFileMode.OtherExecute))!=0)throw new IOException("远程管理凭据文件权限无效");
        var config=JsonSerializer.Deserialize<RemoteAdminConfig>(File.ReadAllBytes(path))??throw new IOException("远程管理配置无效");
        if(config.Iterations!=Work||!Uri.TryCreate(config.Origin,UriKind.Absolute,out var uri)||uri.Scheme!="https"||uri.GetLeftPart(UriPartial.Authority)!=config.Origin||uri.IsLoopback||uri.UserInfo.Length>0)throw new IOException("远程管理配置无效");
        try{if(Convert.FromBase64String(config.Salt).Length!=32||Convert.FromBase64String(config.PasswordHash).Length!=32)throw new IOException("远程管理凭据无效");}catch(FormatException ex){throw new IOException("远程管理凭据无效",ex);}return config;
    }
}
