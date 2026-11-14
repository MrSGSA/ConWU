using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using StreamLink.Core;

namespace StreamLink;

public static class UiUserSelection
{
    [DllImport("advapi32.dll",EntryPoint="LookupAccountNameW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool LookupAccountName(string? system,string account,byte[]? sid,ref uint sidBytes,
        StringBuilder? domain,ref uint domainChars,out int use);

    public static string ResolveAccount(string account)
    {
        if(!WindowsHost.IsAdmin)throw new IOException("选择日常用户授权需要管理员权限");
        account=account.Trim();
        if(account.Length is 0 or >256||account.Any(char.IsControl)||account.StartsWith("S-1-",StringComparison.OrdinalIgnoreCase))
            throw new IOException("请输入明确的用户账号（例如 计算机名\\用户名），不能直接传入SID");
        uint size=0,domainSize=0;
        _=LookupAccountName(null,account,null,ref size,null,ref domainSize,out _);
        int error=Marshal.GetLastWin32Error();
        if(error!=122||size is 0 or >256||domainSize>1024)throw new Win32Exception(error,"无法解析日常用户账号");
        byte[] buffer=new byte[checked((int)size)];var domain=new StringBuilder(checked((int)Math.Max(1u,domainSize)));
        domainSize=(uint)domain.Capacity;
        if(!LookupAccountName(null,account,buffer,ref size,domain,ref domainSize,out int use))
            throw new Win32Exception(Marshal.GetLastWin32Error(),"无法确认日常用户账号");
        var sid=new SecurityIdentifier(buffer,0);
        if(use!=1||!sid.IsAccountSid())throw new IOException("只能授权一个可解析的Windows用户，不能授权组、系统或任意SID");
        return sid.Value;
    }

}
