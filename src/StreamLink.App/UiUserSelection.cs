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

    public static string? ConfirmForInstall(IWin32Window? owner)
    {
        if(!WindowsHost.IsAdmin)throw new IOException("安装后台服务需要管理员权限");
        if(new StreamLink.Service.ProfileStore().UiUserSnapshot()!=null)return null;
        using var dialog=new Form{Text="首次安装 · 确认日常使用者",ClientSize=new(570,250),StartPosition=FormStartPosition.CenterParent,
            FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,Font=Design.Font(),AutoScaleMode=AutoScaleMode.Dpi};
        var explanation=new Label{AutoSize=false,Location=new(20,20),Size=new(530,75),Text=$"当前提权账号：{WindowsIdentity.GetCurrent().Name}\n请填写平时登录桌面、使用StreamLink的账号。\n不会自动把提权管理员当作日常使用者；升级会保留本次授权。"};
        var account=new TextBox{Location=new(20,105),Width=530,MaxLength=256,PlaceholderText=@"计算机名\用户名 或 域\用户名",AccessibleName="日常登录用户账号"};
        var error=new Label{Location=new(20,142),Size=new(530,40),AutoEllipsis=true};
        var ok=new Button{Text="核对并授权",Location=new(300,198),Size=new(120,32)};
        var cancel=new Button{Text="取消",Location=new(430,198),Size=new(120,32),DialogResult=DialogResult.Cancel};
        string? result=null;
        ok.Click+=(_,_)=>{
            try{
                string sid=ResolveAccount(account.Text);
                string resolved=((NTAccount)new SecurityIdentifier(sid).Translate(typeof(NTAccount))).Value;
                if(MessageBox.Show(dialog,$"允许此用户读取受限状态、启动/停止网络及修改名称/日志等级：\n\n{resolved}\n{sid}\n\n不会授予配对私钥或管理员设置访问权限。","确认日常用户",MessageBoxButtons.OKCancel,MessageBoxIcon.Information)!=DialogResult.OK)return;
                result=resolved;dialog.DialogResult=DialogResult.OK;
            }catch(Exception ex){error.Text=ex.Message;}
        };
        dialog.Controls.AddRange([explanation,account,error,ok,cancel]);dialog.AcceptButton=ok;dialog.CancelButton=cancel;
        if(dialog.ShowDialog(owner)!=DialogResult.OK)throw new OperationCanceledException("已取消安装，未改变用户授权或停止现有网络");
        return result;
    }
}
