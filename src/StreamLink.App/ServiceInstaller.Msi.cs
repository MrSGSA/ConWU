using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink;
public static partial class ServiceInstaller
{
    sealed record MsiAuthorization(string Transaction,string? Before,string After);
    static string MsiStatePath(string transaction)
    {
        if(!Guid.TryParse(transaction,out var id))throw new IOException("安装事务标识无效");
        return Path.Combine(ProfileStore.Root,"msi-authorization-"+id.ToString("N")+".json");
    }
    static FileStream MsiLock()
    {
        if(!WindowsHost.IsAdmin)throw new IOException("安装需要管理员权限");
        _=new ProfileStore();string path=Path.Combine(ProfileStore.Root,"install.lock");
        if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("安装锁不能是链接");
        return new FileStream(path,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
    }
    public static async Task ConfigureMsi(string selectedSid,string transaction)
    {
        using var installation=MsiLock();var store=new ProfileStore();
        VerifyBundle(AppContext.BaseDirectory);
        var sid=new SecurityIdentifier(selectedSid);if(!sid.IsAccountSid())throw new IOException("安装必须指定实际登录用户");
        string account=((NTAccount)sid.Translate(typeof(NTAccount))).Value;
        if(UiUserSelection.ResolveAccount(account)!=sid.Value)throw new IOException("安装用户身份核对失败");
        string? before=store.UiUserSnapshot();string after=before??sid.Value;
        string state=MsiStatePath(transaction);if(File.Exists(state))throw new IOException("上次安装授权恢复尚未完成，未覆盖原记录");
        File.WriteAllText(state,JsonSerializer.Serialize(new MsiAuthorization(transaction,before,after)));
        if(before==null){store.AuthorizeUiUser(after);store.AuditUiAuthorization("msi-explicit-user-grant",before,after);}
        if(!Installed)throw new IOException("Windows 安装程序尚未登记个人服务");
        using(var service=new System.ServiceProcess.ServiceController(WindowsInstance.Name))if(service.Status!=System.ServiceProcess.ServiceControllerStatus.Stopped)throw new IOException("原个人服务尚未停止，拒绝修改运行中的服务路径");
        string command="\""+Path.Combine(AppContext.BaseDirectory,"StreamLink.Service.exe")+"\""+(WindowsInstance.IsValidation?" --validation-instance "+WindowsInstance.ValidationId:"");
        await Sc("config",WindowsInstance.Name,"binPath=",command,"start=","auto","obj=","LocalSystem","DisplayName=","StreamLink Personal Network");
        await Sc("description",WindowsInstance.Name,"StreamLink 原生直连网络；配置保留于受保护的 ProgramData 目录。");
        await Sc("failure",WindowsInstance.Name,"reset=","86400","actions=","restart/5000/restart/15000/restart/60000");
    }
    public static void RollbackMsiAuthorization(string transaction)
    {
        using var installation=MsiLock();var store=new ProfileStore();string path=MsiStatePath(transaction);
        if(!File.Exists(path))return;
        if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("授权恢复记录不能是链接");
        var saved=JsonSerializer.Deserialize<MsiAuthorization>(File.ReadAllText(path))??throw new IOException("授权恢复记录无效");
        string? current=store.UiUserSnapshot();
        if(saved.Transaction!=transaction)throw new IOException("授权恢复事务不匹配");
        if(current==saved.Before){File.Delete(path);return;}
        if(current!=saved.After)throw new IOException("授权已被其他操作改变，未覆盖其新值");
        store.RestoreUiUser(saved.Before);store.AuditUiAuthorization("msi-rollback",saved.After,saved.Before);File.Delete(path);
    }
    public static void CommitMsiAuthorization(string transaction)
    {
        using var installation=MsiLock();string path=MsiStatePath(transaction);
        if(File.Exists(path)){if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("安装记录不能是链接");File.Delete(path);}
    }
    public static Task VerifyMsiReady()=>WaitLocalReady(true);
}
