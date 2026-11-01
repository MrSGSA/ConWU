using System.Diagnostics;
using System.Security.Principal;
using StreamLink.Core;

namespace StreamLink.Web;

internal static class DesktopBackend
{
    static int registering;
    public static async Task<UiControlReply> Call(UiControlRequest request,CancellationToken token)
    {
        if(request.Method=="register-service") {
            if(request.Patch!=null||request.Network!=null) return new(false,"服务请求参数无效",null);
            if(Interlocked.Exchange(ref registering,1)!=0)return new(false,"安装或启动仍在进行，请等待 Windows 确认窗口",null);
            try {
                string exe=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"..","StreamLink.exe"));
                if(!File.Exists(exe))return new(false,"请从完整运行包打开 StreamLink，或运行 MSI 安装包",null);
                bool installed=StartupSettings.Read().ServiceRegistered;
                var info=new ProcessStartInfo(exe){UseShellExecute=true,Verb="runas",WorkingDirectory=Path.GetDirectoryName(exe)!};
                if(WindowsInstance.IsValidation)throw new IOException("隔离验证实例不通过 WebUI 注册服务");
                if(installed)info.ArgumentList.Add("--start-service");
                else {info.ArgumentList.Add("--install");info.ArgumentList.Add("--ui-user-account");info.ArgumentList.Add(WindowsIdentity.GetCurrent().Name);}
                using var process=Process.Start(info)??throw new IOException("未能打开 Windows 安装授权窗口");
                await process.WaitForExitAsync(); // installation owns its lifetime; disconnect must not terminate it
                if(process.ExitCode!=0)return new(false,"服务操作未完成，请检查 Windows 安装提示或使用 MSI 修复安装",null);
            }catch(System.ComponentModel.Win32Exception ex)when(ex.NativeErrorCode==1223){return new(false,"已取消 Windows 管理员授权",null);}
            finally{Volatile.Write(ref registering,0);}
            request=new("status");
        }
        try{return await UiControlProtocol.Call(request,token);}
        catch(UiBackendException ex)when(ex.Code is "NotInstalled" or "Stopped"){
            return new(request.Method=="status",request.Method=="status"?"":ex.Message,new UiStatusDto("",Environment.MachineName,"",ex.Message,false,false,0,0,[],"info") {Desktop=StartupSettings.Read()});
        }
    }
}
