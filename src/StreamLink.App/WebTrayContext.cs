using System.Diagnostics;
using System.Security.Principal;
using StreamLink.Core;

namespace StreamLink;

sealed class WebTrayContext : ApplicationContext
{
    readonly NotifyIcon tray;
    readonly Icon icon=ApplicationBranding.CreateIcon();
    readonly AppExitWindow exitWindow;
    readonly SemaphoreSlim gate = new(1,1);
    Process? web;
    bool closing;
    readonly bool openBrowser;
    public WebTrayContext(bool openBrowser=true)
    {
        this.openBrowser=openBrowser;
        var menu = new ContextMenuStrip();
        menu.Items.Add("打开 StreamLink 面板", null, async (_,_) => await Open());
        menu.Items.Add(MsiInstallation.ProductCode==null?"安装／更新个人后台":"修复／卸载安装", null, async (_,_) => await Install());
        menu.Items.Add("启动个人后台",null,async(_,_)=>await StartService());
        menu.Items.Add("桌面应急入口", null, (_,_) => {
            var info = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"StreamLink.exe")) {UseShellExecute=true,Arguments="--desktop"};
            if (!WindowsHost.IsAdmin) info.Verb="runas";
            try {Process.Start(info);} catch(Exception ex){MessageBox.Show(ex.Message,"StreamLink");}
        });
        menu.Items.Add("退出面板（网络继续运行）",null,(_,_) => ExitThread());
        tray = new NotifyIcon { Icon=icon, Text="StreamLink · AQ-1 个人版", ContextMenuStrip=menu, Visible=true };
        tray.DoubleClick += async (_,_) => await Open();
        var initial = new System.Windows.Forms.Timer {Interval=150};
        initial.Tick += async (_,_) => {initial.Stop();initial.Dispose();
            if(!ServiceInstaller.Installed && MessageBox.Show("首次使用需要安装独立的个人后台。安装仅使用 StreamLink-PersonalFeature，不替换 0.3.2。现在安装？","StreamLink",MessageBoxButtons.YesNo,MessageBoxIcon.Information)==DialogResult.Yes) await Install();
            await Open();
        };
        exitWindow=new AppExitWindow(ExitThread);
        initial.Start();
    }
    async Task Install()
    {
        try {
            if(MsiInstallation.ProductCode!=null){await MsiInstallation.Maintain();return;}
            string account=WindowsIdentity.GetCurrent().Name;
            var info=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"StreamLink.exe")) {UseShellExecute=true,Verb="runas",Arguments="--install --ui-user-account \""+account+"\""};
            using var process=Process.Start(info)!; await process.WaitForExitAsync();
            if(process.ExitCode!=0)throw new IOException("个人后台安装未完成，请查看包目录 install-error.log；现有服务未被选择。");
            tray.ShowBalloonTip(3000,"StreamLink","个人后台已准备完成",ToolTipIcon.Info);
        } catch(Exception ex) {MessageBox.Show(ex.Message,"StreamLink",MessageBoxButtons.OK,MessageBoxIcon.Information);}
    }
    async Task StartService()
    {
        try {
            var info=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"StreamLink.exe")){UseShellExecute=true,Verb="runas",Arguments="--start-service"};
            using var process=Process.Start(info)!;await process.WaitForExitAsync();
            if(process.ExitCode!=0)throw new IOException("个人后台未能启动，请修复安装或查看诊断日志。");
            await Open();
        }catch(Exception ex){MessageBox.Show(ex.Message,"StreamLink",MessageBoxButtons.OK,MessageBoxIcon.Information);}
    }
    async Task Open()
    {
        if(closing)return;
        await gate.WaitAsync();
        try {
            if(web==null||web.HasExited){
                web?.Dispose();
                var info=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"web","StreamLink.Web.exe")) {UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
                if(WindowsInstance.IsValidation){info.ArgumentList.Add("--validation-instance");info.ArgumentList.Add(WindowsInstance.ValidationId!);}
                info.ArgumentList.Add("--controlled");
                web=Process.Start(info)??throw new IOException("本机面板启动失败");
                _=web.StandardError.ReadToEndAsync();
            }
            await web.StandardInput.WriteLineAsync("open"); await web.StandardInput.FlushAsync();
            string? link=await web.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15));
            if(!Uri.TryCreate(link,UriKind.Absolute,out var address)||address.Host!="127.0.0.1"||address.Scheme!="http"||address.Fragment.Length!=65)throw new IOException("本机面板未返回有效的临时会话");
            if(openBrowser)Process.Start(new ProcessStartInfo(link!){UseShellExecute=true});
        } catch(Exception ex) {MessageBox.Show(ex.Message,"StreamLink",MessageBoxButtons.OK,MessageBoxIcon.Information);}
        finally {gate.Release();}
    }
    protected override void ExitThreadCore()
    {
        closing=true;tray.Visible=false;tray.Dispose();icon.Dispose();exitWindow.Dispose();
        try{web?.StandardInput.Close();}catch(IOException){}
        web?.Dispose();base.ExitThreadCore();
    }
}
