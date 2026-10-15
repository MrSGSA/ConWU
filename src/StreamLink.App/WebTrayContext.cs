using System.Diagnostics;
using StreamLink.Core;

namespace StreamLink;

sealed class WebTrayContext : ApplicationContext
{
    readonly NotifyIcon tray;
    readonly TrayMenu menu;
    readonly Icon icon=ApplicationBranding.CreateIcon();
    readonly AppExitWindow exitWindow;
    readonly SemaphoreSlim gate=new(1,1);
    readonly CancellationTokenSource lifetime=new();
    readonly System.Windows.Forms.Timer statusTimer=new(){Interval=5000};
    readonly System.Windows.Forms.Timer initial=new(){Interval=150};
    Process? web;
    bool closing,statusBusy;
    readonly bool openBrowser;
    public WebTrayContext(bool openBrowser=true)
    {
        this.openBrowser=openBrowser;
        menu=new TrayMenu(async()=>await Open(),ExitThread);
        tray=new NotifyIcon{Icon=icon,Text=TrayInformation.Format(null),ContextMenuStrip=menu,Visible=true};
        tray.DoubleClick+=async(_,_)=>await Open();
        statusTimer.Tick+=async(_,_)=>await RefreshStatus();
        initial.Tick+=async(_,_)=>{initial.Stop();_=RefreshStatus();await Open();};
        exitWindow=new AppExitWindow(ExitThread,async()=>await Open());
        statusTimer.Start();initial.Start();
    }
    async Task RefreshStatus()
    {
        if(closing||statusBusy)return;
        statusBusy=true;
        try{
            var reply=await UiControlProtocol.Call(new("status"),lifetime.Token);
            if(!closing)tray.Text=TrayInformation.Format(reply.Ok?reply.Status:null,reply.Ok?"等待后台":"账号未授权");
        }catch(OperationCanceledException){if(!closing)tray.Text=TrayInformation.Format(null,"后台响应超时");}
        catch(UiBackendException ex){if(!closing)tray.Text=TrayInformation.Format(null,ex.Code switch{"NotInstalled"=>"后台未安装","Stopped"=>"后台已停止","AccessDenied"=>"账号未授权",_=>"后台连接异常"});}
        catch(Exception){if(!closing)tray.Text=TrayInformation.Format(null,"后台连接异常");}
        finally{statusBusy=false;}
    }
    async Task Open()
    {
        if(closing)return;
        try{
            await gate.WaitAsync(lifetime.Token);
        }catch(OperationCanceledException){return;}
        try{
            if(closing)return;
            if(web==null||web.HasExited){
                web?.Dispose();
                var info=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"web","StreamLink.Web.exe")){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
                if(WindowsInstance.IsValidation){info.ArgumentList.Add("--validation-instance");info.ArgumentList.Add(WindowsInstance.ValidationId!);}
                info.ArgumentList.Add("--controlled");
                web=Process.Start(info)??throw new IOException("本机面板启动失败");
                _=web.StandardError.ReadToEndAsync();
            }
            await web.StandardInput.WriteLineAsync("open");await web.StandardInput.FlushAsync();
            string? link=await web.StandardOutput.ReadLineAsync(lifetime.Token).AsTask().WaitAsync(TimeSpan.FromSeconds(15),lifetime.Token);
            if(!Uri.TryCreate(link,UriKind.Absolute,out var address)||address.Host!="127.0.0.1"||address.Scheme!="http"||address.Fragment.Length!=65)throw new IOException("本机面板未返回有效的临时会话");
            if(openBrowser&&!closing)Process.Start(new ProcessStartInfo(link!){UseShellExecute=true});
        }catch(OperationCanceledException)when(closing){}
        catch(Exception ex){if(!closing)MessageBox.Show(ex.Message,"StreamLink",MessageBoxButtons.OK,MessageBoxIcon.Information);}
        finally{gate.Release();}
    }
    protected override void ExitThreadCore()
    {
        if(closing)return;
        closing=true;initial.Stop();initial.Dispose();statusTimer.Stop();statusTimer.Dispose();lifetime.Cancel();
        tray.Visible=false;tray.Dispose();menu.Dispose();icon.Dispose();exitWindow.Dispose();
        try{web?.StandardInput.Close();}catch(IOException){}
        web?.Dispose();base.ExitThreadCore();
    }
}
