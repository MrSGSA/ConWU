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
    readonly System.Windows.Forms.Timer initial=new(){Interval=150};
    Process? web;
    Task<string>? webError;
    bool closing;
    readonly bool openBrowser;
    public WebTrayContext(bool openBrowser=true)
    {
        this.openBrowser=openBrowser;
        menu=new TrayMenu(async()=>await Open(),ExitThread);
        tray=new NotifyIcon{Icon=icon,Text=TrayInformation.Format(null),ContextMenuStrip=menu,Visible=true};
        tray.DoubleClick+=async(_,_)=>await Open();
        initial.Tick+=async(_,_)=>{
            initial.Stop();
            if(!openBrowser)_=CheckStartupAuthorization();
            if(!closing)await Open(openBrowser);
        };
        exitWindow=new AppExitWindow(ExitThread,async()=>await Open());
        initial.Start();
    }
    async Task CheckStartupAuthorization()
    {
        try{
            var reply=await UiControlProtocol.Call(new("status"),lifetime.Token);
            if(!closing&&!reply.Ok&&reply.Status==null&&reply.Error=="该本机用户未获UI控制授权")ExitThread();
        }catch(UiBackendException ex)when(ex.Code=="AccessDenied"){if(!closing)ExitThread();}
        catch(Exception ex)when(ex is IOException or OperationCanceledException){ }
    }
    async Task Open(bool launchBrowser=true)
    {
        if(closing)return;
        try{
            await gate.WaitAsync(lifetime.Token);
        }catch(OperationCanceledException){return;}
        try{
            if(closing)return;
            if(web==null||web.HasExited){
                web?.Dispose();
                var info=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"web","ConWU.Web.exe")){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
                if(WindowsInstance.IsValidation){info.ArgumentList.Add("--validation-instance");info.ArgumentList.Add(WindowsInstance.ValidationId!);}
                info.ArgumentList.Add("--controlled");
                web=Process.Start(info)??throw new IOException("本机面板启动失败");
                webError=web.StandardError.ReadToEndAsync();
            }
            await web.StandardInput.WriteLineAsync("open");await web.StandardInput.FlushAsync();
            using var readDeadline=CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);readDeadline.CancelAfter(TimeSpan.FromSeconds(15));
            string? link;
            try { link=await web.StandardOutput.ReadLineAsync(readDeadline.Token); }
            catch(OperationCanceledException) when(!closing) {
                // Cancel the actual read, not just a wait around it; otherwise
                // the next click still has a reader attached to the old pipe.
                try { web.StandardInput.Close(); if(!web.HasExited)web.Kill(); } catch(Exception ex) when(ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) { }
                web.Dispose();web=null;webError=null;
                throw new IOException("本机面板响应超时，请从托盘重新打开。");
            }
            if(link==null)throw new IOException(webError?.IsCompletedSuccessfully==true?webError.Result.Trim():"本机面板已退出，请重新打开");
            if(!Uri.TryCreate(link,UriKind.Absolute,out var address)||address.Host!="127.0.0.1"||address.Scheme!="http"||address.Fragment.Length!=65)throw new IOException("本机面板未返回有效的临时会话");
            if(launchBrowser&&!closing)Process.Start(new ProcessStartInfo(link!){UseShellExecute=true});
        }catch(OperationCanceledException)when(closing){}
        catch(Exception ex){if(!closing){if(launchBrowser)MessageBox.Show(ex.Message,"ConWU",MessageBoxButtons.OK,MessageBoxIcon.Information);else tray.Text=TrayInformation.Format(null,"面板启动失败，请从托盘重试");}}
        finally{gate.Release();}
    }
    protected override void ExitThreadCore()
    {
        if(closing)return;
        closing=true;initial.Stop();initial.Dispose();lifetime.Cancel();
        tray.Visible=false;tray.Dispose();menu.Dispose();icon.Dispose();exitWindow.Dispose();
        try{web?.StandardInput.Close();}catch(IOException){}
        web?.Dispose();base.ExitThreadCore();
    }
}
