using System.Text.Json;

namespace StreamLink.Core;

public sealed record LocalUpdateAction(string Version="",string Ticket="");
public sealed record UpdateNetworkState(string Id,string NetworkId,bool Enabled,bool Connected);
public sealed record UpdateRecoveryState(bool Ready,string Version,UpdateNetworkState[] Networks);
public sealed record LocalUpdateStatus(bool Supported,string State="Idle",string Message="")
{
    public string Version {get;init;}="";
    public string Ticket {get;init;}="";
    public long DownloadedBytes {get;init;}
    public long TotalBytes {get;init;}
    public bool CanInstall {get;init;}
    public bool RebootRequired {get;init;}
    public bool Busy=>State is "Downloading" or "Verifying" or "Launching" or "Installing" or "RestoringNetworks";
}
public sealed record PreparedLocalUpdate(string Ticket,string Version,string Directory,string PackagePath,string Sha256,long Bytes);
public interface ILocalUpdateHost:IDisposable
{
    bool Supported {get;}
    Task<PreparedLocalUpdate> Download(ReleaseUpdateStatus release,Action<long,long> progress,CancellationToken token);
    Task Launch(PreparedLocalUpdate prepared,string callerSid,UpdateRecoveryState before,CancellationToken token);
    PreparedLocalUpdate? RestorePrepared()=>null;
    LocalUpdateStatus? ReadExternalStatus();
    void ReportRecovery(UpdateRecoveryState state);
}

// Download and installation are separate, authenticated operations. Neither UI
// cancellation nor a closed tab cancels work already admitted by the service.
public sealed class LocalUpdateManager:IDisposable
{
    readonly ILocalUpdateHost host;
    readonly object gate=new();
    readonly CancellationTokenSource stop=new();
    LocalUpdateStatus status;
    PreparedLocalUpdate? prepared;
    Task? pending,watching;
    bool disposed;
    bool followExternal=true;
    public LocalUpdateManager(ILocalUpdateHost host)
    {
        this.host=host;status=new(host.Supported);
        try{if(host.RestorePrepared() is {} ready){prepared=ready;status=Ready(ready);}}
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or JsonException){status=new(host.Supported,"Error","已下载的更新需要重新校验或下载："+ex.Message);}
    }
    static LocalUpdateStatus Ready(PreparedLocalUpdate value)=>new(true,"Ready","安装包已下载并校验，等待确认更新"){
        Version=value.Version,Ticket=value.Ticket,DownloadedBytes=value.Bytes,TotalBytes=value.Bytes,CanInstall=true};
    public LocalUpdateStatus Status=>Volatile.Read(ref status);
    public void StartRecoveryMonitor(Func<UpdateRecoveryState> read)
    {
        lock(gate){if(watching!=null||disposed)return;watching=Task.Run(async()=>{
            try{while(!stop.IsCancellationRequested){
                try{
                    host.ReportRecovery(read());
                    var external=host.ReadExternalStatus();
                    if(external!=null)lock(gate){
                        if(followExternal&&status.State is not("Downloading" or "Verifying" or "Ready")&&
                            (status.Ticket.Length==0||status.Ticket==external.Ticket))Volatile.Write(ref status,external);
                    }
                }catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or JsonException){}
                await Task.Delay(1000,stop.Token);
            }}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        });}
    }
    public void BeginDownload(ReleaseUpdateStatus release)
    {
        lock(gate){
            if(disposed)throw new ObjectDisposedException(nameof(LocalUpdateManager));
            if(!host.Supported)throw new IOException("当前安装不支持本地 MSI 更新，请使用完整 MSI 安装包");
            if(Status.Busy)throw new IOException("已有更新任务正在进行");
            if(!release.UpdateAvailable||release.Package==null||release.LatestVersion.Length==0)throw new IOException("请先检查并选择适合本机的正式版更新");
            followExternal=false;prepared=null;Volatile.Write(ref status,new(true,"Downloading","正在下载完整安装包，当前连接不受影响"){Version=release.LatestVersion,TotalBytes=release.Package.Bytes});
            pending=Task.Run(async()=>{
                try{
                    var value=await host.Download(release,(done,total)=>{
                        lock(gate)if(!disposed)Volatile.Write(ref status,Status with{DownloadedBytes=done,TotalBytes=total});
                    },stop.Token);
                    lock(gate){if(disposed)return;prepared=value;Volatile.Write(ref status,Ready(value));}
                }catch(Exception ex){lock(gate)if(!disposed)Volatile.Write(ref status,Status with{State="Error",Message="安装包准备未完成："+ex.Message,CanInstall=false});}
            },CancellationToken.None);
        }
    }
    public Task Confirm(string ticket,string callerSid,UpdateRecoveryState before)
    {
        lock(gate){
            if(disposed)throw new ObjectDisposedException(nameof(LocalUpdateManager));
            if(Status.Busy)throw new IOException("已有更新任务正在进行");
            if(!Status.CanInstall||prepared is not{} ready||!Guid.TryParseExact(ticket,"N",out _)||ticket!=ready.Ticket)throw new IOException("完整安装包尚未就绪，或确认的更新已经改变");
            Volatile.Write(ref status,Status with{State="Launching",Message="已确认更新，正在交给本机独立安装程序",CanInstall=false});
            followExternal=true;
            return pending=Task.Run(async()=>{
                try{
                    await host.Launch(ready,callerSid,before,stop.Token);
                    lock(gate)if(!disposed)Volatile.Write(ref status,Status with{State="Installing",Message="正在本机运行 MSI；远程断开后仍会继续安装并恢复组网"});
                }catch(Exception ex){lock(gate)if(!disposed)Volatile.Write(ref status,Status with{State="Error",Message="未能开始安装，当前连接保留："+ex.Message});}
            },CancellationToken.None);
        }
    }
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;}stop.Cancel();host.Dispose();}
}
