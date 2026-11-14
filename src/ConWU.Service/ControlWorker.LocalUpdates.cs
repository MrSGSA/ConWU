using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    internal Func<ILocalUpdateHost>? LocalUpdateHostFactory {get;set;}
    internal UpdateNetworkState UpdateNetwork(string id)
    {
        var current=Volatile.Read(ref snapshot)!;var p=current.Profile!;
        return new(id,p.Mesh?.Pair.Network??"",p.Enabled,current.Status?.Peers?.Any(peer=>peer.Connected)==true);
    }
    UpdateRecoveryState UpdateRecovery()=>new(initialized&&!Volatile.Read(ref applicationStopping),ReleaseUpdateClient.CurrentVersion,
        workspace?.UpdateNetworks()??[UpdateNetwork("")]);
    void StartLocalUpdateRecovery()
    {
        if(networkContext||!OperatingSystem.IsWindows())return;
        // Ordinary status polling never scans packages or hashes an MSI.
        // After an update, recovery reporting starts independently of WebUI.
        if(LocalUpdateHostFactory!=null||File.Exists(Path.Combine(store.DirectoryPath,"updates","active-job.id")))
            localUpdates.Value.StartRecoveryMonitor(UpdateRecovery);
    }
    Task<UiControlReply> HandleLocalUpdate(UiControlRequest request,string callerSid,CancellationToken token)
    {
        if(networkContext||store.AuthorizedUiUser()!=callerSid)return Task.FromResult(new UiControlReply(false,"当前用户没有本机更新权限",null));
        if(request.Patch!=null||request.Network!=null||request.Configuration!=null||request.SettingsBatch!=null||request.UuTakeover!=null||request.NetworkId!=""||request.LocalUpdate==null)
            return Task.FromResult(new UiControlReply(false,"更新操作不能包含网络或其他设置修改",UiSnapshot()));
        try{
            token.ThrowIfCancellationRequested();
            if(Volatile.Read(ref applicationStopping))throw new IOException("后台正在停止");
            var manager=localUpdates.Value;manager.StartRecoveryMonitor(UpdateRecovery);
            if(request.Method=="update-download"){
                var release=updates.Value.Status;
                if(request.LocalUpdate.Version!=release.LatestVersion||request.LocalUpdate.Ticket.Length>0)throw new IOException("版本信息已变化，请重新检查更新");
                manager.BeginDownload(release);
            }else{
                if(request.LocalUpdate.Version!=manager.Status.Version)throw new IOException("确认的更新版本已变化");
                _=manager.Confirm(request.LocalUpdate.Ticket,callerSid,UpdateRecovery());
            }
            return Task.FromResult(new UiControlReply(true,"",UiSnapshot(),Operation:new(request.OperationId,request.Method,"已受理本机更新任务",true,false)));
        }catch(Exception ex)when(ex is IOException or ArgumentException or InvalidOperationException){
            return Task.FromResult(new UiControlReply(false,ex.Message,UiSnapshot()));
        }
    }
}
