using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    readonly object uuGate=new();
    readonly SemaphoreSlim uuWake=new(0,1);
    CancellationTokenSource? uuStop;
    Task? uuRunning;
    UuTakeoverController? uuController;
    internal Func<IUuTakeoverPlatform>? UuTakeoverPlatformFactory {get;set;}

    internal UuTakeoverNetwork TakeoverNetwork(string id,string name)
    {
        var reply=Volatile.Read(ref snapshot)!;var p=reply.Profile!;
        string[] peers=(reply.Status?.Peers??[]).Where(peer=>peer.Connected&&p.Mesh?.Directory?.Members.Any(m=>m.Slot==peer.Slot&&m.Slot!=p.Mesh.Self.Slot)==true)
            .Select(peer=>peer.Ip).Distinct().ToArray();
        return new(id,name,p.Mesh?.LocalIp??"",peers,p.Enabled&&!Volatile.Read(ref applicationStopping)&&peers.Length>0);
    }
    UuTakeoverStatus TakeoverStatus()
    {
        var settings=Volatile.Read(ref snapshot)!.Profile!.UuTakeover;
        var current=Volatile.Read(ref uuController)?.Status??UuTakeoverStatus.Idle(settings);
        return current.Settings==settings?current:current with{Settings=settings,Revision=settings.Revision(),State="Applying",TrafficObserved=false,
            Message=settings.Enabled?"正在准备 UU 通道接管":"正在撤下 UU 临时选路限制"};
    }
    void WakeTakeover()
    {
        if(networkContext||Volatile.Read(ref applicationStopping))return;
        lock(uuGate){
            if(uuRunning==null&&initialized){
                uuStop=new();var token=uuStop.Token;
                uuController=new(UuTakeoverPlatformFactory?.Invoke()??new WindowsUuTakeoverPlatform());
                var controller=uuController;
                uuRunning=Task.Run(async()=>{
                    string previous="";
                    try{while(!token.IsCancellationRequested){
                        var settings=Volatile.Read(ref snapshot)!.Profile!.UuTakeover;
                        var networks=workspace?.TakeoverNetworks()??[TakeoverNetwork("",NetworkDisplayName)];
                        controller.Refresh(settings,networks,DateTimeOffset.UtcNow);
                        var state=controller.Status;
                        string transition=state.State+"/"+state.NetworkId;
                        if(previous!=transition){previous=transition;Log("UU通道接管："+state.Message);}
                        if(settings.Enabled)await uuWake.WaitAsync(TimeSpan.FromMilliseconds(500),token);
                        else await uuWake.WaitAsync(token);
                    }}catch(OperationCanceledException)when(token.IsCancellationRequested){}
                    finally{controller.Dispose();}
                },CancellationToken.None);
            }
            if(uuWake.CurrentCount==0)uuWake.Release();
        }
    }
    async Task StopTakeover()
    {
        Task? ending;lock(uuGate){uuStop?.Cancel();ending=uuRunning;}
        if(ending!=null)await ending.ConfigureAwait(false);
        lock(uuGate){uuStop?.Dispose();uuStop=null;uuRunning=null;}
    }
    void DisposeTakeover()
    {
        lock(uuGate)uuStop?.Cancel();
        Volatile.Read(ref uuController)?.Dispose();
    }
    async Task<UiControlReply> SaveUuTakeover(UiControlRequest request,string caller,CancellationToken token)
    {
        if(networkContext||store.AuthorizedUiUser()!=caller)return new(false,"当前用户没有本机接管控制权限",null);
        if(request.Patch!=null||request.Network!=null||request.Configuration!=null||request.SettingsBatch!=null||request.LocalUpdate!=null||request.NetworkId is null||request.NetworkId.Length>0||request.UuTakeover?.Settings is null)
            return new(false,"UU 接管操作不能包含其他网络或设置修改",UiSnapshot());
        Operation operation;bool duplicate;
        try{operation=OpenOperation(new("uu-takeover",OperationId:request.OperationId),token,out duplicate,new(caller,null,UuTakeover:request.UuTakeover));}
        catch(Exception ex){return new(false,OperationError(ex),UiSnapshot());}
        if(duplicate)return new(!operation.State.Completed||operation.State.Error.Length==0,operation.State.Error,UiSnapshot(),Operation:operation.State);
        bool acquired=false;
        try{
            await requests.WaitAsync(operation.Stop.Token);acquired=true;
            operation.Stop.Token.ThrowIfCancellationRequested();
            if(Volatile.Read(ref applicationStopping))throw new IOException("后台正在停止");
            var action=request.UuTakeover;action.Settings.Validate();
            if(action.Settings.Enabled&&!OperatingSystem.IsWindows()&&UuTakeoverPlatformFactory==null)throw new IOException("本机暂不支持 UU 通道接管");
            SetOperation(operation,"保存 UU 接管设置",false);
            lock(sync){
                if(store.AuthorizedUiUser()!=caller)throw new IOException("本机控制授权已改变");
                // A replay with the already committed value is harmless. A
                // stale window must never overwrite a newer user's preference.
                if(profile.UuTakeover!=action.Settings&&action.ExpectedRevision!=profile.UuTakeover.Revision())throw new IOException("UU 接管设置已被其他窗口修改，请核对最新设置后重试");
                if(profile.UuTakeover!=action.Settings){var updated=ProfileChanges.Copy(profile);updated.UuTakeover=action.Settings;store.Save(updated);profile=updated;PublishReply();}
            }
            if(profile.UuTakeover.Enabled||uuRunning!=null)WakeTakeover();
            CompleteOperation(operation);PublishReply();
            return new(true,"",UiSnapshot(),Operation:operation.State);
        }catch(Exception ex){string error=OperationError(ex,operation);CompleteOperation(operation,error);PublishReply();return new(false,error,UiSnapshot(),Operation:operation.State);}
        finally{if(acquired)requests.Release();}
    }
}
