using System.IO.Pipes;
using System.Security.Principal;
using StreamLink.Core;

namespace StreamLink.Service;
public sealed partial class ControlWorker
{
    sealed record UiOperation(string CallerSid,UiConfigPatch? Patch,UiNetworkAction? Network=null);

    UiStatusDto UiSnapshot()
    {
        if(Volatile.Read(ref uiPairSnapshot) is {Direct:true,Active:true} direct && direct.Expires<=DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            Volatile.Write(ref uiPairSnapshot,direct with{Active=false,Code="",State="直连邀请已过期；未使用的设备授权可从概况中移除"});
        var full=Volatile.Read(ref snapshot)!;var p=full.Profile!;var state=full.Status;var peers=state?.Peers??[];
        return new(System.Reflection.CustomAttributeExtensions.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(typeof(ControlWorker).Assembly)?.InformationalVersion??full.Version,p.DeviceName,p.Mesh?.LocalIp??state?.LocalIp??"",PublicText(state?.State??"网络未启动",p,256),full.ServiceReady,p.Enabled,peers.Count(x=>x.Connected),peers.Length,
            peers.Select(x=>new UiPeerDto(x.Slot,x.Name,x.Ip,x.Connected,x.Degraded,x.RttMs,PublicText(x.Detail,p,256)){Connection=PublicProgress(x.Connection,p),Liveness=x.Liveness,TraversalMethod=x.TraversalMethod,ActualTransport=x.ActualTransport,SentBytes=x.SentBytes,ReceivedBytes=x.ReceivedBytes,DroppedPackets=x.DroppedPackets,LocalDrops=x.LocalDrops,Quality=x.Quality?.Result??"Unknown",OuterSource=x.OuterSource,OuterTarget=x.OuterTarget}).ToArray(),p.LogLevel,SettingsPatchVersion:2)
            {Connection=PublicProgress(state?.Connection??(state==null?null:new("Blocked",state.Detail)),p),Adapter=state?.Adapter is {} adapter ? adapter with {Reason=PublicText(adapter.Reason,p,400)} : null,PersonalFeatureEdition=PersonalFeature.Enabled,NetworkId=p.Mesh?.Pair.Network??"",IsOwner=p.Mesh?.IsOwner==true,
             Settings=PublicSettings(p),SettingsRevision=SettingsRevision(p),MigrationNotice=p.MigrationNotice,Pairing=Volatile.Read(ref uiPairSnapshot),
             NetworkEstablishedAt=p.NetworkEstablishedAt,NetworkCreatedHere=p.NetworkCreatedHere,EntryResolutions=Volatile.Read(ref uiEntryResolutions),Desktop=StartupSettings.Read(),
             QualityText=full.Quality.Length>0?PublicText(full.Quality,p,400):"质量尚未测量",LastQuality=Volatile.Read(ref lastQuality),Logs=full.Logs.TakeLast(40).ToArray(),Operation=PublicOperation(full.Operation,p),Stages=Volatile.Read(ref stageLedger)};
    }
    static ConnectionProgress? PublicProgress(ConnectionProgress? progress,DeviceProfile profile) => progress == null ? null :
        progress with { Detail = PublicText(progress.Detail,profile,400) };
    internal async Task<UiControlReply> HandleUi(UiControlRequest request,string callerSid,CancellationToken token)
    {
        if(store.AuthorizedUiUser()!=callerSid)return new(false,"该本机用户未获UI控制授权",null);
        if(request.Method=="status"&&request.Patch==null&&request.Network==null)return new(true,"",UiSnapshot(),Operation:PublicOperation(OperationState(request.OperationId),Volatile.Read(ref snapshot)!.Profile!));
        if(request.Method is not ("patch" or "start" or "stop" or "retry" or "network" or "check" or "quality" or "cancel")||request.Method!="patch"&&request.Patch!=null||request.Method!="network"&&request.Network!=null)return new(false,"此接口不允许该操作",UiSnapshot());
        if(request.Method=="patch"&&request.Patch==null)return new(false,"设置补丁为空",UiSnapshot());
        if(request.Method=="network"&&request.Network==null)return new(false,"网络操作为空",UiSnapshot());
        if(request.Network is {} network && (network.Action is not {Length:>0 and <=32}||network.Action.Any(char.IsControl)))return new(false,"网络操作名称无效",UiSnapshot());
        var command=request.Method switch{"patch"=>"ui-patch","network"=>"ui-network","check"=>"personal-check",_=>request.Method};
        var result=await HandleCore(new(command,OperationId:request.OperationId,PeerSlot:request.PeerSlot,Mbps:request.Mbps,CancelOperationId:request.CancelOperationId),token,new UiOperation(callerSid,request.Patch,request.Network));
        if(store.AuthorizedUiUser()!=callerSid)return new(false,"该本机用户的UI控制授权已改变",null);
        var publicProfile=Volatile.Read(ref snapshot)!.Profile!;
        return new(result.Ok,PublicText(result.Error,publicProfile,1024),UiSnapshot(),Operation:PublicOperation(result.Operation,publicProfile));
    }

    async Task ServeUi(NamedPipeServerStream pipe,string allowed,CancellationToken token)
    {
        using(pipe)using(var deadline=CancellationTokenSource.CreateLinkedTokenSource(token)){
            string stage="client-identity";bool authorized=false;
            deadline.CancelAfter(20000);try{
                string caller=LocalControlPipe.ClientSid(pipe);
                if(caller!=allowed)return;
                authorized=true;stage="read-request";
                var request=await ServiceProtocol.Read<UiControlRequest>(pipe,deadline.Token);
                stage="handle-request";
                var handling=HandleUi(request,caller,token);
                UiControlReply reply;
                if(request.OperationId!=Guid.Empty && request.Method!="status" && await Task.WhenAny(handling,Task.Delay(700,deadline.Token))!=handling){
                    var operation=PublicOperation(OperationState(request.OperationId),Volatile.Read(ref snapshot)!.Profile!);
                    reply=new(operation?.Completed!=true||operation.Error.Length==0,operation?.Error??"",UiSnapshot(),Operation:operation);
                    _=handling.ContinueWith(t=>Log("UI后台操作异常："+t.Exception!.GetBaseException().GetType().Name),CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted,TaskScheduler.Default);
                }else reply=await handling;
                stage="write-reply";
                await ServiceProtocol.Write(pipe,FitUiReply(reply),deadline.Token);
            }catch(Exception)when(deadline.IsCancellationRequested){}catch(Exception ex){
                string missing=ex is FileNotFoundException file?" assembly="+Path.GetFileName(file.FileName??"unknown"):"";
                Log("受限UI请求失败：stage="+stage+" "+ex.GetType().Name+missing);
                if(authorized&&stage=="handle-request")try{await ServiceProtocol.Write(pipe,new UiControlReply(false,"个人服务处理请求时发生内部错误，请修复安装并查看诊断日志。",null),deadline.Token);}catch(IOException){}
            }
        }
    }
    internal async Task RunUiControl(CancellationToken token)
    {
        string? allowed=store.AuthorizedUiUser();if(allowed==null)return;
        using var limit=new SemaphoreSlim(8,8);var clients=new List<Task>();bool first=true;
        try{while(!token.IsCancellationRequested){await limit.WaitAsync(token);NamedPipeServerStream? pipe=null;
            try{pipe=LocalControlPipe.Create(first,allowed);first=false;await pipe.WaitForConnectionAsync(token);}catch{pipe?.Dispose();limit.Release();throw;}
            clients.RemoveAll(t=>t.IsCompleted);clients.Add(ServeUiAndRelease(pipe,allowed,limit,token));
        }}catch(OperationCanceledException)when(token.IsCancellationRequested){}
        finally{await Task.WhenAll(clients);}
    }
    async Task ServeUiAndRelease(NamedPipeServerStream pipe,string allowed,SemaphoreSlim limit,CancellationToken token){try{await ServeUi(pipe,allowed,token);}finally{limit.Release();}}
}
