using System.IO.Pipes;
using System.Security.Principal;
using StreamLink.Core;

namespace StreamLink.Service;
public sealed partial class ControlWorker
{
    sealed record UiOperation(string CallerSid,UiConfigPatch? Patch);

    UiStatusDto UiSnapshot()
    {
        var full=Volatile.Read(ref snapshot)!;var p=full.Profile!;var state=full.Status;var peers=state?.Peers??[];
        return new(full.Version,p.DeviceName,p.Mesh?.LocalIp??state?.LocalIp??"",SensitiveText.Redact(state?.State??"网络未启动",p),full.ServiceReady,p.Enabled,peers.Count(x=>x.Connected),peers.Length,
            peers.Select(x=>new UiPeerDto(x.Slot,x.Name,x.Ip,x.Connected,x.Degraded,x.RttMs,SensitiveText.Redact(x.Detail,p)[..Math.Min(256,SensitiveText.Redact(x.Detail,p).Length)]){TraversalMethod=x.TraversalMethod,ActualTransport=x.ActualTransport}).ToArray(),p.LogLevel,SettingsPatchVersion:2)
            {Adapter=state?.Adapter,PersonalFeatureEdition=PersonalFeature.Enabled};
    }
    internal async Task<UiControlReply> HandleUi(UiControlRequest request,string callerSid,CancellationToken token)
    {
        if(store.AuthorizedUiUser()!=callerSid)return new(false,"该本机用户未获UI控制授权",null);
        if(request.Method=="status"&&request.Patch==null)return new(true,"",UiSnapshot());
        if(request.Method is not ("patch" or "start" or "stop")||request.Method!="patch"&&request.Patch!=null)return new(false,"此接口不允许该操作",UiSnapshot());
        if(request.Method=="patch"&&request.Patch==null)return new(false,"设置补丁为空",UiSnapshot());
        var command=request.Method=="patch"?"ui-patch":request.Method;
        var result=await HandleCore(new(command,OperationId:request.OperationId),token,new UiOperation(callerSid,request.Patch));
        if(store.AuthorizedUiUser()!=callerSid)return new(false,"该本机用户的UI控制授权已改变",null);
        return new(result.Ok,result.Error,UiSnapshot(),Operation:result.Operation);
    }

    async Task ServeUi(NamedPipeServerStream pipe,string allowed,CancellationToken token)
    {
        using(pipe)using(var deadline=CancellationTokenSource.CreateLinkedTokenSource(token)){
            deadline.CancelAfter(20000);try{
                string? caller=null;pipe.RunAsClient(()=>caller=WindowsIdentity.GetCurrent(true)?.User?.Value);
                if(caller!=allowed)return;
                var request=await ServiceProtocol.Read<UiControlRequest>(pipe,deadline.Token);
                await ServiceProtocol.Write(pipe,await HandleUi(request,caller,deadline.Token),deadline.Token);
            }catch(Exception)when(deadline.IsCancellationRequested){}catch(Exception ex){Log("受限UI请求拒绝："+ex.GetType().Name);}
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
