using System.Net;
using StreamLink.Core;

namespace StreamLink.Service;

// One bounded seed discovery at a time. A proven seed transport is handed to the
// normal per-peer owner, so identifying the entry does not start a second worker.
internal sealed class NetworkEntryConnections(MeshRouter router,Func<string,CancellationToken,Task<IMeshTransport>> create,
    Func<int,MeshPeerTransports> paths,Action<string> log,CancellationToken stop):IAsyncDisposable
{
    readonly Dictionary<string,(int Slot,string Device)> bindings=[];
    readonly Dictionary<string,long> unhealthy=[];
    Task<IMeshTransport>? opening;IMeshTransport? probing;CancellationTokenSource? attempt;
    string endpoint="";long began,next,nextProbe;int cursor;
    public bool OwnsEndpoint(string value)=>value.Length>0&&value==endpoint&&(opening!=null||probing!=null);
    public string[] ForMember(MeshMember member)=>bindings.Where(p=>p.Value.Slot==member.Slot&&p.Value.Device==member.Device).Select(p=>p.Key).ToArray();
    public async Task Tick(string[] sources,MeshMember[] members,long now,ISet<string>? known=null) {
        foreach(var item in bindings.ToArray()) {
            bool gone=!sources.Contains(item.Key)||!members.Any(m=>m.Slot==item.Value.Slot&&m.Device==item.Value.Device);
            if(router.HasHealthyPath(item.Value.Slot))unhealthy.Remove(item.Key);
            else if(!unhealthy.ContainsKey(item.Key))unhealthy[item.Key]=now;
            if(gone||unhealthy.TryGetValue(item.Key,out var since)&&now-since>=60000){paths(item.Value.Slot).RetireNetworkEntry(item.Value.Slot,item.Key);bindings.Remove(item.Key);unhealthy.Remove(item.Key);}
        }
        if(opening!=null&&(!sources.Contains(endpoint)||known?.Contains(endpoint)==true))attempt?.Cancel();
        if(opening?.IsCompleted==true) {
            try{probing=await opening;if(attempt?.IsCancellationRequested==true){probing.Dispose();probing=null;}}
            catch(OperationCanceledException)when(attempt?.IsCancellationRequested==true){next=now+15000;}
            catch(Exception ex)when(!stop.IsCancellationRequested){log("网络入口暂不可达："+ex.Message);next=now+15000;}
            opening=null;
        }
        if(probing!=null&&known?.Contains(endpoint)==true)CloseProbe();
        if(probing!=null) {
            var local=probing.ClientEndpoint;
            int slot=local==null?0:router.IdentifiedNetworkEntry(local);
            if(slot>0&&members.FirstOrDefault(m=>m.Slot==slot) is {} member) {
                bindings[endpoint]=(slot,member.Device);router.ForgetNetworkEntry(local!);
                if(paths(slot).AdoptNetworkEntry(endpoint,probing))probing=null;
                log($"网络入口已认证：由成员 {slot} 提供；继续验证双向数据连接");
                CloseProbe();next=now+1000;
            }else if(probing.Exited||now-began>=15000||!sources.Contains(endpoint)){CloseProbe();next=now+15000;}
            else if(local!=null&&now>=nextProbe){router.ProbeNetworkEntry(local);nextProbe=now+500;}
        }
        if(opening==null&&probing==null&&now>=next&&sources.Length>0&&members.Any(m=>!router.HasHealthyPath(m.Slot))) {
            // Known endpoints are handled by the normal per-peer retry policy.
            var unknown=sources.Where(s=>!bindings.ContainsKey(s)&&known?.Contains(s)!=true).ToArray();if(unknown.Length==0)return;
            endpoint=unknown[(cursor++&int.MaxValue)%unknown.Length];began=now;nextProbe=0;
            attempt?.Dispose();attempt=CancellationTokenSource.CreateLinkedTokenSource(stop);attempt.CancelAfter(15000);
            opening=create(endpoint,attempt.Token);
        }
    }
    void CloseProbe(){if(probing?.ClientEndpoint is {} local)router.ForgetNetworkEntry(local);probing?.Dispose();probing=null;attempt?.Cancel();attempt?.Dispose();attempt=null;}
    public async ValueTask DisposeAsync(){attempt?.Cancel();try{if(opening!=null)try{(await opening).Dispose();}catch(OperationCanceledException){}catch(Exception ex){log("网络入口退出时的准备结果："+ex.Message);}}finally{opening=null;CloseProbe();}}
}
