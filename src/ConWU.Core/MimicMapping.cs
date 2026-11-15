using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// A real reflection flow shares the actual Mimic port. The raw process must
// pass the exact control tuple to the kernel, including before reconnection.
// An owned, expiring P -> P IGD grant also opens endpoint filtering on gateways
// whose WAN is private; the advertised outer candidate is still real STUN.
public interface ITcpSourceMapping:IMapping { IPEndPoint LocalEndpoint{get;} }
public interface IMimicSourceMapping:ITcpSourceMapping { }
public sealed class MimicMapping:IMimicSourceMapping,IMappingRefresh
{
    readonly StreamMapping observation;
    readonly Upnp? router;
    readonly RouterMapping? rule;
    readonly Action<string> log;
    readonly CancellationTokenSource stop=new();
    Task maintenance=Task.CompletedTask;
    readonly object gate=new();
    bool attached,started,disposed;
    public IPEndPoint LocalEndpoint {get;}
    public IPEndPoint ControlPeer=>observation.ControlPeer;
    public string StunServer=>observation.StunServer;
    public bool GatewayGranted=>rule!=null;
    public string Mode{get;}
    public IPAddress LocalAddress=>observation.LocalAddress;
    public IPEndPoint PublicEndpoint=>observation.PublicEndpoint;
    public bool IsValid=>!Volatile.Read(ref disposed)&&observation.IsValid;
    public event Action<IPEndPoint>? Changed;
    MimicMapping(StreamMapping observation,int port,Upnp? router,RouterMapping? rule,Action<string> log,string mode)
    {
        this.observation=observation;this.router=router;this.rule=rule;this.log=log;Mode=mode;
        LocalEndpoint=new(observation.LocalAddress,port);
        observation.Changed+=endpoint=>Changed?.Invoke(endpoint);
    }
    public static async Task<MimicMapping> Create(int port,Action<string> log,CancellationToken token,string[]? servers=null,Action<EntryProbeProgress>? progress=null,bool allowGatewayMapping=true,string mode="mimic")
    {
        if(!TransportModes.PacketCarrier(mode)&&!TransportModes.Stream(mode))throw new ArgumentException("此协议不使用可复用的内核 TCP 源端口");
        StreamMapping? observation=null;Upnp? owned=null;RouterMapping? grant=null;
        try{
            observation=(StreamMapping)await StreamMapping.Create(port,log,token,servers,false,new StreamMapping.Options(DiscoverGateway:false,InitialParallelism:1){Progress=progress});
            int actual=observation.LocalPort;
            progress?.Invoke(new("SamePortGateway",allowGatewayMapping?"已保留实际接收端口，正在检查同端口网关适配":"本轮已禁用显式网关映射，仅保留同源端口候选"));
            using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);budget.CancelAfter(4000);
            try{if(allowGatewayMapping){
                await foreach(var service in Upnp.DiscoverServices(observation.LocalAddress,budget.Token)){
                    var candidate=new Upnp(service);
                    var requested=new RouterMapping(actual,actual,observation.LocalAddress.ToString(),"TCP","ConWU-Mimic-"+Guid.NewGuid().ToString("N"));
                    try{
                        await candidate.Add(requested,budget.Token);
                        token.ThrowIfCancellationRequested();
                        owned=candidate;grant=requested;candidate=null!;break;
                    }catch(Exception ex){
                        // The gateway may have applied the request before its
                        // response/cancellation. Remove only our exact grant.
                        try{await candidate.RemoveOwned(requested,CancellationToken.None);}catch{}
                        token.ThrowIfCancellationRequested();
                        if(ex is not (IOException or HttpRequestException or SocketException or OperationCanceledException))throw;
                    }finally{candidate?.Dispose();}
                }
            }
            }catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or HttpRequestException or SocketException or OperationCanceledException){
                log("同端口 UPnP 未就绪，保留真实源端口并继续双向探测；未把候选当作可达证明");
            }
            token.ThrowIfCancellationRequested();
            var result=new MimicMapping(observation,actual,owned,grant,log,mode);observation=null;owned=null;grant=null;
            log($"{TransportModes.Label(mode)} 已保留同端口入口 {result.LocalEndpoint}，STUN 候选 {result.PublicEndpoint}，网关适配={result.GatewayGranted}；等待对端认证");
            return result;
        }finally{
            if(owned!=null){try{if(grant!=null)await owned.RemoveOwned(grant,CancellationToken.None);}finally{owned.Dispose();}}
            if(observation!=null)await observation.DisposeAsync();
        }
    }
    internal IDisposable Attach(Func<IPEndPoint,CancellationToken,Task> protect)
    {
        lock(gate){ObjectDisposedException.ThrowIf(disposed,this);if(attached)throw new IOException("同端口 Mimic 已有接收器所有者");attached=true;observation.BeforeControlConnect=protect;return new Attachment(this);}
    }
    sealed class Attachment(MimicMapping owner):IDisposable
    {
        int disposed;
        public void Dispose(){if(Interlocked.Exchange(ref disposed,1)!=0)return;lock(owner.gate){owner.observation.BeforeControlConnect=null;owner.attached=false;}}
    }
    public void RequestRefresh()=>observation.RequestRefresh();
    public Task Maintain(CancellationToken token)
    {
        lock(gate){ObjectDisposedException.ThrowIf(disposed,this);if(started)throw new InvalidOperationException("同端口映射只能维护一次");started=true;return maintenance=Run(token);}
    }
    async Task Run(CancellationToken token)
    {
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,stop.Token);
        var observing=observation.Maintain(linked.Token);
        async Task Renew(){
            while(true){await Task.Delay(60000,linked.Token);try{await router!.Add(rule!,linked.Token);}catch(Exception ex)when(!linked.IsCancellationRequested&&ex is IOException or HttpRequestException or OperationCanceledException){log("Mimic 同端口网关续租暂未确认，保持真实 STUN 观察和已建立路径");}}
        }
        var renewing=rule==null?Task.Delay(Timeout.Infinite,linked.Token):Renew();
        try{await await Task.WhenAny(observing,renewing);}
        finally{linked.Cancel();try{await Task.WhenAll(observing,renewing);}catch(OperationCanceledException)when(linked.IsCancellationRequested){}}
    }
    public async ValueTask DisposeAsync()
    {
        lock(gate){if(disposed)return;disposed=true;}
        stop.Cancel();try{await maintenance;}catch(OperationCanceledException){}finally{
            try{await observation.DisposeAsync();}finally{try{if(router!=null&&rule!=null)await router.RemoveOwned(rule,CancellationToken.None);}catch(Exception ex)when(ex is IOException or HttpRequestException or OperationCanceledException){log("Mimic 网关清理未确认，180 秒租约将自动到期");}finally{router?.Dispose();stop.Dispose();}}
        }
    }
}
