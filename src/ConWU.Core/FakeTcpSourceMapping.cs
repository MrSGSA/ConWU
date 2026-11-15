using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// UDP2RAW's prepared SO ABI already owns an exclusive kernel source and its
// exact control tuple. Keep that resource instead of forwarding helper P to Q.
public sealed class FakeTcpSourceMapping:ITcpSourceMapping,IMappingRefresh
{
    public TcpEndpointLease Lease{get;}
    public Guid Generation=>Lease.NetworkGeneration;
    public IPEndPoint LocalEndpoint=>Lease.Local;
    public IPAddress LocalAddress=>Lease.Local.Address;
    public IPEndPoint PublicEndpoint{get;private set;}
    public string StunServer{get;}
    public bool IsValid=>!disposed&&Lease.QueryUsable;
    public event Action<IPEndPoint>? Changed;
    readonly CancellationTokenSource stop=new();
    readonly SemaphoreSlim refresh=new(0,1);
    readonly Action<string> log;
    readonly TcpSamePortGateway? gateway;
    public bool GatewayGranted=>gateway!=null;
    bool disposed,started;
    Task maintenance=Task.CompletedTask;
    FakeTcpSourceMapping(TcpEndpointLease lease,StunResult observed,string server,Action<string> log,TcpSamePortGateway? gateway)
    {Lease=lease;PublicEndpoint=observed.Public;StunServer=server;this.log=log;this.gateway=gateway;}
    public static async Task<FakeTcpSourceMapping> Create(int port,string[] servers,Action<string> log,CancellationToken token,bool allowGatewayMapping=true)
    {
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);budget.CancelAfter(12000);
        Exception? last=null;
        foreach(var server in servers.Distinct(StringComparer.OrdinalIgnoreCase).Take(4)){
            TcpEndpointLease? lease=null;
            try{
                using var attempt=CancellationTokenSource.CreateLinkedTokenSource(budget.Token);attempt.CancelAfter(3000);
                var peer=await Stun.Resolve(server,attempt.Token);
                lease=await TcpEndpointLease.Open(new(Stun.LocalAddress(peer),port),peer,Guid.NewGuid(),attempt.Token);
                using var observing=lease.AcquireAttempt(lease.NetworkGeneration);var result=await observing.Observe(attempt.Token);
                await StunObservationValidation.Validate(result,peer,servers,attempt.Token);
                var gateway=allowGatewayMapping?await TcpSamePortGateway.Try(lease.Local,log,token):null;
                var mapping=new FakeTcpSourceMapping(lease,result,server,log,gateway);lease=null;
                log("FakeTCP＋HTTP 已保留实际同源端口候选；协同探测与对端认证仍待完成");return mapping;
            }catch(Exception error)when(!token.IsCancellationRequested&&error is IOException or SocketException or OperationCanceledException){last=error;}
            finally{lease?.Dispose();}
            if(budget.IsCancellationRequested)break;
        }
        token.ThrowIfCancellationRequested();throw new IOException("FakeTCP 同源端口观察未完成",last);
    }
    public void RequestRefresh(){if(refresh.CurrentCount==0)try{refresh.Release();}catch(SemaphoreFullException){}}
    public Task Maintain(CancellationToken token)
    {
        if(started)throw new InvalidOperationException("同一源端口只能维护一次");started=true;
        return maintenance=Run(token);
    }
    async Task Run(CancellationToken token)
    {
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,stop.Token);
        var observing=Observe(linked.Token);
        var renewing=gateway?.Maintain(linked.Token)??Task.Delay(Timeout.Infinite,linked.Token);
        try{await await Task.WhenAny(observing,renewing);}
        finally{linked.Cancel();try{await Task.WhenAll(observing,renewing);}catch(OperationCanceledException)when(linked.IsCancellationRequested){}}
    }
    async Task Observe(CancellationToken token)
    {
        while(!token.IsCancellationRequested){
            await refresh.WaitAsync(TimeSpan.FromSeconds(15),token);
            try{using var view=Lease.AcquireAttempt(Generation);var observed=await view.Observe(token);if(!observed.Public.Equals(PublicEndpoint)){PublicEndpoint=observed.Public;Changed?.Invoke(PublicEndpoint);}}
            catch(Exception error)when(!token.IsCancellationRequested&&error is IOException or SocketException or OperationCanceledException or InvalidOperationException){log("FakeTCP 同源观察暂不可用，撤回候选并重新准备对应端口资源");return;}
        }
    }
    public async ValueTask DisposeAsync()
    {if(disposed)return;disposed=true;stop.Cancel();try{await maintenance;}catch(OperationCanceledException){}finally{try{if(gateway!=null)await gateway.DisposeAsync();}finally{Lease.Dispose();refresh.Dispose();stop.Dispose();}}}
}
