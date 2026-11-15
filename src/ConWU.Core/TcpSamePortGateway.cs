using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// An owned inner P -> P grant does not turn a private WAN into a public one.
// The candidate still comes from reflection and needs peer authentication.
internal sealed class TcpSamePortGateway(Upnp router,RouterMapping rule,Action<string> log):IAsyncDisposable
{
    public static async Task<TcpSamePortGateway?> Try(IPEndPoint local,Action<string> log,CancellationToken token)
    {
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);budget.CancelAfter(4000);
        try{
            await foreach(var service in Upnp.DiscoverServices(local.Address,budget.Token)){
                var candidate=new Upnp(service);
                var requested=new RouterMapping(local.Port,local.Port,local.Address.ToString(),"TCP","ConWU-TCP-"+Guid.NewGuid().ToString("N"));
                try{await candidate.Add(requested,budget.Token);token.ThrowIfCancellationRequested();return new(candidate,requested,log);}
                catch(Exception error){
                    try{await candidate.RemoveOwned(requested,CancellationToken.None);}catch{}
                    candidate.Dispose();token.ThrowIfCancellationRequested();
                    if(error is not(IOException or HttpRequestException or SocketException or OperationCanceledException))throw;
                }
            }
        }catch(Exception error)when(!token.IsCancellationRequested&&error is IOException or HttpRequestException or SocketException or OperationCanceledException){
            log("同端口 UPnP 未就绪，继续协调探测；尚未确认公网入站可达");
        }
        return null;
    }
    public async Task Maintain(CancellationToken token)
    {
        while(true){await Task.Delay(60000,token);try{await router.Add(rule,token);}catch(Exception error)when(!token.IsCancellationRequested&&error is IOException or HttpRequestException or OperationCanceledException){log("同端口网关续租暂未确认，继续保留实际源端口观察");}}
    }
    public async ValueTask DisposeAsync()
    {
        try{await router.RemoveOwned(rule,CancellationToken.None);}
        catch(Exception error)when(error is IOException or HttpRequestException or OperationCanceledException){log("同端口网关清理未确认，180 秒租约将自动到期");}
        finally{router.Dispose();}
    }
}
