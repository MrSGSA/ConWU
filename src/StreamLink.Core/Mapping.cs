using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

public interface IMapping : IAsyncDisposable
{
    IPAddress LocalAddress { get; }
    IPEndPoint PublicEndpoint { get; }
    event Action<IPEndPoint>? Changed;
    Task Maintain(CancellationToken token);
}

public sealed class UdpMapping : IMapping
{
    readonly UdpClient socket;
    readonly Upnp router;
    readonly RouterMapping rule;
    readonly Action<string> log;
    public IPAddress LocalAddress { get; }
    public IPEndPoint PublicEndpoint { get; private set; }
    public IPEndPoint StunEndpoint => (IPEndPoint)socket.Client.RemoteEndPoint!;
    public event Action<IPEndPoint>? Changed;
    UdpMapping(UdpClient socket, Upnp router, RouterMapping rule, IPEndPoint publicEndpoint, Action<string> log)
    { this.socket=socket; this.router=router; this.rule=rule; this.log=log; LocalAddress=((IPEndPoint)socket.Client.LocalEndPoint!).Address; PublicEndpoint=publicEndpoint; }
    static async Task<IPEndPoint> Pulse(UdpClient socket,CancellationToken token)
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(3500); token=timeout.Token;
        byte[] request=Stun.Request();
        for(int attempt=0;;attempt++)
        {
            await socket.SendAsync(request,token);
            using var retry=CancellationTokenSource.CreateLinkedTokenSource(token); retry.CancelAfter(900);
            try { var response=await socket.ReceiveAsync(retry.Token); return Stun.Parse(response.Buffer,request); }
            catch(OperationCanceledException) when(!token.IsCancellationRequested && attempt<2) { }
        }
    }
    public static async Task<UdpMapping> Create(int sourcePort,int targetPort,Action<string> log,CancellationToken token)
    {
        if(sourcePort!=targetPort || sourcePort is <1024 or >65535) throw new ArgumentException("UDP 探测与传输必须共用同一端口");
        foreach(var server in Stun.UdpServers)
        {
            UdpClient? socket=null; Upnp? router=null; RouterMapping? rule=null;
            try
            {
                using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(4500);
                var remote=await Stun.Resolve(server,deadline.Token); var local=Stun.LocalAddress(remote);
                socket=new UdpClient(AddressFamily.InterNetwork);
                socket.ExclusiveAddressUse=false;
                socket.Client.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.ReuseAddress,true);
                socket.Client.Bind(new IPEndPoint(local,sourcePort)); socket.Connect(remote);
                var mapped=await Pulse(socket,token);
                var services=await Upnp.Discover(local,token);
                if(services.Count==0) throw new IOException("未发现 UPnP 网关，本实验 UDP 入口无法自动建立映射");
                router=new Upnp(services[0]);
                rule=new RouterMapping(sourcePort,targetPort,local.ToString(),"UDP","StreamLink-"+Guid.NewGuid().ToString("N"));
                await router.Add(rule,token);
                log($"UDP STUN 映射 {mapped}；仅表示候选地址，仍需对端及质量验证");
                return new UdpMapping(socket,router,rule,mapped,log);
            }
            catch(Exception ex) when(!token.IsCancellationRequested)
            {
                socket?.Dispose();
                if(router!=null && rule!=null) {try{await router.RemoveOwned(rule,CancellationToken.None);}catch{}}
                router?.Dispose(); log("UDP 映射尝试未完成："+ex.Message);
            }
            catch { socket?.Dispose(); if(router!=null && rule!=null) {try{await router.RemoveOwned(rule,CancellationToken.None);}catch{}} router?.Dispose(); throw; }
        }
        throw new IOException("UDP 自动映射失败；此入口需要可用 STUN 与 UPnP，尚不覆盖双方严格对称 NAT");
    }
    public async Task Maintain(CancellationToken token)
    {
        int tick=0;
        while(true)
        {
            await Task.Delay(10000,token); var mapped=await Pulse(socket,token);
            if(!mapped.Equals(PublicEndpoint)) {PublicEndpoint=mapped;Changed?.Invoke(mapped);}
            if(++tick%6==0) await router.Add(rule,token);
        }
    }
    public async ValueTask DisposeAsync()
    {
        socket.Dispose();
        try{await router.RemoveOwned(rule,CancellationToken.None);log("已移除本软件 UDP 租约");}
        catch(Exception ex){log("UDP 租约删除未确认，将按租期到期："+ex.Message);}
        router.Dispose();
    }
}
