using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// TCP STUN uses the actual receiver port and the ordinary kernel TCP stack.
// Neither raw injection nor a WinDivert observer participates in this mapping.
public sealed class StreamMapping : IMapping
{
    internal sealed record Options(bool DiscoverGateway=true,TimeSpan? MaintenancePeriod=null);
    readonly Socket socket;
    readonly NetworkStream stream;
    readonly CancellationTokenSource stop=new();
    readonly Action<string> log;
    readonly Options options;
    Upnp? router;RouterMapping? rule;PortControlLease? gateway;
    Task maintaining=Task.CompletedTask;
    static int rotation;
    int disposed,started;volatile bool valid=true;
    public IPAddress LocalAddress{get;}
    public IPEndPoint PublicEndpoint{get;private set;}
    public bool IsValid=>valid&&Volatile.Read(ref disposed)==0&&(gateway?.Valid??true);
    public event Action<IPEndPoint>? Changed;
    StreamMapping(Socket socket,IPEndPoint endpoint,Action<string> log,Options options){this.socket=socket;stream=new(socket,false);LocalAddress=((IPEndPoint)socket.LocalEndPoint!).Address;PublicEndpoint=endpoint;this.log=log;this.options=options;}
    public static Task<IMapping> Create(int port,Action<string> log,CancellationToken token,string[]? servers=null,bool portControl=false)=>Create(port,log,token,servers,portControl,new());
    internal static async Task<IMapping> Create(int port,Action<string> log,CancellationToken token,string[]? servers,bool portControl,Options options)
    {
        var choices=(servers??Stun.TcpServers).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if(choices.Length>1){var tail=choices[1..];int offset=(int)((uint)(Interlocked.Add(ref rotation,7)-7)%(uint)tail.Length);choices=[choices[0],..tail.Skip(offset),..tail.Take(offset)];}
        using var round=CancellationTokenSource.CreateLinkedTokenSource(token);round.CancelAfter(12000);
        Exception? last=null;
        foreach(string server in choices.Take(8)){
            Socket? socket=null;StreamMapping? mapping=null;
            try{
                using var attempt=CancellationTokenSource.CreateLinkedTokenSource(round.Token);attempt.CancelAfter(2500);
                var remote=await Stun.Resolve(server,attempt.Token);
                // This control-only STUN flow may be retried with the exact
                // same tuple. An abortive owned close avoids a long TIME_WAIT
                // blocking its receiver port; business sockets are unaffected.
                socket=new Socket(remote.AddressFamily,SocketType.Stream,ProtocolType.Tcp){NoDelay=true,ExclusiveAddressUse=false,LingerState=new(true,0)};
                socket.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.ReuseAddress,true);
                socket.Bind(new IPEndPoint(Stun.LocalAddress(remote),port));
                await socket.ConnectAsync(remote,attempt.Token);
                mapping=new(socket,new IPEndPoint(IPAddress.Any,1),log,options);socket=null;
                mapping.PublicEndpoint=await mapping.Pulse(attempt.Token);
                // A candidate is never described as proven inbound reachability.
                log("真实 TCP STUN 已取得接收端口候选 "+mapping.PublicEndpoint+"，等待对端认证验证");
                if(options.DiscoverGateway)await mapping.TryGateway(port,portControl,round.Token);
                token.ThrowIfCancellationRequested();
                using(var check=CancellationTokenSource.CreateLinkedTokenSource(token)){check.CancelAfter(2500);var current=await mapping.Pulse(check.Token);if(mapping.gateway==null)mapping.PublicEndpoint=current;}
                return mapping;
            }catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or SocketException or OperationCanceledException or ArgumentException){
                last=ex;if(mapping!=null)await mapping.DisposeAsync();socket?.Dispose();if(round.IsCancellationRequested)break;
            }catch{if(mapping!=null)await mapping.DisposeAsync();socket?.Dispose();throw;}
        }
        token.ThrowIfCancellationRequested();throw new IOException("真实 TCP 入口未就绪；请检查 STUN、端口或使用已有入口",last);
    }
    async Task<IPEndPoint> Pulse(CancellationToken token)
    {
        byte[] request=Stun.Request(),header=new byte[20];await stream.WriteAsync(request,token);
        await stream.ReadExactlyAsync(header,token);int length=BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
        if(length>4096||length%4!=0)throw new IOException("TCP STUN 响应长度无效");
        byte[] response=new byte[20+length];header.CopyTo(response,0);await stream.ReadExactlyAsync(response.AsMemory(20),token);
        return Stun.Parse(response,request);
    }
    async Task TryGateway(int port,bool portControl,CancellationToken token)
    {
        try{await foreach(var service in Upnp.DiscoverServices(LocalAddress,token)){
            var candidate=new Upnp(service);RouterMapping? requested=null;
            try{
                string external=await candidate.ExternalAddress(token);
                if(!IPAddress.TryParse(external,out var address)||!address.Equals(PublicEndpoint.Address)){candidate.Dispose();continue;}
                requested=new(PublicEndpoint.Port,port,LocalAddress.ToString(),"TCP","ConWU-stream-"+Guid.NewGuid().ToString("N"));
                await candidate.Add(requested,token);router=candidate;rule=requested;return;
            }catch(Exception ex)when(ex is IOException or HttpRequestException or OperationCanceledException){
                if(requested!=null)try{await candidate.RemoveOwned(requested,CancellationToken.None);}catch{}candidate.Dispose();
                if(token.IsCancellationRequested)break;
            }
        }}catch(Exception ex)when(ex is IOException or SocketException or OperationCanceledException or HttpRequestException){}
        if(portControl&&!token.IsCancellationRequested){
            PortControlLease? opening=null;
            try{opening=await PortControlLease.Create(LocalAddress,port,0,PortMappingProtocol.Tcp,token);PublicEndpoint=TcpMapping.GatewayCandidate(opening);gateway=opening;}
            catch(Exception ex)when(ex is IOException or SocketException or OperationCanceledException){if(opening!=null)await opening.DisposeAsync();}
        }
    }
    public Task Maintain(CancellationToken token)
    {
        if(Interlocked.Exchange(ref started,1)!=0)throw new InvalidOperationException("TCP 入口维护只能启动一次");
        return maintaining=Run(token);
    }
    async Task Run(CancellationToken token)
    {
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,stop.Token);
        Task? gatewayWork=gateway?.Maintain(linked.Token);
        try{
            using var timer=new PeriodicTimer(options.MaintenancePeriod??TimeSpan.FromSeconds(15));
            while(await timer.WaitForNextTickAsync(linked.Token)){
                if(gatewayWork?.IsCompleted==true)await gatewayWork;
                using var pulse=CancellationTokenSource.CreateLinkedTokenSource(linked.Token);pulse.CancelAfter(4000);
                var seen=await Pulse(pulse.Token);var endpoint=gateway?.External??seen;
                if(!endpoint.Equals(PublicEndpoint)){PublicEndpoint=endpoint;Changed?.Invoke(endpoint);}
                if(router!=null&&rule!=null)await router.Add(rule,pulse.Token);
            }
        }finally{valid=false;linked.Cancel();if(gatewayWork!=null)try{await gatewayWork;}catch(Exception ex)when(ex is IOException or SocketException or OperationCanceledException){}}
    }
    public async ValueTask DisposeAsync()
    {
        if(Interlocked.Exchange(ref disposed,1)!=0)return;valid=false;stop.Cancel();socket.Dispose();stream.Dispose();
        try{await maintaining;}catch(Exception ex)when(ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException){}
        try{if(gateway!=null)await gateway.DisposeAsync();if(router!=null&&rule!=null)await router.RemoveOwned(rule,CancellationToken.None);}
        finally{router?.Dispose();stop.Dispose();}
    }
}
