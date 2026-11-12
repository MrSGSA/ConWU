using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// TCP STUN uses the actual receiver port and the ordinary kernel TCP stack.
// Neither raw injection nor a WinDivert observer participates in this mapping.
public sealed class StreamMapping : IMapping, IMappingRefresh
{
    internal sealed record Options(bool DiscoverGateway=true,TimeSpan? MaintenancePeriod=null,int InitialParallelism=2);
    Socket socket;
    readonly CancellationTokenSource stop=new();
    readonly SemaphoreSlim refresh=new(0,1);
    readonly object lifecycle=new();
    readonly TcpHelperRecovery recovery=new();
    readonly Action<string> log;
    readonly Options options;
    readonly string[] servers;
    readonly int port;
    IPEndPoint reflector;
    Upnp? router;RouterMapping? rule;PortControlLease? gateway;
    Task maintaining=Task.CompletedTask;
    static int rotation;
    bool disposed,started;
    volatile bool valid=true,observationValid=true;
    public IPAddress LocalAddress{get;}
    public IPEndPoint PublicEndpoint{get;private set;}
    public string StunServer{get;private set;}
    public bool IsValid=>valid&&!Volatile.Read(ref disposed)&&(gateway?.Valid??observationValid);
    public event Action<IPEndPoint>? Changed;
    StreamMapping(Socket socket,IPEndPoint endpoint,string server,string[] servers,Action<string> log,Options options)
    {
        this.socket=socket;StunServer=server;this.servers=servers;
        reflector=(IPEndPoint)socket.RemoteEndPoint!;
        var local=(IPEndPoint)socket.LocalEndPoint!;
        LocalAddress=local.Address;port=local.Port;PublicEndpoint=endpoint;
        this.log=log;this.options=options;
    }
    public static Task<IMapping> Create(int port,Action<string> log,CancellationToken token,string[]? servers=null,bool portControl=false)=>Create(port,log,token,servers,portControl,new());
    internal static async Task<IMapping> Create(int port,Action<string> log,CancellationToken token,string[]? servers,bool portControl,Options options)
    {
        var choices=(servers??Stun.TcpServers).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if(options.InitialParallelism is <1 or >2)throw new ArgumentOutOfRangeException(nameof(options));
        if(choices.Length>1){var tail=choices[1..];int offset=(int)((uint)(Interlocked.Add(ref rotation,7)-7)%(uint)tail.Length);choices=[choices[0],..tail.Skip(offset),..tail.Take(offset)];}
        using var round=CancellationTokenSource.CreateLinkedTokenSource(token);round.CancelAfter(12000);
        Exception? last=null;
        var remaining=choices.Take(8).ToList();
        while(remaining.Count>0){
            Socket? socket=null;StreamMapping? mapping=null;
            try{
                var opened=await OpenFirst(port,remaining.ToArray(),options.InitialParallelism,round.Token);socket=opened.Socket;
                remaining.Remove(opened.Server);
                mapping=new(socket,opened.Public,opened.Server,choices,log,options);socket=null;
                // A candidate is never described as proven inbound reachability.
                log("真实 TCP STUN 已取得接收端口候选 "+mapping.PublicEndpoint+"，等待对端认证验证");
                if(options.DiscoverGateway)await mapping.TryGateway(port,portControl,round.Token);
                token.ThrowIfCancellationRequested();
                using(var check=CancellationTokenSource.CreateLinkedTokenSource(round.Token)){check.CancelAfter(2500);var current=await Pulse(mapping.socket,check.Token);if(mapping.gateway==null)mapping.PublicEndpoint=current;}
                token.ThrowIfCancellationRequested();
                return mapping;
            }catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or SocketException or OperationCanceledException or ArgumentException){
                last=ex;bool selected=mapping!=null;if(mapping!=null)await mapping.DisposeAsync();socket?.Dispose();if(!selected||round.IsCancellationRequested)break;
            }catch{if(mapping!=null)await mapping.DisposeAsync();socket?.Dispose();throw;}
        }
        token.ThrowIfCancellationRequested();throw new IOException("真实 TCP 入口未就绪；请检查 STUN、端口或使用已有入口",last);
    }
    sealed record Observation(Socket Socket,IPEndPoint Public,string Server);
    static async Task<Observation> OpenFirst(int port,string[] servers,int parallelism,CancellationToken token)
    {
        using var race=CancellationTokenSource.CreateLinkedTokenSource(token);
        using var slots=new SemaphoreSlim(parallelism,parallelism);
        async Task<Observation> Dial(string server,int index){
            // Prefer a working first reflector. Speculate only when it is slow;
            // at most two owned TCP flows share the actual receiver port.
            if(index>0)await Task.Delay(index*200,race.Token);
            await slots.WaitAsync(race.Token);
            try{
                using var attempt=CancellationTokenSource.CreateLinkedTokenSource(race.Token);attempt.CancelAfter(2500);
                var opened=await Open(port,null,server,attempt.Token);
                return new(opened.Socket,opened.Public,server);
            }finally{slots.Release();}
        }
        var attempts=servers.Select(Dial).ToArray();
        var pending=attempts.ToList();Task<Observation>? winner=null;Exception? last=null;
        try{
            while(pending.Count>0){
                var completed=await Task.WhenAny(pending);pending.Remove(completed);
                try{
                    var result=await completed;token.ThrowIfCancellationRequested();
                    winner=completed;return result;
                }catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or SocketException or OperationCanceledException or ArgumentException){last=ex;}
            }
            token.ThrowIfCancellationRequested();throw new IOException("已配置的 TCP STUN 服务本轮均未回应",last);
        }finally{
            // No losing observation, socket, timer or read is left running when
            // gateway mapping or candidate publication starts. Closing losers
            // cannot close the retained listener or the winning TCP four-tuple.
            race.Cancel();
            foreach(var task in attempts.Where(t=>!ReferenceEquals(t,winner)))try{(await task).Socket.Dispose();}catch{}
        }
    }
    static async Task<(Socket Socket,IPEndPoint Public)> Open(int port,IPAddress? local,string server,CancellationToken token)
    {
        var remote=await Stun.Resolve(server,token);
        // Reopen only the owned control flow on its original source tuple.
        // Abortive close avoids TIME_WAIT on this flow's shared listener port.
        var socket=new Socket(remote.AddressFamily,SocketType.Stream,ProtocolType.Tcp){NoDelay=true,ExclusiveAddressUse=false,LingerState=new(true,0)};
        try {
            socket.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.ReuseAddress,true);
            socket.Bind(new IPEndPoint(local??Stun.LocalAddress(remote),port));
            await socket.ConnectAsync(remote,token);
            return(socket,await Pulse(socket,token));
        } catch {socket.Dispose();throw;}
    }
    static async Task<IPEndPoint> Pulse(Socket socket,CancellationToken token)
    {
        using var stream=new NetworkStream(socket,false);
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
        lock(lifecycle) {
            ObjectDisposedException.ThrowIf(disposed,this);
            if(started)throw new InvalidOperationException("TCP 入口维护只能启动一次");
            started=true;
            return maintaining=Run(token);
        }
    }
    public void RequestRefresh()
    {
        lock(lifecycle)if(!disposed&&refresh.CurrentCount==0)refresh.Release();
    }
    async Task Run(CancellationToken token)
    {
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,stop.Token);
        Task? gatewayWork=gateway?.Maintain(linked.Token)??(router!=null?RenewRouter(linked.Token):null);
        var observing=Observe(linked.Token);
        try {
            if(gatewayWork==null)await observing;
            else await await Task.WhenAny(observing,gatewayWork);
        } finally {
            valid=false;linked.Cancel();
            try {await Task.WhenAll(gatewayWork==null?[observing]:[observing,gatewayWork]);}
            catch(Exception ex)when(ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException){}
        }
    }
    async Task RenewRouter(CancellationToken token)
    {
        while(true) {
            // The owned UPnP grant lasts 180 seconds. Observation failures must
            // not stop renewal or repeatedly delete and recreate this grant.
            await Task.Delay(TimeSpan.FromSeconds(60),token);
            await router!.Add(rule!,token);
        }
    }
    async Task Observe(CancellationToken token)
    {
        bool connected=true;
        int failures=0;
        var period=options.MaintenancePeriod??TimeSpan.FromSeconds(15);
        var delay=period;
        while(true) {
            await refresh.WaitAsync(delay,token);
            try {
                IPEndPoint seen;
                if(connected) {
                    using var pulse=CancellationTokenSource.CreateLinkedTokenSource(token);
                    pulse.CancelAfter(4000);
                    seen=await Pulse(socket,pulse.Token);
                } else {
                    seen=await Reconnect(token);
                    connected=true;
                    log("真实 TCP STUN 观察已恢复，继续使用原接收端口");
                }
                var endpoint=gateway?.External??seen;
                bool changed=!endpoint.Equals(PublicEndpoint);
                if(changed)PublicEndpoint=endpoint;
                observationValid=true;
                if(changed)Changed?.Invoke(endpoint);
                failures=0;delay=period;
            } catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or SocketException or OperationCanceledException or ArgumentException) {
                if(connected)recovery.Failed(StunServer);
                connected=false;observationValid=false;socket.Dispose();
                bool sourceUsable=TcpMapping.LocalSourcePresent(LocalAddress);
                if(sourceUsable) {
                    try {sourceUsable=Stun.LocalAddress(reflector).Equals(LocalAddress);}
                    catch(SocketException) {sourceUsable=false;}
                }
                if(!sourceUsable)throw new IOException("本机 TCP 入口源地址或路由已变化，需要重新发现入口",ex);
                delay=TimeSpan.FromSeconds(Math.Min(45,5<<Math.Min(failures++,4)));
                log($"真实 TCP STUN 观察暂不可用 reason={TcpMapping.HelperFailure(ex)}；保留接收端口和已有直连，{delay.TotalSeconds:0} 秒后重试已配置服务");
            }
        }
    }
    async Task<IPEndPoint> Reconnect(CancellationToken token)
    {
        using var round=CancellationTokenSource.CreateLinkedTokenSource(token);
        round.CancelAfter(12000);
        Exception? last=null;
        foreach(string server in recovery.Candidates(servers,StunServer).Take(8)) {
            Socket? opening=null;
            try {
                using var attempt=CancellationTokenSource.CreateLinkedTokenSource(round.Token);
                attempt.CancelAfter(2500);
                var opened=await Open(port,LocalAddress,server,attempt.Token);opening=opened.Socket;
                token.ThrowIfCancellationRequested();
                socket=opening;opening=null;StunServer=server;
                reflector=(IPEndPoint)socket.RemoteEndPoint!;
                return opened.Public;
            } catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or SocketException or OperationCanceledException or ArgumentException) {
                recovery.Failed(server);last=ex;
                if(round.IsCancellationRequested)break;
            } finally {opening?.Dispose();}
        }
        token.ThrowIfCancellationRequested();
        throw new IOException("已配置的 TCP STUN 服务暂不可用",last);
    }
    public async ValueTask DisposeAsync()
    {
        lock(lifecycle) {if(disposed)return;disposed=true;}
        valid=false;stop.Cancel();
        try {
            try{await maintaining;}catch(Exception ex)when(ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException){}
        } finally {
            socket.Dispose();
            try{if(gateway!=null)await gateway.DisposeAsync();if(router!=null&&rule!=null)await router.RemoveOwned(rule,CancellationToken.None);}
            finally{router?.Dispose();stop.Dispose();refresh.Dispose();}
        }
    }
}
