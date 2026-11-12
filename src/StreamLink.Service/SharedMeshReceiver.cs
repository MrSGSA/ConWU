using System.Net;
using System.Net.Sockets;
using StreamLink.Core;

namespace StreamLink.Service;

// Shares only the local native receive process. Every delivered payload still
// enters its network's authenticating router; there is no network-to-network hop.
internal sealed class SharedMeshReceiver(string sessionRoot) : IDisposable
{
    readonly object gate=new();
    readonly Dictionary<string,Receiver> receivers=[];
    bool disposed;
    internal IMeshTransport Acquire(MeshTransportRequest request,Func<MeshTransportRequest,IMeshTransport> factory,Func<ReadOnlyMemory<byte>,bool> acceptsPair,Func<ReadOnlyMemory<byte>,bool> authenticated,Func<ReadOnlyMemory<byte>,int> pairPriority)
    {
        if(!request.Server)return factory(request);
        if(request.Target.AddressFamily!=AddressFamily.InterNetwork||!IPAddress.IsLoopback(request.Target.Address)||request.Target.Port==0)throw new ArgumentException("共享接收器的本机路由目标必须是有效 IPv4 回环入口");
        if(!Guid.TryParseExact(request.Mesh.Pair.Network,"N",out _))throw new FormatException("网络身份无效");
        string key=request.Mesh.Pair.Mode+"/"+request.Port;
        lock(gate){
            ObjectDisposedException.ThrowIf(disposed,this);
            if(!receivers.TryGetValue(key,out var receiver)||receiver.Exited){
                if(receiver!=null){if(receiver.Count>0)throw new IOException("共享接收器正在恢复，请等待现有句柄退出");receiver.Dispose();receivers.Remove(key);}
                receiver=new(request,factory,Path.Combine(sessionRoot,Guid.NewGuid().ToString("N")));receivers[key]=receiver;
            }
            if(receiver.Count>0&&(request.Egress!=null||receiver.Exclusive))throw new IOException("此实验出口设置不能与其他网络共用接收端口");
            return receiver.Subscribe(request.Mesh.Pair.Network,request.Target,acceptsPair,authenticated,pairPriority,()=>Release(key,receiver));
        }
    }
    void Release(string key,Receiver receiver)
    {
        lock(gate){if(receiver.Count==0&&receivers.GetValueOrDefault(key)==receiver){receivers.Remove(key);receiver.Dispose();}}
    }
    public void Dispose(){lock(gate){disposed=true;foreach(var receiver in receivers.Values)receiver.Dispose();receivers.Clear();}}

    sealed class Subscription(Receiver owner,string network,IPEndPoint target,Func<ReadOnlyMemory<byte>,bool> accepts,Func<ReadOnlyMemory<byte>,bool> authenticated,Func<ReadOnlyMemory<byte>,int> priority,Action released):IMeshTransport
    {
        public string Network {get;}=network;
        public byte[] NetworkHeader {get;}=PairNetworkFrame.Wrap(network,[]);
        public IPEndPoint Target {get;}=target;
        public Func<ReadOnlyMemory<byte>,bool> Accepts {get;}=accepts;
        public Func<ReadOnlyMemory<byte>,bool> Authenticated {get;}=authenticated;
        public Func<ReadOnlyMemory<byte>,int> Priority {get;}=priority;
        public long NextValidation;
        public IPEndPoint? ClientEndpoint=>null;
        public bool ControlsWirePackets=>owner.ControlsWirePackets;
        public bool Exited=>Volatile.Read(ref disposed)!=0||owner.Exited;
        public string FailureReason=>owner.FailureReason;
        int disposed;
        public void Dispose(){if(Interlocked.Exchange(ref disposed,1)!=0)return;owner.Unsubscribe(this);released();}
    }
    sealed class Route:IDisposable
    {
        public required IPEndPoint Remote;
        public required Subscription Subscription;
        public required Socket Socket;
        public required CancellationTokenSource Stop;
        public Task? Pump;
        public long LastActive=Environment.TickCount64;
        public bool Pairing;
        int disposed;
        public void Dispose(){if(Interlocked.Exchange(ref disposed,1)!=0)return;Stop.Cancel();Socket.Dispose();}
    }
    sealed class Receiver:IDisposable
    {
        readonly object gate=new();
        readonly Socket ingress=new(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);
        readonly CancellationTokenSource stop=new();
        readonly List<Subscription> subscriptions=[];
        readonly Dictionary<(IPEndPoint Remote,string Network),Route> routes=[];
        readonly System.Collections.Concurrent.ConcurrentDictionary<Route,Task> retiring=new();
        readonly IMeshTransport transport;
        readonly Task receive;
        readonly string folder;
        bool disposed;
        long nextPairError;
        public bool Exited=>disposed||transport.Exited||receive.IsFaulted;
        public string FailureReason=>receive.IsFaulted?"SharedReceiverPumpFailed":transport.FailureReason;
        public bool ControlsWirePackets=>transport.ControlsWirePackets;
        public bool Exclusive {get;}
        public int Count{get{lock(gate)return subscriptions.Count;}}
        public Receiver(MeshTransportRequest request,Func<MeshTransportRequest,IMeshTransport> factory,string folder)
        {
            this.folder=folder;Exclusive=request.Egress!=null;
            // The device receiver binds all local IPv4 addresses. NAT mappings
            // belong to individual network attempts, not to this shared owner.
            bool created=false;
            try{
                if(Directory.Exists(folder)||File.Exists(folder))throw new IOException("共享接收器会话目录已存在");
                if(OperatingSystem.IsLinux())LinuxPlatform.PrivateDirectory(folder);else Directory.CreateDirectory(folder);
                created=true;
                ingress.Bind(new IPEndPoint(IPAddress.Loopback,0));ingress.SendBufferSize=ingress.ReceiveBufferSize=1<<20;ingress.Blocking=false;
                transport=factory(request with{Target=(IPEndPoint)ingress.LocalEndPoint!,Folder=folder,Mapping=null});receive=Task.Run(Receive);
            }
            catch{ingress.Dispose();stop.Dispose();if(created&&Directory.Exists(folder))Directory.Delete(folder,true);throw;}
        }
        public Subscription Subscribe(string network,IPEndPoint target,Func<ReadOnlyMemory<byte>,bool> accepts,Func<ReadOnlyMemory<byte>,bool> authenticated,Func<ReadOnlyMemory<byte>,int> priority,Action released)
        {
            lock(gate){if(subscriptions.Count>=16)throw new IOException("共享接收器网络数已满");
                if(subscriptions.Any(s=>s.Network==network))throw new IOException("此网络已有接收器，拒绝重复入口");
                var subscription=new Subscription(this,network,target,accepts,authenticated,priority,released);subscriptions.Add(subscription);return subscription;}
        }
        public void Unsubscribe(Subscription subscription)
        {
            Route[] removed;lock(gate){subscriptions.Remove(subscription);removed=routes.Where(p=>p.Value.Subscription==subscription).Select(p=>p.Value).ToArray();foreach(var key in routes.Where(p=>p.Value.Subscription==subscription).Select(p=>p.Key).ToArray())routes.Remove(key);}
            foreach(var route in removed)Retire(route);
        }
        void Retire(Route route)
        {
            route.Dispose();
            var completion=FinishRoute(route);retiring[route]=completion;
            _=completion.ContinueWith(_=>retiring.TryRemove(route,out var ignored),CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
        }
        static async Task FinishRoute(Route route){try{if(route.Pump!=null)await route.Pump;}catch(Exception){}finally{route.Stop.Dispose();}}
        async Task Receive()
        {
            byte[] buffer=new byte[2048];int batch=0;
            try{while(!stop.IsCancellationRequested){
                if(++batch>=64){batch=0;await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);}
                SocketReceiveFromResult incoming;
                try{incoming=await ingress.ReceiveFromAsync(buffer,SocketFlags.None,new IPEndPoint(IPAddress.Loopback,0),stop.Token);}
                catch(SocketException ex)when(ex.SocketErrorCode is SocketError.MessageSize or SocketError.ConnectionReset or SocketError.ConnectionRefused){continue;}
                var remote=(IPEndPoint)incoming.RemoteEndPoint;if(!IPAddress.IsLoopback(remote.Address))continue;
                var frame=buffer.AsMemory(0,incoming.ReceivedBytes);Subscription? subscription=null;
                lock(gate){
                    if(PairNetworkFrame.IsFrame(frame.Span)){
                        foreach(var candidate in subscriptions)if(frame.Span[..PairNetworkFrame.HeaderSize].SequenceEqual(candidate.NetworkHeader)){
                            subscription=candidate;break;
                        }
                    }
                    else if(DirectPairWire.IsFrame(frame.Span)){
                        DirectPairRequest pair;try{pair=DirectPairWire.Decode<DirectPairRequest>(frame.Span);}catch{continue;}
                        if(pair.TargetNetwork is null||pair.TargetNetwork.Length>0&&!Guid.TryParseExact(pair.TargetNetwork,"N",out _))continue;
                        string wanted=pair.TargetNetwork.Length>0?pair.TargetNetwork:pair.Rejoin?.Network??"";
                        var candidates=subscriptions.Where(s=>(wanted.Length==0||s.Network==wanted)&&s.Accepts(frame)).Select(s=>(Subscription:s,Rank:s.Priority(frame))).ToArray();
                        int highest=candidates.Length>0?candidates.Max(c=>c.Rank):0;var matches=candidates.Where(c=>c.Rank==highest).ToArray();
                        if(matches.Length==1)subscription=matches[0].Subscription;
                        else if(pair.Method=="join"&&Environment.TickCount64>=nextPairError){
                            nextPairError=Environment.TickCount64+200;
                            string error=matches.Length>1?"此入口有多条待配对网络，请使用目标网络的配对码、直连邀请或专属 DDNS 链接":"目标网络当前未接收入网申请，请确认主机已准备配对或重新生成邀请";
                            // A newly created network can still be attaching its
                            // subscription while an older (already paired) one
                            // owns this listener. A bare entry has no network ID
                            // with which to distinguish that short preparation
                            // gap. Let the client's bounded attempt retry it;
                            // ambiguity and an explicitly unknown target still
                            // fail immediately.
                            bool preparing=matches.Length==0&&pair.EntryAdmission&&(wanted.Length==0||subscriptions.Any(s=>s.Network==wanted&&s.Priority(frame)>0));
                            try{ingress.SendTo(DirectPairWire.Encode(new DirectPairReply(pair.Id,error){Retryable=preparing}),remote);}catch(SocketException){}
                        }
                    }
                    if(subscription==null)continue;
                    var key=(remote,subscription.Network);
                    if(!routes.TryGetValue(key,out var route)||route.Pump?.IsCompleted==true){
                        if(route!=null){Retire(route);routes.Remove(key);}
                        bool pairing=DirectPairWire.IsFrame(frame.Span);
                        if(!pairing){
                            long now=Environment.TickCount64;if(now<subscription.NextValidation)continue;subscription.NextValidation=now+100;
                            if(!subscription.Authenticated(frame))continue;
                        }
                        foreach(var expired in routes.Where(p=>Environment.TickCount64-p.Value.LastActive>120000||p.Value.Pump?.IsCompleted==true).Select(p=>p.Key).ToArray()){Retire(routes[expired]);routes.Remove(expired);}
                        var belonging=routes.Where(p=>p.Value.Subscription==subscription&&p.Value.Pairing==pairing).OrderBy(p=>p.Value.LastActive).ToArray();
                        if(belonging.Length>=4){
                            // An old authenticated packet can be replayed from
                            // a fresh carrier tuple. It must not evict a live
                            // business route; idle routes were expired above.
                            if(!pairing)continue;
                            Retire(belonging[0].Value);routes.Remove(belonging[0].Key);
                        }
                        if(routes.Count>=128)continue;
                        var socket=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);socket.Bind(new IPEndPoint(IPAddress.Loopback,0));socket.SendBufferSize=socket.ReceiveBufferSize=1<<20;socket.Blocking=false;
                        route=new(){Remote=remote,Subscription=subscription,Socket=socket,Stop=CancellationTokenSource.CreateLinkedTokenSource(stop.Token),Pairing=pairing};
                        routes[key]=route;route.Pump=Task.Run(()=>Return(route));
                    }
                    route.LastActive=Environment.TickCount64;
                    try{route.Socket.SendTo(frame.Span,SocketFlags.None,subscription.Target);}catch(SocketException ex)when(ex.SocketErrorCode is SocketError.NoBufferSpaceAvailable or SocketError.WouldBlock){}
                }
            }}catch(Exception ex)when(stop.IsCancellationRequested&&ex is OperationCanceledException or ObjectDisposedException or SocketException){}
        }
        async Task Return(Route route)
        {
            byte[] buffer=new byte[2048];try{while(!route.Stop.IsCancellationRequested){
                SocketReceiveFromResult incoming;
                try{incoming=await route.Socket.ReceiveFromAsync(buffer,SocketFlags.None,new IPEndPoint(IPAddress.Loopback,0),route.Stop.Token);}
                catch(SocketException ex)when(ex.SocketErrorCode is SocketError.MessageSize or SocketError.ConnectionReset or SocketError.ConnectionRefused){continue;}
                if(!incoming.RemoteEndPoint.Equals(route.Subscription.Target))continue;
                route.LastActive=Environment.TickCount64;
                await ingress.SendToAsync(buffer.AsMemory(0,incoming.ReceivedBytes),SocketFlags.None,route.Remote,route.Stop.Token);
            }}catch(Exception ex)when(route.Stop.IsCancellationRequested&&ex is OperationCanceledException or ObjectDisposedException or SocketException){}
        }
        public void Dispose()
        {
            Route[] owned;lock(gate){if(disposed)return;disposed=true;stop.Cancel();ingress.Dispose();owned=routes.Values.ToArray();routes.Clear();subscriptions.Clear();}
            foreach(var route in owned)Retire(route);
            try{Task.WhenAll(retiring.Values.Append(receive)).GetAwaiter().GetResult();}catch(OperationCanceledException){}finally{transport.Dispose();stop.Dispose();}
            if(Directory.Exists(folder))Directory.Delete(folder,true);
        }
    }
}
