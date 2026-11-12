using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace StreamLink.Core;

public sealed record StreamTransportIo(long NetworkWrites,long NetworkReads,long SentDatagrams,long ReceivedDatagrams);

// A bounded datagram bridge for the existing authenticating MeshLink router.
// The loopback socket is local plumbing; all remote traffic is real TCP/TLS.
public sealed class StreamMeshTransport : IMeshTransport,IAsyncDisposable
{
    public const int MaximumDatagram=2048;
    const string Subprotocol="conwu.stream.v1";
    const string BatchHeader="X-ConWU-Datagram-Batch";
    const int MaximumBatchBytes=16384,MaximumBatchDatagrams=16;
    readonly CancellationTokenSource stop=new();
    readonly ConcurrentDictionary<Guid,TcpClient> clients=new();
    readonly ConcurrentDictionary<Guid,Task> tasks=new();
    readonly bool https;
    readonly bool batchDatagrams;
    long networkWrites,networkReads,sentDatagrams,receivedDatagrams;
    readonly Task lifetime;
    readonly Socket? local;
    readonly TcpListener? listener;
    readonly IDisposable? listenerAccess;
    int disposed;
    string failure="",peerPin="",lastConnectionFailure="";
    public IPEndPoint? ClientEndpoint {get;}
    public string PeerCertificatePin=>Volatile.Read(ref peerPin);
    public string TlsProtocol {get;private set;}="";
    public bool BatchingEnabled {get;private set;}
    public StreamTransportIo Io=>new(Interlocked.Read(ref networkWrites),Interlocked.Read(ref networkReads),Interlocked.Read(ref sentDatagrams),Interlocked.Read(ref receivedDatagrams));
    public bool Exited=>Volatile.Read(ref disposed)!=0||lifetime.IsCompleted;
    public string FailureReason=>Volatile.Read(ref failure);
    public string LastConnectionFailure=>Volatile.Read(ref lastConnectionFailure);
    static string FailureDetails(Exception error)=>string.Join(" / ",Errors(error).Select(e=>e.GetType().Name+" (0x"+e.HResult.ToString("X8")+(e is System.ComponentModel.Win32Exception native?", native="+native.NativeErrorCode:"")+")"));
    static IEnumerable<Exception> Errors(Exception error){for(int n=0;n<4&&error!=null;n++,error=error.InnerException!)yield return error;}

    public StreamMeshTransport(MeshProfile mesh,IPEndPoint target,bool server,int listenPort,
        Func<X509Certificate2>? certificate=null,bool pairingBootstrap=false,Action<IPEndPoint>? reserveEndpoint=null,Func<IDisposable>? allowListener=null,bool batchDatagrams=true)
    {
        if(!TransportModes.Stream(mesh.Pair.Mode))throw new ArgumentException("真实流传输需要 TCP 或 HTTPS 模式");
        https=mesh.Pair.Mode=="https";
        this.batchDatagrams=batchDatagrams;
        if(https&&server&&certificate==null)throw new ArgumentException("HTTPS 监听缺少证书");
        if(https&&!server&&!pairingBootstrap&&mesh.Pair.TransportKeyPin?.Length!=64)throw new IOException("HTTPS 对端尚未通过配对绑定证书身份");
        try{
            if(server){
                listener=new(IPAddress.Any,listenPort);
                // A retained TCP STUN flow uses this same local port. Ownership
                // is coordinated by the device workspace, never by raw filters.
                listener.Server.ExclusiveAddressUse=false;
                listener.Server.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.ReuseAddress,true);
                listener.Start(32);listenerAccess=allowListener?.Invoke();lifetime=Accept(target,certificate);
            }else{
                local=LocalSocket();ClientEndpoint=(IPEndPoint)local.LocalEndPoint!;
                reserveEndpoint?.Invoke(ClientEndpoint);
                lifetime=Connect(mesh,target,pairingBootstrap);
            }
        }catch{local?.Dispose();listener?.Stop();listenerAccess?.Dispose();stop.Dispose();throw;}
    }
    static Socket LocalSocket(){var value=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);try{value.ReceiveBufferSize=value.SendBufferSize=1<<20;value.Bind(new IPEndPoint(IPAddress.Loopback,0));return value;}catch{value.Dispose();throw;}}
    async Task Accept(IPEndPoint target,Func<X509Certificate2>? certificate)
    {
        try{while(!stop.IsCancellationRequested){
            var tcp=await listener!.AcceptTcpClientAsync(stop.Token);tcp.NoDelay=true;
            if(clients.Count>=16){tcp.Dispose();continue;}
            var id=Guid.NewGuid();clients[id]=tcp;
            var serving=ServeAccepted(tcp,target,certificate);
            tasks[id]=serving;
            _=serving.ContinueWith(_=>{clients.TryRemove(id,out var closed);closed?.Dispose();tasks.TryRemove(id,out var ignored);},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
        }}catch(Exception ex)when(stop.IsCancellationRequested&&ex is OperationCanceledException or SocketException or ObjectDisposedException){}
        catch(Exception ex){Volatile.Write(ref failure,"TCP 监听退出："+ex.GetType().Name);}
    }
    async Task ServeAccepted(TcpClient tcp,IPEndPoint target,Func<X509Certificate2>? certificate)
    {
        using var udp=LocalSocket();
        try{await Bridge(tcp,udp,target,certificate,null,false);}
        catch(Exception ex)when(ex is IOException or SocketException or OperationCanceledException or AuthenticationException or WebSocketException or ObjectDisposedException){if(!stop.IsCancellationRequested)Volatile.Write(ref lastConnectionFailure,FailureDetails(ex));}
    }
    async Task Connect(MeshProfile mesh,IPEndPoint target,bool bootstrap)
    {
        using var tcp=new TcpClient(target.AddressFamily){NoDelay=true};var id=Guid.NewGuid();clients[id]=tcp;
        try{
            using(var deadline=CancellationTokenSource.CreateLinkedTokenSource(stop.Token)){deadline.CancelAfter(10000);await tcp.ConnectAsync(target.Address,target.Port,deadline.Token);}
            await Bridge(tcp,local!,null,null,(target,mesh.Pair.TransportKeyPin??""),bootstrap);
            if(!stop.IsCancellationRequested)Volatile.Write(ref failure,"TCP 对端已关闭连接");
        }catch(Exception ex)when(ex is IOException or SocketException or OperationCanceledException or AuthenticationException or WebSocketException or ObjectDisposedException){if(!stop.IsCancellationRequested)Volatile.Write(ref failure,"TCP 连接未完成："+FailureDetails(ex));}
        finally{clients.TryRemove(id,out _);}
    }
    public static string CertificatePin(X509Certificate2 certificate)=>Convert.ToHexString(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()));
    static bool ValidCertificate(X509Certificate2 certificate)=>certificate.NotBefore.ToUniversalTime()<=DateTime.UtcNow&&certificate.NotAfter.ToUniversalTime()>DateTime.UtcNow;
    async Task Bridge(TcpClient tcp,Socket udp,IPEndPoint? fixedReceiver,Func<X509Certificate2>? certificate,(IPEndPoint Target,string Pin)? remote,bool bootstrap)
    {
        using var connection=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
        Stream stream=tcp.GetStream();SslStream? tls=null;WebSocket? web=null;
        bool framedBatch=!https&&batchDatagrams;
        try{
            if(https){
                using var handshake=CancellationTokenSource.CreateLinkedTokenSource(connection.Token);handshake.CancelAfter(8000);
                if(remote is {} peer){
                    tls=new SslStream(stream,false,(_,value,_,_)=>{
                        if(value==null)return false;
                        using var cert=X509CertificateLoader.LoadCertificate(value.GetRawCertData());
                        if(!ValidCertificate(cert))return false;
                        string actual=CertificatePin(cert);Volatile.Write(ref peerPin,actual);
                        return peer.Pin.Length==64?CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(actual),Encoding.ASCII.GetBytes(peer.Pin.ToUpperInvariant())):bootstrap;
                    });
                    await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions{TargetHost=peer.Target.Address.ToString(),EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13,CertificateRevocationCheckMode=X509RevocationMode.NoCheck},handshake.Token);
                    string key=Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                    string batching=batchDatagrams?$"{BatchHeader}: 1\r\n":"";
                    await WriteHttp(tls,$"GET /conwu/stream HTTP/1.1\r\nHost: {peer.Target}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {Subprotocol}\r\n{batching}\r\n",handshake.Token);
                    var reply=await ReadHttp(tls,handshake.Token);
                    if(!reply.Start.StartsWith("HTTP/1.1 101 ",StringComparison.Ordinal)||!Upgrade(reply.Headers)||reply.Headers.GetValueOrDefault("Sec-WebSocket-Accept")!=AcceptKey(key)||reply.Headers.GetValueOrDefault("Sec-WebSocket-Protocol")!=Subprotocol)throw new IOException("HTTPS 升级响应无效");
                    if(reply.Headers.TryGetValue(BatchHeader,out var batchingReply)){
                        if(!batchDatagrams||batchingReply!="1")throw new IOException("HTTPS 批量数据报协商无效");
                        framedBatch=true;
                    }
                }else{
                    tls=new SslStream(stream,false);
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=certificate!(),EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13,ClientCertificateRequired=false},handshake.Token);
                    var request=await ReadHttp(tls,handshake.Token);
                    if(request.Start!="GET /conwu/stream HTTP/1.1"||!Upgrade(request.Headers)||request.Headers.GetValueOrDefault("Sec-WebSocket-Version")!="13"||request.Headers.GetValueOrDefault("Sec-WebSocket-Protocol")!=Subprotocol||!request.Headers.TryGetValue("Sec-WebSocket-Key",out string? key))throw new IOException("HTTPS 升级请求无效");
                    try{if(Convert.FromBase64String(key).Length!=16)throw new FormatException();}catch(FormatException){throw new IOException("WebSocket key 无效");}
                    framedBatch=batchDatagrams&&request.Headers.GetValueOrDefault(BatchHeader)=="1";
                    string batching=framedBatch?$"{BatchHeader}: 1\r\n":"";
                    await WriteHttp(tls,$"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {AcceptKey(key)}\r\nSec-WebSocket-Protocol: {Subprotocol}\r\n{batching}\r\n",handshake.Token);
                }
                TlsProtocol=tls.SslProtocol.ToString();stream=tls;web=WebSocket.CreateFromStream(stream,remote==null,Subprotocol,TimeSpan.FromSeconds(15));
            }
            BatchingEnabled=framedBatch;
            IPEndPoint? receiver=fixedReceiver;long lastRead=Environment.TickCount64;
            async Task ToNetwork()
            {
                byte[] buffer = new byte[MaximumBatchBytes];
                byte[] packetBuffer = new byte[MaximumDatagram + 1];
                EndPoint any = new IPEndPoint(IPAddress.Loopback, 0);
                ValueTask<SocketReceiveFromResult>? pending = null;
                try {
                    while (!connection.IsCancellationRequested) {
                        int used = 0, count = 0;
                        for (int attempt = 0; attempt < MaximumBatchDatagrams; attempt++) {
                            var receiving = pending ?? udp.ReceiveFromAsync(packetBuffer, SocketFlags.None, any, connection.Token);
                            pending = null;
                            var packet = await receiving;
                            if (packet.ReceivedBytes is >= 1 and <= MaximumDatagram &&
                                packet.RemoteEndPoint is IPEndPoint sender && IPAddress.IsLoopback(sender.Address) &&
                                (fixedReceiver == null || sender.Equals(fixedReceiver))) {
                                receiver ??= sender;
                                if (sender.Equals(receiver)) {
                                    BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(used, 2), (ushort)packet.ReceivedBytes);
                                    packetBuffer.AsSpan(0, packet.ReceivedBytes).CopyTo(buffer.AsSpan(used + 2));
                                    used += packet.ReceivedBytes + 2;
                                    count++;
                                }
                            }
                            // Drain only packets already queued. A lone control or
                            // input packet is sent immediately without a batch timer.
                            if (!framedBatch || used + MaximumDatagram + 3 > buffer.Length) break;
                            pending = udp.ReceiveFromAsync(packetBuffer, SocketFlags.None, any, connection.Token);
                            if (!pending.Value.IsCompleted) break;
                        }
                        if (count == 0) continue;
                        if (web != null) {
                            var message = framedBatch ? buffer.AsMemory(0, used) : buffer.AsMemory(2, used - 2);
                            await web.SendAsync(message, WebSocketMessageType.Binary, true, connection.Token);
                        } else {
                            await stream.WriteAsync(buffer.AsMemory(0, used), connection.Token);
                        }
                        Interlocked.Increment(ref networkWrites);
                        Interlocked.Add(ref sentDatagrams, count);
                    }
                } finally {
                    if (pending is {} unfinished) {
                        connection.Cancel();
                        try { await unfinished; }
                        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException) { }
                    }
                }
            }
            async Task FromNetwork(){
                byte[] buffer=new byte[MaximumBatchBytes+1];int buffered=0;
                while(!connection.IsCancellationRequested){
                    int length;
                    if(web!=null){
                        length=0;ValueWebSocketReceiveResult frame;
                        int maximum=framedBatch?MaximumBatchBytes:MaximumDatagram;
                        do{
                            if(length>maximum)throw new IOException("HTTPS 消息过大");
                            frame=await web.ReceiveAsync(buffer.AsMemory(length,maximum+1-length),connection.Token);
                            Interlocked.Increment(ref networkReads);
                            if(frame.MessageType==WebSocketMessageType.Close)return;
                            if(frame.MessageType!=WebSocketMessageType.Binary)throw new IOException("HTTPS 只接收二进制数据");
                            length+=frame.Count;
                        }while(!frame.EndOfMessage);
                        if(length<1||length>maximum)throw new IOException("HTTPS 数据报长度无效");
                        if(!framedBatch){await Deliver(0,length);continue;}
                        int count=0;
                        for(int offset=0;offset<length;){
                            if(length-offset<2||++count>MaximumBatchDatagrams)throw new IOException("HTTPS 批量数据帧无效");
                            int size=BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(offset,2));
                            if(size is <1 or >MaximumDatagram||size>length-offset-2)throw new IOException("HTTPS 批量数据帧长度无效");
                            offset+=size+2;
                        }
                    }else{
                        int read=await stream.ReadAsync(buffer.AsMemory(buffered,MaximumBatchBytes-buffered),connection.Token);
                        Interlocked.Increment(ref networkReads);
                        if(read==0)throw new EndOfStreamException("TCP 数据流已关闭");
                        buffered+=read;length=buffered;
                    }
                    int consumed=0;
                    while(length-consumed>=2){
                        int size=BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(consumed,2));
                        if(size is <1 or >MaximumDatagram)throw new IOException("TCP 数据帧长度无效");
                        if(size>length-consumed-2)break;
                        await Deliver(consumed+2,size);consumed+=size+2;
                    }
                    if(web==null){buffered=length-consumed;buffer.AsSpan(consumed,buffered).CopyTo(buffer);}
                }
                async Task Deliver(int offset,int length){
                    Interlocked.Exchange(ref lastRead,Environment.TickCount64);
                    if(receiver is {} localTarget)await udp.SendToAsync(buffer.AsMemory(offset,length),SocketFlags.None,localTarget,connection.Token);
                    Interlocked.Increment(ref receivedDatagrams);
                }
            }
            async Task Watch(){using var timer=new PeriodicTimer(TimeSpan.FromSeconds(5));while(await timer.WaitForNextTickAsync(connection.Token))if(Environment.TickCount64-Interlocked.Read(ref lastRead)>20000)throw new IOException("TCP 对端长时间未回应");}
            var pumps=new[]{ToNetwork(),FromNetwork(),Watch()};
            try{await await Task.WhenAny(pumps);}
            finally{connection.Cancel();tcp.Dispose();try{await Task.WhenAll(pumps);}catch(Exception ex)when(ex is OperationCanceledException or IOException or SocketException or WebSocketException or ObjectDisposedException){}}
        }finally{web?.Dispose();tls?.Dispose();}
    }
    static bool Upgrade(Dictionary<string,string> headers)=>headers.TryGetValue("Upgrade",out var upgrade)&&upgrade.Equals("websocket",StringComparison.OrdinalIgnoreCase)&&headers.TryGetValue("Connection",out var connection)&&connection.Split(',').Any(v=>v.Trim().Equals("Upgrade",StringComparison.OrdinalIgnoreCase));
    static string AcceptKey(string key)=>Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
    static Task WriteHttp(Stream stream,string text,CancellationToken token)=>stream.WriteAsync(Encoding.ASCII.GetBytes(text),token).AsTask();
    static async Task<(string Start,Dictionary<string,string> Headers)> ReadHttp(Stream stream,CancellationToken token)
    {
        byte[] buffer=new byte[4096],one=new byte[1];int length=0;
        while(length<buffer.Length){await stream.ReadExactlyAsync(one,token);buffer[length++]=one[0];if(length>=4&&buffer[length-4]==13&&buffer[length-3]==10&&buffer[length-2]==13&&buffer[length-1]==10)break;}
        if(length==buffer.Length)throw new IOException("HTTPS 请求头过大");
        var lines=Encoding.ASCII.GetString(buffer,0,length).Split("\r\n");var headers=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        foreach(var line in lines.Skip(1).Where(v=>v.Length>0)){int colon=line.IndexOf(':');if(colon<=0||!headers.TryAdd(line[..colon].Trim(),line[(colon+1)..].Trim()))throw new IOException("HTTPS 请求头无效");}
        return(lines[0],headers);
    }
    public void Dispose(){if(Interlocked.Exchange(ref disposed,1)!=0)return;stop.Cancel();listener?.Stop();local?.Dispose();foreach(var tcp in clients.Values)tcp.Dispose();listenerAccess?.Dispose();}
    public async ValueTask DisposeAsync(){Dispose();await lifetime;await Task.WhenAll(tasks.Values.ToArray());stop.Dispose();}
}
