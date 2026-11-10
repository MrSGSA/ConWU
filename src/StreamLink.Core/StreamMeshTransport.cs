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

// A bounded datagram bridge for the existing authenticating MeshLink router.
// The loopback socket is local plumbing; all remote traffic is real TCP/TLS.
public sealed class StreamMeshTransport : IMeshTransport,IAsyncDisposable
{
    public const int MaximumDatagram=2048;
    const string Subprotocol="conwu.stream.v1";
    readonly CancellationTokenSource stop=new();
    readonly ConcurrentDictionary<Guid,TcpClient> clients=new();
    readonly ConcurrentDictionary<Guid,Task> tasks=new();
    readonly bool https;
    readonly Task lifetime;
    readonly Socket? local;
    readonly TcpListener? listener;
    readonly IDisposable? listenerAccess;
    int disposed;
    string failure="",peerPin="",lastConnectionFailure="";
    public IPEndPoint? ClientEndpoint {get;}
    public string PeerCertificatePin=>Volatile.Read(ref peerPin);
    public string TlsProtocol {get;private set;}="";
    public bool Exited=>Volatile.Read(ref disposed)!=0||lifetime.IsCompleted;
    public string FailureReason=>Volatile.Read(ref failure);
    public string LastConnectionFailure=>Volatile.Read(ref lastConnectionFailure);
    static string FailureDetails(Exception error)=>string.Join(" / ",Errors(error).Select(e=>e.GetType().Name+" (0x"+e.HResult.ToString("X8")+(e is System.ComponentModel.Win32Exception native?", native="+native.NativeErrorCode:"")+")"));
    static IEnumerable<Exception> Errors(Exception error){for(int n=0;n<4&&error!=null;n++,error=error.InnerException!)yield return error;}

    public StreamMeshTransport(MeshProfile mesh,IPEndPoint target,bool server,int listenPort,
        Func<X509Certificate2>? certificate=null,bool pairingBootstrap=false,Action<IPEndPoint>? reserveEndpoint=null,Func<IDisposable>? allowListener=null)
    {
        if(!TransportModes.Stream(mesh.Pair.Mode))throw new ArgumentException("真实流传输需要 TCP 或 HTTPS 模式");
        https=mesh.Pair.Mode=="https";
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
                    await WriteHttp(tls,$"GET /conwu/stream HTTP/1.1\r\nHost: {peer.Target}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {Subprotocol}\r\n\r\n",handshake.Token);
                    var reply=await ReadHttp(tls,handshake.Token);
                    if(!reply.Start.StartsWith("HTTP/1.1 101 ",StringComparison.Ordinal)||!Upgrade(reply.Headers)||reply.Headers.GetValueOrDefault("Sec-WebSocket-Accept")!=AcceptKey(key)||reply.Headers.GetValueOrDefault("Sec-WebSocket-Protocol")!=Subprotocol)throw new IOException("HTTPS 升级响应无效");
                }else{
                    tls=new SslStream(stream,false);
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=certificate!(),EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13,ClientCertificateRequired=false},handshake.Token);
                    var request=await ReadHttp(tls,handshake.Token);
                    if(request.Start!="GET /conwu/stream HTTP/1.1"||!Upgrade(request.Headers)||request.Headers.GetValueOrDefault("Sec-WebSocket-Version")!="13"||request.Headers.GetValueOrDefault("Sec-WebSocket-Protocol")!=Subprotocol||!request.Headers.TryGetValue("Sec-WebSocket-Key",out string? key))throw new IOException("HTTPS 升级请求无效");
                    try{if(Convert.FromBase64String(key).Length!=16)throw new FormatException();}catch(FormatException){throw new IOException("WebSocket key 无效");}
                    await WriteHttp(tls,$"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {AcceptKey(key)}\r\nSec-WebSocket-Protocol: {Subprotocol}\r\n\r\n",handshake.Token);
                }
                TlsProtocol=tls.SslProtocol.ToString();stream=tls;web=WebSocket.CreateFromStream(stream,remote==null,Subprotocol,TimeSpan.FromSeconds(15));
            }
            IPEndPoint? receiver=fixedReceiver;long lastRead=Environment.TickCount64;
            async Task ToNetwork(){
                byte[] buffer=new byte[MaximumDatagram+3];EndPoint any=new IPEndPoint(IPAddress.Loopback,0);
                while(!connection.IsCancellationRequested){
                    var packet=await udp.ReceiveFromAsync(buffer.AsMemory(2),SocketFlags.None,any,connection.Token);
                    if(packet.ReceivedBytes is <1 or >MaximumDatagram||packet.RemoteEndPoint is not IPEndPoint sender||!IPAddress.IsLoopback(sender.Address))continue;
                    if(fixedReceiver!=null&&!sender.Equals(fixedReceiver))continue;
                    receiver??=sender;if(!sender.Equals(receiver))continue;
                    if(web!=null)await web.SendAsync(buffer.AsMemory(2,packet.ReceivedBytes),WebSocketMessageType.Binary,true,connection.Token);
                    else{BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0,2),(ushort)packet.ReceivedBytes);await stream.WriteAsync(buffer.AsMemory(0,packet.ReceivedBytes+2),connection.Token);}
                }
            }
            async Task FromNetwork(){
                byte[] buffer=new byte[MaximumDatagram+1],header=new byte[2];
                while(!connection.IsCancellationRequested){
                    int length;
                    if(web!=null){
                        length=0;ValueWebSocketReceiveResult frame;
                        do{if(length>MaximumDatagram)throw new IOException("HTTPS 消息过大");frame=await web.ReceiveAsync(buffer.AsMemory(length),connection.Token);if(frame.MessageType==WebSocketMessageType.Close)return;if(frame.MessageType!=WebSocketMessageType.Binary)throw new IOException("HTTPS 只接收二进制数据");length+=frame.Count;}while(!frame.EndOfMessage);
                    }else{await stream.ReadExactlyAsync(header,connection.Token);length=BinaryPrimitives.ReadUInt16BigEndian(header);if(length is <1 or >MaximumDatagram)throw new IOException("TCP 数据帧长度无效");await stream.ReadExactlyAsync(buffer.AsMemory(0,length),connection.Token);}
                    if(length is <1 or >MaximumDatagram)throw new IOException("流数据报长度无效");
                    Interlocked.Exchange(ref lastRead,Environment.TickCount64);
                    if(receiver is {} localTarget)await udp.SendToAsync(buffer.AsMemory(0,length),SocketFlags.None,localTarget,connection.Token);
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
