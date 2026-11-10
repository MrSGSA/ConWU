using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using StreamLink.Core;

static class StreamSecurityChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var cert=StreamCertificates.CreateServer(key,DateTimeOffset.UtcNow.AddDays(1));
        var owner=MeshIdentity.Create("","","https",direct:true);int port=FreePort();
        using var sink=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        await using var listener=new StreamMeshTransport(owner,(IPEndPoint)sink.Client.LocalEndPoint!,true,port,()=>cert);
        using var deadline=new CancellationTokenSource(10000);
        bool missingPin=false;try{using var unsigned=new StreamMeshTransport(owner,new(IPAddress.Loopback,port),false,0);}catch(IOException){missingPin=true;}
        check(missingPin,"HTTPS cannot silently bootstrap an ordinary unpinned business connection");
        async Task<ClientWebSocket> Open(){var socket=new ClientWebSocket();socket.Options.Proxy=null;socket.Options.AddSubProtocol("conwu.stream.v1");socket.Options.RemoteCertificateValidationCallback=(_,certificate,_,_)=>certificate?.GetCertHashString()==cert.GetCertHashString();await socket.ConnectAsync(new($"wss://127.0.0.1:{port}/conwu/stream"),deadline.Token);return socket;}
        using(var socket=await Open()){
            byte[] expected=RandomNumberGenerator.GetBytes(StreamMeshTransport.MaximumDatagram);
            await socket.SendAsync(expected.AsMemory(0,1000),WebSocketMessageType.Binary,false,deadline.Token);
            await socket.SendAsync(expected.AsMemory(1000),WebSocketMessageType.Binary,true,deadline.Token);
            var received=await sink.ReceiveAsync(deadline.Token);
            check(received.Buffer.SequenceEqual(expected),"fragmented HTTPS messages preserve exactly one bounded datagram");
            await sink.SendAsync(received.Buffer,received.RemoteEndPoint,deadline.Token);
            byte[] reply=new byte[expected.Length];var frame=await socket.ReceiveAsync(reply.AsMemory(),deadline.Token);
            check(frame.EndOfMessage&&frame.Count==expected.Length&&reply.SequenceEqual(expected),"HTTPS return traffic preserves a full-size binary datagram");
            await socket.SendAsync(expected,WebSocketMessageType.Binary,false,deadline.Token);
            await socket.SendAsync(new byte[]{1},WebSocketMessageType.Binary,true,deadline.Token);
            bool closed=false;try{await socket.ReceiveAsync(new byte[1],deadline.Token);}catch(WebSocketException){closed=true;}
            using var quiet=new CancellationTokenSource(150);bool noLeak=false;try{await sink.ReceiveAsync(quiet.Token);}catch(OperationCanceledException){noLeak=true;}
            check(closed&&noLeak&&!listener.Exited,"oversized fragmented HTTPS input is discarded completely and closes only its own connection");
        }
        using(var invalid=new TcpClient()){
            await invalid.ConnectAsync(IPAddress.Loopback,port,deadline.Token);
            using var tls=new SslStream(invalid.GetStream(),false,(_,certificate,_,_)=>certificate?.GetCertHashString()==cert.GetCertHashString());await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions{TargetHost="127.0.0.1"},deadline.Token);
            await tls.WriteAsync(Encoding.ASCII.GetBytes("GET /wrong HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),deadline.Token);
            bool refused=false;try{refused=await tls.ReadAsync(new byte[1],deadline.Token)==0;}catch(IOException){refused=true;}
            check(refused&&!listener.Exited,"TLS alone does not bypass the exact bounded HTTP upgrade protocol");
        }
        using var healthy=await Open();check(healthy.State==WebSocketState.Open,"a healthy HTTPS peer can still connect after malformed handshakes and messages");
    }
    static int FreePort(){var l=new TcpListener(IPAddress.Loopback,0);l.Start();int p=((IPEndPoint)l.LocalEndpoint).Port;l.Stop();return p;}
}
