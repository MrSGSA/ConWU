using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using ConWU.Mobile;
using StreamLink.Core;

static class PairingFailureTests
{
    static int FreePort(){var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();return port;}
    static async Task<(string Message,StreamConnectionStatus Status)> Failure(int port)
    {
        var profile=MeshIdentity.Create("","","https",direct:true);StreamMeshTransport? stream=null;
        using var key=new PairKeyExchange();using var stop=new CancellationTokenSource(15000);
        using var client=new DirectPairClient(_=>stream=new StreamMeshTransport(profile,new(IPAddress.Loopback,port),false,0,pairingBootstrap:true));
        try{await client.Join("123456",key,"Phone",stop.Token);throw new Exception("Expected pairing failure");}
        catch(IOException error){return(error.Message,stream!.ClientConnection);}
    }
    public static async Task Run(Action<bool,string> check)
    {
        var absent=await Failure(FreePort());
        check(absent.Status.FailedAt=="TcpConnecting"&&absent.Message.Contains("TCP 入口"),"an unreachable TCP entry is distinguished from an unanswered pairing room");
        using var certificateKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate=StreamCertificates.CreateServer(certificateKey,DateTimeOffset.UtcNow.AddHours(1));
        foreach(bool tls in new[]{false,true}){
            var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;
            using var stop=new CancellationTokenSource(15000);
            var serving=Task.Run(async()=>{
                using var socket=await listener.AcceptTcpClientAsync(stop.Token);
                if(tls){
                    using var secure=new SslStream(socket.GetStream(),false);
                    await secure.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=certificate,EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13},stop.Token);
                    await secure.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"u8.ToArray(),stop.Token);
                    await Task.Delay(200,stop.Token);
                }else{await socket.GetStream().WriteAsync("HTTP/1.1 400 Bad Request\r\n\r\n"u8.ToArray(),stop.Token);await Task.Delay(200,stop.Token);}
            });
            try{
                var failed=await Failure(port);
                check(failed.Status.FailedAt==(tls?"HttpUpgrade":"TlsHandshake")&&failed.Message.Contains(tls?"通道协商":"HTTPS 握手"),tls?"a TLS web server without ConWU upgrade reports channel negotiation failure":"a non-TLS listener reports HTTPS handshake failure after TCP connects");
            }finally{stop.Cancel();listener.Stop();try{await serving;}catch(OperationCanceledException){} }
        }
        var owner=MeshIdentity.Create("","","https",direct:true,pairwise:true);
        await using var router=new MeshRouter(owner,new TestAdapter());int readyPort=FreePort();
        await using var server=new StreamMeshTransport(owner,router.LocalEndpoint,true,readyPort,()=>certificate);
        var noRoom=await Failure(readyPort);
        check(noRoom.Status.Phase=="Ready"&&noRoom.Message.Contains("直连码"),"a ready HTTPS channel with no matching invitation reports a pairing-code problem");
    }
}
