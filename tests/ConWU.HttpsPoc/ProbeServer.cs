using System.Collections.Concurrent;
using System.Net;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets;
using StreamLink.Core;

namespace ConWU.HttpsPoc;

sealed class ProbeServer:IAsyncDisposable
{
    readonly WebApplication app;
    readonly X509Certificate2 certificate;
    readonly string token;
    readonly CancellationTokenSource stop=new();
    readonly ConcurrentDictionary<Guid,WebSocket> connections=new();
    readonly ConcurrentDictionary<string,int> tls=new();
    long accepted,packets,bytes,rejected;int active;
    ProbeServer(WebApplication app,X509Certificate2 certificate,string token){this.app=app;this.certificate=certificate;this.token=token;}
    public string Pin=>ProbeProtocol.Pin(certificate);
    public string Url=>app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
    public long Accepted=>Interlocked.Read(ref accepted);
    public object Statistics=>new{accepted=Accepted,active=Volatile.Read(ref active),packets=Interlocked.Read(ref packets),payloadBytes=Interlocked.Read(ref bytes),rejected=Interlocked.Read(ref rejected),tlsVersions=tls.Keys.Order().ToArray(),maximumConnections=4,maximumMessageBytes=ProbeProtocol.MaximumMessage,httpVersion="HTTP/1.1 WebSocket Upgrade",compression=false};
    public static async Task<ProbeServer> Start(IPEndPoint endpoint,string token,CancellationToken cancel)
    {
        using var signing=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request=new CertificateRequest("CN=ConWU isolated HTTPS probe",signing,HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature,true));
        var names=new SubjectAlternativeNameBuilder();names.AddDnsName("localhost");names.AddIpAddress(IPAddress.Loopback);names.AddIpAddress(IPAddress.IPv6Loopback);
        if(!endpoint.Address.Equals(IPAddress.Any)&&!endpoint.Address.Equals(IPAddress.IPv6Any))names.AddIpAddress(endpoint.Address);
        request.CertificateExtensions.Add(names.Build());
        using var generated=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddDays(1));
        var cert=X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx),null);
        var builder=WebApplication.CreateSlimBuilder();builder.Logging.ClearProviders();
        builder.Services.Configure<SocketTransportOptions>(options=>options.NoDelay=true);
        builder.WebHost.ConfigureKestrel(options=>{
            options.Limits.MaxRequestBodySize=0;options.Limits.MaxConcurrentConnections=8;
            options.Listen(endpoint,listen=>{listen.Protocols=HttpProtocols.Http1;listen.UseHttps(https=>{https.ServerCertificate=cert;https.SslProtocols=SslProtocols.Tls12|SslProtocols.Tls13;});});
        });
        var app=builder.Build();var server=new ProbeServer(app,cert,token);
        app.UseWebSockets(new(){KeepAliveInterval=TimeSpan.FromSeconds(15)});
        app.MapGet("/health",()=>Results.Json(new{service="ConWU isolated HTTPS probe",protocol=1,relay=false}));
        app.Map(ProbeProtocol.Path,server.Serve);
        try{await app.StartAsync(cancel);return server;}
        catch{await server.DisposeAsync();throw;}
    }
    async Task Serve(HttpContext context)
    {
        string authorization=context.Request.Headers.Authorization.ToString();
        if(!CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(authorization)),SHA256.HashData(Encoding.UTF8.GetBytes("Bearer "+token)))){
            Interlocked.Increment(ref rejected);context.Response.StatusCode=401;return;
        }
        if(!context.WebSockets.IsWebSocketRequest||!context.WebSockets.WebSocketRequestedProtocols.Contains(ProbeProtocol.Subprotocol)){
            context.Response.StatusCode=400;return;
        }
        if(Interlocked.Increment(ref active)>4){Interlocked.Decrement(ref active);context.Response.StatusCode=429;return;}
        Guid id=Guid.NewGuid();WebSocket? socket=null;
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(stop.Token,context.RequestAborted);
        byte[] key=ProbeProtocol.Key(token);using var mesh=new MeshLink(2,1,key);CryptographicOperations.ZeroMemory(key);
        try{
            socket=await context.WebSockets.AcceptWebSocketAsync(new WebSocketAcceptContext{SubProtocol=ProbeProtocol.Subprotocol,DangerousEnableCompression=false});
            connections[id]=socket;Interlocked.Increment(ref accepted);
            string version=context.Features.Get<ITlsHandshakeFeature>()?.Protocol.ToString()??"unknown";tls.TryAdd(version,0);
            while(!linked.IsCancellationRequested){
                byte[]? message=await ProbeProtocol.Read(socket,linked.Token);
                if(message==null){await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure,"",linked.Token);break;}
                var received=mesh.Receive(message);
                if(!received.Authenticated)throw new ProbeProtocolException(WebSocketCloseStatus.PolicyViolation,"Inner datagram authentication failed");
                if(received.Reply!=null)await socket.SendAsync(received.Reply,WebSocketMessageType.Binary,true,linked.Token);
                if(received.Packet!=null){
                    ProbeProtocol.Inspect(received.Packet);Interlocked.Increment(ref packets);Interlocked.Add(ref bytes,received.Packet.Length);
                    byte[] response=mesh.Data(received.Packet)??throw new IOException("Inner authenticated session expired");
                    await socket.SendAsync(response,WebSocketMessageType.Binary,true,linked.Token);
                }
            }
        }catch(ProbeProtocolException ex){
            Interlocked.Increment(ref rejected);
            if(socket?.State==WebSocketState.Open)try{await socket.CloseOutputAsync(ex.Status,ex.Message,linked.Token);}catch(WebSocketException){}
        }catch(Exception ex)when(ex is OperationCanceledException or WebSocketException or IOException){ }
        finally{connections.TryRemove(id,out _);socket?.Dispose();Interlocked.Decrement(ref active);}
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel();foreach(var socket in connections.Values)socket.Abort();
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try{await app.StopAsync(timeout.Token);}finally{await app.DisposeAsync();certificate.Dispose();stop.Dispose();}
    }
}
