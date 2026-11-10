using System.Diagnostics;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using StreamLink.Core;

namespace ConWU.HttpsPoc;

sealed class ProbeClient:IAsyncDisposable
{
    readonly ClientWebSocket socket;
    readonly MeshLink mesh;
    public double HandshakeMs{get;private set;}
    ProbeClient(ClientWebSocket socket,string token){this.socket=socket;byte[] key=ProbeProtocol.Key(token);mesh=new(1,2,key);CryptographicOperations.ZeroMemory(key);}
    public static async Task<ClientWebSocket> Socket(string url,string pin,string token,CancellationToken cancel)
    {
        var socket=new ClientWebSocket();socket.Options.Proxy=null;socket.Options.HttpVersion=HttpVersion.Version11;
        socket.Options.HttpVersionPolicy=HttpVersionPolicy.RequestVersionExact;socket.Options.RemoteCertificateValidationCallback=ProbeProtocol.Trust(pin);
        socket.Options.AddSubProtocol(ProbeProtocol.Subprotocol);socket.Options.SetRequestHeader("Authorization","Bearer "+token);
        try{await socket.ConnectAsync(ProbeProtocol.Endpoint(url),cancel);return socket;}catch{socket.Dispose();throw;}
    }
    public static async Task<ProbeClient> Connect(string url,string pin,string token,CancellationToken cancel)
    {
        long began=Stopwatch.GetTimestamp();var client=new ProbeClient(await Socket(url,pin,token,cancel),token);
        try{
            await client.socket.SendAsync(client.mesh.Hello(),WebSocketMessageType.Binary,true,cancel);
            while(!client.mesh.Connected){
                var message=await ProbeProtocol.Read(client.socket,cancel)??throw new IOException("Closed during inner authentication");
                var result=client.mesh.Receive(message);if(!result.Authenticated)throw new IOException("Inner authentication rejected");
                if(result.Reply!=null)await client.socket.SendAsync(result.Reply,WebSocketMessageType.Binary,true,cancel);
            }
            client.HandshakeMs=Stopwatch.GetElapsedTime(began).TotalMilliseconds;return client;
        }catch{await client.DisposeAsync();throw;}
    }
    public async Task CheckPacket(int length,bool fragment,CancellationToken cancel)
    {
        byte[] payload=ProbeProtocol.Payload(1,length),message=mesh.Data(payload)??throw new IOException("Session not ready");
        if(fragment){await socket.SendAsync(message.AsMemory(0,17),WebSocketMessageType.Binary,false,cancel);await socket.SendAsync(message.AsMemory(17),WebSocketMessageType.Binary,true,cancel);}
        else await socket.SendAsync(message,WebSocketMessageType.Binary,true,cancel);
        var received=mesh.Receive(await ProbeProtocol.Read(socket,cancel)??throw new IOException("Echo closed"));
        if(!received.Authenticated||received.Packet==null||!received.Packet.SequenceEqual(payload))throw new IOException("Echo did not preserve the entire authenticated datagram");
    }
    public async Task<object> Benchmark(int mbps,int seconds,int packetBytes,CancellationToken cancel)
    {
        if(mbps is <1 or >500||seconds is <1 or >60||packetBytes is <64 or >MeshLink.Mtu)throw new ArgumentException("Probe bounds: 1–500 Mbps, 1–60 seconds, 64–1280 byte payloads");
        const int maximumInflight=8192;
        using var window=new SemaphoreSlim(maximumInflight,maximumInflight);
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(cancel);
        var latencies=new Latencies();long sent=0,received=0,highestInflight=0;var process=Process.GetCurrentProcess();TimeSpan cpu=process.TotalProcessorTime;
        long began=Stopwatch.GetTimestamp(),ended=0,last=0;
        var receive=Task.Run(async()=>{
            try{while(!linked.IsCancellationRequested){
                var frame=await ProbeProtocol.Read(socket,linked.Token)??throw new IOException("Connection closed before all echoes arrived");
                var result=mesh.Receive(frame);
                if(!result.Authenticated||result.Packet==null)throw new IOException("Echo was not an authenticated data packet");
                var value=ProbeProtocol.Inspect(result.Packet);
                if(value.Sequence!=++last||result.Packet.Length!=packetBytes)throw new IOException("An echo was missing, duplicated or changed");
                latencies.Add(Stopwatch.GetElapsedTime(value.Timestamp).TotalMilliseconds);
                Interlocked.Increment(ref received);window.Release();
            }}catch(Exception ex)when(linked.IsCancellationRequested&&ex is OperationCanceledException or WebSocketException){}catch{linked.Cancel();throw;}
        },CancellationToken.None);
        Exception? failure=null;
        try{
            double perSecond=mbps*1_000_000d/8/packetBytes,credit=0;long creditedAt=began;
            using var timer=new PeriodicTimer(TimeSpan.FromMilliseconds(10));
            while(Stopwatch.GetElapsedTime(began).TotalSeconds<seconds&&await timer.WaitForNextTickAsync(linked.Token)){
                // Windows can deliver a requested 10 ms timer every ~15.6 ms.
                // Credit actual elapsed time, with a bounded 50 ms burst rather
                // than reducing the load or catching up an unbounded backlog.
                long now=Stopwatch.GetTimestamp();credit=Math.Min(credit+perSecond*Stopwatch.GetElapsedTime(creditedAt,now).TotalSeconds,perSecond*.05);creditedAt=now;
                int batch=(int)credit;credit-=batch;
                for(int i=0;i<batch;i++){
                    if(Stopwatch.GetElapsedTime(began).TotalSeconds>=seconds)break;
                    while(!await window.WaitAsync(TimeSpan.FromMilliseconds(20),linked.Token))if(Stopwatch.GetElapsedTime(began).TotalSeconds>=seconds)goto SendingFinished;
                    long sequence=Interlocked.Increment(ref sent);highestInflight=Math.Max(highestInflight,sequence-Interlocked.Read(ref received));
                    byte[] payload=ProbeProtocol.Payload(sequence,packetBytes),frame=mesh.Data(payload)??throw new IOException("Inner session expired");
                    await socket.SendAsync(frame,WebSocketMessageType.Binary,true,linked.Token);
                }
            }
            SendingFinished:ended=Stopwatch.GetTimestamp();
            long drain=Stopwatch.GetTimestamp();while(Interlocked.Read(ref received)<Interlocked.Read(ref sent)){
                if(Stopwatch.GetElapsedTime(drain).TotalSeconds>15)throw new TimeoutException("Echo drain exceeded 15 seconds");
                await Task.Delay(5,linked.Token);
            }
        }catch(Exception ex){failure=ex;}
        finally{linked.Cancel();socket.Abort();try{await receive;}catch(Exception ex){failure??=ex;}}
        if(failure!=null)throw new IOException("HTTPS benchmark did not complete",failure);
        double active=Stopwatch.GetElapsedTime(began,ended).TotalSeconds,total=Stopwatch.GetElapsedTime(began).TotalSeconds;
        return new{status="Pass",targetMbps=mbps,durationSeconds=seconds,payloadBytes=packetBytes,sentPackets=sent,receivedPackets=received,
            sentPayloadMbps=sent*packetBytes*8/active/1_000_000d,echoPayloadMbps=received*packetBytes*8/total/1_000_000d,
            targetRateMet=received*packetBytes*8/total/1_000_000d>=mbps*.9,
            activeSeconds=active,elapsedWithDrainSeconds=total,handshakeMs=HandshakeMs,roundTrip=latencies.Report(),maximumInflightPackets=highestInflight,
            maximumAllowedInflightPackets=maximumInflight,processCpuMs=(Process.GetCurrentProcess().TotalProcessorTime-cpu).TotalMilliseconds,
            scope="Synthetic full-size MeshLink payload echo over TCP/TLS/HTTP1.1/WebSocket; round trip includes queueing; no TUN, NAT traversal, Moonlight or congestion-immunity claim"};
    }
    public ValueTask DisposeAsync(){socket.Abort();socket.Dispose();mesh.Dispose();return ValueTask.CompletedTask;}
}
