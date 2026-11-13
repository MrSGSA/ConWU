using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using StreamLink.Core;

// The authenticated controller supplies ephemeral keys through stdin, never
// command-line arguments or ready/results output. No production profile is read.
static class StreamBench
{
    sealed record Configuration(string Mode,string Key,int Port=48443,string Endpoint="",string Pin="",int Mbps=50,int Seconds=8,bool Firewall=false,int LifetimeSeconds=240,bool Autonomous=false,int MaxInFlight=512,bool BatchDatagrams=true,int SourcePort=44691,bool GatewayHelper=false);
    public static async Task Run(string[] args)
    {
        var line=await Console.In.ReadLineAsync()??throw new IOException("Private test input missing");
        var configuration=JsonSerializer.Deserialize<Configuration>(line)??throw new IOException("Private test input invalid");
        if(!TransportModes.Stream(configuration.Mode)||configuration.LifetimeSeconds is <10 or >600||configuration.Seconds is <1 or >60||configuration.Mbps is <1 or >500||configuration.MaxInFlight is <32 or >8192)throw new IOException("Test bounds invalid");
        byte[] key=Convert.FromBase64String(configuration.Key);if(key.Length!=32)throw new IOException("Test key invalid");
        try{if(args[0]=="serve")await Serve(configuration,key);else await Bench(configuration,key);}
        catch(Exception error)when(args[0]=="bench"&&error is IOException or SocketException or OperationCanceledException){
            Console.WriteLine("CONWU_BENCH_RESULT "+JsonSerializer.Serialize(new{status="Fail",mode=configuration.Mode,targetMbps=configuration.Mbps,targetAchieved=false,phase="connect-or-setup",error=error.GetType().Name,scope="No successful data-plane measurement"}));Environment.ExitCode=1;
        }
        finally{CryptographicOperations.ZeroMemory(key);}
    }
    static async Task Serve(Configuration c,byte[] key)
    {
        using var signing=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate=StreamCertificates.CreateServer(signing,DateTimeOffset.UtcNow.AddDays(1));
        var mesh=MeshIdentity.Create("","",c.Mode,direct:true);
        using var udp=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));udp.Client.ReceiveBufferSize=udp.Client.SendBufferSize=4<<20;
        await using var transport=new StreamMeshTransport(mesh,(IPEndPoint)udp.Client.LocalEndPoint!,true,c.Port,()=>certificate,allowListener:c.Firewall?()=>OperatingSystem.IsWindows()?WindowsHost.AllowStreamListener(c.Port):LinuxFirewall.AllowStreamListener(c.Port):null,batchDatagrams:c.BatchDatagrams);
        using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(c.LifetimeSeconds));
        await using var mapping=c.Autonomous?(c.GatewayHelper
            ?await GatewayMapping.CreateTcp(c.SourcePort,c.Port,Console.Error.WriteLine,stop.Token,owner:Guid.NewGuid().ToString("N"))
            :await StreamMapping.Create(c.Port,Console.Error.WriteLine,stop.Token,sourcePort:c.SourcePort,owner:Guid.NewGuid().ToString("N"))):null;
        var mappingWork=mapping?.Maintain(stop.Token);
        var input=Task.Run(async()=>{try{if(await Console.In.ReadLineAsync().WaitAsync(stop.Token)=="stop")stop.Cancel();}catch(OperationCanceledException){}});
        Console.WriteLine("CONWU_READY "+JsonSerializer.Serialize(new{mode=c.Mode,port=c.Port,pin=c.Mode=="https"?StreamMeshTransport.CertificatePin(certificate):"",process=Environment.ProcessId,endpoint=mapping?.PublicEndpoint.ToString()??"",mapping=mapping?.GetType().Name??"none",helper=mapping is TcpMapping tcp?tcp.HelperResource.Local:""}));
        await Console.Out.FlushAsync();
        var peers=new Dictionary<IPEndPoint,MeshLink>();long packets=0,bytes=0,rejected=0;var cpu=Process.GetCurrentProcess().TotalProcessorTime;
        try{while(!stop.IsCancellationRequested){
            var datagram=await udp.ReceiveAsync(stop.Token);
            if(!peers.TryGetValue(datagram.RemoteEndPoint,out var link)){
                if(peers.Count>=32){var first=peers.Keys.First();peers[first].Dispose();peers.Remove(first);}
                peers[datagram.RemoteEndPoint]=link=new MeshLink(1,2,key);
            }
            var result=link.Receive(datagram.Buffer);
            if(result.Reply!=null)await udp.SendAsync(result.Reply,datagram.RemoteEndPoint,stop.Token);
            if(result.Packet!=null){packets++;bytes+=result.Packet.Length;var echo=link.Data(result.Packet);if(echo!=null)await udp.SendAsync(echo,datagram.RemoteEndPoint,stop.Token);}
            else if(!result.Authenticated)rejected++;
        }}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        finally{stop.Cancel();foreach(var link in peers.Values)link.Dispose();if(mappingWork!=null)try{await mappingWork;}catch(Exception e)when(e is OperationCanceledException or IOException or SocketException){}}
        Console.WriteLine("CONWU_SERVER_RESULT "+JsonSerializer.Serialize(new{mode=c.Mode,packets,bytes,rejected,cpuMs=(Process.GetCurrentProcess().TotalProcessorTime-cpu).TotalMilliseconds,workingSet=Process.GetCurrentProcess().WorkingSet64,scope="Production stream transport and authenticated MeshLink; no TUN or Moonlight"}));
    }
    static async Task Bench(Configuration c,byte[] key)
    {
        if(!IPEndPoint.TryParse(c.Endpoint,out var endpoint))throw new IOException("Benchmark endpoint invalid");
        var mesh=MeshIdentity.Create("","",c.Mode,direct:true);mesh.Pair=mesh.Pair with{TransportKeyPin=c.Pin.Length>0?c.Pin:null};
        using var udp=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));udp.Client.ReceiveBufferSize=udp.Client.SendBufferSize=4<<20;
        await using var transport=new StreamMeshTransport(mesh,endpoint,false,0,batchDatagrams:c.BatchDatagrams);
        using var link=new MeshLink(2,1,key);using var handshake=new CancellationTokenSource(10000);
        var target=transport.ClientEndpoint!;long connectAt=Stopwatch.GetTimestamp();
        await udp.SendAsync(link.Hello(),target,handshake.Token);
        while(!link.Connected){var frame=await udp.ReceiveAsync(handshake.Token);var result=link.Receive(frame.Buffer);if(result.Reply!=null)await udp.SendAsync(result.Reply,target,handshake.Token);}
        double handshakeMs=Stopwatch.GetElapsedTime(connectAt).TotalMilliseconds;
        using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(c.Seconds+15));
        // Bound the echo's outstanding workload below the local datagram
        // bridge capacity. A slow carrier applies backpressure to this test;
        // missing the requested bitrate remains visible in targetAchieved.
        int inFlightLimit=c.MaxInFlight;
        using var window=new SemaphoreSlim(inFlightLimit,inFlightLimit);var latency=new List<double>();
        long sent=0,received=0,last=0,lastReceivedAt=0;Exception? failure=null;var cryptoGate=new object();
        var cpu=Process.GetCurrentProcess().TotalProcessorTime;long allocatedAt=GC.GetTotalAllocatedBytes(true);long began=Stopwatch.GetTimestamp(),ended=0;
        var reading=Task.Run(async()=>{
            try{while(!stop.IsCancellationRequested){
                var frame=await udp.ReceiveAsync(stop.Token);MeshReceive result;lock(cryptoGate)result=link.Receive(frame.Buffer);
                if(result.Reply!=null)await udp.SendAsync(result.Reply,target,stop.Token);
                if(result.Packet is not {} payload)continue;
                long sequence=BinaryPrimitives.ReadInt64LittleEndian(payload),stamp=BinaryPrimitives.ReadInt64LittleEndian(payload.AsSpan(8));
                if(sequence!=++last||payload.Length!=1280||payload[^1]!=73)throw new IOException("Echo loss, reordering or changed data");
                latency.Add(Stopwatch.GetElapsedTime(stamp).TotalMilliseconds);Interlocked.Exchange(ref lastReceivedAt,Stopwatch.GetTimestamp());Interlocked.Increment(ref received);window.Release();
            }}catch(Exception ex)when(stop.IsCancellationRequested&&ex is OperationCanceledException or ObjectDisposedException){}
            catch(Exception ex){failure=ex;stop.Cancel();}
        });
        try{
            double perSecond=c.Mbps*1_000_000d/8/1280,credit=0;long creditedAt=began;
            using var timer=new PeriodicTimer(TimeSpan.FromMilliseconds(10));
            while(Stopwatch.GetElapsedTime(began).TotalSeconds<c.Seconds&&await timer.WaitForNextTickAsync(stop.Token)){
                long now=Stopwatch.GetTimestamp();credit=Math.Min(credit+perSecond*Stopwatch.GetElapsedTime(creditedAt,now).TotalSeconds,perSecond*.05);creditedAt=now;
                int batch=(int)credit;credit-=batch;
                for(int index=0;index<batch;index++){
                    if(Stopwatch.GetElapsedTime(began).TotalSeconds>=c.Seconds)break;
                    while(!await window.WaitAsync(TimeSpan.FromMilliseconds(20),stop.Token))if(Stopwatch.GetElapsedTime(began).TotalSeconds>=c.Seconds)goto Sent;
                    byte[] payload=new byte[1280];BinaryPrimitives.WriteInt64LittleEndian(payload,Interlocked.Increment(ref sent));BinaryPrimitives.WriteInt64LittleEndian(payload.AsSpan(8),Stopwatch.GetTimestamp());payload[^1]=73;
                    byte[] encoded;lock(cryptoGate)encoded=link.Data(payload)??throw new IOException("Authenticated session unavailable");
                    await udp.SendAsync(encoded,target,stop.Token);
                }
            }
            Sent:ended=Stopwatch.GetTimestamp();long drain=Stopwatch.GetTimestamp();
            while(Interlocked.Read(ref received)<Interlocked.Read(ref sent)&&Stopwatch.GetElapsedTime(drain).TotalSeconds<6){stop.Token.ThrowIfCancellationRequested();await Task.Delay(10,stop.Token);}
        }catch(Exception ex)when(ex is IOException or OperationCanceledException){failure??=ex;}
        finally{if(ended==0)ended=Stopwatch.GetTimestamp();stop.Cancel();await reading;}
        latency.Sort();double Percentile(double fraction)=>latency.Count==0?0:latency[(int)Math.Min(latency.Count-1,Math.Ceiling(latency.Count*fraction)-1)];
        double seconds=Stopwatch.GetElapsedTime(began,ended).TotalSeconds;
        double deliverySeconds=Stopwatch.GetElapsedTime(began,Math.Max(ended,lastReceivedAt)).TotalSeconds;
        double deliveryMbps=received*1280*8/deliverySeconds/1_000_000;
        var resultValue=new{status=failure==null&&sent>0&&sent==received?"Pass":"Fail",mode=c.Mode,targetMbps=c.Mbps,targetAchieved=deliveryMbps>=c.Mbps*.95,handshakeMs,inFlightLimit,sent,received,seconds,deliverySeconds,drainSeconds=Math.Max(0,deliverySeconds-seconds),sendingMbps=sent*1280*8/seconds/1_000_000,payloadMbps=deliveryMbps,p95Ms=Percentile(.95),p99Ms=Percentile(.99),cpuMs=(Process.GetCurrentProcess().TotalProcessorTime-cpu).TotalMilliseconds,allocatedBytes=GC.GetTotalAllocatedBytes(true)-allocatedAt,workingSet=Process.GetCurrentProcess().WorkingSet64,tls=transport.TlsProtocol,batching=transport.BatchingEnabled,io=transport.Io,error=failure?.GetType().Name??"",scope="Production transport plus encrypted MeshLink echo; no TUN, Moonlight or WAN claim"};
        Console.WriteLine("CONWU_BENCH_RESULT "+JsonSerializer.Serialize(resultValue));if(resultValue.status!="Pass")Environment.ExitCode=1;
    }
}
