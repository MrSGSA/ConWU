using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.IO.Pipes;
using System.Text.Json;
using StreamLink.Core;

int rounds=1;
if(args is ["--native",_,"--output",_,"--rounds",var count])rounds=int.Parse(count);
if(args.Length is not (4 or 6)||args[0]!="--native"||args[2]!="--output"||rounds is <1 or >30)throw new ArgumentException("--native cpp-test --output result.json [--rounds 30]");
string binary=args[1],output=args[3];
binary=Path.GetFullPath(binary);output=Path.GetFullPath(output);Directory.CreateDirectory(Path.GetDirectoryName(output)!);
// Keep a stable executable path across rounds; only credentials/session files
// get a private per-round directory. Random executable paths repeatedly trigger
// Windows application firewall prompts and leave unrelated deny-rule copies.
var info = new ProcessStartInfo(binary) { UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true };
info.ArgumentList.Add("--native-info");
using(var query=Process.Start(info)??throw new IOException("Native capability query could not start")) {
    var text=query.StandardOutput.ReadToEndAsync();var errors=query.StandardError.ReadToEndAsync();
    if(!query.WaitForExit(3000)){query.Kill();throw new IOException("Native capability query timed out");}
    using var capabilities=JsonDocument.Parse(text.GetAwaiter().GetResult());errors.GetAwaiter().GetResult();
    if(query.ExitCode!=0||capabilities.RootElement.GetProperty("backend").GetString()!="loopback-test-only")
        throw new ArgumentException("This local regression requires the separate loopback test backend");
}
string components=Path.Combine(Path.GetDirectoryName(output)!,"legacy-control-components");Directory.CreateDirectory(components);
File.Copy(binary,Path.Combine(components,"udp2raw-native.exe"),true);
int checks=0;var rows=new List<object>();
void Check(bool pass,string why){if(!pass)throw new IOException(why);checks++;Console.WriteLine("PASS "+why);}
using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(Math.Max(240,120+rounds*30)));var token=deadline.Token;
try {
    rows.Add(await Budget());
    rows.Add(await RouteEvidence());
    rows.Add(await RouteLatencyTests.Run(Check,token));
    rows.Add(await RouteLatencyTests.Bounds(Check,token));
    rows.Add(await Authorization());
    rows.Add(await NativeWrongAuthorization());
    rows.Add(await NativeControlFailureTests.Run(binary,Path.GetDirectoryName(output)!,Check,token));
    rows.Add(await Pair("faketcp",slowRoute:true));
    for(int i=0;i<rounds;i++){rows.Add(await Pair("faketcp"));rows.Add(await Pair("udp"));}
    for(int i=0;i<rounds;i++){rows.Add(await Pair("faketcp",10));rows.Add(await Pair("faketcp",0));}
    await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{status="Pass",checks,rounds,rows,
        scope="real C++ legacy protocol/HTTP, authenticated Windows named pipes, shared controls and full MeshRouter IP; raw carriage and IP adapter are loopback fixtures, no physical WinDivert/Wintun/NAT"},new JsonSerializerOptions{WriteIndented=true}));
}catch(Exception ex){await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{status="Fail",checks,rows,error=ex.ToString()},new JsonSerializerOptions{WriteIndented=true}));throw;}

async Task<object> Budget()
{
    var resources=new TraversalResources();var governor=new LegacyControlGovernor(resources);var events=new ConcurrentQueue<long>();
    var owners=Enumerable.Range(0,8).Select(_=>Guid.NewGuid()).ToArray();var shares=new int[8];
    var clock=Stopwatch.StartNew();
    await Task.WhenAll(owners.Select(async(id,slot)=>{
        for(int i=0;i<20;i++){
            var req=new LegacyControlRequest((ulong)i+1,1,i%4==0?NativeWireKind.Maintenance:NativeWireKind.Handshake,128,
                IPAddress.Loopback,(ushort)(41000+slot),IPAddress.Loopback,43000,6,2,false,Environment.TickCount64);
            if(await governor.Admit(id,req,token)==0){events.Enqueue(Stopwatch.GetTimestamp());Interlocked.Increment(ref shares[slot]);}
        }
    }));
    var stats=governor.Snapshot();var usage=resources.Usage();
    Check(stats.AdmittedPackets<=8+60*clock.Elapsed.TotalSeconds&&stats.AdmittedBytes==stats.AdmittedPackets*128&&
        stats.AdmittedPackets==usage.SearchAdmitted+usage.MaintenanceAdmitted,"eight concurrent compatibility owners share one packet and outer-byte budget");
    Check(shares.Min()>0&&shares.Max()-shares.Min()<=3&&stats.Pending==0,"old waiters receive a fair turn without a per-peer copy of the device allowance; shares="+string.Join(',',shares));
    var stale=new LegacyControlRequest(1,1,NativeWireKind.Handshake,40,IPAddress.Loopback,50000,IPAddress.Loopback,43000,6,2,false,Environment.TickCount64-500);
    Check(await governor.Admit(Guid.NewGuid(),stale,token)==3,"expired queued packet consumes no fresh control permit");
    foreach(var id in owners)governor.Retire(id);
    Check(governor.Snapshot().TupleRecords==0,"retiring resources releases their tuple/window records");
    return new{elapsedMs=clock.Elapsed.TotalMilliseconds,shares,stats,usage,scope="eight logical owners, actual shared controller/timers; no claim of eight real devices"};
}
async Task<object> RouteEvidence()
{
    var generation=Guid.NewGuid();var source=new IPEndPoint(IPAddress.Parse("10.0.0.2"),40001);var target=new IPEndPoint(IPAddress.Parse("198.51.100.1"),443);
    using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
    var routes=new LegacyRouteEvidence(generation,true,(s,t,g,e)=>{if(e==1){entered.Set();release.Wait(token);}return new(g,e,s.ToString(),t.ToString(),7,3,"10.0.0.1","ControlledFixture","Fixture","");});
    var old=Task.Run(()=>routes.Prepare(1,source,target,out _));Check(entered.Wait(2000),"old route lookup actually waits before an epoch change");
    Check(routes.Prepare(2,source,target,out var witness),"new epoch synchronously prepares exact source/target before a permit");release.Set();
    Check(!await old&&routes.Snapshot().CaptureEpoch==2,"late old-generation route result cannot authorize or overwrite the new state");
    Check(!routes.Use(1,source,target,out _)&&routes.Use(2,source,target,out _),"business requires a prepared current-generation tuple");
    var second=new IPEndPoint(IPAddress.Parse("10.0.0.3"),40002);routes.Prepare(2,second,target,out var other);
    Check(witness!.PacingKey==other!.PacingKey,"multiple source addresses on the same LUID share one outlet identity");
    var unknown=new LegacyRouteEvidence(Guid.NewGuid(),true,(s,t,g,e)=>new(g,e,s.ToString(),t.ToString(),0,0,"Unknown","Unknown","Unavailable","NoRoute"));
    Check(!unknown.Prepare(1,source,target,out var rejected)&&rejected!.PacingKey=="Unresolved","unknown route remains conservative and cannot claim preparation");
    var actualTarget=new IPEndPoint(IPAddress.Parse("1.1.1.1"),443);var actualSource=new IPEndPoint(Stun.LocalAddress(actualTarget),40001);
    var actual=EgressRouteSnapshot.Bound(actualSource,actualTarget,Guid.NewGuid(),1);
    return new{controlledEpochChecks="Pass",actualReadOnlyOsRoute=actual,scope="deterministic route observer concurrency plus real Windows route lookup; no packet sent, no physical egress capture"};
}

async Task<object> Authorization()
{
    var governor=new LegacyControlGovernor(new TraversalResources());
    foreach(bool wrongPid in new[]{true,false}){
        using var channel=new LegacyControlChannel(Guid.NewGuid(),true,0,governor);
        channel.Start(wrongPid?Environment.ProcessId+1:Environment.ProcessId);
        using var peer=new NamedPipeClientStream(".",channel.Name,PipeDirection.InOut,PipeOptions.Asynchronous);
        await peer.ConnectAsync(token);
        if(!wrongPid)await peer.WriteAsync(new byte[64],token);
        for(int i=0;!channel.Failed&&i<100;i++)await Task.Delay(10,token);
        Check(channel.Failed&&!channel.Authorized&&governor.Snapshot().Requests==0,
            wrongPid?"unauthorized pipe process obtains zero control permits":"wrong attachment secret obtains zero control permits");
    }
    var frame=new byte[56];BinaryPrimitives.WriteUInt64LittleEndian(frame,1);BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(8),1);
    frame[16]=2;frame[17]=6;bool rejected=false;
    try{LegacyControlRequest.Decode(frame,6,0);}catch(IOException){rejected=true;}
    Check(rejected,"business labels cannot masquerade as scheduled metadata requests");
    var controlled=new LegacyControlChannel(Guid.NewGuid(),true,0,governor);controlled.Start(Environment.ProcessId);
    using(var peer=new NamedPipeClientStream(".",controlled.Name,PipeDirection.InOut,PipeOptions.Asynchronous)){
        await peer.ConnectAsync(token);byte[] secret=Convert.FromHexString(controlled.Authorization);await peer.WriteAsync(secret,token);var echoed=new byte[64];await peer.ReadExactlyAsync(echoed,token);
        Check(echoed.SequenceEqual(secret)&&controlled.Authorized,"correct local process and attachment secret authorize the control channel");
        controlled.Dispose();bool closed=false;try{closed=await peer.ReadAsync(new byte[1],token)==0;}catch(IOException){closed=true;}
        Check(closed,"parent stop cancels the control channel instead of leaving an unbounded read or permit stream");
    }
    controlled.Dispose();return new{authorizedAndRejected=true,scope="actual Windows named-pipe credentials/PID/EOF; no simulated authorization result"};
}

async Task<object> NativeWrongAuthorization()
{
    using var raw=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
    using var local=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);local.Bind(new IPEndPoint(IPAddress.Loopback,0));int port=((IPEndPoint)local.LocalEndPoint!).Port;local.Dispose();
    using var carrier=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));int io=((IPEndPoint)carrier.Client.LocalEndPoint!).Port;carrier.Dispose();
    var governor=new LegacyControlGovernor(new TraversalResources());using var channel=new LegacyControlChannel(Guid.NewGuid(),true,port,governor);
    using var job=new ChildJob();string wrong=new('0',128);if(wrong==channel.Authorization)wrong=new('1',128);
    var env=new Dictionary<string,string>{["STREAMLINK_LEGACY_CONTROL"]=channel.Name,["STREAMLINK_LEGACY_AUTH"]=wrong,
        ["STREAMLINK_LEGACY_PARENT"]=Environment.ProcessId.ToString(),["STREAMLINK_TEST_BIND"]=io.ToString(),["STREAMLINK_TEST_PEER"]=((IPEndPoint)raw.Client.LocalEndPoint!).Port.ToString()};
    var child=job.Start(binary,["-s","-l","127.0.0.1:"+port,"-r","127.0.0.1:9","-k","fixture-control","--raw-mode","faketcp","--fake-http","test.ustc.edu.cn","--log-level","0"],null,env,[wrong]);
    channel.Start(child.Id);await child.WaitForExitAsync(token).WaitAsync(TimeSpan.FromSeconds(7),token);
    Check(child.ExitCode!=0&&channel.Failed&&governor.Snapshot().Requests==0&&raw.Available==0,
        "actual C++ rejects a bad parent attachment before opening raw capture or sending a SYN");
    return new{nativeExitCode=child.ExitCode,rawPackets=0,permitRequests=governor.Snapshot().Requests,scope="actual authorized-worker PID with wrong secret, C++ loopback backend; not a simulated authentication assertion"};
}

async Task<object> Pair(string mode,int? rate=null,bool slowRoute=false)
{
    string folder=Path.Combine(Path.GetTempPath(),"streamlink-legacy-control-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
    var owner=MeshIdentity.Create("https://example.com/","",mode);var guest=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));guest.Directory=owner.Directory;
    var adapters=new[]{new Adapter(),new Adapter()};await using var a=new MeshRouter(owner,adapters[0]);await using var b=new MeshRouter(guest,adapters[1]);
    int rawPort=NativeTestPorts.Take();
    using var serverCarrier=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));int serverIo=((IPEndPoint)serverCarrier.Client.LocalEndPoint!).Port;serverCarrier.Dispose();
    using var clientCarrier=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));int clientIo=((IPEndPoint)clientCarrier.Client.LocalEndPoint!).Port;clientCarrier.Dispose();
    await using var proxy=new Proxy(rawPort,new(IPAddress.Loopback,serverIo));
    using var serverPacer=rate.HasValue?new EgressPacer(rate.Value):null;
    using var clientPacer=rate.HasValue?new EgressPacer(rate.Value):null;
    Dictionary<string,string> EnvironmentFor(int port)=>new(){["STREAMLINK_TEST_BIND"]=port.ToString(),["STREAMLINK_TEST_PEER"]=proxy.Port.ToString()};
    var before=LegacyControlGovernor.Shared.Snapshot();var clock=Stopwatch.StartNew();
    MeshTransport? server=null,client=null;
    object? pressureReport=null;
    EgressRouteWitness SlowRoute(IPEndPoint s,IPEndPoint t,Guid g,ulong e){Thread.Sleep(1300);return new(g,e,s.ToString(),t.ToString(),0,0,"LoopbackFixture","LoopbackFixture","LoopbackFixture","");}
    try {
        server=new(components,folder,owner,a.LocalEndpoint,true,rawPort,null,"debug",EnvironmentFor(serverIo),pacer:serverPacer,testInject:proxy.Inject,routeObserver:slowRoute?SlowRoute:null);
        bool reserved = false;
        client=new(components,folder,guest,new(IPAddress.Loopback,rawPort),false,rawPort,null,"debug",EnvironmentFor(clientIo),
            endpoint => { b.CancelLegacyCandidate(1, endpoint); reserved = true; },clientPacer,proxy.Inject,slowRoute?SlowRoute:null);
        Check(reserved && !b.Status().Single().Connected, mode+": actual native constructor reserves its loopback source before candidate activation");
        a.SetLegacyListenerControl(server.ControlsWirePackets);
        b.SetCandidate(1,client.ClientEndpoint,"fixture","controlled native",client.ControlsWirePackets);
        while(!a.Status().Single().Connected||!b.Status().Single().Connected){if(clock.ElapsedMilliseconds>10000||server.Exited||client.Exited){await CaptureStacks(folder);throw new IOException(mode+" real controlled native pair did not authenticate; server="+server.ControlFailure+" client="+client.ControlFailure+" proxyPackets="+proxy.Packets+" logFolder="+folder);}await Task.Delay(20,token);}
        double authenticatedMs=clock.Elapsed.TotalMilliseconds;
        Check(server.ControlsWirePackets&&client.ControlsWirePackets,mode+": real MeshTransport opted into parent-owned control before its native SYN");
        byte[] packet=new byte[1280];packet[0]=0x45;packet[8]=64;packet[9]=17;BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2),1280);
        IPAddress.Parse(owner.LocalIp).GetAddressBytes().CopyTo(packet,12);IPAddress.Parse(guest.LocalIp).GetAddressBytes().CopyTo(packet,16);
        Checksum(packet);Check(MeshPackets.Valid(packet),mode+": fixture creates a valid full IPv4 datagram before testing transport");
        adapters[0].Outgoing.Add(packet);
        byte[] received;
        try{received=await adapters[1].Incoming.Reader.ReadAsync(token).AsTask().WaitAsync(TimeSpan.FromSeconds(3),token);}catch(Exception ex){throw new IOException("first business failed: server="+server.ControlFailure+" client="+client.ControlFailure+" resources="+JsonSerializer.Serialize(LegacyTransportLedger.Shared.Snapshot().Resources.Select(r=>new{r.Route,r.BusinessEgress})),ex);}
        Check(received.SequenceEqual(packet),mode+": authenticated real legacy C++ carries full 1280-byte inner IP through MeshRouter");
        IPAddress.Parse(guest.LocalIp).GetAddressBytes().CopyTo(packet,12);IPAddress.Parse(owner.LocalIp).GetAddressBytes().CopyTo(packet,16);
        Checksum(packet);adapters[1].Outgoing.Add(packet);received=await adapters[0].Incoming.Reader.ReadAsync(token).AsTask().WaitAsync(TimeSpan.FromSeconds(3),token);
        Check(received.SequenceEqual(packet),mode+": reverse business packet remains a datagram with no control round-trip wait");
        if(slowRoute)pressureReport=await ControlledPressureTests.Run(a,b,adapters,owner,guest,server,client,Check,token,Path.ChangeExtension(output,"pressure.json"),proxy.Snapshot);
        await Task.Delay(1200,token);var after=LegacyControlGovernor.Shared.Snapshot();
        Check(after.AdmittedPackets>before.AdmittedPackets&&!server.Exited&&!client.Exited,mode+": controls were actually admitted while both protocol workers stayed live");
        // Receiving UDP on a scheduled managed continuation can drain two
        // buffered packets back-to-back. Keep that observation, but measure
        // the actual native injection boundary for the unchanged 32ms gate.
        string ReadLiveLog(string file){using var stream=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite);using var reader=new StreamReader(stream);return reader.ReadToEnd();}
        var nativeHttpGaps=Directory.GetFiles(folder,"*.log").SelectMany(file=>System.Text.RegularExpressions.Regex.Matches(ReadLiveLog(file),@"\[legacy-http-spacing\] elapsed_us=(\d+)").Select(m=>long.Parse(m.Groups[1].Value))).ToArray();
        if(mode=="faketcp")Check(nativeHttpGaps.Length>=2&&nativeHttpGaps.All(us=>us>=32000),"actual native HTTP GET/bare injection gap >=32ms; nativeUs="+string.Join(',',nativeHttpGaps)+" receiveMs="+string.Join(',',proxy.HttpGaps));
        if(mode=="faketcp"){
            using var pressure=new CancellationTokenSource();
            var filling=Task.Run(async()=>{while(!pressure.IsCancellationRequested){TraversalResources.Shared.TrySend(64,true);TraversalResources.Shared.TrySend(64);await Task.Delay(1,pressure.Token);}});
            try{
                long start=Environment.TickCount64;while(LegacyControlGovernor.Shared.Snapshot().Pending==0&&Environment.TickCount64-start<3000)await Task.Delay(1,token);
                Check(LegacyControlGovernor.Shared.Snapshot().Pending>0,"test creates an actual native control request waiting on the exhausted shared budget");
                IPAddress.Parse(owner.LocalIp).GetAddressBytes().CopyTo(packet,12);IPAddress.Parse(guest.LocalIp).GetAddressBytes().CopyTo(packet,16);Checksum(packet);
                adapters[0].Outgoing.Add(packet);received=await adapters[1].Incoming.Reader.ReadAsync(token).AsTask().WaitAsync(TimeSpan.FromSeconds(1),token);
                Check(received.SequenceEqual(packet)&&!server.Exited&&!client.Exited,"business traverses real native I/O while a control request is pending; no cross-datagram ordering wait");
            }finally{pressure.Cancel();try{await filling;}catch(OperationCanceledException){}}
        }
        var queueReports=LegacyTransportLedger.Shared.Snapshot().Resources.Where(r=>r.ProcessId>0&&!r.RetirementRequested).Select(r=>r.ControlQueue).Where(r=>r!=null).ToArray();
        Check(queueReports.Length>=2&&queueReports.All(r=>r!.PipeFailures==0),mode+": actual C++ queue snapshots reach the parent ledger independently of injection counters");
        var paced=LegacyTransportLedger.Shared.Snapshot().Resources.Where(r=>!r.RetirementRequested&&r.BusinessEgress!=null).Select(r=>r.BusinessEgress!).ToArray();
        if(rate.HasValue)Check(paced.Length==2&&paced.All(s=>s.InjectedPackets>0&&s.InjectedBytes>1280&&s.Failure.Length==0)&&serverPacer!.Snapshot().SentBytes==paced[0].InjectedBytes&&clientPacer!.Snapshot().SentBytes==paced[1].InjectedBytes,"actual native compatibility business uses shared outer-byte pacer and successful parent injection receipts, rate="+rate);
        if(rate.HasValue){var native=LegacyTransportLedger.Shared.Snapshot().Resources.Where(r=>!r.RetirementRequested).Select(r=>r.BusinessHandoff).Where(r=>r!=null).ToArray();Check(native.Length==2&&native.All(n=>n!.Injected>0&&n.PeakOutstanding<=64&&n.Faults==0),"bounded native handoff telemetry and actual parent receipts reach the production ledger");}
        return new{mode,rate,slowRoute,pressureReport,authenticatedMs,elapsedMs=clock.Elapsed.TotalMilliseconds,before,after,queueReports,paced,serverPacer=serverPacer?.Snapshot(),clientPacer=clientPacer?.Snapshot(),rawPackets=proxy.Packets,httpGapMs=proxy.HttpGaps.ToArray(),nativeHttpGapUs=nativeHttpGaps,
            scope="actual named pipes/C++/HTTP/MeshRouter and real UDP raw-IP carrier; memory IP adapter, no physical NAT or Windows driver"};
    }finally{client?.Dispose();server?.Dispose();}
}
async Task CaptureStacks(string folder)
{
    // Test-owned children only; omit frame arguments so keys/payloads never enter
    // the evidence. Diagnostic time is outside the unchanged connection gate.
    string debugger="C:/Program Files/mingw64/bin/gdb.exe";if(!File.Exists(debugger))return;
    foreach(var resource in LegacyTransportLedger.Shared.Snapshot().Resources.Where(r=>!r.RetirementRequested&&r.ProcessId>0)){
        try{
            var start=new ProcessStartInfo(debugger){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(var word in new[]{"--batch","-p",resource.ProcessId.ToString(),"-ex","set print frame-arguments none","-ex","thread apply all bt 12","-ex","detach"})start.ArgumentList.Add(word);
            using var process=Process.Start(start)!;var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
            using var timeout=new CancellationTokenSource(10000);try{await process.WaitForExitAsync(timeout.Token);}catch(OperationCanceledException){process.Kill();await process.WaitForExitAsync();}
            await File.WriteAllTextAsync(Path.Combine(folder,"stack-"+resource.ProcessId+".txt"),(await stdout)+(await stderr));
        }catch(Exception){ }
    }
}

void Checksum(byte[] packet){packet[10]=packet[11]=0;uint sum=0;for(int i=0;i<20;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(i));while(sum>65535)sum=(sum&65535)+(sum>>16);BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10),(ushort)~sum);}

sealed class Adapter:IPacketAdapter
{
    public readonly BlockingCollection<byte[]> Outgoing=[];
    public readonly System.Threading.Channels.Channel<byte[]> Incoming=System.Threading.Channels.Channel.CreateUnbounded<byte[]>();
    public int Read(byte[] packet){if(!Outgoing.TryTake(out var data,20))return 0;data.CopyTo(packet,0);return data.Length;}
    public bool Write(byte[] packet)=>Incoming.Writer.TryWrite(packet.ToArray());
    public void Dispose()=>Incoming.Writer.TryComplete();
}
sealed class Proxy:IAsyncDisposable
{
    readonly UdpClient socket=new(new IPEndPoint(IPAddress.Loopback,0));readonly CancellationTokenSource stop=new();readonly Task running;
    readonly ConcurrentDictionary<ushort,IPEndPoint> targets=[];readonly Dictionary<string,long> http=[];
    public readonly ConcurrentBag<double> HttpGaps=[];public long Packets;
    public int Port=>((IPEndPoint)socket.Client.LocalEndPoint!).Port;
    public object Snapshot()=>new{Packets,receiveBufferBytes=socket.Client.ReceiveBufferSize,sendBufferBytes=socket.Client.SendBufferSize};
    public Proxy(int serverPort,IPEndPoint server){
        // This extra loopback hop is a test carrier, not a product queue. Its
        // default 64KiB buffer drops the combined bidirectional burst before
        // either native receiver; match the product bridge's 1MiB buffer.
        socket.Client.SendBufferSize=socket.Client.ReceiveBufferSize=1<<20;
        socket.Client.IOControl((IOControlCode)unchecked((int)0x9800000C),new byte[]{0,0,0,0},null);targets[(ushort)serverPort]=server;running=Run();
    }
    public bool Inject(ReadOnlyMemory<byte> packet){int h=(packet.Span[0]&15)*4;ushort port=BinaryPrimitives.ReadUInt16BigEndian(packet.Span.Slice(h+2));return targets.TryGetValue(port,out var target)&&socket.Send(packet.Span,target)==packet.Length;}
    async Task Run(){try{while(true){var received=await socket.ReceiveAsync(stop.Token);var p=received.Buffer;if(p.Length<28)continue;
        int ip=(p[0]&15)*4;if(p.Length<ip+8)continue;ushort source=BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(ip)),target=BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(ip+2));
        targets[source]=received.RemoteEndPoint;Interlocked.Increment(ref Packets);
        int headers=ip+(p[9]==6?(p[ip+12]>>4)*4:8);string tuple=source+"/"+target;
        if(p.Length>=headers+4&&p.AsSpan(headers,4).SequenceEqual("GET "u8))http[tuple]=Stopwatch.GetTimestamp();
        else if(http.Remove(tuple,out long sent))HttpGaps.Add(Stopwatch.GetElapsedTime(sent).TotalMilliseconds);
        if(targets.TryGetValue(target,out var destination))await socket.SendAsync(p,destination,stop.Token);
    }}catch(OperationCanceledException)when(stop.IsCancellationRequested){}}
    public async ValueTask DisposeAsync(){stop.Cancel();await running;socket.Dispose();stop.Dispose();}
}
