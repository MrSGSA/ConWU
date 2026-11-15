using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.Service;

static class PunchAssistanceTests
{
    public static async Task Run(Action<bool,string> check)
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(45));var token=deadline.Token;
        string root=Path.Combine(Path.GetTempPath(),"conwu-punch-assist-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        string pem=Path.Combine(root,"cert.pem"),secret=Path.Combine(root,"key.pem"),data=Path.Combine(root,"data");
        File.WriteAllText(pem,cert.ExportCertificatePem());File.WriteAllText(secret,key.ExportPkcs8PrivateKeyPem());
        string pin=Convert.ToHexString(SHA256.HashData(cert.RawData));
        await using var host=CoordinationHost.Create(new(data,"https://127.0.0.1:0",pem,secret));await host.Start(token);
        string address=host.Addresses.Single()+"/";int port=new Uri(address).Port;
        using var handler=new HttpClientHandler{UseProxy=false,AllowAutoRedirect=false,ServerCertificateCustomValidationCallback=(_,value,_,_)=>value!=null&&Convert.ToHexString(SHA256.HashData(value.RawData))==pin};
        using var http=new HttpClient(handler){BaseAddress=new(address),Timeout=TimeSpan.FromSeconds(4)};
        using var assist=new PunchAssistClient(address,pin);
        await assist.RequireSupport(token);check(true,"HTTPS health advertises assistance on the integrated listener");
        using(var tcp=new TcpClient()){
            await tcp.ConnectAsync(IPAddress.Loopback,port,token);var local=(IPEndPoint)tcp.Client.LocalEndPoint!;if(local.Address.IsIPv4MappedToIPv6)local=new(local.Address.MapToIPv4(),local.Port);var stream=tcp.GetStream();
            var request=Stun.Request();await stream.WriteAsync(request.AsMemory(0,7),token);await Task.Delay(15,token);await stream.WriteAsync(request.AsMemory(7),token);
            byte[] response=new byte[32];await stream.ReadExactlyAsync(response,token);
            check(Stun.Parse(response,request).Equals(local),"fragmented TCP STUN on the HTTPS port reports the actual source tuple");
            request=Stun.Request();await stream.WriteAsync(request,token);await stream.ReadExactlyAsync(response,token);
            check(Stun.Parse(response,request).Equals(local),"the retained TCP STUN flow supports a fresh keepalive transaction");
        }
        using(var malformed=new TcpClient()){
            await malformed.ConnectAsync(IPAddress.Loopback,port,token);var request=Stun.Request();BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4),0);
            await malformed.GetStream().WriteAsync(request,token);byte[] one=new byte[1];
            check(await malformed.GetStream().ReadAsync(one,token)==0,"invalid STUN cookies are closed without a reflected response");
        }
        check((await http.GetAsync("health",token)).IsSuccessStatusCode,"TCP STUN does not interfere with ordinary HTTPS on the same listener");
        int retainedSourcePort=0;
        for(int cycle=0;cycle<3;cycle++){
            await using var mapping=await FakeTcpSourceMapping.Create(retainedSourcePort,["127.0.0.1:"+port],_=>{},token,allowGatewayMapping:false);
            retainedSourcePort=mapping.LocalEndpoint.Port;
            check(mapping.PublicEndpoint.Port==retainedSourcePort,"FakeTCP helper can immediately reopen the exact source port after retirement, cycle "+cycle);
        }
        if(OperatingSystem.IsWindows()){
            await using var mapping=await MimicMapping.Create(0,_=>{},token,["127.0.0.1:"+port],allowGatewayMapping:false);
            check(!mapping.GatewayGranted&&mapping.PublicEndpoint.Port==mapping.LocalEndpoint.Port,
                "Mimic can retain the real same-port observation with explicit gateway mapping disabled and no native driver");
        }
        foreach(string mode in new[]{"faketcp","phantun","mimic","tcpraw","tcp","https"}){
            await assist.RequireSupport(token,mode);
            var modes=new PunchAssistSessions();var source=IPAddress.Loopback;
            using var mk=new PairKeyExchange();using var gk=new PairKeyExchange();
            var unready=modes.Create(new("127.0.0.1:49200","001235",mk.Commitment,mode,Ready:false),source);
            bool mismatch=false;try{modes.Join(new(unready.Room,Guid.NewGuid().ToString("N"),gk.Commitment,mode=="tcp"?"https":"tcp"),source);}catch(IOException){mismatch=true;}
            check(mismatch,mode+" helper room rejects a different protocol before allocating a guest");
            var member=modes.Join(new(unready.Room,Guid.NewGuid().ToString("N"),gk.Commitment,mode),source);
            member=modes.Update(member.Room,new(member.Token,"127.0.0.1:49201",Ready:false),source);
            unready=modes.Update(unready.Room,new(unready.Token,unready.HostEndpoint,Ready:false),source);
            check(member.Round==Guid.Empty&&unready.Round==Guid.Empty&&unready.GuestEndpoint=="127.0.0.1:49201",mode+" candidates are exchanged without starting an unprepared carrier");
            member=modes.Update(member.Room,new(member.Token,member.GuestEndpoint),source);unready=modes.Update(unready.Room,new(unready.Token,unready.HostEndpoint),source);
            member=modes.Update(member.Room,new(member.Token,member.GuestEndpoint),source);
            check(unready.Round!=Guid.Empty&&member.Round==unready.Round&&member.Mode==mode,mode+" starts only after both actual adapters report ready");
            modes.Update(unready.Room,new(unready.Token,Close:true),source);
        }
        using var ownerKey=new PairKeyExchange();using var guestKey=new PairKeyExchange();
        var room=await assist.Create(new("127.0.0.1:49197","001234",ownerKey.Commitment),token);
        check(room.Round==Guid.Empty&&host.PunchAssist.Waiting==1&&!File.Exists(Path.Combine(data,"mesh-networks.json")),"a temporary hint room does not create network membership or claim reachability");
        var guest=await assist.Join(new(room.Room,Guid.NewGuid().ToString("N"),guestKey.Commitment),token);
        check(guest.Token!=room.Token&&guest.Round==Guid.Empty,"an unready guest receives a separate capability without starting probes");
        using(var wrong=await http.PostAsJsonAsync("v1/punch-assist/"+room.Room,new PunchAssistUpdate(new string('A',64)),token))check(wrong.StatusCode==HttpStatusCode.Unauthorized,"unknown room capabilities cannot poll candidates");
        using(var privateTarget=await http.PostAsJsonAsync("v1/punch-assist/"+guest.Room,new PunchAssistUpdate(guest.Token,"10.0.0.1:1234"),token))check(!privateTarget.IsSuccessStatusCode,"a guest cannot turn assistance into arbitrary private-address probing");
        using(var malformed=await http.PostAsJsonAsync("v1/punch-assist/"+guest.Room,new{token=guest.Token,endpoint=(string?)null,close=false},token))check(malformed.StatusCode==HttpStatusCode.BadRequest,"malformed nullable candidate input is rejected without a server exception");
        guest=await assist.Update(guest,"127.0.0.1:49198",token);room=await assist.Update(room,room.HostEndpoint,token);
        check(guest.Round!=Guid.Empty&&guest.Round==room.Round&&room.StartAfterMilliseconds<=1000&&room.StartAfterMilliseconds>0,"both ready participants retrieve the same future round without clock synchronization");
        check(room.HostRoom=="001234"&&room.Commitment==ownerKey.Commitment&&room.GuestEndpoint=="127.0.0.1:49198","the helper binds the direct room and candidate hints without exchanging keys or configuration");
        using(var changed=await http.PostAsJsonAsync("v1/punch-assist/"+guest.Room,new PunchAssistUpdate(guest.Token,"127.0.0.1:49199"),token))check(changed.StatusCode==HttpStatusCode.Conflict,"candidate changes cannot silently replace an armed round");
        using(var close=await http.PostAsJsonAsync("v1/punch-assist/"+guest.Room,new PunchAssistUpdate(guest.Token,Close:true),token))check(close.StatusCode==HttpStatusCode.Unauthorized,"a guest cannot delete the owner's invitation");
        await assist.Close(room,token);check(host.PunchAssist.Waiting+host.PunchAssist.Scheduled==0,"closing the owner session retires all temporary candidates");
        using(var untrusted=new PunchAssistClient(new HttpClient(new Reply(JsonSerializer.Serialize(room))){BaseAddress=new Uri("https://8.8.8.8/")})){
            bool rejected=false;try{await untrusted.Join(new(room.Room,Guid.NewGuid().ToString("N"),guestKey.Commitment),token);}catch(IOException){rejected=true;}
            check(rejected,"an untrusted public helper cannot redirect a guest to loopback or private services");
        }
        using(var broken=new PunchAssistClient(new HttpClient(new Reply("{")){BaseAddress=new Uri("https://8.8.8.8/")})){
            bool rejected=false;try{await broken.Join(new(room.Room,Guid.NewGuid().ToString("N"),guestKey.Commitment),token);}catch(IOException){rejected=true;}
            check(rejected,"malformed helper JSON becomes a bounded connection failure rather than a worker fault");
        }

        var owner=MeshIdentity.Create(address,pin,"mimic",pairwise:true);var peer=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));owner.Directory=peer.Directory;
        using var a=new MeshDiscoveryClient(owner);using var b=new MeshDiscoveryClient(peer);await a.SaveDirectory(owner.Directory!,token);
        var first=await a.AssistMimic("127.0.0.1:51001",token);var second=await b.AssistMimic("127.0.0.1:51002",token);
        check(first.Round==Guid.Empty&&second.Round==Guid.Empty,"a new peer candidate waits for both participants to confirm the same generation");
        first=await a.AssistMimic("127.0.0.1:51001",token);second=await b.AssistMimic("127.0.0.1:51002",token);
        check(first.Round!=Guid.Empty&&first.Round==second.Round&&first.PeerEndpoint=="127.0.0.1:51002"&&second.PeerEndpoint=="127.0.0.1:51001","approved members use signed fresh-candidate assistance for their own pair");
        var forged=PunchAssistProtocol.Create(owner,Guid.NewGuid(),"127.0.0.1:51001") with{Endpoint="127.0.0.1:51003"};
        using(var message=new HttpRequestMessage(HttpMethod.Post,$"v3/mesh/{owner.Pair.Network}/mimic-assist"){Content=JsonContent.Create(forged)}){
            message.Headers.Authorization=new("Bearer",owner.Pair.Auth);using var response=await http.SendAsync(message,token);
            check(response.StatusCode==HttpStatusCode.Forbidden,"candidate tampering fails member-signature validation");
        }
        var replay=PunchAssistProtocol.Create(owner,Guid.NewGuid(),"127.0.0.1:51001");
        async Task<HttpStatusCode> Send(MimicAssistRequest value){using var message=new HttpRequestMessage(HttpMethod.Post,$"v3/mesh/{owner.Pair.Network}/mimic-assist"){Content=JsonContent.Create(value)};message.Headers.Authorization=new("Bearer",owner.Pair.Auth);using var reply=await http.SendAsync(message,token);return reply.StatusCode;}
        check(await Send(replay)==HttpStatusCode.OK&&await Send(replay)==HttpStatusCode.Conflict,"a signed assistance request cannot be replayed to rearm probes");
        var moved=await a.AssistMimic("127.0.0.1:51003",token);
        check(moved.Round==Guid.Empty,"a changed source or boot invalidates the old scheduled round immediately");

        await RoutedGreetings(owner,peer,a,b,check,token);
        MeshIdentity.Revoke(owner,peer.Self.Slot);await a.SaveDirectory(owner.Directory!,token);
        bool revoked=false;try{await b.AssistMimic("127.0.0.1:51002",token);}catch(HttpRequestException){revoked=true;}
        check(revoked,"removed members cannot continue obtaining coordinated candidate hints");

        var time=new Clock();var sessions=new PunchAssistSessions(time);var input=new PunchAssistCreate("8.8.8.8:42000","123456",ownerKey.Commitment);
        var ephemeral=sessions.Create(input,IPAddress.Parse("8.8.8.8"));time.Advance(TimeSpan.FromSeconds(301));
        check(sessions.Status.Waiting==0,"invitation expiry uses elapsed time and releases memory without a cleanup timer");
        bool expired=false;try{sessions.Update(ephemeral.Room,new(ephemeral.Token),IPAddress.Parse("8.8.8.8"));}catch(KeyNotFoundException){expired=true;}check(expired,"expired invitation capabilities cannot restart a session");
        for(int i=0;i<PunchAssistProtocol.MaximumSessions;i++)sessions.Create(input,IPAddress.Parse("8.8.8.8"));
        bool full=false;try{sessions.Create(input,IPAddress.Parse("8.8.8.8"));}catch(IOException){full=true;}check(full,"temporary assistance capacity is bounded");
    }
    static async Task RoutedGreetings(MeshProfile owner,MeshProfile guest,MeshDiscoveryClient a,MeshDiscoveryClient b,Action<bool,string> check,CancellationToken token)
    {
        await using var left=new MeshRouter(owner,new EmptyAdapter());await using var right=new MeshRouter(guest,new EmptyAdapter());
        left.SetLegacyListenerControl(true);right.SetLegacyListenerControl(true);
        using var wire=new Wire(left.LocalEndpoint,right.LocalEndpoint,token);
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(token);
        var sourceA=new Mapping(51011);var sourceB=new Mapping(51012);
        var controlA=new Count(a);var controlB=new Count(b);
        await using var loopA=new TcpAssistLoop(owner,controlA,_=>{},stop.Token);await using var loopB=new TcpAssistLoop(guest,controlB,_=>{},stop.Token);
        long until=Environment.TickCount64+22000;
        while((!left.HasHealthyPath(guest.Self.Slot)||!right.HasHealthyPath(owner.Self.Slot))&&Environment.TickCount64<until){
            await loopA.Tick(sourceA,wire.Left,left);await loopB.Tick(sourceB,wire.Right,right);await Task.Delay(30,token);
        }
        check(wire.Probes is >=1 and <=2&&left.HasHealthyPath(guest.Self.Slot)&&right.HasHealthyPath(owner.Self.Slot),
            $"synchronized authenticated greetings establish both real MeshRouter AEAD paths over an isolated carrier fixture (probes={wire.Probes}, left={left.HasHealthyPath(guest.Self.Slot)}, right={right.HasHealthyPath(owner.Self.Slot)}, requests={controlA.Requests}/{controlB.Requests})");
        await loopA.Tick(sourceA,wire.Left,left);await loopB.Tick(sourceB,wire.Right,right);int before=controlA.Requests+controlB.Requests;
        await Task.Delay(1100,token);await loopA.Tick(sourceA,wire.Left,left);await loopB.Tick(sourceB,wire.Right,right);
        check(controlA.Requests+controlB.Requests==before,"healthy direct paths stop assistance polling and further probes");
    }
    sealed class Count(ITcpAssistDiscovery inner):ITcpAssistDiscovery{public int Requests;public Task<MimicAssistState> AssistTcp(string endpoint,string mode,bool ready,CancellationToken token){Requests++;return inner.AssistTcp(endpoint,mode,ready,token);}}
    sealed class Reply(string body):HttpMessageHandler{protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(body,System.Text.Encoding.UTF8,"application/json")});}
    sealed class Mapping(int port):IMapping
    {public IPAddress LocalAddress=>IPAddress.Loopback;public IPEndPoint PublicEndpoint=>new(IPAddress.Loopback,port);public bool IsValid=>true;public event Action<IPEndPoint>? Changed{add{}remove{}}public Task Maintain(CancellationToken token)=>Task.Delay(Timeout.Infinite,token);public ValueTask DisposeAsync()=>ValueTask.CompletedTask;}
    sealed class Clock:TimeProvider
    {long now;readonly DateTimeOffset began=DateTimeOffset.UtcNow;public override long TimestampFrequency=>1000;public override long GetTimestamp()=>now;public override DateTimeOffset GetUtcNow()=>began.AddMilliseconds(now);public void Advance(TimeSpan value)=>now+=(long)value.TotalMilliseconds;}
    sealed class Wire:IDisposable
    {
        readonly UdpClient left=new(new IPEndPoint(IPAddress.Loopback,0)),right=new(new IPEndPoint(IPAddress.Loopback,0));
        readonly CancellationTokenSource stop;readonly Task[] pumps;public readonly Endpoint Left,Right;public int Probes;
        public Wire(IPEndPoint a,IPEndPoint b,CancellationToken token){
            stop=CancellationTokenSource.CreateLinkedTokenSource(token);
            Left=new(()=>{Probes++;right.Send(helloLeft!,b);});Right=new(()=>{Probes++;left.Send(helloRight!,a);});
            Left.Hello=hello=>helloLeft=hello;Right.Hello=hello=>helloRight=hello;
            pumps=[Pump(left,right,b,a),Pump(right,left,a,b)];
        }
        byte[]? helloLeft,helloRight;
        async Task Pump(UdpClient from,UdpClient to,IPEndPoint target,IPEndPoint allowed){try{while(!stop.IsCancellationRequested){var data=await from.ReceiveAsync(stop.Token);if(data.RemoteEndPoint.Equals(allowed))await to.SendAsync(data.Buffer,target,stop.Token);}}catch(OperationCanceledException){}}
        public sealed class Endpoint(Action send):IMeshTransport,IMeshPunchTransport
        {public Action<byte[]>? Hello;public IPEndPoint? ClientEndpoint=>null;public bool ControlsWirePackets=>true;public bool Exited=>false;public void Dispose(){}public void Punch(IPEndPoint peer)=>throw new Exception("authenticated greeting required");public void Punch(IPEndPoint peer,ReadOnlyMemory<byte> greeting){Hello!(greeting.ToArray());send();}}
        public void Dispose(){stop.Cancel();try{Task.WhenAll(pumps).GetAwaiter().GetResult();}catch(OperationCanceledException){}left.Dispose();right.Dispose();stop.Dispose();}
    }
}
