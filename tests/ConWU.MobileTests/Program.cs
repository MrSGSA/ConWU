using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ConWU.Mobile;
using StreamLink.Core;

if(args is ["--make-code",var codeMode,var codeEndpoint]){Console.WriteLine(CompactDirectCode.Issue(codeEndpoint,codeMode,"000000"));return;}
if(args is ["--probe-stream",var probeMode,var probeEndpoint]){
    MobileEnrollment.RequireProtocol(probeMode);var parsed=ExistingEntryResolver.ParseEndpoint(probeEndpoint);
    await using var stream=new StreamMeshTransport(MeshIdentity.Create("","",probeMode,direct:true),new(IPAddress.Parse(parsed.Host),parsed.Port),false,0,pairingBootstrap:true);
    using var deadline=new CancellationTokenSource(14000);
    while(stream.ClientConnection.Phase is not ("Ready" or "Failed" or "Closed"))await Task.Delay(50,deadline.Token);
    Console.WriteLine(JsonSerializer.Serialize(new{endpoint=probeEndpoint,connection=stream.ClientConnection,changesMembership=false}));return;
}
if(args is ["--android-host",var output,var protocol]){
    await using var fixture=new HostFixture(protocol,"10.0.2.2",output);
    await fixture.Start();Console.WriteLine("Android host fixture ready; metadata written without private keys");
    await Task.Delay(Timeout.Infinite);return;
}
if(args is ["--android-host",var automaticOutput,var automaticProtocol,"autonomous"]){
    await using var fixture=new HostFixture(automaticProtocol,"10.0.2.2",automaticOutput,autonomous:true);
    await fixture.Start();Console.WriteLine("Autonomous-config Android host fixture ready");
    await Task.Delay(Timeout.Infinite);return;
}
int checks=0;
var hubNetworks=new List<MobileNetwork>();
void Check(bool value,string name){if(!value)throw new Exception(name);checks++;Console.WriteLine("PASS "+name);}
async Task Until(Func<bool> ready,string name,int milliseconds=12000){using var stop=new CancellationTokenSource(milliseconds);while(!ready()){await Task.Delay(25,stop.Token);}Check(true,name);}
Check(CompactCodeInput.Format("abcd-efgh-jkmn-pqrs")=="ABCD-EFGH-JKMN-PQRS","pasting an already grouped code never duplicates separators");
Check(CompactCodeInput.Format("abcd efgh jkmn pqrs")=="ABCD-EFGH-JKMN-PQRS","spaces and lower-case input normalize into four groups");
Check(CompactCodeInput.Format("OI1L")=="0111","ambiguous glyphs follow the existing direct-code alphabet");
Check(CompactCodeInput.Edit("ABCD-EFGH","ABCDEFGH",4,5,4,1,0).Text=="ABCE-FGH","backspace removes the separator and preceding symbol in one edit");
Check(CompactCodeInput.Edit("ABCD-EFGH","ABCDEFGH",4,4,4,1,0).Text=="ABCD-FGH","forward delete removes the following symbol instead of reinserting a stuck separator");
foreach(string mode in new[]{"faketcp","phantun","mimic","tcpraw","udp"}){
    bool blocked=false;try{MobileEnrollment.RequireProtocol(mode);}catch(NotSupportedException){blocked=true;}Check(blocked,"mobile cannot silently switch unsupported "+mode+" codes to a different protocol");
}
foreach(string mode in new[]{"tcp","https"}){
    await using var host=new HostFixture(mode);await host.Start();
    var mobile=new MobileDeviceState();string sas="";
    var joined=await MobileEnrollment.Join(host.Code,mobile.SigningPrivate,"Phone",p=>{if(p.Verification.Length>0)sas=p.Verification;},default,
        (mesh,target)=>new StreamMeshTransport(mesh,host.Endpoint,false,0,pairingBootstrap:true));
    Check(host.Verification==sas&&sas.Length==6,"mobile and host verify the same committed exchange over real "+mode+" sockets");
    mobile.Networks=[joined];mobile.Validate();
    hubNetworks.Add(joined);
    var reloaded=JsonSerializer.Deserialize<MobileDeviceState>(JsonSerializer.Serialize(mobile))!;reloaded.Validate();
    Check(reloaded.DeviceId==mobile.DeviceId&&reloaded.Networks[0].Mesh.ExchangePrivate==joined.Mesh.ExchangePrivate,"mobile credential serialization preserves device and per-network identity: "+mode);
    Check(MobileGuestSession.Sources(joined).Single().Source==HostFixture.Subscription,"approved subscription exclusively replaces the compact bootstrap address: "+mode);
    var phone=new TestAdapter();MobileConnectionStatus? status=null;var targets=new ConcurrentQueue<string>();
    using var stop=new CancellationTokenSource();long networkGeneration=0;int transientFailure=mode=="tcp"?1:0;
    var runner=new MobileGuestSession(joined,phone,"Phone",s=>status=s).Run(stop.Token,
        (sources,_,_)=>{Check(sources.Length==1&&sources[0].Source==HostFixture.Subscription,"recovery resolves only the currently approved subscription");return Task.FromResult(new[]{new EntryResolution(1,0,"TXT",[host.Published],"")});},
        (mesh,target)=>{targets.Enqueue(target.ToString());if(Interlocked.Exchange(ref transientFailure,0)==1)throw new SocketException((int)SocketError.HostNotFound);return new StreamMeshTransport(mesh,host.Endpoint,false,0);},()=>Interlocked.Read(ref networkGeneration));
    try{
        await Until(()=>status?.Connected==true,"mobile authenticates a bidirectional data path: "+mode);
        if(mode=="tcp")Check(targets.Count>=2,"a transient socket/hostname failure retries instead of terminating the saved network");
        phone.Outgoing.Add(Packet(joined.Mesh.LocalIp,host.Profile.LocalIp));
        await Until(()=>host.Adapter.Received.Count>0,"host receives a complete authenticated mobile IP packet: "+mode);
        host.Adapter.Outgoing.Add(Packet(host.Profile.LocalIp,joined.Mesh.LocalIp));
        await Until(()=>phone.Received.Count>0,"mobile receives an authenticated host IP packet: "+mode);
        int beforeRestart=targets.Count;await host.Restart();
        await Until(()=>targets.Count>beforeRestart&&status?.Connected==true,"subscription change reconnects the same mobile membership after host transport restart: "+mode,20000);
        int received=host.Adapter.Received.Count;
        phone.Outgoing.Add(Packet(joined.Mesh.LocalIp,host.Profile.LocalIp));
        await Until(()=>host.Adapter.Received.Count>received,"reconnected membership still delivers complete encrypted IP packets: "+mode);
        int dialed=targets.Count;Interlocked.Increment(ref networkGeneration);
        await Until(()=>targets.Count>dialed&&status?.Connected==true,"a system network-change signal rebinds the transport without replacing saved credentials: "+mode);
        Check(!targets.Contains(joined.BootstrapEndpoint),"a stale compact endpoint is never dialed after receiving a subscription: "+mode);
    }finally{stop.Cancel();await runner;}
    Check(phone.Stopped&&phone.Disposed,"mobile session cancellation joins data pumps and releases its packet adapter: "+mode);
}
{
    var device=new TestAdapter();
    await using var hub=new MobilePacketHub(device,hubNetworks);
    var first=hub.Adapter(hubNetworks[0].Id);var second=hub.Adapter(hubNetworks[1].Id);
    // Fill one pair's queue. It must neither block the VPN read pump nor leak
    // a packet into the independent second pair's receive path.
    for(int i=0;i<160;i++)device.Outgoing.Add(Packet(hubNetworks[0].Mesh.LocalIp,hubNetworks[0].HostIp));
    var spoof=Packet(hubNetworks[0].Mesh.LocalIp,hubNetworks[1].HostIp);device.Outgoing.Add(spoof);
    var valid=Packet(hubNetworks[1].Mesh.LocalIp,hubNetworks[1].HostIp);device.Outgoing.Add(valid);
    byte[] buffer=new byte[MeshLink.Mtu];using var deadline=new CancellationTokenSource(3000);
    int count=await Task.Run(()=>second.Read(buffer,deadline.Token));
    Check(count==valid.Length&&buffer.AsSpan(0,count).SequenceEqual(valid),"a full network queue cannot block another network or deliver packets from the wrong local IP");
    using(var empty=new CancellationTokenSource(120)){
        bool canceled=false;try{await Task.Run(()=>second.Read(buffer,empty.Token));}catch(OperationCanceledException){canceled=true;}
        Check(canceled,"empty pair queues honor cancellation without closing the shared system VPN");
    }
    Check(!second.Write(Packet(hubNetworks[0].HostIp,hubNetworks[1].Mesh.LocalIp)),"host-to-mobile packets cannot impersonate another network's peer");
    var malformed=Packet(hubNetworks[1].HostIp,hubNetworks[1].Mesh.LocalIp);malformed[2]=0;
    Check(!second.Write(malformed),"invalid IPv4 length cannot enter the OS VPN");
    first.Stop();Check(first.Read(buffer)==0&&!device.Stopped,"stopping one network discards its backlog and keeps the shared VPN alive");
    Check(second.Write(Packet(hubNetworks[1].HostIp,hubNetworks[1].Mesh.LocalIp))&&device.Received.Count==1,"the remaining network still delivers authenticated host packets to the OS VPN");
    await hub.DisposeAsync();Check(device.Stopped&&device.Disposed&&hub.Completion.IsCompleted,"stopping the VPN joins its read pump and releases the system adapter");
    var duplicate=new TestAdapter();bool rejected=false;
    try{_ =new MobilePacketHub(duplicate,[hubNetworks[0],hubNetworks[0]]);}catch(FormatException){rejected=true;}
    Check(rejected&&duplicate.Disposed,"a failed VPN hub construction releases the transferred system descriptor");
}
await VpnTranslationTests.Run(Check,hubNetworks);
await PairingFailureTests.Run(Check);
await using(var host=new HostFixture("https",badPin:true)){
    await host.Start();bool rejected=false;
    try{await MobileEnrollment.Join(host.Code,NodeIdentityProof.GeneratePrivate(),"Phone",_=>{},default,(mesh,_)=>new StreamMeshTransport(mesh,host.Endpoint,false,0,pairingBootstrap:true));}catch(CryptographicException){rejected=true;}
    Check(rejected,"approval cannot replace the certificate actually observed during HTTPS pairing");
}
await using(var host=new HostFixture("tcp",reject:true)){
    await host.Start();bool rejected=false;
    try{await MobileEnrollment.Join(host.Code,NodeIdentityProof.GeneratePrivate(),"Phone",_=>{},default,(mesh,_)=>new StreamMeshTransport(mesh,host.Endpoint,false,0,pairingBootstrap:true));}
    catch(IOException ex)when(ex.Message.Contains("拒绝")){rejected=true;}
    Check(rejected&&host.Profile.Directory!.Members.Length==1,"host rejection cannot create or return mobile membership credentials");
}
await using(var host=new HostFixture("tcp",wait:true)){
    await host.Start();using var userCancel=new CancellationTokenSource(8000);bool canceled=false;
    try{await MobileEnrollment.Join(host.Code,NodeIdentityProof.GeneratePrivate(),"Phone",progress=>{if(progress.Verification.Length>0)userCancel.Cancel();},userCancel.Token,(mesh,_)=>new StreamMeshTransport(mesh,host.Endpoint,false,0,pairingBootstrap:true));}
    catch(OperationCanceledException){canceled=true;}
    Check(canceled&&(await host.Poll()).Outcome=="Cancelled"&&host.Profile.Directory!.Members.Length==1,"canceling approval notifies the host and releases the unapproved exchange");
}
Console.WriteLine($"PASS {checks} mobile core checks; real local TCP/TLS and encrypted IP traffic, no installed service changes");

static byte[] Packet(string source,string target){byte[] bytes=new byte[1280];bytes[0]=0x45;BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2),1280);bytes[8]=64;bytes[9]=17;IPAddress.Parse(source).GetAddressBytes().CopyTo(bytes,12);IPAddress.Parse(target).GetAddressBytes().CopyTo(bytes,16);BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(20),45123);BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(22),45124);BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(24),1260);uint sum=0;for(int i=0;i<20;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(i));while(sum>65535)sum=(sum&65535)+(sum>>16);BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10),(ushort)~sum);return bytes;}

sealed class TestAdapter : IPacketAdapter
{
    public readonly BlockingCollection<byte[]> Outgoing=new();public readonly ConcurrentQueue<byte[]> Received=new();public bool Stopped,Disposed;
    public bool EchoUdp;
    public int Read(byte[] buffer)=>Read(buffer,default);
    public int Read(byte[] buffer,CancellationToken token){try{var packet=Outgoing.Take(token);packet.CopyTo(buffer,0);return packet.Length;}catch(InvalidOperationException){return 0;}}
    public bool Write(byte[] packet){
        Received.Enqueue(packet.ToArray());
        bool icmp=packet.Length>=28&&packet[9]==1&&packet[20]==8;
        bool udp=EchoUdp&&packet.Length>=28&&packet[0]==0x45&&packet[9]==17&&BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(22))==45124;
        if(icmp||udp){
            var reply=packet.ToArray();packet.AsSpan(12,4).CopyTo(reply.AsSpan(16));packet.AsSpan(16,4).CopyTo(reply.AsSpan(12));
            if(icmp){reply[20]=0;reply[22]=reply[23]=0;BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(22),Checksum(reply.AsSpan(20)));}
            else{
                packet.AsSpan(20,2).CopyTo(reply.AsSpan(22));packet.AsSpan(22,2).CopyTo(reply.AsSpan(20));reply[26]=reply[27]=0;
                byte[] pseudo=new byte[12+reply.Length-20];reply.AsSpan(12,8).CopyTo(pseudo);pseudo[9]=17;BinaryPrimitives.WriteUInt16BigEndian(pseudo.AsSpan(10),(ushort)(reply.Length-20));reply.AsSpan(20).CopyTo(pseudo.AsSpan(12));
                ushort checksum=Checksum(pseudo);BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(26),checksum==0?(ushort)65535:checksum);
            }
            reply[10]=reply[11]=0;BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(10),Checksum(reply.AsSpan(0,(reply[0]&15)*4)));Outgoing.Add(reply);
        }return true;
    }
    static ushort Checksum(ReadOnlySpan<byte> bytes){uint sum=0;for(int i=0;i<bytes.Length;i+=2)sum+=(uint)(bytes[i]<<8)+(i+1<bytes.Length?bytes[i+1]:0u);while(sum>>16!=0)sum=(sum&65535)+(sum>>16);return (ushort)~sum;}
    public void Stop(){Stopped=true;Outgoing.CompleteAdding();}public void Dispose(){Disposed=true;Stop();}
}

sealed class HostFixture : IAsyncDisposable
{
    public const string Subscription="txt://mobile-fixture.example#host";
    readonly string mode,codeIp;readonly string? output;readonly bool badPin,reject,wait,autonomous;
    readonly string signing=NodeIdentityProof.GeneratePrivate();readonly DirectPairHost pairing=new();
    readonly PairKeyExchange key;readonly X509Certificate2 certificate;
    MeshRouter router=null!;StreamMeshTransport server=null!;PairRoomTicket room=null!;
    readonly CancellationTokenSource stop=new();Task approval=Task.CompletedTask;
    int generation;
    public MeshProfile Profile {get;}
    public TestAdapter Adapter {get;}=new();
    public string Code {get;private set;}="";public string Verification {get;private set;}="";
    public string Published=>"203.0.113.31:"+(51000+generation);
    public IPEndPoint Endpoint {get;private set;}=null!;
    public HostFixture(string mode,string codeIp="203.0.113.9",string? output=null,bool badPin=false,bool reject=false,bool wait=false,bool autonomous=false)
    {
        this.mode=mode;this.codeIp=codeIp;this.output=output;this.badPin=badPin;this.reject=reject;this.wait=wait;this.autonomous=autonomous;
        Adapter.EchoUdp=output!=null;
        key=new(signing);
        Profile=MeshIdentity.Create("","",mode,direct:true,pairwise:true,deviceId:MeshIdentity.NetworkId(MeshIdentity.PublicSigning(signing)));
        using var certificateKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        certificate=StreamCertificates.CreateServer(certificateKey,DateTimeOffset.UtcNow.AddHours(2));
        if(mode=="https")Profile.Pair=Profile.Pair with{TransportKeyPin=badPin?new string('A',64):StreamMeshTransport.CertificatePin(certificate)};
    }
    public async Task Start()
    {
        room=await pairing.Create(key,"Fixture host",stop.Token);
        router=new(Profile,Adapter){DirectPairing=pairing.Handle};Open();
        Code=CompactDirectCode.Issue(codeIp+":"+Endpoint.Port,mode,room.Code);WriteState();approval=Approve();
    }
    void Open()
    {
        var choose=new TcpListener(IPAddress.Loopback,0);choose.Start();int port=((IPEndPoint)choose.LocalEndpoint).Port;choose.Stop();Endpoint=new(IPAddress.Loopback,port);
        server=new(Profile,router.LocalEndpoint,true,port,()=>certificate);
        server.RouteOpened+=endpoint=>{var peer=Profile.Directory!.Members.FirstOrDefault(m=>m.Slot!=Profile.Self.Slot);if(peer!=null)router.SetCandidate(peer.Slot,endpoint,"Phone","mobile fixture peer");};
        server.RouteClosed+=endpoint=>{var peer=Profile.Directory!.Members.FirstOrDefault(m=>m.Slot!=Profile.Self.Slot);if(peer!=null)router.FailLegacyTransport(peer.Slot,endpoint);};
    }
    async Task Approve()
    {
        try{
            PairRoomState state;
            do{state=await pairing.Poll(room,true,stop.Token);if(state.Candidate.Length==0)await Task.Delay(40,stop.Token);}while(state.Candidate.Length==0);
            await pairing.Reveal(room,true,key,stop.Token);
            do{state=await pairing.Poll(room,true,stop.Token);if(state.GuestPublic.Length==0)await Task.Delay(40,stop.Token);}while(state.GuestPublic.Length==0);
            byte[] shared=key.Derive(state.GuestPublic,state.GuestCommitment,room.Room,state.Candidate,true);Verification=PairKeyExchange.Verification(shared);WriteState();
            try{
            if(wait)await Task.Delay(Timeout.Infinite,stop.Token);
            await Task.Delay(output==null?700:6000,stop.Token);
            if(reject){await pairing.Finish(room,true,stop.Token);return;}
            string credential=DirectInvitation.Issue(Profile,[],deviceId:state.GuestIdentity!.DeviceId);router.ApplyDirectory(Profile.Directory!);
            var settings=new UiNetworkSettings(PathSelection:TransportModes.Policy(mode)){ConnectionSource=autonomous?"custom":"existing",DirectMode=true,DiscoveryMode=autonomous?"direct":"existing",EntryRefreshSeconds=1,
                ExistingEntries=autonomous?[]:[new(0,output==null?Subscription:codeIp+":"+Endpoint.Port)]};
            var approved=ApprovedNetworkSettings.Create(Profile,settings,"Mobile test");
            var envelope=NetworkEntryEnrollment.Encode(credential,[],approved);
            await pairing.Approve(room,state.Candidate,PairKeyExchange.EncryptInvitation(shared,envelope,room.Room,state.Candidate),stop.Token);
            }finally{CryptographicOperations.ZeroMemory(shared);}
            while(!stop.IsCancellationRequested){WriteState();await Task.Delay(500,stop.Token);}
        }catch(OperationCanceledException)when(stop.IsCancellationRequested){}
    }
    void WriteState()
    {
        if(output==null)return;
        System.IO.Directory.CreateDirectory(output);string path=Path.Combine(output,"host.json");
        File.WriteAllText(path+".tmp",JsonSerializer.Serialize(new{code=Code,verification=Verification,virtualIp=Profile.LocalIp,port=Endpoint.Port,packets=Adapter.Received.Count,connected=router?.Status().Any(s=>s.Connected)==true}));File.Move(path+".tmp",path,true);
    }
    public async Task Restart(){await server.DisposeAsync();generation++;Open();}
    public Task<PairRoomState> Poll()=>pairing.Poll(room,true,stop.Token);
    public async ValueTask DisposeAsync(){stop.Cancel();try{await approval;}finally{if(server!=null)await server.DisposeAsync();if(router!=null)await router.DisposeAsync();pairing.Dispose();key.Dispose();certificate.Dispose();stop.Dispose();}}
}
