using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.Service;

if(args is ["--wal-foreground"]){ForegroundWalRecoveryTests.Run();return;}
int count=0;
void Check(bool condition,string name){if(!condition)throw new Exception(name);count++;Console.WriteLine("PASS "+name);}
void Invalid(Action action,string name){try{action();}catch(Exception ex)when(ex is FormatException or ArgumentException or IOException){Check(true,name);return;}throw new Exception("accepted: "+name);}
var owner=MeshIdentity.Create("https://coord.example.test/","","faketcp");
MeshGovernance.Enable(owner);
var guest=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));
owner.Directory=guest.Directory;
var request=MeshEntryHandshake.Request(guest);
var reply=MeshEntryHandshake.Reply(owner,request.Frame)!;
Check(reply!=null&&MeshEntryHandshake.VerifyReply(guest,request.Nonce,reply)==owner.Self.Slot,"network entry identifies a current member without selecting a host slot");
Check(MeshEntryHandshake.VerifyReply(guest,new string('A',48),reply)==0,"entry response is tied to the initiating nonce");
var tampered=(byte[])reply.Clone();tampered[^8]^=1;
Check(MeshEntryHandshake.VerifyReply(guest,request.Nonce,tampered)==0,"tampered entry identity is rejected");
var other=MeshIdentity.Create("https://coord.example.test/","","faketcp");
Check(MeshEntryHandshake.Reply(other,request.Frame)==null,"an address pointing at a different network is not silently adopted");
var oldDirectory=owner.Directory;
MeshIdentity.Revoke(owner,guest.Self.Slot);
Check(MeshEntryHandshake.Reply(owner,request.Frame)==null,"a revoked device cannot probe as a current member");
owner.Directory=oldDirectory;
await using(var a=new MeshRouter(owner,new EmptyAdapter()))
await using(var b=new MeshRouter(guest,new EmptyAdapter())) {
    b.ProbeNetworkEntry(a.LocalEndpoint);
    var deadline=DateTime.UtcNow.AddSeconds(3);
    while(b.IdentifiedNetworkEntry(a.LocalEndpoint)==0&&DateTime.UtcNow<deadline)await Task.Delay(20);
    Check(b.IdentifiedNetworkEntry(a.LocalEndpoint)==owner.Self.Slot,"real router socket returns a signed network entry identity");
    b.ForgetNetworkEntry(a.LocalEndpoint);
    Check(b.IdentifiedNetworkEntry(a.LocalEndpoint)==0,"retired probes cannot retain address ownership");
}
ExistingEntryResolver.Validate([new(ExistingEntry.Network,"203.0.113.1:44680")]);
await using(var a=new MeshRouter(owner,new EmptyAdapter()))
await using(var b=new MeshRouter(guest,new EmptyAdapter())) {
    int opens=0;var transport=new FixtureTransport(a.LocalEndpoint);
    using var paths=new MeshPeerTransports(b,_=>throw new Exception("must reuse the entry transport"),_=>{});
    await using var manager=new NetworkEntryConnections(b,(_,_)=>{opens++;return Task.FromResult<IMeshTransport>(transport);},_=>paths,_=>{},CancellationToken.None);
    var members=new[]{owner.Self};string[] sources=["203.0.113.1:44680"];
    var until=DateTime.UtcNow.AddSeconds(4);
    while(manager.ForMember(owner.Self).Length==0&&DateTime.UtcNow<until){await manager.Tick(sources,members,Environment.TickCount64);await Task.Delay(20);}
    Check(manager.ForMember(owner.Self).SequenceEqual(sources)&&opens==1&&paths.HasPending&&!transport.Disposed,"entry manager authenticates and transfers the same transport without a second worker");
    await manager.Tick([],members,Environment.TickCount64);
    Check(manager.ForMember(owner.Self).Length==0&&transport.Disposed,"removing an unproven network entry retires its pending transport");
    var delayed=new TaskCompletionSource<IMeshTransport>();var late=new FixtureTransport(a.LocalEndpoint);
    await using var cancelled=new NetworkEntryConnections(b,(_,_)=>delayed.Task,_=>paths,_=>{},CancellationToken.None);
    await cancelled.Tick(sources,members,Environment.TickCount64);
    await cancelled.Tick([],members,Environment.TickCount64);
    delayed.SetResult(late);await cancelled.Tick([],members,Environment.TickCount64);
    Check(late.Disposed&&cancelled.ForMember(owner.Self).Length==0,"late entry preparation cannot restore a removed source");
}
Check(ExistingEntry.ForJoinedNetwork([new(ExistingEntry.Network,"203.0.113.1:44680")]).Single().PeerSlot==ExistingEntry.Network,"unbound network entry remains unbound during enrollment");
var before=new DeviceProfile{DeviceName="saved-name",ExistingEntries=[new(ExistingEntry.Network,"203.0.113.1:44680")]};
var after=ProfileChanges.Copy(before);after.Coordinator=after.Coordinator with{Enabled=true};
Check(ProfileChanges.Impact(before,after)!=ProfileChangeImpact.RestartNetwork,"coordinator role changes do not rebuild the data path");
Invalid(()=>new CoordinatorSettings(true,"http://0.0.0.0:47822").Validate(),"plaintext public coordination is rejected");
Invalid(()=>new CoordinatorSettings(true,"https://0.0.0.0:47822").Validate(),"public HTTPS requires configured certificates");
string root=Path.Combine(Path.GetTempPath(),"streamlink-coordinator-test-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
await using(var host=CoordinationHost.Create(new(root,"http://127.0.0.1:0"))) {
    await host.Start();using var http=new HttpClient();
    var health=JsonDocument.Parse(await http.GetStringAsync(host.Addresses.Single()+"/health"));
    Check(health.RootElement.GetProperty("meshGovernance").GetInt32()==1&&health.RootElement.GetProperty("integratedCoordinator").GetInt32()==1,"embedded host uses production coordination routes");
    Invalid(()=>CoordinationHost.Create(new(root,"http://127.0.0.1:0")),"two hosts cannot own one coordinator data directory");
}
await using(var restarted=CoordinationHost.Create(new(root,"http://127.0.0.1:0"))) {
    await restarted.Start();Check(restarted.Addresses.Length==1,"coordinator releases its listener and storage lock on stop");
}
if(args.Contains("--tun")) {
    if(!OperatingSystem.IsLinux())throw new Exception("--tun needs an isolated Linux namespace");
    string name;
    using(var tun=new LinuxTunAdapter("10.231.241.1")) {
        name=tun.Name;Check(LinuxPlatform.Run("ip","-j","address","show","dev",name).Contains("10.231.241.1"),"production TUN owns the requested virtual address");
        Invalid(()=>new LinuxTunAdapter("10.231.241.2"),"overlapping existing Linux routes are rejected");
        var read=Task.Run(()=>tun.Read(new byte[2048]));tun.Stop();await read.WaitAsync(TimeSpan.FromSeconds(1));
        Check(tun.Statistics.Stopping,"TUN stop interrupts bounded reads");
    }
    Check(!LinuxPlatform.Run("ip","-j","link","show").Contains(name),"TUN close removes only its nonpersistent interface");
}
if(Array.IndexOf(args,"--native") is var nativeIndex && nativeIndex>=0) {
    string binary=Path.GetFullPath(args[nativeIndex+1]);
    string session=Path.Combine(Path.GetTempPath(),"sl-native-test-"+Guid.NewGuid().ToString("N"));
    LinuxPlatform.PrivateDirectory(session);
    Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",session);
    Console.WriteLine("Native evidence: "+session);
    using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(60));
    var token=deadline.Token;var generation=Guid.NewGuid();
    using var reflector=new TcpListener(IPAddress.Loopback,0);reflector.Start();
    using var a=await TcpEndpointLease.Open(new(IPAddress.Parse("127.0.0.2"),0),(IPEndPoint)reflector.LocalEndpoint,generation,token);
    using var helperA=await reflector.AcceptTcpClientAsync(token);
    using var b=await TcpEndpointLease.Open(new(IPAddress.Parse("127.0.0.3"),0),(IPEndPoint)reflector.LocalEndpoint,generation,token);
    using var helperB=await reflector.AcceptTcpClientAsync(token);
    var context=new TraversalAttemptContext("test-network","alpha",Guid.NewGuid(),"beta",Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),1,Guid.NewGuid(),1,TraversalProfile.FakeTcpHttpSo,true,true,Guid.NewGuid());
    var reverse=context with {LocalNodeId=context.RemoteNodeId,LocalBootId=context.RemoteBootId,RemoteNodeId=context.LocalNodeId,RemoteBootId=context.LocalBootId,LocalCandidateId=context.RemoteCandidateId,RemoteCandidateId=context.LocalCandidateId,ProtocolClient=false,Nominator=false};
    var shared=RandomNumberGenerator.GetBytes(32);
    await using(var client=await NativeDatagramPath.Prepare(binary,session,a,generation,context,b.Local,shared,token))
    await using(var server=await NativeDatagramPath.Prepare(binary,session,b,generation,reverse,a.Local,shared,token)) {
        Check(client.Armed&&server.Armed&&!client.Started&&!server.Started,"Linux native prepare arms both authorized tuples without sending before Start");
        await Task.WhenAll(client.StartAndQualify(token),server.StartAndQualify(token));
        Check(client.Diagnostics.PayloadQualified&&server.Diagnostics.PayloadQualified,"Linux managed FakeTCP HTTP SO authenticates full payload in both directions");
        byte[] packet=RandomNumberGenerator.GetBytes(TraversalLimits.UdpRequiredPayload);"SLM4"u8.CopyTo(packet);
        Check(client.TrySend(packet),"qualified client accepts full payload");
        var received=await server.Receive(token);Check(received.Span.SequenceEqual(packet),"Linux native preserves full client payload");
        Check(server.TrySend(packet),"qualified server accepts full payload");
        received=await client.Receive(token);Check(received.Span.SequenceEqual(packet),"Linux native preserves full server payload");
        Check(helperA.Connected&&helperB.Connected,"raw tuple guards leave TCP reflection helpers connected");
    }
    Check(!LinuxPlatform.Run("nft","list","tables").Contains("sl_"),"native teardown removes its firewall guards");
    Check(!Directory.EnumerateFiles(session,"*.conf").Any(),"native teardown removes temporary secrets");
    using var destination=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
    using(var foreign=new TcpListener(IPAddress.Any,0)) {
        foreign.Start();int occupied=((IPEndPoint)foreign.LocalEndpoint).Port;
        Invalid(()=>new LinuxMeshTransport(Path.GetDirectoryName(binary)!,session,owner,(IPEndPoint)destination.Client.LocalEndPoint!,true,occupied,null,"off"),"occupied entry ports fail before installing a kernel drop rule");
        using var ordinary=new TcpClient();await ordinary.ConnectAsync(IPAddress.Loopback,occupied,token);
        using var accepted=await foreign.AcceptTcpClientAsync(token);
        Check(ordinary.Connected,"failed entry startup leaves the pre-existing TCP listener reachable");
    }
    int rawPort;using(var reserve=new TcpListener(IPAddress.Loopback,0)){reserve.Start();rawPort=((IPEndPoint)reserve.LocalEndpoint).Port;}
    using(var ingress=new LinuxMeshTransport(Path.GetDirectoryName(binary)!,session,owner,(IPEndPoint)destination.Client.LocalEndPoint!,true,rawPort,null,"debug"))
    using(var outbound=new LinuxMeshTransport(Path.GetDirectoryName(binary)!,session,owner,new(IPAddress.Loopback,rawPort),false,0,null,"debug"))
    using(var second=new LinuxMeshTransport(Path.GetDirectoryName(binary)!,session,owner,new(IPAddress.Loopback,rawPort),false,0,null,"debug")) {
        foreach(var transport in new[]{outbound,second}) {
            using var application=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            byte[] payload=RandomNumberGenerator.GetBytes(1344);
            var incoming=destination.ReceiveAsync(token).AsTask();
            while(!incoming.IsCompleted){await application.SendAsync(payload,transport.ClientEndpoint!,token);await Task.WhenAny(incoming,Task.Delay(200,token));token.ThrowIfCancellationRequested();}
            var datagram=await incoming;Check(datagram.Buffer.SequenceEqual(payload),"Linux existing-entry client carries the full wire payload");
            await destination.SendAsync(payload,datagram.RemoteEndPoint,token);
            var answer=await application.ReceiveAsync(token);Check(answer.Buffer.SequenceEqual(payload),"Linux existing-entry return path preserves data");
        }
    }
    Check(!LinuxPlatform.Run("nft","list","tables").Contains("sl_"),"parallel existing-entry teardown removes only owned guards");
}
await EntryBackupTests.Run(Check);
await CoordinatorReliabilityTests.Run(Check);
await CoordinatorClientTests.Run(Check);
Console.WriteLine(JsonSerializer.Serialize(new{status="Pass",checks=count,scope=OperatingSystem.IsLinux()?"Linux isolated":"Windows loopback"}));

sealed class EmptyAdapter:IPacketAdapter
{
    public int Read(byte[] buffer){Thread.Sleep(5);return 0;}
    public bool Write(byte[] packet)=>true;
    public void Dispose(){}
}
sealed class FixtureTransport(IPEndPoint endpoint):IMeshTransport {
    public IPEndPoint? ClientEndpoint=>endpoint;public bool Disposed;public bool Exited=>Disposed;public void Dispose()=>Disposed=true;
}
