using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using StreamLink.Core;

if(args.Length>0&&args[0] is "serve" or "bench"){await StreamBench.Run(args);return;}
if(args is ["--formal-flow-node"]){await FormalFlowBench.Run();return;}
if(args is ["--linux-firewall"]){LinuxStreamFirewallChecks.Run();return;}
if(args is ["--router-bench",var routerMode,var routerMbps,var routerSeconds,var routerReport]){await RouterBench.Run(routerMode,int.Parse(routerMbps),int.Parse(routerSeconds),routerReport);return;}
if(args is ["--router-bench",var directionMode,var directionMbps,var directionSeconds,var directionReport,var direction]){await RouterBench.Run(directionMode,int.Parse(directionMbps),int.Parse(directionSeconds),directionReport,direction);return;}
var checks=new List<string>();
void Check(bool value,string name){if(!value)throw new Exception(name);checks.Add(name);Console.WriteLine("PASS "+name);}
if(args is ["--flow-lanes"]){await StreamFlowChecks.Run(Check);Console.WriteLine(JsonSerializer.Serialize(new{status="Pass",checks=checks.Count,cases=checks}));return;}
if(args is ["--mapping-recovery"]){await StreamMappingRecoveryChecks.Run(Check);Console.WriteLine(JsonSerializer.Serialize(new{status="Pass",checks=checks.Count,cases=checks}));return;}
if(args is ["--mapping-race"]){await StreamMappingRaceChecks.Run(Check);Console.WriteLine(JsonSerializer.Serialize(new{status="Pass",checks=checks.Count,cases=checks}));return;}
foreach(var mode in new[]{"faketcp","udp","tcp","https"}){
    var text=CompactDirectCode.Issue("203.0.113.42:44680",mode,"123456");var decoded=CompactDirectCode.Import(text.ToLowerInvariant());
    Check(text.Length==19&&decoded.Mode==mode&&decoded.RoomCode=="123456",mode+" retains sixteen-symbol code with an unambiguous protocol");
    var profile=new DeviceProfile();profile.SelectTransport(TransportModes.Policy(mode));profile.RequireFixedTransport();profile.Validate();
    Check(profile.TransportMode==mode&&!profile.AllowUdpFallback,mode+" settings retain the exact selected protocol");
}
foreach(string mode in new[]{"tcp","https"}){
    using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using var certificate=StreamCertificates.CreateServer(key,DateTimeOffset.UtcNow.AddDays(1));
    var owner=MeshIdentity.Create("","",mode,direct:true,pairwise:true);
    if(mode=="https")owner.Pair=owner.Pair with{TransportKeyPin=StreamMeshTransport.CertificatePin(certificate)};
    using var hostPair=new DirectPairHost();using var hostKey=new PairKeyExchange();using var guestKey=new PairKeyExchange();
    var hostAdapter=new MemoryAdapter();await using var hostRouter=new MeshRouter(owner,hostAdapter,selection:new(mode=="tcp"?PathPolicy.TcpOnly:PathPolicy.HttpsOnly)){DirectPairing=hostPair.Handle};
    int port=FreePort();int accessOpened=0,accessClosed=0;
    await using(var listener=new StreamMeshTransport(owner,hostRouter.LocalEndpoint,true,port,()=>certificate,allowListener:()=>{accessOpened++;return new Release(()=>accessClosed++);})){
        var endpoint=new IPEndPoint(IPAddress.Loopback,port);
        var temporary=MeshIdentity.Create("","",mode,direct:true);
        StreamMeshTransport? boot=null;
        using var guestPair=new DirectPairClient(_=>boot=new StreamMeshTransport(temporary,endpoint,false,0,pairingBootstrap:true));
        using var timeout=new CancellationTokenSource(20000);
        var room=await hostPair.Create(hostKey,"Host",timeout.Token);
        PairRoomTicket ticket;
        try{ticket=await guestPair.Join(room.Code,guestKey,"Guest",timeout.Token);}catch(Exception error){throw new IOException($"{mode} pairing: client={boot?.FailureReason}; listener={listener.LastConnectionFailure}",error);}
        var initial=await hostPair.Poll(room,true,timeout.Token);
        Check(!initial.Approved&&owner.Directory!.Members.Length==1&&hostAdapter.Incoming.IsEmpty,mode+" pre-pairing access grants no membership or data-plane traffic");
        await hostPair.Reveal(room,true,hostKey,timeout.Token);
        var guestState=await guestPair.Poll(ticket,false,timeout.Token);
        PairKeyExchange.ValidateState(ticket,null,guestState,guestKey,false);
        guestState=await guestPair.Reveal(ticket,false,guestKey,timeout.Token);
        var hostState=await hostPair.Poll(room,true,timeout.Token);
        PairKeyExchange.ValidateState(room,initial,hostState,hostKey,true);
        byte[] hostShared=hostKey.Derive(hostState.GuestPublic,hostState.GuestCommitment,room.Room,ticket.Candidate,true);
        byte[] guestShared=guestKey.Derive(guestState.HostPublic,ticket.HostCommitment,ticket.Room,ticket.Candidate,false);
        Check(PairKeyExchange.Verification(hostShared)==PairKeyExchange.Verification(guestShared),mode+" actual socket pairing derives matching user verification codes");
        string advertised="203.0.113.42:"+port;
        var settings=new UiNetworkSettings(PathSelection:TransportModes.Policy(mode)){ConnectionSource="existing",DirectMode=true,DiscoveryMode="existing",ExistingEntries=[new(0,advertised)]};
        string invitation=DirectInvitation.Issue(owner,[new(0,advertised)]);
        string enrollment=NetworkEntryEnrollment.Encode(invitation,[new(1,advertised)],ApprovedNetworkSettings.Create(owner,settings,"stream fixture"));
        await hostPair.Approve(room,ticket.Candidate,PairKeyExchange.EncryptInvitation(hostShared,enrollment,room.Room,ticket.Candidate),timeout.Token);
        var approved=await guestPair.Poll(ticket,false,timeout.Token);
        var received=NetworkEntryEnrollment.ImportSettings(PairKeyExchange.DecryptInvitation(guestShared,approved.Ciphertext,room.Room,ticket.Candidate,DirectPairWire.MaximumCipher));
        var inherited=received.Settings!.ForGuest(received.Mesh,new());
        Check(inherited.PathSelection==TransportModes.Policy(mode)&&received.Mesh.Pair.Mode==mode,mode+" encrypted approval carries the protocol, host settings and network identity");
        if(mode=="https")Check(guestPair.PeerCertificatePin==received.Mesh.Pair.TransportKeyPin,"HTTPS bootstrap certificate matches the identity delivered in approved enrollment");
        CryptographicOperations.ZeroMemory(hostShared);CryptographicOperations.ZeroMemory(guestShared);
        guestPair.Dispose();hostRouter.ApplyDirectory(owner.Directory!);
        var guestAdapter=new MemoryAdapter();await using var guestRouter=new MeshRouter(received.Mesh,guestAdapter,selection:new(mode=="tcp"?PathPolicy.TcpOnly:PathPolicy.HttpsOnly));
        await using(var client=new StreamMeshTransport(received.Mesh,endpoint,false,0)){
            guestRouter.SetCandidate(1,client.ClientEndpoint,"Host","");
            await Until(()=>guestRouter.Status().Single().Connected&&hostRouter.Status().Single().Connected,mode+" authenticated bidirectional path");
            byte[] toHost=Packet(received.Mesh.LocalIp,owner.LocalIp,1280),toGuest=Packet(owner.LocalIp,received.Mesh.LocalIp,1280);toHost[^1]=17;toGuest[^1]=29;
            guestAdapter.Outgoing.Add(toHost);hostAdapter.Outgoing.Add(toGuest);
            await Until(()=>hostAdapter.Incoming.Any(p=>p.SequenceEqual(toHost))&&guestAdapter.Incoming.Any(p=>p.SequenceEqual(toGuest)),mode+" both directions preserve complete virtual-IP packets");
            var hostBurst=new List<byte[]>();var guestBurst=new List<byte[]>();
            for(int index=0;index<96;index++){
                int size=index%2==0?52:MeshLink.Mtu;
                byte[] outbound=Packet(owner.LocalIp,received.Mesh.LocalIp,size),inbound=Packet(received.Mesh.LocalIp,owner.LocalIp,size);
                outbound.AsSpan(28).Fill((byte)index);inbound.AsSpan(28).Fill((byte)(index+96));
                hostBurst.Add(outbound);guestBurst.Add(inbound);
                hostAdapter.Outgoing.Add(outbound);guestAdapter.Outgoing.Add(inbound);
            }
            await Until(()=>hostAdapter.Incoming.Count>=97&&guestAdapter.Incoming.Count>=97,mode+" bidirectional mixed-size burst is delivered");
            Check(hostAdapter.Incoming.Count==97&&guestAdapter.Incoming.Count==97&&hostAdapter.Incoming.Skip(1).Zip(guestBurst).All(pair=>pair.First.SequenceEqual(pair.Second))&&
                guestAdapter.Incoming.Skip(1).Zip(hostBurst).All(pair=>pair.First.SequenceEqual(pair.Second)),
                mode+" reused routing buffers preserve every mixed-size payload and its network in both directions");
            Check(hostRouter.Status().Single().ActualTransport==(mode=="tcp"?"TCP":"HTTPS"),mode+" actual transport status identifies the real carrier");
            if(mode=="https"){
                Check(client.TlsProtocol is "Tls12" or "Tls13","HTTPS records the negotiated real TLS version");
                var wrong=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(MeshIdentity.Create("","","https",direct:true,pairwise:true))));
                wrong.Pair=wrong.Pair with{TransportKeyPin=new string('0',64)};
                await using var rejected=new StreamMeshTransport(wrong,endpoint,false,0);
                await Until(()=>rejected.Exited,"wrong TLS key is rejected");
                Check(rejected.FailureReason.Contains("AuthenticationException"),"HTTPS refuses a mismatched paired certificate");
                using var textSocket=new ClientWebSocket();textSocket.Options.Proxy=null;textSocket.Options.AddSubProtocol("conwu.stream.v1");
                textSocket.Options.RemoteCertificateValidationCallback=(_,cert,_,_)=>cert!=null&&cert.GetCertHashString()==certificate.GetCertHashString();
                await textSocket.ConnectAsync(new Uri($"wss://127.0.0.1:{port}/conwu/stream"),timeout.Token);
                await textSocket.SendAsync(new byte[]{65},WebSocketMessageType.Text,true,timeout.Token);
                bool refused=false;try{await textSocket.ReceiveAsync(new byte[16],timeout.Token);}catch(WebSocketException){refused=true;}
                Check(refused&&!listener.Exited&&guestRouter.Status().Single().Connected,"invalid HTTPS messages close only their connection and preserve established peers");
            }else{
                using var malformed=new TcpClient();await malformed.ConnectAsync(endpoint,timeout.Token);
                await malformed.GetStream().WriteAsync(new byte[]{255,255},timeout.Token);
                Check(await malformed.GetStream().ReadAsync(new byte[1],timeout.Token)==0&&!listener.Exited,"oversized TCP frames are rejected without stopping the listener");
            }
        }
    }
    Check(accessOpened==1&&accessClosed==1,mode+" listener access is released once with its owner");
    var reused=new TcpListener(IPAddress.Loopback,port);reused.Start();reused.Stop();Check(true,mode+" listening port is immediately reusable after shutdown");
}
await StreamMappingChecks.Run(Check);
await StreamMappingRecoveryChecks.Run(Check);
await StreamMappingRaceChecks.Run(Check);
await SharedStreamChecks.Run(Check);
await SharedRouteEndpointChecks.Run(Check);
await StreamSecurityChecks.Run(Check);
await StreamBatchChecks.Run(Check);
await StreamFlowChecks.Run(Check);
StreamIdentityChecks.Run(Check);
await RunnerStreamChecks.Run(Check);
await ControlPairStreamChecks.Run(Check);
Console.WriteLine(JsonSerializer.Serialize(new{status="Pass",checks=checks.Count,cases=checks}));

static int FreePort(){var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();return port;}
static async Task Until(Func<bool> ready,string name){using var timeout=new CancellationTokenSource(10000);try{while(!ready())await Task.Delay(25,timeout.Token);}catch(OperationCanceledException){throw new IOException("Timed out: "+name);}}
static byte[] Packet(string from,string to,int size){byte[] p=new byte[size];p[0]=0x45;p[8]=64;p[9]=17;BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2),(ushort)size);IPAddress.Parse(from).GetAddressBytes().CopyTo(p,12);IPAddress.Parse(to).GetAddressBytes().CopyTo(p,16);BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20),45123);BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22),45124);BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(24),(ushort)(size-20));uint sum=0;for(int i=0;i<20;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i));while(sum>65535)sum=(sum&65535)+(sum>>16);BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10),(ushort)~sum);return p;}
sealed class Release(Action action):IDisposable {public void Dispose()=>action();}
sealed class MemoryAdapter:IPacketAdapter
{
    public readonly BlockingCollection<byte[]> Outgoing=new();public readonly ConcurrentQueue<byte[]> Incoming=new();
    public int Read(byte[] buffer){if(!Outgoing.TryTake(out var packet,50))return 0;packet.CopyTo(buffer,0);return packet.Length;}
    public bool Write(byte[] packet){Incoming.Enqueue(packet);return true;}
    public void Dispose()=>Outgoing.CompleteAdding();
}
