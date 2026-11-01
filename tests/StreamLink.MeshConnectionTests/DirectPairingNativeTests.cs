using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    sealed class PairNativeProxy(int serverPort,IPEndPoint serverCarrier):IAsyncDisposable
    {
        readonly UdpClient socket=new(new IPEndPoint(IPAddress.Loopback,0));readonly CancellationTokenSource stop=new();Task? pump;IPEndPoint? client;
        public bool SawHttp{get;private set;} public int FromServer,FromClient,Forwarded;
        public int Port=>((IPEndPoint)socket.Client.LocalEndPoint!).Port;
        public void Start()=>pump=Run();
        async Task Run(){while(!stop.IsCancellationRequested){UdpReceiveResult r;try{r=await socket.ReceiveAsync(stop.Token);}catch(SocketException ex)when(ex.SocketErrorCode==SocketError.ConnectionReset){continue;}var p=r.Buffer;if(p.Length<28)continue;int h=(p[0]&15)*4;if(h<20||p.Length<h+8)continue;
            int target=BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(h+2));bool fromServer=r.RemoteEndPoint.Equals(serverCarrier);if(fromServer)FromServer++;else FromClient++;if(!fromServer&&target==serverPort)client=r.RemoteEndPoint;
            if(p.AsSpan().IndexOf("Host: test.ustc.edu.cn"u8)>=0)SawHttp=true;
            var to=fromServer?client:target==serverPort?serverCarrier:null;if(to!=null){await socket.SendAsync(p,to,stop.Token);Forwarded++;}
        }}
        public async ValueTask DisposeAsync(){stop.Cancel();if(pump!=null)try{await pump;}catch(OperationCanceledException){}socket.Dispose();stop.Dispose();}
    }
    static async Task DirectPairingNative(string binary,string folder,string mode="faketcp")
    {
        Directory.CreateDirectory(folder);var components=Path.Combine(Path.GetDirectoryName(binary)!,"direct-pair-test");Directory.CreateDirectory(components);File.Copy(binary,Path.Combine(components,"udp2raw-native.exe"),true);
        static int Port(){using var socket=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));return ((IPEndPoint)socket.Client.LocalEndPoint!).Port;}
        var owner=MeshIdentity.Create("","",mode,direct:true);using var host=new DirectPairHost();using var hostKey=new PairKeyExchange();using var guestKey=new PairKeyExchange();
        var ownerAdapter=new MemoryAdapter();await using var router=new MeshRouter(owner,ownerAdapter){DirectPairing=host.Handle};
        int listener=Port(),serverWire=Port();await using var proxy=new PairNativeProxy(listener,new(IPAddress.Loopback,serverWire));proxy.Start();
        Dictionary<string,string> Env(int port)=>new(){["STREAMLINK_TEST_BIND"]=port.ToString(),["STREAMLINK_TEST_PEER"]=proxy.Port.ToString()};
        using var nativeServer=new MeshTransport(components,folder,owner,router.LocalEndpoint,true,listener,null,"info",Env(serverWire));router.SetLegacyListenerControl(true);
        var ticket=await host.Create(hostKey,"native host",default);var temporary=MeshIdentity.Create("","",mode,direct:true);
        MeshProfile enrolled;
        using(var client=new DirectPairClient(_=>new MeshTransport(components,folder,temporary,new(IPAddress.Loopback,listener),false,0,null,"info",Env(Port())))){
            PairRoomTicket join;try{join=await client.Join(ticket.Code,guestKey,"native guest",default);}catch{Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new{proxy.FromServer,proxy.FromClient,proxy.Forwarded,proxy.SawHttp,stats=LegacyTransportLedger.Shared.Snapshot()}));throw;}
            await host.Reveal(ticket,true,hostKey,default);var state=await client.Reveal(join,false,guestKey,default);var ownerState=await host.Poll(ticket,true,default);
            var a=hostKey.Derive(ownerState.GuestPublic,ownerState.GuestCommitment,ticket.Room,join.Candidate,true);var b=guestKey.Derive(state.HostPublic,join.HostCommitment,join.Room,join.Candidate,false);
            Check(PairKeyExchange.Verification(a)==PairKeyExchange.Verification(b),"actual native "+mode+" carries direct short-code commitments and matching SAS without a coordinator");
            // Human approval can take longer than a native eight-second search window.
            await Task.Delay(9000);
            var invitation=DirectInvitation.Issue(owner,[new(0,"203.0.113.42:44680")]);router.ApplyDirectory(owner.Directory!);
            await host.Approve(ticket,join.Candidate,PairKeyExchange.EncryptInvitation(a,invitation,ticket.Room,join.Candidate),default);
            var approved=await client.Poll(join,false,default);
            enrolled=DirectInvitation.Import(PairKeyExchange.DecryptInvitation(b,approved.Ciphertext,ticket.Room,join.Candidate,DirectPairWire.MaximumCipher)).Mesh;
            Check(approved.Approved&&enrolled.Self.Slot==2&&(mode!="faketcp"||proxy.SawHttp),"native short pairing survives human approval delay and delivers the signed invitation in bounded chunks");
            CryptographicOperations.ZeroMemory(a);CryptographicOperations.ZeroMemory(b);
        }
        var adapter=new MemoryAdapter();await using var guestRouter=new MeshRouter(enrolled,adapter);
        using var nativeClient=new MeshTransport(components,folder,enrolled,new(IPAddress.Loopback,listener),false,0,null,"info",Env(Port()));
        guestRouter.SetCandidate(1,nativeClient.ClientEndpoint,"native host","",true);
        await Until(()=>router.HasHealthyPath(2)&&guestRouter.HasHealthyPath(1),"fresh per-device encrypted membership authenticates after short pairing over the same native listener",15000);
        adapter.Outgoing.Add(Packet(enrolled.LocalIp,owner.LocalIp));
        await Until(()=>router.Status().Single().ReceivedBytes>=1280,"full-MTU business traverses actual production MeshTransport after direct short pairing");
        using(var secondConversation=new UdpClient(new IPEndPoint(IPAddress.Loopback,0)))using(var thirdConversation=new UdpClient(new IPEndPoint(IPAddress.Loopback,0))){
            await Task.Delay(1100);
            var request=DirectPairWire.Encode(new DirectPairRequest(Guid.NewGuid().ToString("N"),"join",Code:ticket.Code,Commitment:guestKey.Commitment,Name:"limit check"));
            await secondConversation.SendAsync(request,nativeClient.ClientEndpoint!);using var allowed=new CancellationTokenSource(5000);await secondConversation.ReceiveAsync(allowed.Token);
            await thirdConversation.SendAsync(request,nativeClient.ClientEndpoint!);using var denied=new CancellationTokenSource(900);
            bool bounded=false;try{await thirdConversation.ReceiveAsync(denied.Token);}catch(OperationCanceledException){bounded=true;}
            Check(bounded,"public rendezvous carriage rejects a third conversation instead of allocating the legacy ten-thousand allowance");
        }
        adapter.Outgoing.Add(Packet(enrolled.LocalIp,owner.LocalIp));await Until(()=>router.Status().Single().ReceivedBytes>=2560,"bounded pre-membership attempts do not evict an established business conversation");
        Check(!nativeServer.Exited&&!nativeClient.Exited,"pre-enrollment service and business reuse one persistent native server");
        Console.WriteLine("PASS "+mode+" native direct short pairing; actual C++ protocol and parent control, loopback raw carrier only");
    }
}
