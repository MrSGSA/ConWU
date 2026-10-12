using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

static class UdpExplorationAdmissionTests
{
    public static async Task Run(Action<bool,string> check,CancellationToken token)
    {
        var mesh=MeshIdentity.Create("https://example.com/","","faketcp");var peer=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(mesh))).Self;
        var config=new DeviceProfile{Mesh=mesh,TraversalMode="tcp-udp",AllowUdpFallback=true,UdpExploration=true};
        int resolutions=0,opened=0;await using var factory=new MeshCandidateFactory(config,"unused","unused",[TraversalProfile.UdpDirect]){
            ResolveTarget=(_,_,_)=>{resolutions++;return Task.FromResult(IPEndPoint.Parse("192.0.2.9:3478"));},
            OpenExplorationSocketForTest=_=>{opened++;throw new IOException();}
        };
        long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // No packet is sent to this address: these cases must exit before DNS
        // or allocation. A globally routable input isolates permission/health
        // checks from the separate non-public-address rejection below.
        var stable=new MeshTraversalCandidate(Guid.NewGuid(),1,"8.8.8.8:43000",null,now,now+12,CandidatePurpose.UdpDirect,
            Exploration:new(true,Guid.NewGuid(),"public-local",now,"",""));
        async Task Reject(Func<Task<IMeshCandidateResource>> run,string why){bool rejected=false;try{await using var unused=await run();}catch(IOException){rejected=true;}check(rejected&&resolutions==0&&opened==0,why);}
        Task<IMeshCandidateResource> Gather(bool allowed,Func<bool> healthy,MeshTraversalCandidate c,TraversalProfile p=TraversalProfile.UdpDirect)=>factory.GatherEnhanced(peer,p,Guid.NewGuid(),false,c,2,false,false,allowed,healthy,token);
        await Reject(()=>Gather(false,()=>true,stable),"missing bilateral/server permission rejects exploration before DNS or source allocation");
        await Reject(()=>Gather(true,()=>false,stable),"healthy target rejects expensive exploration before any source allocation");
        await Reject(()=>Gather(true,()=>true,stable,TraversalProfile.FakeTcpHttpSo),"UDP enhancement cannot authorize a TCP factory path");
        await Reject(()=>Gather(true,()=>true,stable with{Endpoint="[2001:db8::1]:43000"}),"IPv6 cannot use the IPv4 probability factory");
        config.UdpExploration=false;await Reject(()=>Gather(true,()=>true,stable),"local opt-out refuses remote UDP source expansion");
        config.UdpExploration=true;
        foreach(string endpoint in new[]{"127.0.0.1:43000","10.0.0.1:43000","100.64.0.1:43000","192.0.2.1:43000"})
            await Reject(()=>Gather(true,()=>true,stable with{Endpoint=endpoint}),
                "production source expansion rejects loopback/private/CGN/documentation targets before DNS or allocation: "+endpoint);
        int routeAllocations=0;
        await using var badRoute=new MeshCandidateFactory(new DeviceProfile{Mesh=mesh,TraversalMode="tcp-udp",AllowUdpFallback=true,UdpExploration=true},"unused","unused",[TraversalProfile.UdpDirect]){
            ResolveTarget=(_,_,_)=>Task.FromResult(UdpExplorationNatWire.Reflector),RouteCheckForTest=(_,_,_)=>throw new IOException("physical route unavailable"),
            OpenExplorationSocketForTest=_=>{routeAllocations++;throw new IOException();}};
        bool routeRejected=false;try{await using var unused=await badRoute.GatherEnhanced(peer,TraversalProfile.UdpDirect,Guid.NewGuid(),false,stable,2,false,false,true,()=>true,token);}catch(IOException){routeRejected=true;}
        check(routeRejected&&routeAllocations==0,"all rejected physical routes leave no remembered target and never allocate a source");
        var unknownConfig=new DeviceProfile{Mesh=mesh,TraversalMode="tcp-udp",AllowUdpFallback=true,UdpExploration=true};
        var unknownWire=new UdpExplorationNatWire(0);var unknownBudget=new TraversalResources();
        await using var unknown=new MeshCandidateFactory(unknownConfig,"unused","unused",[TraversalProfile.UdpDirect]){
            ExplorationBudgetForTest=unknownBudget,ResolveTarget=(_,_,_)=>Task.FromResult(UdpExplorationNatWire.Reflector),
            RouteCheckForTest=(_,_,_)=>{},OpenExplorationSocketForTest=_=>unknownWire.Open(1)};
        var hard=stable with{Exploration=new(false,Guid.Empty,"",0,"43000","")};
        bool noProof=false;try{await using var unused=await unknown.GatherEnhanced(peer,TraversalProfile.UdpDirect,Guid.NewGuid(),false,hard,2,false,false,true,()=>true,token);}
        catch(IOException e)when(e.Message.Contains("UdpStableEndpointUnavailable")){noProof=true;}
        check(noProof&&unknownWire.Sources.Length==1&&unknownWire.Sources.All(p=>p.Closed)&&unknownBudget.Usage().OpenUdpResources==0,
            "two unqualified private-source roles return an explicit failure after one observation, without expanding or scanning");

        await using var reflector=new UdpReflector();var machine=new TraversalResources();var generation=Guid.NewGuid();var attempt=Guid.NewGuid();byte[] key=RandomNumberGenerator.GetBytes(32);
        await using var node=UdpTraversal.CreateUsing(()=>new TraversalSocket(new(IPAddress.Loopback,0)),generation,attempt,1,2,key,machine);
        await using var seed=new UdpExplorationSeed(node,machine);
        var observation=await node.Observe(reflector.Endpoint,token);
        check(observation.SocketId==node.SocketId&&seed.Round.Packets==1&&seed.Round.Bytes==20&&seed.Began>0,
            "actual Windows UDP STUN charges the seed's shared ledger and begins its only observation clock");
        bool invalid=false;try{UdpStableSourceEvidence.PublicLocal(node,generation,[observation],true);}catch(IOException){invalid=true;}
        check(invalid,"single loopback or private STUN observation cannot claim native public stability");
        var proof=UdpStableSourceEvidence.PeerPorts(node,generation,reflector.Endpoint.Address,[reflector.Endpoint.Port],[observation]);
        proof.Require(node,generation,observation.Mapped,reflector.Endpoint.Address,[reflector.Endpoint.Port]);
        check(proof.Description.EvidenceId!=node.SocketId,"published proof ID never exposes the local socket resource identity");
        invalid=false;try{proof.Require(node,Guid.NewGuid(),observation.Mapped,reflector.Endpoint.Address,[reflector.Endpoint.Port]);}catch(IOException){invalid=true;}
        check(invalid,"stability proof cannot cross an egress/resource generation");
        invalid=false;try{UdpStableSourceEvidence.PeerPorts(node,generation,reflector.Endpoint.Address,[reflector.Endpoint.Port,reflector.Endpoint.Port+1],[observation]);}catch(IOException){invalid=true;}
        check(invalid,"one peer port cannot authorize a larger guess set");
        invalid=false;try{UdpStableSourceEvidence.PeerPorts(node,generation,reflector.Endpoint.Address,[reflector.Endpoint.Port],[observation with{Protocol="tcp"}]);}catch(IOException){invalid=true;}
        check(invalid,"TCP observations cannot qualify a UDP endpoint");
        var context=new TraversalAttemptContext(mesh.Pair.Network,mesh.Self.Device,Guid.NewGuid(),peer.Device,Guid.NewGuid(),attempt,
            Guid.NewGuid(),1,Guid.NewGuid(),1,TraversalProfile.UdpDirect,true,true,Guid.NewGuid(),true);
        var scope=new TraversalEnhancementScope(context.NetworkId,context.LocalNodeId,context.RemoteNodeId,generation);
        using var held=machine.Enhancements.TryEnter(scope,TraversalEnhancementKind.TcpCalibration)!;
        using var cancelled=CancellationTokenSource.CreateLinkedTokenSource(token);
        var pending=UdpProbabilityPreparation.CreateForSeed(seed,context,generation,key,false,IPAddress.Loopback,reflector.Endpoint,[],32,_=>{opened++;throw new IOException();},cancelled.Token);
        cancelled.Cancel();invalid=false;try{await using var unwanted=await pending;}catch(OperationCanceledException){invalid=true;}
        check(invalid&&opened==0&&machine.Usage().OpenUdpResources==1,"queue cancellation never opens extra sockets or closes the held seed");
        held.Dispose();invalid=false;
        try{await using var unwanted=await UdpProbabilityPreparation.CreateForSeed(seed,context,generation,key,false,IPAddress.Loopback,reflector.Endpoint,[],32,
            _=>{opened++;throw new IOException();},token,()=>false);}catch(IOException){invalid=true;}
        check(invalid&&opened==0&&machine.Usage().OpenUdpResources==1,"post-admission health recheck cancels expansion while preserving seed ownership");
        CryptographicOperations.ZeroMemory(key);
    }
    internal sealed class UdpReflector:IAsyncDisposable{
        readonly UdpClient socket=new(new IPEndPoint(IPAddress.Loopback,0));readonly CancellationTokenSource stop=new();readonly Task pump;
        public IPEndPoint Endpoint=>(IPEndPoint)socket.Client.LocalEndPoint!;
        public UdpReflector(){pump=Run();}
        async Task Run(){while(!stop.IsCancellationRequested){var input=await socket.ReceiveAsync(stop.Token);var p=new byte[32];input.Buffer.AsSpan(0,20).CopyTo(p);p[0]=1;p[1]=1;p[3]=12;p[21]=0x20;p[23]=8;p[25]=1;
            BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(26),(ushort)(input.RemoteEndPoint.Port^0x2112));BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(28),BinaryPrimitives.ReadUInt32BigEndian(input.RemoteEndPoint.Address.GetAddressBytes())^0x2112a442);await socket.SendAsync(p,input.RemoteEndPoint,stop.Token);}}
        public async ValueTask DisposeAsync(){stop.Cancel();try{await pump;}catch(OperationCanceledException){}socket.Dispose();stop.Dispose();}
    }
}
