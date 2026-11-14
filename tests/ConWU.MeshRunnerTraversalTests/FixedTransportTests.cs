using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

static class FixedTransportTests
{
    public static async Task Run(Action<bool,string> check,CancellationToken token)
    {
        foreach(string mode in new[]{"faketcp","udp"}) {
            // Keep the signed network identity from the opposite legacy mode.
            // Settings must change eligibility without reissuing every member.
            var mesh=MeshIdentity.Create("https://example.com/","",mode=="udp"?"faketcp":"udp");
            var peer=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(mesh)));peer.Directory=mesh.Directory;
            var config=new DeviceProfile{Mesh=mesh};config.SelectTransport(mode+"-only");config.Validate();config.RequireFixedTransport();
            await using var router=new MeshRouter(mesh,new EmptyAdapter(),selection:config.Selection());
            using var socket=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback,0));
            bool rejected=false;
            try { router.SetCandidate(peer.Self.Slot,(IPEndPoint)socket.LocalEndPoint!,"peer",""); } catch(InvalidOperationException) { rejected=true; }
            check(rejected && !router.LegacyAllowed,mode+": opposite legacy candidate is rejected at router boundary");
            byte[] key=MeshIdentity.SharedKey(peer,mesh.Self);
            using var link=new MeshLink(peer.Self.Slot,mesh.Self.Slot,key);CryptographicOperations.ZeroMemory(key);
            socket.SendTo(link.Hello(),router.LocalEndpoint);
            for(int i=0;i<50 && router.Status().Single().LocalDrops!.ReceivePolicyRejected==0;i++)await Task.Delay(10,token);
            check(router.Status().Single().LocalDrops!.ReceivePolicyRejected>0 && !socket.Poll(10000,SelectMode.SelectRead) && !router.Status().Single().Connected,
                mode+": authenticated unsolicited legacy traffic cannot trigger a reply or promote another protocol");
            var factory=new FailingFactory();var discovery=new Discovery();
            await using var manager=new MeshTraversalManager(mesh,router,discovery,factory,new(),_=>{},token);
            var expected=mode=="udp"?TraversalProfile.UdpDirect:TraversalProfile.FakeTcpHttpSo;
            check(manager.Capabilities.Profiles.SequenceEqual(new[]{expected}),mode+": only selected protocol advertised even when factory offers both");
            var remote=new MeshTraversalCapabilities(1,1,Guid.NewGuid(),factory.Profiles,BackgroundUpgrade:1);
            var announced=new Dictionary<int,MeshAnnouncement>{[peer.Self.Slot]=new(peer.Self.Slot,peer.Self.Device,1,DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(),"","peer",remote)};
            for(int i=0;i<150;i++) { manager.Tick(announced,"");await Task.Delay(20,token); }
            check(factory.Attempts.Count>0 && factory.Attempts.All(p=>p==expected),mode+": preparation failures never fall back to the other protocol");
            var other=expected==TraversalProfile.UdpDirect?TraversalProfile.FakeTcpHttpSo:TraversalProfile.UdpDirect;
            announced[peer.Self.Slot]=announced[peer.Self.Slot] with{Traversal=remote with{Profiles=[other],NativeAbi=other==TraversalProfile.FakeTcpHttpSo?1:0}};
            for(int i=0;i<20;i++) { manager.Tick(announced,"");await Task.Delay(10,token); }
            check(manager.Progress(peer.Self.Slot,Environment.TickCount64) is {Phase:"Blocked",ReasonCode:"NoCommonTransport",CanRetry:false},mode+": incompatible peer displays an actionable protocol message instead of endless connecting");
        }
    }
    sealed class FailingFactory:IMeshCandidateFactory
    {
        public TraversalProfile[] Profiles=>[TraversalProfile.FakeTcpHttpSo,TraversalProfile.UdpDirect];
        public List<TraversalProfile> Attempts {get;}=[];
        public Task<IMeshCandidateResource> Gather(MeshMember peer,TraversalProfile profile,Guid attempt,CancellationToken token) {
            Attempts.Add(profile);return Task.FromException<IMeshCandidateResource>(new IOException("controlled preparation failure"));
        }
    }
    sealed class Discovery:IMeshTraversalDiscovery {
        public Guid BootId {get;}=Guid.NewGuid();public bool SupportsTraversal=>true;
        public Task PublishTraversal(MeshTraversalMessage[] messages,CancellationToken token)=>Task.CompletedTask;
    }
    sealed class EmptyAdapter:IPacketAdapter {
        public int Read(byte[] buffer) { Thread.Sleep(10);return 0; }
        public bool Write(byte[] packet)=>true;
        public void Dispose() { }
    }
}
