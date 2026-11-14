using System.Net;
using System.Net.Sockets;
using StreamLink.Core;
using StreamLink.Service;

// Isolate return-source filtering from the separate cryptographic admission
// tests. Every socket, frame and simulated native carrier belongs to this run.
static class SharedRouteEndpointChecks
{
    sealed class Carrier:IMeshTransport
    {
        public IPEndPoint? ClientEndpoint=>null;
        public bool Exited{get;private set;}
        public void Dispose()=>Exited=true;
    }
    public static async Task Run(Action<bool,string> check)
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(8));
        using var wire=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        using var router=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        using var unrelated=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        var mesh=MeshIdentity.Create("","","tcp",direct:true);
        byte[] initial=PairNetworkFrame.Wrap(mesh.Pair.Network,new byte[]{1,2,3,4});
        byte[] reply=PairNetworkFrame.Wrap(mesh.Pair.Network,new byte[]{5,6,7,8});
        IPEndPoint? ingress=null,routeEndpoint=null;
        string folder=Path.Combine(Path.GetTempPath(),"conwu-route-peer-"+Guid.NewGuid().ToString("N"));
        using var shared=new SharedMeshReceiver(folder);
        try{
            bool refused=false;
            try{shared.Acquire(new(folder,mesh,new(IPAddress.Parse("192.0.2.1"),12345),true,0,null,"off"),_=>throw new Exception("invalid target reached carrier factory"),_=>false,_=>true,_=>0);}
            catch(ArgumentException){refused=true;}
            check(refused,"shared receiver rejects a non-loopback local router before creating any carrier");
            using var lease=shared.Acquire(new(folder,mesh,(IPEndPoint)router.Client.LocalEndPoint!,true,0,null,"off"),request=>{
                ingress=request.Target;return new Carrier();
            },_=>false,frame=>frame.Span.SequenceEqual(initial),_=>0);
            await wire.SendAsync(initial,ingress!,deadline.Token);
            var incoming=await router.ReceiveAsync(deadline.Token);routeEndpoint=incoming.RemoteEndPoint;
            check(incoming.Buffer.SequenceEqual(initial),"shared route forwards the admitted network frame to its fixed local router");
            await unrelated.SendAsync(reply,routeEndpoint,deadline.Token);
            using(var quiet=new CancellationTokenSource(180)){
                bool denied=false;try{await wire.ReceiveAsync(quiet.Token);}catch(OperationCanceledException){denied=true;}
                check(denied,"another local UDP sender cannot impersonate the route's pinned router on the return path");
            }
            await router.SendAsync(reply,routeEndpoint,deadline.Token);
            check((await wire.ReceiveAsync(deadline.Token)).Buffer.SequenceEqual(reply),"legitimate router replies survive source filtering and preserve the complete network frame");
        }finally{shared.Dispose();if(Directory.Exists(folder))Directory.Delete(folder,true);}
        using var rebound=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp){ExclusiveAddressUse=true};
        rebound.Bind(routeEndpoint!);
        check(true,"shared receiver teardown joins the owned route and releases its exact UDP port");
    }
}
