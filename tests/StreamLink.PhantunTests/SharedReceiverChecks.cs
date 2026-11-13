using System.Net;
using System.Net.Sockets;
using StreamLink.Core;
using StreamLink.Service;

static class SharedReceiverChecks
{
    sealed class Carrier:IMeshTransport,IMeshCarrierRoutes
    {
        public IPEndPoint? ClientEndpoint=>null;
        public bool Exited{get;private set;}
        public event Action<IPEndPoint>? RouteClosed;
        public event Action<IPEndPoint>? RouteOpened;
        public void Open(IPEndPoint peer)=>RouteOpened?.Invoke(peer);
        public void Close(IPEndPoint peer)=>RouteClosed?.Invoke(peer);
        public void Dispose()=>Exited=true;
    }
    static Socket Udp(){var s=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);s.Bind(new IPEndPoint(IPAddress.Loopback,0));return s;}
    static async Task<byte[]?> Receive(Socket socket,int milliseconds=1000){
        byte[] buffer=new byte[2048];using var stop=new CancellationTokenSource(milliseconds);
        try{int size=await socket.ReceiveAsync(buffer,SocketFlags.None,stop.Token);return buffer[..size];}
        catch(OperationCanceledException){return null;}
    }
    public static async Task Run(Action<bool,string> check)
    {
        string folder=Path.Combine(Path.GetTempPath(),"conwu-phantun-mux-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try{
            var owners=Enumerable.Range(0,2).Select(_=>MeshIdentity.Create("","","phantun",direct:true,pairwise:true)).ToArray();
            var guests=owners.Select(owner=>MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)))).ToArray();
            using var first=Udp();using var second=Udp();using var sender=Udp();
            using var shared=new SharedMeshReceiver(folder);
            int starts=0;Carrier? carrier=null;IPEndPoint? ingress=null;
            IMeshTransport Factory(MeshTransportRequest request){starts++;ingress=request.Target;return carrier=new();}
            var one=shared.Acquire(new(folder,owners[0],(IPEndPoint)first.LocalEndPoint!,true,49197,null,"off"),Factory,_=>false,p=>PairNetworkFrame.Authenticated(owners[0],p.Span),_=>0);
            var two=shared.Acquire(new(folder,owners[1],(IPEndPoint)second.LocalEndPoint!,true,49197,null,"off"),Factory,_=>false,p=>PairNetworkFrame.Authenticated(owners[1],p.Span),_=>0);
            check(starts==1,"two Phantun networks share one native listener");
            var member=owners[0].Directory!.Members.Single(m=>m.Slot==guests[0].Self.Slot);
            using var link=new MeshLink(guests[0].Self.Slot,owners[0].Self.Slot,MeshIdentity.SharedKey(guests[0],guests[0].Directory!.Members.Single(m=>m.Slot==owners[0].Self.Slot)));
            var endpoint=(IPEndPoint)sender.LocalEndPoint!;
            for(int round=0;round<10;round++){
                carrier!.Open(endpoint);
                byte[] frame=PairNetworkFrame.Wrap(owners[0].Pair.Network,link.Hello());
                await sender.SendToAsync(frame,SocketFlags.None,ingress!);
                check((await Receive(first))?.SequenceEqual(frame)==true,"authenticated carrier reopen "+round);
                carrier.Close(endpoint);
                await sender.SendToAsync(frame,SocketFlags.None,ingress!);
                check(await Receive(first,120)==null,"queued packet after close cannot resurrect route "+round);
            }
            carrier!.Open(endpoint);
            byte[] wrong=PairNetworkFrame.Wrap(owners[1].Pair.Network,link.Hello());
            await sender.SendToAsync(wrong,SocketFlags.None,ingress!);
            check(await Receive(second,150)==null,"forged network header cannot cross authenticated networks");
            one.Dispose();check(!carrier.Exited,"removing one network keeps shared listener alive");
            two.Dispose();check(carrier.Exited,"last network releases listener");
        }finally{if(Directory.Exists(folder))Directory.Delete(folder,true);}
    }
}
