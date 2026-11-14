using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task SharedReceiverRouteProtection()
    {
        var owner=MeshIdentity.Create("","","faketcp",direct:true,pairwise:true);var guest=Guest(owner);
        byte[] signed=PairNetworkFrame.Wrap(owner.Pair.Network,MeshEntryHandshake.Request(guest).Frame);
        string folder=Path.Combine(Path.GetTempPath(),"conwu-route-"+Guid.NewGuid().ToString("N"));
        using var echo=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        using var stop=new CancellationTokenSource();var observed=new ConcurrentQueue<IPEndPoint>();
        var pump=Task.Run(async()=>{try{while(!stop.IsCancellationRequested){var p=await echo.ReceiveAsync(stop.Token);observed.Enqueue(p.RemoteEndPoint);await echo.SendAsync(p.Buffer,p.RemoteEndPoint,stop.Token);}}catch(OperationCanceledException)when(stop.IsCancellationRequested){}});
        IPEndPoint? ingress=null;
        using var receiver=new SharedMeshReceiver(folder);
        using var subscription=receiver.Acquire(new(folder,owner,(IPEndPoint)echo.Client.LocalEndPoint!,true,45200,null,"off"),r=>{ingress=r.Target;return new StubTransport(null);},_=>false,p=>PairNetworkFrame.Authenticated(owner,p.Span),_=>0);
        var clients=new List<UdpClient>();
        async Task<bool> Exchange(UdpClient client){await client.SendAsync(signed,ingress!);using var deadline=new CancellationTokenSource(300);try{await client.ReceiveAsync(deadline.Token);return true;}catch(OperationCanceledException){return false;}}
        try{
            for(int i=0;i<4;i++){
                var client=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));clients.Add(client);
                Check(await Exchange(client),"authenticated carrier route is established within the per-network budget");await Task.Delay(130);
            }
            var original=observed.First();
            using var extra=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            Check(!await Exchange(extra),"an authenticated replay from a fifth carrier cannot evict an existing business route");
            Check(await Exchange(clients[0])&&observed.Last().Equals(original),"the original healthy carrier retains its exact return socket after replay pressure");
        }finally{
            foreach(var client in clients)client.Dispose();subscription.Dispose();receiver.Dispose();stop.Cancel();await pump;
            if(Directory.Exists(folder))Directory.Delete(folder,true);
        }
    }
}
