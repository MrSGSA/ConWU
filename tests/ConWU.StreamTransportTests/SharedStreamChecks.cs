using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

static class SharedStreamChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        foreach(string mode in new[]{"tcp","https"}){
            string folder=Path.Combine(Path.GetTempPath(),"conwu-shared-stream-"+Guid.NewGuid().ToString("N"));
            using var signing=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var certificate=StreamCertificates.CreateServer(signing,DateTimeOffset.UtcNow.AddDays(1));
            var hosts=Enumerable.Range(0,2).Select(_=>MeshIdentity.Create("","",mode,direct:true,pairwise:true)).ToArray();
            if(mode=="https")foreach(var host in hosts)host.Pair=host.Pair with{TransportKeyPin=StreamMeshTransport.CertificatePin(certificate)};
            var guests=hosts.Select(h=>MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(h)))).ToArray();
            var sinks=hosts.Select(_=>new MemoryAdapter()).ToArray();
            var routers=hosts.Select((h,i)=>new MeshRouter(h,sinks[i])).ToArray();
            int port=FreePort(),listeners=0;using var shared=new SharedMeshReceiver(folder);
            var leases=hosts.Select((h,i)=>shared.Acquire(new(folder,h,routers[i].LocalEndpoint,true,port,null,"off"),r=>{listeners++;return new StreamMeshTransport(r.Mesh,r.Target,true,port,()=>certificate);},_=>false,p=>PairNetworkFrame.Authenticated(h,p.Span),_=>0)).ToArray();
            try{
                check(listeners==1,mode+" two independent networks share exactly one real TCP listener");
                for(int i=0;i<2;i++){
                    using var socket=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
                    await using var client=new StreamMeshTransport(guests[i],new(IPAddress.Loopback,port),false,0);
                    byte[] authenticated=PairNetworkFrame.Wrap(hosts[i].Pair.Network,MeshEntryHandshake.Request(guests[i]).Frame);
                    byte[] forged=authenticated.ToArray();forged[^1]^=1;
                    using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(4));
                    await socket.SendAsync(forged,client.ClientEndpoint!,deadline.Token);
                    using(var quiet=new CancellationTokenSource(200)){
                        bool silent=false;try{await socket.ReceiveAsync(quiet.Token);}catch(OperationCanceledException){silent=true;}
                        check(silent,mode+" a forged network handshake cannot establish a shared return route");
                    }
                    await socket.SendAsync(authenticated,client.ClientEndpoint!,deadline.Token);
                    var reply=await socket.ReceiveAsync(deadline.Token);
                    check(PairNetworkFrame.Network(reply.Buffer)==hosts[i].Pair.Network,mode+" shared receiver returns the authenticated response only for its selected network");
                    var wrongNetwork=PairNetworkFrame.Wrap(hosts[1-i].Pair.Network,authenticated.AsSpan(PairNetworkFrame.HeaderSize));
                    await socket.SendAsync(wrongNetwork,client.ClientEndpoint!,deadline.Token);
                    using var silence=new CancellationTokenSource(200);bool denied=false;
                    try{await socket.ReceiveAsync(silence.Token);}catch(OperationCanceledException){denied=true;}
                    check(denied&&sinks.All(s=>s.Incoming.IsEmpty),mode+" a valid credential cannot cross into another network or inject business packets");
                }
                leases[0].Dispose();check(!leases[1].Exited,mode+" leaving one network preserves the other network's listener");
            }finally{
                foreach(var lease in leases)lease.Dispose();shared.Dispose();foreach(var router in routers)await router.DisposeAsync();
                if(Directory.Exists(folder))Directory.Delete(folder,true);
            }
        }
    }
    static int FreePort(){var l=new TcpListener(IPAddress.Loopback,0);l.Start();int p=((IPEndPoint)l.LocalEndpoint).Port;l.Stop();return p;}
}
