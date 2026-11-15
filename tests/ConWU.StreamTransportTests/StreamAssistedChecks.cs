using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;

static class StreamAssistedChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        foreach(string mode in new[]{"tcp","https"}){
            using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var certificate=StreamCertificates.CreateServer(key,DateTimeOffset.UtcNow.AddDays(1));
            var owner=MeshIdentity.Create("","",mode,direct:true,pairwise:true);
            if(mode=="https")owner.Pair=owner.Pair with{TransportKeyPin=StreamMeshTransport.CertificatePin(certificate)};
            var guest=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));owner.Directory=guest.Directory;
            using var deadline=new CancellationTokenSource(12000);var token=deadline.Token;
            await using var left=new MeshRouter(owner,new MemoryAdapter());await using var right=new MeshRouter(guest,new MemoryAdapter());
            var a=new Source(FreePort());var b=new Source(FreePort());
            while(b.LocalEndpoint.Port==a.LocalEndpoint.Port)b=new Source(FreePort());
            await using var host=new StreamMeshTransport(owner,left.LocalEndpoint,true,a.LocalEndpoint.Port,()=>certificate,sourceMapping:a);
            await using var client=new StreamMeshTransport(guest,right.LocalEndpoint,true,b.LocalEndpoint.Port,sourceMapping:b);
            await host.PreparePunch(b.LocalEndpoint,false,token);await client.PreparePunch(a.LocalEndpoint,true,token);
            await host.StartPunch(b.LocalEndpoint,left.AssistanceGreeting(guest.Self.Slot),token);
            await client.StartPunch(a.LocalEndpoint,right.AssistanceGreeting(owner.Self.Slot),token);
            try{while(!left.HasHealthyPath(guest.Self.Slot)||!right.HasHealthyPath(owner.Self.Slot))await Task.Delay(20,token);}
            catch(OperationCanceledException){throw new IOException(mode+" fixed source active-open failed: host="+host.LastConnectionFailure+"; guest="+client.LastConnectionFailure);}
            check(!host.Exited&&!client.Exited,mode+" fixed-source listeners actively connect and establish both real AEAD routes");
            if(mode=="https")check(client.PeerCertificatePin==owner.Pair.TransportKeyPin,"HTTPS keeps host TLS identity when both participants actively open");
        }
        // A paired HTTPS client must reject a wrong pin even when the physical
        // connection was initiated by the logical TLS server (the host).
        using var wrongKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongCertificate=StreamCertificates.CreateServer(wrongKey,DateTimeOffset.UtcNow.AddDays(1));
        var owner2=MeshIdentity.Create("","","https",direct:true,pairwise:true);
        owner2.Pair=owner2.Pair with{TransportKeyPin=new string('0',64)};
        var guest2=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner2)));
        using var sink=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        var sa=new Source(FreePort());var sb=new Source(FreePort());
        await using var h=new StreamMeshTransport(owner2,(IPEndPoint)sink.Client.LocalEndPoint!,true,sa.LocalEndpoint.Port,()=>wrongCertificate,sourceMapping:sa);
        await using var g=new StreamMeshTransport(guest2,(IPEndPoint)sink.Client.LocalEndPoint!,true,sb.LocalEndpoint.Port,sourceMapping:sb);
        await h.StartPunch(sb.LocalEndpoint,ReadOnlyMemory<byte>.Empty,CancellationToken.None);
        using(var timeout=new CancellationTokenSource(10000))while(g.LastConnectionFailure.Length==0)await Task.Delay(20,timeout.Token);
        check(g.PeerCertificatePin.Length==0&&g.LastConnectionFailure.Contains("AuthenticationException")&&!g.Exited&&!h.Exited,
            "HTTPS reverse physical connection rejects the wrong approved key while retaining both listeners");
    }
    static int FreePort(){var l=new TcpListener(IPAddress.Loopback,0);l.Start();int p=((IPEndPoint)l.LocalEndpoint).Port;l.Stop();return p;}
    sealed class Source(int port):ITcpSourceMapping
    {
        public IPEndPoint LocalEndpoint=>new(IPAddress.Loopback,port);
        public IPAddress LocalAddress=>IPAddress.Loopback;
        public IPEndPoint PublicEndpoint=>LocalEndpoint;
        public bool IsValid=>true;
        public event Action<IPEndPoint>? Changed{add{}remove{}}
        public Task Maintain(CancellationToken token)=>Task.Delay(Timeout.Infinite,token);
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
    }
}
