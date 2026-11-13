using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using StreamLink.Core;

// Real loopback TCP/STUN/SOAP traffic. The forwarding fixture represents an
// outer public port whose inner gateway port differs from the receiver port.
// It forwards only when the actual helper-source rule exists; a rule keyed by
// the outer STUN port cannot accidentally make these checks succeed.
static class StreamGatewayMappingChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(55));
        var token=deadline.Token;
        foreach(string mode in new[]{"tcp","https"}){
            await using var gateway=new Gateway();
            await using var outer=new Forwarder(()=>gateway.Rules.Values.FirstOrDefault(r=>r.ExternalPort==gateway.HelperPort));
            await using var reflector=new StreamMappingRecoveryChecks.Reflector(outer.Port);
            int receiver=FreePort(),source=FreePort();
            using var sink=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            using var application=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            using var signing=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var certificate=StreamCertificates.CreateServer(signing,DateTimeOffset.UtcNow.AddDays(1));
            var mesh=MeshIdentity.Create("","",mode,direct:true);
            if(mode=="https")mesh.Pair=mesh.Pair with{TransportKeyPin=StreamMeshTransport.CertificatePin(certificate)};
            await using var listener=new StreamMeshTransport(mesh,(IPEndPoint)sink.Client.LocalEndPoint!,true,receiver,()=>certificate);
            int factoryCalls=0;
            var options=new StreamMapping.Options(GatewayFactory:async(p,q,ct)=>{
                factoryCalls++;
                check(p==source&&q==receiver,mode+" gateway preparation receives this network's distinct source and receiver ports");
                return await TcpMapping.Create(p,q,_=>{},ct,[reflector.Address],Guid.NewGuid().ToString("N"),false,gateway.Discover);
            });
            await using var mapping=await StreamMapping.Create(receiver,_=>{},token,[reflector.Address],false,options,source);
            var retained=(TcpMapping)mapping;
            gateway.HelperPort=IPEndPoint.Parse(retained.HelperResource.Local).Port;
            check(factoryCalls==1&&mapping.PublicEndpoint.Port==outer.Port&&gateway.HelperPort!=outer.Port&&gateway.HelperPort!=receiver,
                mode+" retains the helper and publishes its different outer STUN port");
            check(gateway.Rules.TryGetValue(gateway.HelperPort,out var rule)&&rule.InternalPort==receiver&&!gateway.Rules.ContainsKey(outer.Port),
                mode+" maps the inner helper port to the receiver without substituting the outer port");
            var maintaining=mapping.Maintain(token);
            // The documentation IP is not routed locally; the fixture exposes
            // that advertised outer PORT on loopback for the two-layer check.
            await using var client=new StreamMeshTransport(mesh,new(IPAddress.Loopback,mapping.PublicEndpoint.Port),false,0);
            async Task<bool> RoundTrip(){
                using var bound=CancellationTokenSource.CreateLinkedTokenSource(token);bound.CancelAfter(4000);
                byte[] payload=RandomNumberGenerator.GetBytes(1280);
                await application.SendAsync(payload,client.ClientEndpoint!,bound.Token);
                var incoming=await sink.ReceiveAsync(bound.Token);
                await sink.SendAsync(incoming.Buffer,incoming.RemoteEndPoint,bound.Token);
                return (await application.ReceiveAsync(bound.Token)).Buffer.SequenceEqual(payload);
            }
            check(await RoundTrip(),mode+" delivers unchanged data in both directions through the simulated outer-to-inner mapping chain");
            if(mode=="https")check(client.TlsProtocol is "Tls12" or "Tls13","mapped HTTPS still completes a genuine pinned TLS handshake");
            if(mode=="tcp"){
                reflector.Mode=1;retained.RequestRefresh();
                await Until(()=>!mapping.IsValid,token);
                check(gateway.Rules.ContainsKey(gateway.HelperPort)&&!maintaining.IsCompleted&&await RoundTrip(),
                    "lost helper observation withdraws the mapped TCP candidate while retaining its rule and established business connection");
                reflector.Mode=0;retained.RequestRefresh();
                await Until(()=>mapping.IsValid,token,15000);
                check(IPEndPoint.Parse(retained.HelperResource.Local).Port==gateway.HelperPort&&await RoundTrip(),
                    "mapped TCP helper recovery retains the same inner port and existing stream");
            }
            await mapping.DisposeAsync();
            try{await maintaining;}catch(OperationCanceledException){}
            check(retained.HelperResource.Closed&&!gateway.Rules.ContainsKey(gateway.HelperPort)&&!listener.Exited&&await RoundTrip(),
                mode+" mapping disposal closes its helper and removes its own rule while keeping accepted streams alive");
        }
        // A foreign rule on P must survive. Failure of that owned gateway
        // attempt leaves only the existing shared-receiver STUN fallback.
        await using(var gateway=new Gateway())
        await using(var reflector=new StreamMappingRecoveryChecks.Reflector(48039)){
            int source=FreePort(),receiver=FreePort();
            var foreign=new RouterMapping(source,12345,"127.0.0.2","TCP","foreign application");
            gateway.Rules[source]=foreign;
            var options=new StreamMapping.Options(GatewayFactory:(p,q,ct)=>Create(p,q,ct));
            async Task<IMapping> Create(int p,int q,CancellationToken ct)=>await TcpMapping.Create(p,q,_=>{},ct,[reflector.Address],null,false,gateway.Discover);
            await using var mapping=await StreamMapping.Create(receiver,_=>{},token,[reflector.Address],false,options,source);
            check(mapping is StreamMapping&&gateway.Rules[source]==foreign&&gateway.Adds==0&&reflector.SourcePorts.Contains(receiver),
                "foreign inner mapping is preserved and failed helper creation falls back to the actual receiver's STUN flow");
        }
        // A busy local helper port is distinct from a busy gateway rule. Use
        // the allocator's actual port for both observation and the IGD grant.
        await using(var gateway=new Gateway())
        await using(var reflector=new StreamMappingRecoveryChecks.Reflector(48040)){
            using var occupied=new TcpListener(IPAddress.Loopback,0);occupied.Server.ExclusiveAddressUse=true;occupied.Start();
            int preferred=((IPEndPoint)occupied.LocalEndpoint).Port,receiver=FreePort();
            async Task<IMapping> Create(int p,int q,CancellationToken ct)=>await TcpMapping.Create(p,q,_=>{},ct,[reflector.Address],null,false,gateway.Discover);
            await using var mapping=await StreamMapping.Create(receiver,_=>{},token,[reflector.Address],false,new(GatewayFactory:Create),preferred);
            var mapped=(TcpMapping)mapping;int actual=IPEndPoint.Parse(mapped.HelperResource.Local).Port;
            check(actual!=preferred&&actual!=receiver&&gateway.Rules[actual].InternalPort==receiver&&reflector.SourcePorts.Contains(actual),
                "busy helper allocation maps the actually allocated port and preserves the existing local listener");
        }
        using(var canceled=CancellationTokenSource.CreateLinkedTokenSource(token)){
            var grant=new Grant();int calls=0;
            var options=new StreamMapping.Options(GatewayFactory:(p,q,ct)=>{calls++;canceled.Cancel();return Task.FromResult<IMapping>(grant);});
            bool rejected=false;try{await StreamMapping.Create(48180,_=>{},canceled.Token,[],false,options,48181);}catch(OperationCanceledException){rejected=true;}
            check(rejected&&calls==1&&grant.Disposed==1,"cancellation after gateway creation disposes the untransferred grant exactly once");
        }
    }
    static int FreePort(){using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();return ((IPEndPoint)listener.LocalEndpoint).Port;}
    static async Task Until(Func<bool> ready,CancellationToken token,int milliseconds=4000){
        using var bound=CancellationTokenSource.CreateLinkedTokenSource(token);bound.CancelAfter(milliseconds);
        while(!ready())await Task.Delay(20,bound.Token);
    }
    sealed class Grant:IMapping
    {
        public int Disposed;
        public IPAddress LocalAddress=>IPAddress.Loopback;
        public IPEndPoint PublicEndpoint=>new(IPAddress.Parse("203.0.113.20"),48041);
        public bool IsValid=>Disposed==0;
        public event Action<IPEndPoint>? Changed {add{}remove{}}
        public Task Maintain(CancellationToken token)=>Task.Delay(Timeout.Infinite,token);
        public ValueTask DisposeAsync(){Disposed++;return ValueTask.CompletedTask;}
    }
    sealed class Forwarder:IAsyncDisposable
    {
        readonly TcpListener listener=new(IPAddress.Loopback,0);
        readonly CancellationTokenSource stop=new();
        readonly ConcurrentBag<Task> peers=[];
        readonly Func<RouterMapping?> rule;
        readonly Task accepting;
        public int Port=>((IPEndPoint)listener.LocalEndpoint).Port;
        public Forwarder(Func<RouterMapping?> rule){this.rule=rule;listener.Start();accepting=Accept();}
        async Task Accept(){
            try{while(true)peers.Add(Forward(await listener.AcceptTcpClientAsync(stop.Token)));}
            catch(Exception error)when(stop.IsCancellationRequested&&error is OperationCanceledException or SocketException or ObjectDisposedException){}
        }
        async Task Forward(TcpClient incoming){
            using(incoming)using(var target=new TcpClient())using(var lifetime=CancellationTokenSource.CreateLinkedTokenSource(stop.Token)){
                try{
                    var mapped=rule();if(mapped==null)return;
                    await target.ConnectAsync(IPAddress.Parse(mapped.InternalClient),mapped.InternalPort,lifetime.Token);
                    var up=incoming.GetStream().CopyToAsync(target.GetStream(),lifetime.Token);
                    var down=target.GetStream().CopyToAsync(incoming.GetStream(),lifetime.Token);
                    try{await await Task.WhenAny(up,down);}finally{lifetime.Cancel();try{await Task.WhenAll(up,down);}catch(Exception error)when(error is IOException or OperationCanceledException or SocketException){}}
                }catch(Exception error)when(error is IOException or OperationCanceledException or SocketException){}
            }
        }
        public async ValueTask DisposeAsync(){stop.Cancel();listener.Stop();await accepting;await Task.WhenAll(peers);stop.Dispose();}
    }
    sealed class Gateway:IAsyncDisposable
    {
        readonly TcpListener listener=new(IPAddress.Loopback,0);
        readonly CancellationTokenSource stop=new();
        readonly Task running;
        public readonly ConcurrentDictionary<int,RouterMapping> Rules=new();
        public int Adds,HelperPort;
        public Gateway(){listener.Start();running=Serve();}
        public async IAsyncEnumerable<RouterService> Discover(IPAddress local,[System.Runtime.CompilerServices.EnumeratorCancellation]CancellationToken token){
            token.ThrowIfCancellationRequested();await Task.Yield();
            yield return new(new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/control"),"urn:schemas-upnp-org:service:WANIPConnection:1",local);
        }
        async Task Serve(){
            try{while(true){
                using var client=await listener.AcceptTcpClientAsync(stop.Token);
                using var stream=client.GetStream();using var reader=new StreamReader(stream,Encoding.UTF8,leaveOpen:true);
                await reader.ReadLineAsync(stop.Token);string action="";int length=0;
                while(await reader.ReadLineAsync(stop.Token) is {Length:>0} line){
                    if(line.StartsWith("SOAPAction:",StringComparison.OrdinalIgnoreCase))action=line;
                    if(line.StartsWith("Content-Length:",StringComparison.OrdinalIgnoreCase))length=int.Parse(line[15..]);
                }
                char[] body=new char[length];await reader.ReadBlockAsync(body.AsMemory(),stop.Token);
                var doc=XDocument.Parse(new string(body));string Value(string key)=>doc.Descendants().First(v=>v.Name.LocalName==key).Value;
                string xml="<root/>";
                if(action.Contains("GetExternalIPAddress"))xml="<root><NewExternalIPAddress>10.190.165.5</NewExternalIPAddress></root>";
                else{
                    int port=int.Parse(Value("NewExternalPort"));
                    if(action.Contains("GetSpecificPortMappingEntry"))xml=Rules.TryGetValue(port,out var rule)
                        ?$"<root><NewInternalPort>{rule.InternalPort}</NewInternalPort><NewInternalClient>{rule.InternalClient}</NewInternalClient><NewPortMappingDescription>{rule.Description}</NewPortMappingDescription></root>"
                        :"<root><errorCode>714</errorCode></root>";
                    else if(action.Contains("AddPortMapping")){Adds++;Rules[port]=new(port,int.Parse(Value("NewInternalPort")),Value("NewInternalClient"),Value("NewProtocol"),Value("NewPortMappingDescription"));}
                    else if(action.Contains("DeletePortMapping"))Rules.TryRemove(port,out _);
                }
                byte[] bytes=Encoding.UTF8.GetBytes(xml);
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n"),stop.Token);
                await stream.WriteAsync(bytes,stop.Token);
            }}catch(Exception error)when(stop.IsCancellationRequested&&error is OperationCanceledException or SocketException or ObjectDisposedException){}
        }
        public async ValueTask DisposeAsync(){stop.Cancel();listener.Stop();await running;stop.Dispose();}
    }
}
