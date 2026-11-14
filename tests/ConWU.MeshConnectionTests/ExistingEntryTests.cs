using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task ExistingEntries()
    {
        await EntryResilience();
        await TaggedEntries();
        static void Reject(Action action){try{action();}catch(Exception ex)when(ex is FormatException or CryptographicException){return;}throw new Exception("unexpected acceptance");}
        foreach(string invalid in new[]{"127.0.0.1:80","169.254.169.254:80","0.0.0.0:1","224.0.0.1:8","https://127.0.0.1/key","http://10.0.0.1/","file:///x","https://a:b@example.com/","[::1]:80","example.com:0"})Reject(()=>ExistingEntryResolver.Validate([new(0,invalid)]));
        Check(true,"existing sources reject local-service fetches, invalid ports, credentials, multicast and unsupported formats");
        ExistingEntryResolver.Validate([new(0,"203.0.113.1:44680"),new(2,"txt://_streamlink.example.com"),new(0,"https://example.com/entry?token=test")]);
        var http=new EntryHttp();
        using(var resolver=new ExistingEntryResolver((_,_)=>Task.FromResult(new[]{IPAddress.Parse("203.0.113.2")}),(_,_)=>Task.FromResult(new[]{"streamlink=edge.example.com:44680"}),http)) {
            var results=await resolver.Resolve([new(0,"txt://_streamlink.example.com"),new(2,"https://example.com/entries")],"faketcp",default);
            Check(results[0].Endpoints.SequenceEqual(new[]{"203.0.113.2:44680"}) && results[1].Endpoints.Length==2 && results[1].PeerSlot==2,"TXT and bounded JSON resolve multiple hints with explicit device ownership");
            var mismatch=await resolver.Resolve([new(2,"udp://203.0.113.1:44")],"faketcp",default);
            Check(mismatch[0].Endpoints.Length==0&&mismatch[0].Error.Contains("协议"),"source scheme never changes selected wire protocol");
            http.Body=new string('a',9000);Check((await resolver.Resolve([new(0,"https://example.com/entries?secret=never-log")],"faketcp",default))[0] is {Endpoints.Length:0,Error:var error} && !error.Contains("secret"),"oversized source is bounded and query secrets are absent from error");
            http.Body="{\"unexpected\":true}";Check((await resolver.Resolve([new(0,"https://example.com/entries")],"faketcp",default))[0].Error.Length>0,"malformed JSON cannot terminate resolver batch");
            http.Body="http://169.254.169.254/latest";Check((await resolver.Resolve([new(0,"https://example.com/entries")],"faketcp",default))[0].Endpoints.Length==0,"returned URLs are not fetched recursively");
        }
        using(var rebinding=new ExistingEntryResolver((_,_)=>Task.FromResult(new[]{IPAddress.Loopback}),(_,_)=>Task.FromResult(Array.Empty<string>()))) {
            Check((await rebinding.Resolve([new(0,"http://rebound.example.com/private")],"faketcp",default))[0].Endpoints.Length==0,"connection callback blocks DNS rebinding to loopback before socket connect");
        }
        using(var timeout=new ExistingEntryResolver((_,_)=>Task.FromResult(Array.Empty<IPAddress>()),async(_,ct)=>{await Task.Delay(Timeout.Infinite,ct);return [];})) {
            using var cancelled=new CancellationTokenSource(50);bool stopped=false;try{await timeout.Resolve([new(0,"txt://example.com")],"faketcp",cancelled.Token);}catch(OperationCanceledException){stopped=true;}
            Check(stopped,"cancellation joins outstanding resolver work");
        }
        var plan=new ExistingEntryPlan();string[] hints=["203.0.113.1:1","203.0.113.2:2"];
        var reconnect=new PeerReconnectPolicy();
        Check(!reconnect.Allow(false,false,false,hints,1000)&&reconnect.Allow(false,false,true,hints,1001),"server-backed offline member waits for fresh presence even when its old IP remains configured");
        Check(reconnect.Allow(true,false,false,hints,1000)&&!reconnect.Allow(true,false,false,hints,20000)&&!reconnect.Allow(true,false,false,hints,24000)&&reconnect.Allow(true,false,false,hints,25000),"serverless unanswered entry keeps bounded attempts and resumes after a short idle pause");
        Check(reconnect.Allow(true,false,false,["203.0.113.3:3"],70001),"changed subscription endpoint immediately wakes a paused direct peer");
        var period=new DeviceProfile{EntryRefreshSeconds=1};period.Validate();period.EntryRefreshSeconds=86400;period.Validate();period.EntryRefreshSeconds=0;Reject(period.Validate);
        Check(plan.Select(hints,"fallback",false,false,1000)==hints[0]&&plan.Priority,"first supplied endpoint wins priority");
        Check(plan.Select(hints,"fallback",false,false,5001)==hints[1]&&plan.Priority,"next endpoint is tried within one bounded window");
        Check(plan.Select(hints,"fallback",false,false,9001)=="fallback"&&!plan.Priority&&plan.FellBack,"exhausted hint window returns to autonomous candidate");
        Check(plan.Select(hints,"changed",false,true,10000)==""&&!plan.Priority,"healthy path is not churned by address refresh");
        Check(plan.Select(hints,"fallback",false,false,11000)==hints[0]&&plan.Priority,"loss of healthy path starts a new bounded hint window");
        Check(plan.Select(["203.0.113.3:3"],"fallback",false,false,99000)=="203.0.113.3:3"&&plan.Priority,"updated subscription restarts an exhausted entry window");
        var custom=MeshIdentity.Create("https://example.com/","","faketcp","10.171.139.42");
        var enrolled=MeshIdentity.Issue(custom,"10.171.139.77");var guest=MeshIdentity.Import(MeshIdentity.Export(enrolled));guest.Directory=custom.Directory;
        Check(custom.LocalIp=="10.171.139.42"&&guest.LocalIp=="10.171.139.77","custom /24 addresses survive signed enrollment and import");
        Reject(()=>MeshIdentity.Issue(custom,"10.171.139.77"));Reject(()=>MeshIdentity.Issue(custom,"10.171.140.5"));
        Reject(()=>MeshIdentity.ValidateMember(custom.Pair.Network,custom.OwnerKey,guest.Self with{VirtualIp="10.171.139.88"}));
        MeshIdentity.Revoke(custom,guest.Self.Slot);Reject(()=>MeshIdentity.Issue(custom,"10.171.139.77"));Check(true,"duplicate, wrong subnet, tampering and reuse of revoked IP are rejected");
        var legacy=MeshIdentity.Create("https://example.com/","","faketcp");var legacyJson=JsonSerializer.Serialize(legacy.Directory);
        Check(!legacyJson.Contains("VirtualIp")&&!legacyJson.Contains("ReservedAddresses"),"default networks preserve legacy signed serialization");
        var routed=MeshIdentity.Create("https://example.com/","","faketcp","10.171.139.42");
        var remote=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(routed,"10.171.139.77")));remote.Directory=routed.Directory;
        byte[] key=MeshIdentity.SharedKey(remote,routed.Self);using var link=new MeshLink(remote.Self.Slot,routed.Self.Slot,key);CryptographicOperations.ZeroMemory(key);
        await using var endpoint=new PeerEndpoint(link);var adapter=new MemoryAdapter();await using(var router=new MeshRouter(routed,adapter)) {
            router.SetCandidate(remote.Self.Slot,endpoint.Endpoint,"custom peer","");await Until(()=>router.HasHealthyPath(remote.Self.Slot),"signed custom-address peer authenticates");
            adapter.Outgoing.Add(Packet(routed.LocalIp,remote.LocalIp));await Until(()=>endpoint.DataPackets==1,"custom host octet routes to authenticated member slot without identity aliasing");
            endpoint.ReplyPacket=Packet(remote.LocalIp,routed.LocalIp);adapter.Outgoing.Add(Packet(routed.LocalIp,remote.LocalIp));await Until(()=>router.Status().Single().ReceivedBytes>0,"signed custom source address delivers return traffic");
            long received=router.Status().Single().ReceivedBytes;endpoint.ReplyPacket=Packet("10.171.139.2",routed.LocalIp);adapter.Outgoing.Add(Packet(routed.LocalIp,remote.LocalIp));await Until(()=>router.Status().Single().LocalDrops!.ReceivePolicyRejected>0,"peer cannot impersonate its old slot-derived address");Check(router.Status().Single().ReceivedBytes==received,"spoofed packet is not delivered to adapter");
        }
        await ExistingRunner();await ExistingRunner(true);await StrictExistingOnly();await MappingProbeCancellation();
        Console.WriteLine($"PASS {checks} existing entry and custom addressing checks");
    }
    static async Task MappingProbeCancellation()
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        var discovery=new Discovery(owner,guest,"");var adapter=new MemoryAdapter();using var stop=new CancellationTokenSource();int probes=0;
        string folder=Path.Combine(Path.GetTempPath(),"streamlink-probe-cancel-"+Guid.NewGuid().ToString("N"));
        var services=new MeshRuntimeServices(_=>discovery,_=>Task.FromResult<IPacketAdapter>(adapter),(_,_,_)=>{
            probes++;stop.Cancel();return Task.FromException<IMapping>(new IOException("probe failure concurrent with stop"));
        },_=>throw new Exception("no transport should be created"),(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},folder){
            NetworkWake=()=>new MeshNetworkWake(false),Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null)
        };
        var runner=new MeshRunner(new DeviceProfile{Mesh=owner},_=>{},_=>{},_=>{},_=>{},services);
        try {
            bool cancelled=false;try{await runner.Run(stop.Token).WaitAsync(TimeSpan.FromSeconds(3));}catch(OperationCanceledException)when(stop.IsCancellationRequested){cancelled=true;}
            Check(cancelled&&probes==1,"failed optional probe concurrent with stop reports caller cancellation");
            Check(runner.CleanupComplete&&adapter.Disposed&&discovery.Disposed,"probe cancellation still joins adapter and discovery cleanup");
        } finally {stop.Cancel();if(Directory.Exists(folder)){foreach(var d in Directory.EnumerateDirectories(folder))Directory.Delete(d);Directory.Delete(folder);}}
    }
    sealed class EntryHttp : HttpMessageHandler {
        public string Body="{\"endpoints\":[\"203.0.113.1:44680\",\"edge.example.com:44681\"]}";
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(Body,Encoding.UTF8)});
    }
    static async Task ExistingRunner(bool refresh=false)
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        byte[] key=MeshIdentity.SharedKey(guest,owner.Self);using var link=new MeshLink(2,1,key);CryptographicOperations.ZeroMemory(key);
        await using var endpoint=new PeerEndpoint(link);using var sink=new System.Net.Sockets.UdpClient(new IPEndPoint(IPAddress.Loopback,0));string dead=sink.Client.LocalEndPoint!.ToString()!;
        var discovery=new Discovery(owner,guest,endpoint.Endpoint.ToString());var adapter=new MemoryAdapter();var logs=new ConcurrentQueue<string>();var transports=new ConcurrentBag<ForwardingTransport>();
        int probes=0,resolutions=0;SessionStatus? status=null;string folder=Path.Combine(Path.GetTempPath(),"streamlink-existing-"+Guid.NewGuid().ToString("N"));
        var services=new MeshRuntimeServices(_=>discovery,_=>Task.FromResult<IPacketAdapter>(adapter),(_,_,_)=>{Interlocked.Increment(ref probes);return Task.FromException<IMapping>(new IOException("no local mapping"));},request=>{if(request.Mesh.Pair.Mode!="faketcp")throw new Exception("wrong fixed wire mode");var t=new ForwardingTransport(request.Target);transports.Add(t);return t;},(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},folder){
            NetworkWake=()=>new MeshNetworkWake(false),Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null),
            ResolveEntries=(_,_,_)=>{int count=Interlocked.Increment(ref resolutions);return Task.FromResult(new EntryResolution[]{new(2,0,refresh?"TXT":"地址",refresh?(count==1?[dead]:[endpoint.Endpoint.ToString()]):[dead,endpoint.Endpoint.ToString()],"")});}
        };
        var runner=new MeshRunner(new DeviceProfile{Mesh=owner,EntryRefreshSeconds=refresh?1:60,TransportMode="faketcp",PathSelection="faketcp-only",TraversalMode="tcp-udp",ConnectionSource="existing",ExistingEntries=[new(2,"203.0.113.1:44680")]},logs.Enqueue,s=>status=s,_=>{},_=>{},services);
        using var stop=new CancellationTokenSource();var running=runner.Run(stop.Token);
        try{await Until(()=>status?.Connected==true,"real Runner tries supplied endpoints and authenticates a working one",25000);
            Check(status!.Peers!.Single().OuterTarget==endpoint.Endpoint.ToString()&&status.Peers!.Single().EntryDirection=="Outbound","actual endpoint display comes from the authenticated carrying client rather than an unverified entry or local bridge");
            Check(!refresh||resolutions>=2,"configured one-second subscription refresh adopts a changed endpoint without user retry");
            int count=transports.Count;runner.RequestRetry();await Task.Delay(600);Check(transports.Count==count&&!adapter.Disposed,"manual retry preserves healthy existing transport and adapter");
            int previousResolutions=resolutions;
            runner.UpdateEntries(new DeviceProfile{ConnectionSource="existing",ExistingEntries=[new(2,"203.0.113.9:44680")]});
            await Until(()=>resolutions>previousResolutions,"edited source is resolved immediately by the live runner");
            await Task.Delay(300);Check(transports.Count==count&&!adapter.Disposed&&status?.Connected==true,"editing subscription source preserves authenticated transport and Wintun owner");
            adapter.Outgoing.Add(Packet(owner.LocalIp,guest.LocalIp));await Until(()=>endpoint.DataPackets>0,"actual encrypted payload crosses selected supplied/fallback transport");
            if(refresh){
                int reads=discovery.Reads;discovery.ExpiresOverride=DateTimeOffset.UtcNow.ToUnixTimeSeconds()+8;
                await Until(()=>discovery.Reads>reads,"fixture publishes its bounded presence before simulating shutdown",6000);
                await Task.Delay((int)Math.Max(0,(discovery.ExpiresOverride-DateTimeOffset.UtcNow.ToUnixTimeSeconds())*1000+300));
                foreach(var transport in transports.Where(t=>!t.Disposed))transport.Exited=true;
                await Until(()=>status?.Peers?.Single().Connection?.Phase=="Offline","expired remote presence settles the real Runner to offline despite a configured subscription",6000);
                int offlineCount=transports.Count;await Task.Delay(1500);
                Check(transports.Count==offlineCount,"offline device does not allocate fresh native transports on retry ticks");
                discovery.ExpiresOverride=0;
                await Until(()=>status?.Connected==true,"new valid presence automatically reconnects the returning member",7000);
            }
        }finally{await Stop(running,stop);foreach(var d in Directory.EnumerateDirectories(folder))Directory.Delete(d);Directory.Delete(folder);}
        Check(transports.All(t=>t.Disposed)&&adapter.Disposed,"existing endpoint shutdown joins all transport owners");
    }
}
