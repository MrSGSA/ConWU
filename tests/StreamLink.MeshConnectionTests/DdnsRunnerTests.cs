using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task DdnsRunner() {
        foreach(var scenario in new[]{"autonomous","custom-source","existing-source"}) {
            var mesh=MeshIdentity.Create("https://example.com/","","faketcp");var adapter=new MemoryAdapter();var mapping=new Mapping();mapping.Change(IPEndPoint.Parse("203.0.113.5:44680"));
            int probes=0,reads=0,listeners=0,factories=0;var api=new DdnsApi();
            string folder=Path.Combine(Path.GetTempPath(),"conwu-ddns-runner-"+Guid.NewGuid().ToString("N"));
            var services=new MeshRuntimeServices(_=>new QuietDiscovery(mesh),_=>Task.FromResult<IPacketAdapter>(adapter),
                (_,_,_)=>{Interlocked.Increment(ref probes);return Task.FromResult<IMapping>(mapping);},
                request=>{if(!request.Server)throw new Exception("no peer should be dialed");Interlocked.Increment(ref listeners);return new StubTransport(null);},
                (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},folder) {
                Candidates=(_,_,_,_)=>{Interlocked.Increment(ref factories);return Task.FromResult<IMeshCandidateFactory?>(null);},NetworkWake=()=>new MeshNetworkWake(false),
                Ddns=ct=>new MeshDdnsSession(ct,new(api)),
                ResolveEntries=(sources,_,_)=>{Interlocked.Increment(ref reads);if(sources.Any(e=>e.PeerSlot!=0))throw new Exception("remote settings unexpectedly activated");return Task.FromResult(new[]{new EntryResolution(0,0,"HTTPS",["203.0.113.6:44680"],"")});}
            };
            var profile=new DeviceProfile{Mesh=mesh,ConnectionSource=scenario=="existing-source"?"existing":"custom",EntryRefreshSeconds=1,
                ExistingEntries=scenario=="autonomous"?[]:[new(0,"https://entry.example.test/latest")],
                Ddns=new(true,"conwu.example.test",new string('a',32),true,60),CloudflareDdnsToken="fixture-only-ddns-token-1234567890"};
            string settings=JsonSerializer.Serialize(profile);
            var runner=new MeshRunner(profile,_=>{},_=>{},_=>{},_=>{},services);using var stop=new CancellationTokenSource();var running=runner.Run(stop.Token);
            try {
                string expected=scenario=="autonomous"?"203.0.113.5:44680":"203.0.113.6:44680";
                await Until(()=>api.Published.Any(r=>r.Endpoints.Contains(expected)),scenario+": real runner publishes its live listener's selected ingress without waiting for peers",22000);
                Check(listeners==1&&!adapter.Disposed&&DdnsEntryLink.Parse(runner.DdnsStatus.EntryLink).Device==mesh.Self.Device,scenario+": publication exposes a stable link without recreating adapter/listener");
                Check(scenario=="autonomous"?probes==1&&reads==0:probes==0&&reads>0,scenario+": only the appropriate ingress acquisition path runs");
                if(scenario=="existing-source")Check(factories==0,"DDNS publishing in existing mode never starts autonomous candidate machinery");
                Check(JsonSerializer.Serialize(profile)==settings,scenario+": runtime DDNS leaves persisted settings unchanged");
            } finally {await Stop(running,stop);if(Directory.Exists(folder))Directory.Delete(folder,true);}
        }
        await DdnsReconnect();
    }
    static async Task DdnsReconnect() {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        byte[] key=MeshIdentity.SharedKey(guest,owner.Self);using var link=new MeshLink(guest.Self.Slot,owner.Self.Slot,key);System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
        await using var peer=new PeerEndpoint(link);var adapter=new MemoryAdapter();var discovery=new Discovery(owner,guest,""){ExpiresOverride=1};
        var transports=new ConcurrentBag<ForwardingTransport>();bool withdrawn=false;int resolutions=0;SessionStatus? status=null;
        string folder=Path.Combine(Path.GetTempPath(),"conwu-ddns-reconnect-"+Guid.NewGuid().ToString("N"));
        var services=new MeshRuntimeServices(_=>discovery,_=>Task.FromResult<IPacketAdapter>(adapter),(_,_,_)=>throw new Exception("no autonomous probe allowed"),
            r=>{var t=new ForwardingTransport(r.Target);transports.Add(t);return t;},(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},folder) {
            NetworkWake=()=>new MeshNetworkWake(false),Candidates=(_,_,_,_)=>throw new Exception("no autonomous factory allowed"),
            ResolveEntries=(_,_,_)=>{Interlocked.Increment(ref resolutions);return Task.FromResult(new[]{new EntryResolution(guest.Self.Slot,0,"DDNS",withdrawn?[]:[peer.Endpoint.ToString()],""){ExpiresAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds()+60,AllowCached=false}});}
        };
        var profile=new DeviceProfile{Mesh=owner,ConnectionSource="existing",EntryRefreshSeconds=1,ExistingEntries=[new(guest.Self.Slot,DdnsEntryLink.Create("conwu.example.test",guest))]};
        var runner=new MeshRunner(profile,_=>{},s=>status=s,_=>{},_=>{},services);using var stop=new CancellationTokenSource();var running=runner.Run(stop.Token);
        try {
            await Until(()=>status?.Connected==true,"a verified DDNS entry reconnects an approved member while coordinator presence is stale",10000);
            withdrawn=true;int before=resolutions;
            await Until(()=>resolutions>before,"runner consumes signed endpoint withdrawal");await Task.Delay(500);
            adapter.Outgoing.Add(Packet(owner.LocalIp,guest.LocalIp));await Until(()=>peer.DataPackets==1,"withdrawal stops new dialing hints without tearing down an authenticated live data path");
            Check(transports.Count==1&&!transports.Single().Disposed&&!adapter.Disposed,"DDNS refresh/retraction retains the same healthy transport and adapter");
        }finally{await Stop(running,stop);if(Directory.Exists(folder))Directory.Delete(folder,true);}
    }
    sealed class QuietDiscovery(MeshProfile mesh):IMeshDiscovery {
        public Task SaveDirectory(MeshDirectory directory,CancellationToken token)=>Task.CompletedTask;
        public Task Publish(MeshAnnouncement announcement,CancellationToken token)=>Task.CompletedTask;
        public Task<MeshSnapshot?> Read(CancellationToken token)=>Task.FromResult<MeshSnapshot?>(new(mesh.Directory!,[]));
        public void Dispose(){}
    }
    sealed class DdnsApi:HttpMessageHandler {
        public ConcurrentQueue<DdnsAddressRecord> Published {get;}=[];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token) {
            if(request.RequestUri!.Host!="api.cloudflare.com")throw new Exception("wrong authority");
            JsonNode result;
            if(request.Method==HttpMethod.Get)result=new JsonArray();
            else {var body=JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!.AsObject();Published.Enqueue(DdnsAddressRecords.Decode(DdnsAddressRecords.Unquote(body["content"]!.GetValue<string>())));body["id"]=new string('b',32);result=body;}
            return new(HttpStatusCode.OK){Content=new StringContent(new JsonObject{["success"]=true,["result"]=result}.ToJsonString(),Encoding.UTF8,"application/json")};
        }
    }
}
