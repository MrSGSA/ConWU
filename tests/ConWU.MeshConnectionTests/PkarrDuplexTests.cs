using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    sealed class DuplexPkarrGateway:HttpMessageHandler
    {
        public readonly ConcurrentDictionary<string,byte[]> Packets=new();
        public volatile bool Offline,FirstOffline;
        public int Requests;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();Interlocked.Increment(ref Requests);
            if(Offline||FirstOffline&&request.RequestUri!.Host.StartsWith("one."))return new(HttpStatusCode.ServiceUnavailable);
            string key=request.RequestUri!.AbsolutePath[1..];
            if(request.Method==HttpMethod.Put){Packets[key]=await request.Content!.ReadAsByteArrayAsync(token);return new(HttpStatusCode.NoContent);}
            return Packets.TryGetValue(key,out var bytes)?new(HttpStatusCode.OK){Content=new ByteArrayContent(bytes)}:new(HttpStatusCode.NotFound);
        }
    }
    static async Task PkarrDuplex()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));string folder=Path.Combine(ProfileStore.Root,"pkarr-duplex");
        using var gateway=new DuplexPkarrGateway();using var http=new HttpClient(gateway);PkarrClient Factory()=>new(http,["https://one.fixture","https://two.fixture"]);
        using var blackhole=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);blackhole.Bind(new IPEndPoint(IPAddress.Loopback,0));
        WorkspaceNode? host=null,guest=null;
        IPEndPoint hostPublic=new(IPAddress.Parse("203.0.113.54"),45460),guestPublic=new(IPAddress.Parse("203.0.113.64"),45470);
        var hostMappings=new ConcurrentBag<Mapping>();var guestMappings=new ConcurrentBag<Mapping>();
        var hostTargets=new ConcurrentQueue<string>();var guestTargets=new ConcurrentQueue<string>();
        IMapping HostMapping(){var m=new Mapping();m.Change(hostPublic);hostMappings.Add(m);return m;}
        IMapping GuestMapping(){var m=new Mapping();m.Change(guestPublic);guestMappings.Add(m);return m;}
        IMeshTransport HostTransport(MeshTransportRequest r){if(r.Server)return new StubTransport(null);hostTargets.Enqueue(r.Target.ToString());return new ForwardingTransport(r.Target.Equals(guestPublic)&&guest?.NativeTarget!=null?guest.NativeTarget:(IPEndPoint)blackhole.LocalEndPoint!,true);}
        IMeshTransport GuestTransport(MeshTransportRequest r){if(r.Server)return new StubTransport(null);guestTargets.Enqueue(r.Target.ToString());return new ForwardingTransport(r.Target.Equals(hostPublic)&&host?.NativeTarget!=null?host.NativeTarget:(IPEndPoint)blackhole.LocalEndPoint!,true);}
        host=new WorkspaceNode(Path.Combine(folder,"host"),"Host",mappingFactory:HostMapping,transportOverride:HostTransport,pkarrFactory:Factory);
        guest=new WorkspaceNode(Path.Combine(folder,"guest"),"Guest",host,mappingFactory:GuestMapping,transportOverride:GuestTransport,pkarrFactory:Factory);
        try{
            var configuration=(await host.State()).Configurations.Single();
            var saved=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",configuration.Id,configuration.Name,configuration.Revision,configuration.Settings with{ConnectionSource="custom",DirectMode=true,DiscoveryMode="pkarr",ExistingEntries=[],Service=""})));
            Check(saved.Ok,"host selects PKARR without any coordination server: "+saved.Error);
            var created=await host.Action("",new("create-direct"){Name="Duplex",ConfigurationId=configuration.Id});Check(created.Ok,"host creates the direct pair: "+created.Error);
            string hostId=created.Status!.SelectedNetworkId,network=created.Status.NetworkId;
            await Until(()=>gateway.Packets.Count==1&&host.NativeTarget!=null,"only the host has a discovery record before approval",18000);
            var opened=await host.Action(hostId,new("invite-compact",ExpectedNetwork:network));Check(opened.Ok,"host issues a compact code: "+opened.Error);
            var joined=await guest.Action("",new("join-compact",Code:opened.Status!.Pairing!.Code){AutoConfigure=true});Check(joined.Ok,"guest requests approval directly from the compact code: "+joined.Error);
            string guestId=joined.Status!.SelectedNetworkId;UiPairingDto? pair=null;
            for(int i=0;i<100;i++){await guest.Action(guestId,new("pair-poll"));await host.Action(hostId,new("pair-poll"));pair=(await host.State()).Networks.Single().Status.Pairing;if(pair?.Verification.Length==6)break;await Task.Delay(40);}
            Check(pair?.Verification.Length==6&&gateway.Packets.Count==1,"pending clients receive no publishing authority or network membership");
            var approved=await host.Action(hostId,new("approve",ExpectedNetwork:network,Verification:pair!.Verification,Candidate:pair.Candidate,ProposedIp:pair.ProposedIp));Check(approved.Ok,"host approves matching verification: "+approved.Error);
            for(int i=0;i<100;i++){var poll=await guest.Action(guestId,new("pair-poll"));Check(poll.Ok,"guest receives approved credentials: "+poll.Error);if(poll.Status!.NetworkId.Length>0)break;await Task.Delay(40);}
            await PairReady(host,25000,guest);
            async Task WaitState(Func<UiStatusDto,UiStatusDto,bool> accept,string message,int timeout=35000){
                var timer=System.Diagnostics.Stopwatch.StartNew();while(timer.ElapsedMilliseconds<timeout){if(accept(await host.State(),await guest.State())){Check(true,message);return;}await Task.Delay(100);}
                var a=(await host.State()).Networks.Single().Status;var b=(await guest.State()).Networks.Single().Status;
                Console.WriteLine(JsonSerializer.Serialize(new{host=new{a.Pkarr,logs=a.Logs.TakeLast(5)},guest=new{b.Pkarr,logs=b.Logs.TakeLast(5)}}));throw new Exception(message);
            }
            await WaitState((a,b)=>gateway.Packets.Count==2&&a.Networks.Single().Status.Pkarr?.PeerAcknowledged==true&&b.Networks.Single().Status.Pkarr?.PeerAcknowledged==true,"both independent publishers confirm receipt of the exact current peer entry");
            var beforeHost=new ProfileStore(Path.Combine(host.Store.DirectoryPath,"networks",hostId),host.Store).LoadForMaintenance();
            var beforeGuest=new ProfileStore(Path.Combine(guest.Store.DirectoryPath,"networks",guestId),guest.Store).LoadForMaintenance();
            string hostSource=PkarrPacket.Source(beforeHost.PkarrSeed),guestSource=PkarrPacket.Source(beforeGuest.PkarrSeed);
            Check(hostSource!=guestSource&&beforeHost.PkarrPeers.Single().Source==guestSource&&beforeGuest.PkarrPeers.Single().Source==hostSource,"approval pins distinct discovery identities to the correct device and network on both ends");
            string hostSettings=JsonSerializer.Serialize(beforeHost.SavedNetworkSettings),guestSettings=JsonSerializer.Serialize(beforeGuest.SavedNetworkSettings);
            async Task Refresh(){Check((await host.Action(hostId,new("refresh-pkarr",ExpectedNetwork:network))).Ok,"host refresh is accepted without restarting its path");Check((await guest.Action(guestId,new("refresh-pkarr",ExpectedNetwork:network))).Ok,"guest refresh is accepted without restarting its path");}
            gateway.FirstOffline=true;await Refresh();
            await WaitState((a,b)=>a.Networks.Single().Status.Pkarr is {AcceptedGateways:1,TotalGateways:2}&&b.Networks.Single().Status.Pkarr is {AcceptedGateways:1,TotalGateways:2},"one unavailable gateway does not stop publication and partial acceptance is reported honestly");
            gateway.Offline=true;await Refresh();
            await WaitState((a,b)=>a.Networks.Single().Status.Pkarr is {Error.Length:>0,QueryError.Length:>0}&&b.Networks.Single().Status.Pkarr is {Error.Length:>0,QueryError.Length:>0},"all-gateway outage is visible in both publication and lookup status");
            async Task PacketBothWays(){
                var a=(await host.State()).Networks.Single().Status;var b=(await guest.State()).Networks.Single().Status;long ha=(await host.State()).Aggregate!.ReceivedBytes,gb=(await guest.State()).Aggregate!.ReceivedBytes;
                host.Adapters[network].Outgoing.Add(Packet(a.VirtualIp,b.VirtualIp));guest.Adapters[network].Outgoing.Add(Packet(b.VirtualIp,a.VirtualIp));
                await WaitState((x,y)=>x.Aggregate!.ReceivedBytes>=ha+1280&&y.Aggregate!.ReceivedBytes>=gb+1280,"authenticated bidirectional data continues independently of discovery gateway availability",10000);
            }
            await PacketBothWays();gateway.Offline=false;gateway.FirstOffline=false;await Refresh();
            await WaitState((a,b)=>a.Networks.Single().Status.Pkarr is {Error:"",QueryError:"",AcceptedGateways:2,PeerAcknowledged:true}&&b.Networks.Single().Status.Pkarr is {Error:"",QueryError:"",AcceptedGateways:2,PeerAcknowledged:true},"gateway recovery clears stale error state and restores explicit peer confirmation");
            await guest.Worker.StopLocal();guest.Dispose();guest=null;await host.Worker.StopLocal();host.Dispose();host=null;
            Check(hostMappings.All(m=>m.Disposed)&&guestMappings.All(m=>m.Disposed),"both original mapping owners finish shutdown before replacement");
            hostPublic=new(IPAddress.Parse("203.0.113.55"),45461);guestPublic=new(IPAddress.Parse("203.0.113.65"),45471);hostTargets.Clear();guestTargets.Clear();
            host=new WorkspaceNode(Path.Combine(folder,"host"),"ignored",reuseProfile:true,mappingFactory:HostMapping,transportOverride:HostTransport,pkarrFactory:Factory);
            guest=new WorkspaceNode(Path.Combine(folder,"guest"),"ignored",host,reuseProfile:true,mappingFactory:GuestMapping,transportOverride:GuestTransport,pkarrFactory:Factory);
            // One authenticated physical connection carries both directions.
            // A healthy incoming path must not require a redundant outgoing dial.
            await WaitState((a,b)=>a.Aggregate!.ConnectedNetworks==1&&b.Aggregate!.ConnectedNetworks==1&&
                a.Networks.Single().Status.Pkarr is {PeerAcknowledged:true} pa&&pa.Endpoints.Contains(hostPublic.ToString())&&
                b.Networks.Single().Status.Pkarr is {PeerAcknowledged:true} pb&&pb.Endpoints.Contains(guestPublic.ToString())&&
                (hostTargets.Contains(guestPublic.ToString())||guestTargets.Contains(hostPublic.ToString())),"both restarted devices confirm changed peer endpoints and reconnect; every stale physical address is blackholed",70000);
            await PacketBothWays();
            var afterHost=new ProfileStore(Path.Combine(host.Store.DirectoryPath,"networks",hostId),host.Store).LoadForMaintenance();
            var afterGuest=new ProfileStore(Path.Combine(guest.Store.DirectoryPath,"networks",guestId),guest.Store).LoadForMaintenance();
            Check(afterHost.PkarrSeed==beforeHost.PkarrSeed&&afterGuest.PkarrSeed==beforeGuest.PkarrSeed&&afterHost.PkarrSequence>beforeHost.PkarrSequence&&afterGuest.PkarrSequence>beforeGuest.PkarrSequence,"both publishing identities and monotonic sequences survive restart");
            Check(hostSettings==JsonSerializer.Serialize(afterHost.SavedNetworkSettings)&&guestSettings==JsonSerializer.Serialize(afterGuest.SavedNetworkSettings),"address refresh, recovery and restart never rewrite either side's saved settings");
            Check(host.Servers==1&&guest.Servers==1&&gateway.Packets.Count==2,"discovery refresh never duplicates native listeners or creates extra discovery identities");
        }finally{if(guest!=null){await guest.Worker.StopLocal();guest.Dispose();}if(host!=null){await host.Worker.StopLocal();host.Dispose();}}
        Console.WriteLine($"PASS {checks} bidirectional PKARR checks; isolated HTTPS handler and loopback data only, no physical NAT or streaming claim");
    }
}
