using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PkarrPairingTests(bool pkarr=true,bool existing=false)
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));string folder=Path.Combine(ProfileStore.Root,"pkarr-pairing");
        using var gateway=new PublishingGateway();using var http=new HttpClient(gateway);PkarrClient Factory()=>new(http,["https://fixture.invalid"]);
        var mapping=new Mapping();mapping.Change(new(IPAddress.Parse("203.0.113.54"),45460));
        using var host=new WorkspaceNode(Path.Combine(folder,"host"),"Autonomous host",pkarrFactory:Factory,mappingFactory:()=>mapping);
        using var unreachable=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);unreachable.Bind(new IPEndPoint(IPAddress.Loopback,0));
        var targets=new ConcurrentQueue<string>();
        IMeshTransport Transport(MeshTransportRequest request){if(request.Server)return new StubTransport(null);targets.Enqueue(request.Target.ToString());return new ForwardingTransport(request.Target.Equals(mapping.PublicEndpoint)?host.NativeTarget!:(IPEndPoint)unreachable.LocalEndPoint!,toleratePeerOffline:true);}
        string mode=pkarr?"pkarr":existing?"existing":"direct";
        var guest=new WorkspaceNode(Path.Combine(folder,"guest"),"Local guest",host,listenPort:45210,pkarrFactory:Factory,mappingFactory:()=>new PreparedMapping(),transportOverride:Transport);bool guestClosed=false;
        try{
            var c=(await host.State()).Configurations.Single();
            var configured=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",c.Id,c.Name,c.Revision,c.Settings with{ConnectionSource=existing?"existing":"custom",DirectMode=true,DiscoveryMode=mode,ExistingEntries=existing?[new(0,mapping.PublicEndpoint.ToString())]:c.Settings.ExistingEntries})));Check(configured.Ok,configured.Error);
            var created=await host.Action("",new("create-direct"){Name="PKARR relation",ConfigurationId=c.Id});Check(created.Ok,created.Error);string ownerId=created.Status!.SelectedNetworkId;
            await Until(()=>(!pkarr||gateway.Packets.Count==1)&&(existing||host.Probes>0)&&host.NativeTarget!=null,"host entry is prepared using only its selected strategy",18000);
            if(!existing)for(int attempt=0;attempt<100&&(await host.State()).Networks.Single().Status.EntryPreparation?.Endpoint!="203.0.113.54:45460";attempt++)await Task.Delay(30);
            var invited=await host.Action(ownerId,new("invite",ExpectedNetwork:created.Status.NetworkId));Check(invited.Ok,invited.Error);
            var invitation=DirectPairInvitation.Import(invited.Status!.Pairing!.Code);
            Check(invitation.Entries.Any(e=>e.Source=="203.0.113.54:45460")&&invitation.Entries.Any(e=>e.Source.StartsWith("pkarr://"))==pkarr&&!invitation.Entries.Any(e=>e.Source==c.Settings.ExistingEntries.Single().Source),"invitation carries the prepared candidate, adds a public discovery key only when selected, and excludes dormant third-party entries");
            var joined=await guest.Action("",new("join-invitation",Code:invited.Status.Pairing.Code){AutoConfigure=true});Check(joined.Ok,joined.Error);string guestId=joined.Status!.SelectedNetworkId;
            UiPairingDto? pair=null;
            for(int attempt=0;attempt<80;attempt++){
                var poll=await guest.Action(guestId,new("pair-poll"));Check(poll.Ok,poll.Error);
                pair=(await host.State()).Networks.Single(n=>n.Id==ownerId).Status.Pairing;if(pair?.Verification.Length==6)break;await Task.Delay(50);
            }
            Check(pair?.Verification.Length==6,"first autonomous relation still requires mutual verification and host approval");
            var approved=await host.Action(ownerId,new("approve",ExpectedNetwork:created.Status.NetworkId,Verification:pair!.Verification,Candidate:pair.Candidate,ProposedIp:pair.ProposedIp));Check(approved.Ok,approved.Error);
            UiNetworkDto? received=null;
            for(int attempt=0;attempt<80;attempt++){
                var poll=await guest.Action(guestId,new("pair-poll"));Check(poll.Ok,poll.Error);received=(await guest.State()).Networks.Single(n=>n.Id==guestId);
                if(received.Status.NetworkId.Length>0)break;await Task.Delay(50);
            }
            Check(received?.Status.ReceivedNetworkSettings?.DiscoveryMode==mode&&received.Status.Settings?.DiscoveryMode==mode&&received.Status.Settings.PkarrPublish==false,"encrypted approval preserves the selected discovery mode independently of publishing permission");
            var saved=new ProfileStore(Path.Combine(guest.Store.DirectoryPath,"networks",guestId),guest.Store).LoadForMaintenance();
            Check((pkarr?saved.PkarrSeed.Length>0&&PkarrPacket.Source(saved.PkarrSeed)!=invitation.Entries.Single(e=>e.Source.StartsWith("pkarr://")).Source:saved.PkarrSeed.Length==0)&&saved.ExistingEntries.Any(e=>e.Source=="203.0.113.54:45460")&&saved.ExistingEntries.Any(e=>e.Source.StartsWith("pkarr://"))==pkarr,"guest persists the approved initial entry and creates only its independent publishing identity in PKARR mode");
            await PairReady(host,12000,guest);
            Check(true,"autonomous relation connects through real loopback MeshLink with injected physical transports");
            if(existing)Check(host.Probes==0&&guest.Probes==0,"existing-entry invitation and automatic settings never start autonomous hole punching");
            if(pkarr){
                // Publication is asynchronous to route readiness. Wait for both
                // identities before a restart can interrupt the negotiation.
                await Until(()=>gateway.Packets.Count==2,"both independently approved publishers finish their first record",18000);
                mapping.Change(new(IPAddress.Parse("203.0.113.55"),45461));
                string hostKey=PkarrPacket.KeyFromSource(invitation.Entries.Single(e=>e.Source.StartsWith("pkarr://")).Source);
                await Until(()=>gateway.Packets.TryGetValue(hostKey,out var packet)&&PkarrPacket.Read(hostKey,packet,DateTimeOffset.UtcNow).Announcement.Endpoints.Contains("203.0.113.55:45461"),"a changed autonomous candidate is published under the original discovery key",18000);
            }
            await guest.Worker.StopLocal();guest.Dispose();guestClosed=true;
            targets.Clear();using var reopened=new WorkspaceNode(guest.Store.DirectoryPath,"ignored",host,listenPort:45210,reuseProfile:true,pkarrFactory:Factory,mappingFactory:()=>new PreparedMapping(),transportOverride:Transport);
            try{
                bool recovered=false;for(int attempt=0;attempt<300;attempt++){recovered=(await reopened.State()).Aggregate!.ConnectedNetworks==1;if(recovered)break;await Task.Delay(100);}
                Check(recovered&&targets.Contains(mapping.PublicEndpoint.ToString()),"guest restart reconnects through the current reachable entry; stale physical candidates cannot bypass the emulated mapping");
                Check(gateway.Packets.Count==(pkarr?2:0),"PKARR host and guest keep distinct records; other modes start no publisher");
            }finally{await reopened.Worker.StopLocal();}
        }finally{if(!guestClosed){await guest.Worker.StopLocal();guest.Dispose();}await host.Worker.StopLocal();}
        Console.WriteLine($"PASS {checks} {mode} approval/reconnect checks; isolated gateway and loopback transport, no WAN NAT claim");
    }
}
