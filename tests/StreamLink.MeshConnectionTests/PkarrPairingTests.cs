using System.Net;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PkarrPairingTests()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));string folder=Path.Combine(ProfileStore.Root,"pkarr-pairing");
        using var gateway=new PublishingGateway();using var http=new HttpClient(gateway);PkarrClient Factory()=>new(http,["https://fixture.invalid"]);
        var mapping=new Mapping();mapping.Change(new(IPAddress.Parse("203.0.113.54"),45460));
        using var host=new WorkspaceNode(Path.Combine(folder,"host"),"Autonomous host",pkarrFactory:Factory,mappingFactory:()=>mapping);
        var guest=new WorkspaceNode(Path.Combine(folder,"guest"),"Local guest",host,listenPort:45210,pkarrFactory:Factory,mappingFactory:()=>new PreparedMapping());bool guestClosed=false;
        try{
            var c=(await host.State()).Configurations.Single();
            var configured=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",c.Id,c.Name,c.Revision,c.Settings with{ConnectionSource="custom",DirectMode=true,DiscoveryMode="pkarr"})));Check(configured.Ok,configured.Error);
            var created=await host.Action("",new("create-direct"){Name="PKARR relation",ConfigurationId=c.Id});Check(created.Ok,created.Error);string ownerId=created.Status!.SelectedNetworkId;
            await Until(()=>gateway.Packets.Count==1&&host.NativeTarget!=null,"autonomous host prepares and publishes its own candidate",18000);
            var invited=await host.Action(ownerId,new("invite",ExpectedNetwork:created.Status.NetworkId));Check(invited.Ok,invited.Error);
            var invitation=DirectPairInvitation.Import(invited.Status!.Pairing!.Code);
            Check(invitation.Entries.Any(e=>e.Source=="203.0.113.54:45460")&&invitation.Entries.Any(e=>e.Source.StartsWith("pkarr://"))&&!invitation.Entries.Any(e=>e.Source==c.Settings.ExistingEntries.Single().Source),"invitation carries the prepared candidate and persistent public discovery key, never a dormant third-party entry");
            var joined=await guest.Action("",new("join-invitation",Code:invited.Status.Pairing.Code){AutoConfigure=true});Check(joined.Ok,joined.Error);string guestId=joined.Status!.SelectedNetworkId;
            UiPairingDto? pair=null;
            for(int attempt=0;attempt<80;attempt++){
                var poll=await guest.Action(guestId,new("pair-poll"));Check(poll.Ok,poll.Error);
                pair=(await host.State()).Networks.Single(n=>n.Id==ownerId).Status.Pairing;if(pair?.Verification.Length==6)break;await Task.Delay(50);
            }
            Check(pair?.Verification.Length==6,"first PKARR relation still requires mutual verification and host approval");
            var approved=await host.Action(ownerId,new("approve",ExpectedNetwork:created.Status.NetworkId,Verification:pair!.Verification,Candidate:pair.Candidate,ProposedIp:pair.ProposedIp));Check(approved.Ok,approved.Error);
            UiNetworkDto? received=null;
            for(int attempt=0;attempt<80;attempt++){
                var poll=await guest.Action(guestId,new("pair-poll"));Check(poll.Ok,poll.Error);received=(await guest.State()).Networks.Single(n=>n.Id==guestId);
                if(received.Status.NetworkId.Length>0)break;await Task.Delay(50);
            }
            Check(received?.Status.ReceivedNetworkSettings?.DiscoveryMode=="pkarr"&&received.Status.Settings?.DiscoveryMode=="pkarr"&&received.Status.Settings.PkarrPublish==false,"encrypted approval preserves PKARR lookup mode independently of publishing permission");
            var saved=new ProfileStore(Path.Combine(guest.Store.DirectoryPath,"networks",guestId),guest.Store).LoadForMaintenance();
            Check(saved.PkarrSeed.Length==0&&saved.ExistingEntries.Any(e=>e.Source.StartsWith("pkarr://")),"guest stores the authenticated public hint without creating or receiving a publishing private key");
            bool connected=false;for(int attempt=0;attempt<120;attempt++){connected=(await guest.State()).Aggregate!.ConnectedNetworks==1;if(connected)break;await Task.Delay(100);}
            Check(connected,"autonomous PKARR relation connects through real loopback MeshLink with injected physical transports");
            mapping.Change(new(IPAddress.Parse("203.0.113.55"),45461));
            await Until(()=>gateway.Packets.Values.Any(p=>PkarrPacket.Read(PkarrPacket.KeyFromSource(invitation.Entries.Single(e=>e.Source.StartsWith("pkarr://")).Source),p,DateTimeOffset.UtcNow).Announcement.Endpoints.Contains("203.0.113.55:45461")),"a changed autonomous candidate is published under the original discovery key",18000);
            await guest.Worker.StopLocal();guest.Dispose();guestClosed=true;
            using var reopened=new WorkspaceNode(guest.Store.DirectoryPath,"ignored",host,listenPort:45210,reuseProfile:true,pkarrFactory:Factory,mappingFactory:()=>new PreparedMapping());
            try{
                bool recovered=false;for(int attempt=0;attempt<120;attempt++){recovered=(await reopened.State()).Aggregate!.ConnectedNetworks==1;if(recovered)break;await Task.Delay(100);}
                Check(recovered,"guest restart reconnects using the saved approved identity and updated signed discovery");
                Check(gateway.Packets.Count==1,"joining and guest restart never publish a competing record for the host");
            }finally{await reopened.Worker.StopLocal();}
        }finally{if(!guestClosed){await guest.Worker.StopLocal();guest.Dispose();}await host.Worker.StopLocal();}
        Console.WriteLine($"PASS {checks} PKARR approval/reconnect checks; isolated gateway and loopback transport, no WAN NAT claim");
    }
}
