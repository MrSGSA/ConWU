using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task AutomaticNetworkSettings()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        string folder=Path.Combine(ProfileStore.Root,"automatic-settings");
        using var host=new WorkspaceNode(Path.Combine(folder,"host"),"Host");
        var guest=new WorkspaceNode(Path.Combine(folder,"guest"),"Local guest",host,listenPort:45210);
        bool guestClosed=false;
        try{
            var config=(await host.State()).Configurations.Single();
            var desired=config.Settings with{EntryRefreshSeconds=137,ExistingEntries=[new(0,"https://entry.example.com/current#streamlink1")]};
            var saved=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",config.Id,config.Name,config.Revision,desired)));Check(saved.Ok,saved.Error);
            var before=await guest.State();string beforeDevice=JsonSerializer.Serialize(before.DeviceSettings);
            var created=await host.Action("",new("create-direct"){Name="Automatic pair",ConfigurationId=config.Id});Check(created.Ok,created.Error);
            await Until(()=>host.NativeTarget!=null,"automatic settings fixture has an actual loopback pairing receiver");
            var pending=await guest.Action("",new("join-direct-short",Code:created.Status!.Pairing!.Code){AutoConfigure=true,Entry="203.0.113.1:45200"});Check(pending.Ok,pending.Error);
            string id=pending.Status!.SelectedNetworkId,hostId=created.Status.SelectedNetworkId;UiPairingDto? pair=null;
            for(int attempt=0;attempt<90;attempt++){
                var poll=await guest.Action(id,new("pair-poll"));Check(poll.Ok,poll.Error);
                pair=(await host.State()).Networks.Single(n=>n.Id==hostId).Status.Pairing;
                if(pair?.Verification.Length==6)break;await Task.Delay(30);
            }
            Check(pair?.Verification.Length==6,"automatic settings exchange remains gated by mutual verification");
            Check((await guest.State()).Networks.Single(n=>n.Id==id).Status.ReceivedNetworkSettings==null,"no host settings are applied before approval");
            var approved=await host.Action(hostId,new("approve",ExpectedNetwork:created.Status.NetworkId,Verification:pair!.Verification,Candidate:pair.Candidate,ProposedIp:pair.ProposedIp));Check(approved.Ok,approved.Error);
            UiNetworkDto? joined=null;
            for(int attempt=0;attempt<70;attempt++){
                var poll=await guest.Action(id,new("pair-poll"));Check(poll.Ok,poll.Error);
                joined=(await guest.State()).Networks.Single(n=>n.Id==id);if(joined.Status.NetworkId.Length>0)break;await Task.Delay(30);
            }
            Check(joined?.Status.ReceivedNetworkSettings!=null,"approved encrypted envelope delivers host network settings");
            var settings=joined!.Status.Settings!;
            Check(settings.EntryRefreshSeconds==137&&settings.ExistingEntries.Any(e=>e.PeerSlot==ExistingEntry.NetworkOwner&&e.Source==desired.ExistingEntries[0].Source),"host source subscription is retained and translated into a target-host entry");
            Check(settings.ListenPort==45210&&settings.SourcePort==45211&&settings.Coordinator.Enabled==false,"guest listener resources and local coordination role are not copied from the host");
            Check(joined.Status.VirtualIp!=created.Status.VirtualIp&&joined.ConfigurationId.Length==0,"guest has its own address and no editable shared configuration reference");
            var after=await guest.State();Check(after.DeviceName==before.DeviceName&&JsonSerializer.Serialize(after.DeviceSettings)==beforeDevice,"joining never changes the local device's saved preferences");
            var rejected=await guest.Action(id,new("settings",Settings:settings,ExpectedRevision:joined.Status.SettingsRevision));
            Check(!rejected.Ok&&rejected.Error.Contains("仅供查看"),"backend rejects edits to host-managed network settings");
            var localConfig=(await guest.State()).Configurations.Single();
            var reassigned=await guest.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("assign",localConfig.Id,ExpectedRevision:localConfig.Revision,ConfirmReconnect:true)){NetworkId=id});
            Check(!reassigned.Ok&&reassigned.Error.Contains("仅供查看")&&(await guest.State()).Networks.Single(n=>n.Id==id).ConfigurationId.Length==0,"configuration assignment cannot bypass received-settings protection or alter its reference");
            await guest.Worker.StopLocal();guest.Dispose();guestClosed=true;
            using var reopened=new WorkspaceNode(guest.Store.DirectoryPath,"ignored",host,listenPort:45210,reuseProfile:true);
            try{var restored=(await reopened.State()).Networks.Single(n=>n.Id==id);Check(restored.Status.ReceivedNetworkSettings!=null&&restored.Status.Settings!.ExistingEntries.Any(e=>e.Source==desired.ExistingEntries[0].Source),"restart preserves received settings and the subscription source");}
            finally{await reopened.Worker.StopLocal();}
            var mesh=MeshIdentity.Create("https://example.com/","","faketcp");var member=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(mesh)));
            var malformed=new ApprovedNetworkSettings("udp-only","existing",[],60,[],[],false,member.Pair.Service,member.Pair.CertificatePin,44680);
            bool invalid=false;try{malformed.ForGuest(member,new());}catch(FormatException){invalid=true;}Check(invalid,"settings cannot change the protocol bound to the approved network identity");
        }finally{if(!guestClosed){await guest.Worker.StopLocal();guest.Dispose();}await host.Worker.StopLocal();}
        Console.WriteLine($"PASS {checks} authenticated automatic settings checks; isolated loopback transport");
    }
}
