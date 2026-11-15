using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task CompactMimicPrimary()
    {
        string folder=Path.Combine(Path.GetTempPath(),"conwu-mimic-primary-"+Guid.NewGuid().ToString("N"));
        using var host=new WorkspaceNode(Path.Combine(folder,"host"),"Reachable Mimic",forbidMimicPreparation:true);
        using var guest=new WorkspaceNode(Path.Combine(folder,"guest"),"Outbound only",host,forbidMimicPreparation:true);
        var configuration=(await host.State()).Configurations.Single();
        var settings=configuration.Settings with{PathSelection="mimic-only",ConnectionSource="existing",DirectMode=true,DiscoveryMode="existing"};
        var saved=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",configuration.Id,configuration.Name,configuration.Revision,settings)));Check(saved.Ok,saved.Error);
        var created=await host.Action("",new("create-direct",Mode:"mimic"){LocalEnrollment=true,Name="Reachable",ConfigurationId=configuration.Id});Check(created.Ok,created.Error);
        var code=await host.Action(created.Status!.SelectedNetworkId,new("invite-compact",ExpectedNetwork:created.Status.NetworkId));Check(code.Ok,code.Error);
        var decoded=CompactDirectCode.Import(code.Status!.Pairing!.Code);
        string enhanced=CompactDirectCode.Issue(decoded.Endpoint,decoded.Mode,decoded.RoomCode,true);
        var joined=await guest.Action("",new("join-compact",Code:enhanced){AutoConfigure=true});
        Check(joined.Ok,"a discovery-capable Mimic code pairs directly with a reachable host without any guest STUN/UPnP: "+joined.Error);
        Check(host.Probes+guest.Probes==0&&!joined.Status!.Networks.Single().Status.NetworkEnabled,
            "direct first contact starts no autonomous probe and grants no membership before approval");
        await guest.Worker.StopLocal();await host.Worker.StopLocal();
    }
}
