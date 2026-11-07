using System.Collections;
using System.Reflection;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PairWorkspaceConcurrentIdentity()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        using var host=new WorkspaceNode(Path.Combine(ProfileStore.Root,"concurrent-owner"),"Owner");
        var one=await host.Action("",new("create-direct"){Name="first"});Check(one.Ok,one.Error);
        var two=await host.Action("",new("create-direct"){Name="second"});Check(two.Ok,two.Error);
        var workspace=typeof(ControlWorker).GetField("workspace",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(host.Worker)!;
        var dictionary=(IEnumerable)workspace.GetType().GetField("networks",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(workspace)!;
        var stores=new Dictionary<string,ProfileStore>();
        foreach(var pair in dictionary){var type=pair!.GetType();string id=(string)type.GetProperty("Key")!.GetValue(pair)!;object context=type.GetProperty("Value")!.GetValue(pair)!;stores[id]=(ProfileStore)context.GetType().GetProperty("Store")!.GetValue(context)!;}
        string[] ids=[one.Status!.SelectedNetworkId,two.Status!.SelectedNetworkId];
        string sameDevice=Guid.NewGuid().ToString("N");
        var profiles=ids.Select(id=>stores[id].LoadForMaintenance()).ToArray();
        foreach(var profile in profiles)MeshIdentity.Issue(profile.Mesh!,deviceId:sameDevice);
        using var barrier=new Barrier(2);
        var saves=ids.Select((id,i)=>Task.Run(()=>{barrier.SignalAndWait(TimeSpan.FromSeconds(10));try{stores[id].Save(profiles[i]);return "ok";}catch(IOException ex){return ex.Message;}})).ToArray();
        var outcomes=await Task.WhenAll(saves);
        Check(outcomes.Count(x=>x=="ok")==1&&outcomes.Count(x=>x.Contains("已保存与此设备"))==1,"concurrent cross-network enrollment of the same authenticated device commits exactly one relationship");
        Check(ids.Count(id=>stores[id].LoadForMaintenance().Mesh!.Directory!.Members.Any(m=>m.Device==sameDevice))==1,"persisted network files contain only one relationship to the device");
        await host.Worker.StopLocal();
    }
}
