using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task SavedSettingsLifecycle()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var owner=MeshIdentity.Create("https://network.example/","","faketcp");var guest=Guest(owner);
        var profile=new DeviceProfile{Mesh=guest,Enabled=false,ConnectionSource="existing",ListenPort=45000,SourcePort=45001,
            EntryRefreshSeconds=180,RequestedVirtualIp="10.171.139.2",DeviceName="Saved laptop",LogLevel="warn",
            ExistingEntries=[new(0,"203.0.113.10:45000"),new(1,"https://entries.example/streamlink"),new(9,"203.0.113.90:45000")]};
        var store=new ProfileStore();store.Save(profile);string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        string before;string revision;
        using(var worker=new ControlWorker()){
            var original=(await worker.HandleUi(new("status"),sid,default)).Status!;
            before=JsonSerializer.Serialize(original.Settings);revision=original.SettingsRevision;
            Check(original.Settings!.ExistingEntries.Any(e=>e.PeerSlot==ExistingEntry.NetworkOwner),"legacy target entry migrates to a stable owner reference without changing its address");
            var left=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("leave",ExpectedNetwork:guest.Pair.Network,ConfirmReplace:true)),sid,default);
            Check(left.Ok&&left.Status!.NetworkId.Length==0,"actual guest leave removes membership without contacting the offline owner");
            Check(JsonSerializer.Serialize(left.Status!.Settings)==before&&left.Status.SettingsRevision==revision,"all saved connection settings and their revision survive actual network leave unchanged");
            Check(left.Status.DeviceName==profile.DeviceName&&left.Status.LogLevel==profile.LogLevel,"leaving preserves device name and log level");
            var persisted=store.Load();
            Check(persisted.ExistingEntries.Any(e=>e.PeerSlot==-1)&&persisted.SavedNetworkSettings!.ExistingEntries.Any(e=>e.PeerSlot==9)&&persisted.ExistingEntries.All(e=>e.PeerSlot!=9),"user target remains reusable while old member-specific entries are retained only as inactive settings");
            var created=await worker.Handle(new("mesh-create",Service:"https://other-network.example/"));
            Check(created.Ok&&JsonSerializer.Serialize((await worker.HandleUi(new("status"),sid,default)).Status!.Settings)==before,"creating a different network cannot rewrite the saved settings");
        }
        using(var restarted=new ControlWorker()){
            var current=(await restarted.HandleUi(new("status"),sid,default)).Status!;
            Check(JsonSerializer.Serialize(current.Settings)==before&&current.SettingsRevision==revision,"independent settings survive service reconstruction from the protected store");
            var settings=current.Settings! with{Service="https://changed.example/",EntryRefreshSeconds=240};
            var saved=await restarted.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:settings,ExpectedRevision:current.SettingsRevision)),sid,default);
            Check(!saved.Ok&&JsonSerializer.Serialize((await restarted.HandleUi(new("status"),sid,default)).Status!.Settings)==before,"invalid network-bound save cannot partly change the independent settings");
            var active=(await restarted.Handle(new("status"))).Profile!.Mesh!;
            var leave=await restarted.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("leave",ExpectedNetwork:active.Pair.Network,ConfirmReplace:true)),sid,default);
            var now=leave.Status!;
            var changed=await restarted.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:now.Settings! with{EntryRefreshSeconds=240},ExpectedRevision:now.SettingsRevision)),sid,default);
            Check(changed.Ok&&changed.Status!.Settings!.EntryRefreshSeconds==240&&changed.Status.SettingsRevision!=revision,"explicit user save changes independent settings and advances their revision");
        }
        Console.WriteLine($"PASS {checks} saved settings lifecycle checks");
    }
}
