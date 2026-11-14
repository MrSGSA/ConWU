using StreamLink.Core;
using StreamLink.Service;
using System.Text.Json;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PairWorkspaceBudgets()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        using var host=new WorkspaceNode(Path.Combine(ProfileStore.Root,"budgets"),"Budget host");
        try{
            var rows=new List<UiNetworkDto>();
            for(int i=0;i<8;i++){
                var created=await host.Action("",new("create-direct"){Name="Budget "+i});Check(created.Ok,created.Error);
                rows.Add(created.Status!.Networks.Single(n=>n.Id==created.Status.SelectedNetworkId));
            }
            await Until(()=>host.Adapters.Count==8,"eight independently owned network adapters start under the supported runtime budget");
            var state=await host.State();
            Check(host.Servers==1&&state.Networks.Select(n=>n.Status.Settings!.SourcePort).Distinct().Count()==8,"eight compatible networks share one native receiver and own eight distinct source ports");
            Check(state.Networks.Select(n=>MeshAddressing.Prefix(n.Status.VirtualIp)).Distinct().Count()==8,"all automatically allocated network prefixes are distinct");
            var tooMany=await host.Action("",new("create-direct"){Name="Over budget"});
            Check(!tooMany.Ok&&tooMany.Error.Contains("8 条")&&tooMany.Status!.Networks.Length==8,"the ninth enabled network is rejected before a persistent reservation is created");
            foreach(var row in rows){var stopped=await host.Ui(new("stop"){NetworkId=row.Id});Check(stopped.Ok,stopped.Error);}
            for(int i=8;i<16;i++){
                var created=await host.Action("",new("create-direct"){Name="Stored "+i});Check(created.Ok,created.Error);
                var stopped=await host.Ui(new("stop"){NetworkId=created.Status!.SelectedNetworkId});Check(stopped.Ok,stopped.Error);
            }
            var full=await host.Action("",new("create-direct"){Name="Too many stored"});
            Check(!full.Ok&&full.Error.Contains("16 条")&&full.Status!.Networks.Length==16,"stored configuration budget remains bounded independently of active connections");
            var removed=await host.Action(rows[0].Id,new("remove-network",ExpectedNetwork:rows[0].Status.NetworkId,ConfirmReplace:true));Check(removed.Ok,removed.Error);
            var replacement=await host.Action("",new("create-direct"){Name="Replacement"});
            Check(replacement.Ok&&replacement.Status!.Networks.Length==16,"explicit removal releases exactly one configuration slot for reuse");
            Check(host.Probes==0,"budget and recovery paths never run forbidden autonomous traversal");
            await host.Worker.StopLocal();host.Dispose();
            string marker=Directory.EnumerateFiles(Path.Combine(host.Store.DirectoryPath,"networks"),"network-info.json",SearchOption.AllDirectories)
                .Where(p=>!JsonDocument.Parse(File.ReadAllBytes(p)).RootElement.GetProperty("Removed").GetBoolean()).Order(StringComparer.Ordinal).Last();
            byte[] previous=File.ReadAllBytes(marker);File.WriteAllText(marker,"{}");
            try{
                using var invalid=new ControlWorker(host.Store,enableWorkspace:true);
                throw new Exception("invalid network metadata was accepted");
            }catch(FormatException){Check(true,"corrupt later network metadata rejects the workspace without resetting any saved profile");}
            finally{File.WriteAllBytes(marker,previous);}
            using var recovered=new ControlWorker(host.Store,enableWorkspace:true);
            Check(recovered.ProfileSnapshot().Mesh==null,"failed workspace initialization releases all earlier network leases so the repaired instance can reopen");
        }finally{await host.Worker.StopLocal();}
        Console.WriteLine($"PASS {checks} supported multi-network resource budget checks; memory adapters, not eight physical machines");
    }
}
