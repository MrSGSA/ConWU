using System.Reflection;
using System.Text.Json;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task OfflineLocalExit(ProfileStore store,string sid)
    {
        foreach(string scenario in new[]{"owner","guest","equal-owner","equal-guest","pending-close"}){
            var owner=MeshIdentity.Create("https://unreachable.example.test/","","faketcp");var guest=Guest(owner);
            if(scenario.StartsWith("equal")||scenario=="pending-close")MeshGovernance.Enable(owner);
            guest.Directory=owner.Directory;
            var mesh=scenario.EndsWith("guest")?guest:owner;
            var original=new DeviceProfile{Mesh=mesh,Enabled=false,ConnectionSource="existing",DeviceName="Offline preserved",LogLevel="debug",
                ExistingEntries=[new(0,"203.0.113.5:44680"),new(ExistingEntry.Network,"https://entries.example.test/streamlink?token=fixture")],
                EntryRefreshSeconds=300,RequestedVirtualIp="10.73.74.9",CloudflareDdnsToken="fixture-offline-ddns-token-1234567",JoinedEntryNetwork=mesh.Pair.Network,JoinedEntrySources=[new(ExistingEntry.Network,"203.0.113.7:44680")]};
            if(scenario=="pending-close")original.PendingMembership=new(MeshGovernance.Head(mesh.Directory!),MeshGovernance.Change(mesh,"close"),"close");
            store.Save(original);
            using var worker=new ControlWorker();
            var before=(await worker.HandleUi(new("status"),sid,default)).Status!;
            var closing=new ClosingPairClient(true);
            foreach(var pair in new Dictionary<string,object>{{"uiPairClient",closing},{"uiPairOwner",true},{"uiRoom",new PairRoomTicket("offline-room","123456","fixture-token","fixture-commit","fixture",DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds())}})
                typeof(ControlWorker).GetField(pair.Key,BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(worker,pair.Value);
            var noConfirm=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("forget-network",ExpectedNetwork:mesh.Pair.Network)),sid,default);
            Check(!noConfirm.Ok&&store.Load().Mesh!=null,"local exit requires explicit confirmation: "+scenario);
            var stale=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("forget-network",ExpectedNetwork:Guid.NewGuid().ToString("N"),ConfirmReplace:true)),sid,default);
            Check(!stale.Ok&&store.Load().Mesh?.Pair.Network==mesh.Pair.Network,"stale local-exit actions cannot remove another current network: "+scenario);
            var priorBackups=Directory.GetFiles(ProfileStore.Root,"profile-before-local-exit-*").ToHashSet();
            bool retainProof=MeshRejoin.Retain(mesh)!=null;
            var watch=System.Diagnostics.Stopwatch.StartNew();
            var result=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("forget-network",ExpectedNetwork:mesh.Pair.Network,ConfirmReplace:true)),sid,default);
            Check(result.Ok&&watch.ElapsedMilliseconds<2000&&result.Status!.NetworkId.Length==0,"unreachable coordinator cannot block a local exit: "+scenario);
            var after=result.Status!;var saved=store.Load();
            Check(closing.Closed==0&&closing.Disposed,"local exit discards pairing resources without a network cleanup request: "+scenario);
            Check(JsonSerializer.Serialize(before.Settings)==JsonSerializer.Serialize(after.Settings)&&before.SettingsRevision==after.SettingsRevision&&saved.CloudflareDdnsToken==original.CloudflareDdnsToken,"local exit preserves complete settings and DNS credentials: "+scenario);
            Check(saved.Mesh==null&&!saved.Enabled&&saved.PendingMembership==null&&saved.JoinedEntryNetwork.Length==0&&saved.JoinedEntrySources.Length==0&&(saved.RejoinCredential!=null)==retainProof,"local exit clears active state and retains only an authorized rejoin proof: "+scenario);
            string backup=Directory.GetFiles(ProfileStore.Root,"profile-before-local-exit-*").Single(p=>!priorBackups.Contains(p));
            byte[] protectedBytes=File.ReadAllBytes(backup);
            byte[] clearBytes=OperatingSystem.IsLinux()?protectedBytes:ProtectedData.Unprotect(protectedBytes,"StreamLink-profile-v2"u8.ToArray(),DataProtectionScope.LocalMachine);
            var retained=JsonSerializer.Deserialize<DeviceProfile>(clearBytes)!;
            Check(retained.Mesh?.Pair.Network==mesh.Pair.Network&&retained.CloudflareDdnsToken==original.CloudflareDdnsToken,"local exit creates an actual protected network backup: "+scenario);
            var changed=after.Settings! with{Service="https://new.example.test/",CertificatePin=""};
            var edit=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:changed,ExpectedRevision:after.SettingsRevision)),sid,default);
            Check(edit.Ok&&edit.Status!.Settings!.Service==changed.Service,"coordination settings unlock immediately after offline exit: "+scenario);
        }
    }
}
