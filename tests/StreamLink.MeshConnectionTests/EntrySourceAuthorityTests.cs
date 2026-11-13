using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    static void EntrySourceAuthority()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var owner=MeshIdentity.Create("","","faketcp",direct:true);
        var guest=Guest(owner);
        const string seed="203.0.113.4:45000",oldSubscription="txt://old.example#host";
        var profile=new DeviceProfile {
            Mesh=guest,ConnectionSource="existing",DirectMode=true,AutoConfigureJoin=true,
            SavedNetworkSettings=new(){ConnectionSource="existing",DirectMode=true,DiscoveryMode="existing",
                ExistingEntries=[new(ExistingEntry.NetworkOwner,"txt://current.example#host")]},
            ExistingEntries=[new(ExistingEntry.Network,seed),new(ExistingEntry.NetworkOwner,"txt://current.example#host")],
            JoinedEntryNetwork=guest.Pair.Network,
            JoinedEntrySources=[new(ExistingEntry.Network,seed),new(owner.Self.Slot,oldSubscription)]
        };
        string identity=JsonSerializer.Serialize(profile.Mesh),observations=JsonSerializer.Serialize(profile.JoinedEntrySources);
        foreach(string source in new[]{"txt://current.example#host","https://current.example/entry#host","203.0.113.8:45001"}){
            profile.SavedNetworkSettings=profile.SavedNetworkSettings with{ExistingEntries=[new(ExistingEntry.NetworkOwner,source)]};
            var entries=ControlWorker.RuntimeEntries(profile);
            Check(entries.SequenceEqual(profile.SavedNetworkSettings.ExistingEntries),"current configured host source exclusively replaces bootstrap and previously learned sources: "+source);
        }
        Check(JsonSerializer.Serialize(profile.Mesh)==identity&&JsonSerializer.Serialize(profile.JoinedEntrySources)==observations,
            "selecting current entries does not modify identity or enrollment observations");

        var editable=ProfileChanges.Copy(profile);editable.AutoConfigureJoin=false;
        var changed=ControlWorker.PrepareConnectionSettings(editable,editable.SavedNetworkSettings! with{
            ExistingEntries=[new(ExistingEntry.NetworkOwner,"txt://replacement.example#host")]
        });
        Check(changed.ExistingEntries.SequenceEqual(changed.SavedNetworkSettings!.ExistingEntries),
            "saving a replacement host source cannot reactivate a previous subscription or pairing endpoint");

        var crowded=ProfileChanges.Copy(profile);
        crowded.SavedNetworkSettings=crowded.SavedNetworkSettings! with{ExistingEntries=Enumerable.Range(1,12).Select(i=>new ExistingEntry(ExistingEntry.NetworkOwner,$"203.0.113.{i}:45001")).ToArray()};
        Check(ControlWorker.RuntimeEntries(crowded).SequenceEqual(crowded.SavedNetworkSettings.ExistingEntries),
            "a historical seed neither displaces nor precedes any of twelve configured host sources");

        var manual=ProfileChanges.Copy(profile);
        manual.SavedNetworkSettings=manual.SavedNetworkSettings! with{ExistingEntries=[]};
        manual.JoinedEntrySources=[new(ExistingEntry.Network,seed)];
        Check(ControlWorker.RuntimeEntries(manual).Single().Source==seed,"a manual-only enrollment retains its sole authenticated bootstrap when no host source exists");
        manual.SavedNetworkSettings=manual.SavedNetworkSettings with{ExistingEntries=[new(0,"203.0.113.9:45002")]};
        Check(ControlWorker.RuntimeEntries(manual).Any(e=>e.Source==seed),"a local ingress cannot supersede the remote host bootstrap");
        manual.ConnectionSource="custom";
        manual.SavedNetworkSettings=manual.SavedNetworkSettings with{ConnectionSource="custom",DiscoveryMode="direct"};
        Check(ControlWorker.RuntimeEntries(manual).Single().Source==seed,"autonomous manual discovery keeps the bootstrap required by its selected mode");

        var otherNetwork=ProfileChanges.Copy(manual);
        otherNetwork.JoinedEntryNetwork=Guid.NewGuid().ToString("N");
        Check(ControlWorker.RuntimeEntries(otherNetwork).Length==0,"entry observations remain isolated to their approved network");

        profile.SavedNetworkSettings=profile.SavedNetworkSettings with{ExistingEntries=[new(ExistingEntry.NetworkOwner,"txt://current.example#host")]};
        string settings=JsonSerializer.Serialize(profile.SavedNetworkSettings);
        var store=new ProfileStore();store.Save(profile);
        for(int restart=0;restart<2;restart++){
            using var worker=new ControlWorker();
            var restored=worker.ProfileSnapshot();
            Check(restored.ExistingEntries.SequenceEqual(profile.SavedNetworkSettings!.ExistingEntries)&&store.Load().ExistingEntries.SequenceEqual(restored.ExistingEntries),
                "service startup discards a persisted superseded runtime seed without re-pairing: "+restart);
            Check(JsonSerializer.Serialize(restored.SavedNetworkSettings)==settings&&JsonSerializer.Serialize(restored.Mesh)==identity&&JsonSerializer.Serialize(restored.JoinedEntrySources)==observations,
                "startup reconciliation preserves saved settings, membership and enrollment history: "+restart);
        }
        Console.WriteLine($"PASS {checks} entry source authority checks; no installed service changes");
    }
}
