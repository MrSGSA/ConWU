using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    internal static ExistingEntry[] RuntimeEntries(DeviceProfile profile)
    {
        var settings=PublicSettings(profile);
        var saved=settings.ConnectionSource=="existing"?settings.ExistingEntries:Array.Empty<ExistingEntry>();
        if(profile.Mesh is not {} mesh)return saved.Where(e=>e.PeerSlot is 0 or ExistingEntry.NetworkOwner or ExistingEntry.Network).ToArray();
        var bound=new List<ExistingEntry>();
        foreach(var entry in saved){
            if(entry.PeerSlot==ExistingEntry.NetworkOwner&&mesh.IsDecentralized){
                int target=MeshGovernance.CurrentSlot(mesh.Directory!,mesh.IntroducerSlot);
                if(target>0&&target!=mesh.Self.Slot)bound.Add(entry with{PeerSlot=target});
            }
            else if(entry.PeerSlot is 0 or ExistingEntry.Network||entry.PeerSlot==ExistingEntry.NetworkOwner&&mesh.IntroducerSlot!=mesh.Self.Slot)bound.Add(entry);
            else if(entry.PeerSlot>0&&ActiveSavedPeerSlot(profile,entry.PeerSlot) is >0 and var slot)bound.Add(entry with{PeerSlot=slot});
        }
        var learned=new List<ExistingEntry>();
        if(profile.JoinedEntryNetwork==mesh.Pair.Network)foreach(var hint in profile.JoinedEntrySources){
            if(hint.PeerSlot==ExistingEntry.Network){learned.Add(hint);continue;}
            int slot=mesh.IsDecentralized?MeshGovernance.CurrentSlot(mesh.Directory!,hint.PeerSlot):hint.PeerSlot;
            if(slot!=mesh.Self.Slot&&mesh.Directory?.Members.Any(m=>m.Slot==slot)==true)learned.Add(hint with{PeerSlot=slot});
        }
        var pkarr=PkarrRendezvous.Uses(profile)&&profile.PkarrStateVersion==1?profile.PkarrPeers.Where(p=>PkarrRendezvous.Matches(p,mesh)).Select(p=>new ExistingEntry(p.Slot,p.Source)).ToArray():[];
        // Enrollment endpoints only bootstrap discovery. Once a peer has a
        // configured source (or an authenticated PKARR binding), that source
        // replaces its enrollment observations, even while resolution fails.
        // A local ingress is not a replacement for a remote peer's address.
        int Target(ExistingEntry entry)=>entry.PeerSlot is ExistingEntry.Network or ExistingEntry.NetworkOwner?mesh.IntroducerSlot:entry.PeerSlot;
        var current=pkarr.Concat(bound).Where(e=>e.PeerSlot!=0).ToArray();
        learned.RemoveAll(hint=>current.Any(entry=>entry.PeerSlot==ExistingEntry.Network||Target(entry)==Target(hint)));
        return pkarr.Concat(learned.Take(1)).Concat(bound).Concat(learned.Skip(1)).DistinctBy(e=>e.Source,StringComparer.Ordinal).Take(ExistingEntryResolver.MaximumSources).ToArray();
    }

    static int ActiveSavedPeerSlot(DeviceProfile profile,int slot)
    {
        if(profile.Mesh is not {} mesh||profile.SavedPeerEntryNetwork!=mesh.Pair.Network)return 0;
        if(mesh.Directory?.Members.Any(m=>m.Slot==slot&&m.Slot!=mesh.Self.Slot)==true)return slot;
        if(mesh.IsDecentralized){int current=MeshGovernance.CurrentSlot(mesh.Directory!,slot);return current!=mesh.Self.Slot?current:0;}
        var rejoined=profile.RejoinHistory.LastOrDefault(h=>h.Network==mesh.Pair.Network&&h.Former.Slot==slot);
        return rejoined!=null&&mesh.Directory?.Members.Any(m=>m.Slot==rejoined.CurrentSlot&&m.Slot!=mesh.Self.Slot)==true?rejoined.CurrentSlot:0;
    }

    static void RestoreSavedNetworkSettings(DeviceProfile profile)
    {
        var saved=PublicSettings(profile);
        ConnectionSettings.Apply(profile,saved);
        profile.ExistingEntries=RuntimeEntries(profile);
    }

    void RequireSavedProtocol(string mode)
    {
        string selected=TransportModes.Mode(PublicSettings(profile).PathSelection);
        if(mode!=selected)throw new IOException("目标网络使用的协议与已保存的设置不同。请在设置中自行选择并保存相同协议后重试；原设置未改动。");
    }
}
