using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    internal static ExistingEntry[] RuntimeEntries(DeviceProfile profile)
    {
        var saved=PublicSettings(profile).ExistingEntries;
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
        return learned.Take(1).Concat(bound).Concat(learned.Skip(1)).DistinctBy(e=>e.Source,StringComparer.Ordinal).Take(ExistingEntryResolver.MaximumSources).ToArray();
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
        profile.ManualEndpoint=saved.ManualEndpoint;
        profile.SelectTransport(saved.PathSelection);
        profile.AllowManualQualityRequests=saved.AllowManualQualityRequests;
        profile.ListenPort=saved.ListenPort;profile.SourcePort=saved.SourcePort;
        profile.ConnectionSource=saved.ConnectionSource;profile.DirectMode=saved.DirectMode;
        profile.CoordinationService=saved.Service;profile.CoordinationPin=saved.CertificatePin;
        profile.ExistingEntries=RuntimeEntries(profile);
        profile.EntryRefreshSeconds=saved.EntryRefreshSeconds;
        profile.RequestedVirtualIp=saved.RequestedVirtualIp;
        profile.TcpStun=saved.TcpStun?.ToArray()??profile.TcpStun;
        profile.UdpStun=saved.UdpStun?.ToArray()??profile.UdpStun;
    }

    void RequireSavedProtocol(string mode)
    {
        string selected=PublicSettings(profile).PathSelection=="udp-only"?"udp":"faketcp";
        if(mode!=selected)throw new IOException("目标网络使用的协议与已保存的设置不同。请在设置中自行选择并保存相同协议后重试；原设置未改动。");
    }
}
