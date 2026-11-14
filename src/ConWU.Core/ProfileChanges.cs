using System.Text.Json;

namespace StreamLink.Core;

public enum ProfileChangeImpact { None, LiveMetadata, NextAttempt, RestartNetwork }
public static class ProfileChanges
{
    public static DeviceProfile Copy(DeviceProfile value) => JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(value))!;
    public static void PreserveLatestDirectory(DeviceProfile current,DeviceProfile draft)
    {
        if(draft.Mesh is {} target&&current.Mesh is {} source&&target.Pair.Network==source.Pair.Network&&target.OwnerKey==source.OwnerKey&&target.Self.Device==source.Self.Device&&target.Self.Slot==source.Self.Slot&&target.Self.SigningKey==source.Self.SigningKey){
            draft.PkarrSeed=current.PkarrSeed;draft.PkarrSequence=current.PkarrSequence;draft.PkarrPeers=current.PkarrPeers;draft.PkarrStateVersion=current.PkarrStateVersion;
        }
        if(draft.Mesh is {} next && current.Mesh is {} live && next.Pair.Network==live.Pair.Network &&
           next.OwnerKey==live.OwnerKey && live.Directory is {} latest && latest.Revision>(next.Directory?.Revision??0)){
            MeshIdentity.ValidateDirectory(latest,next.Pair.Network,next.OwnerKey);
            next.Directory=latest;
        }
    }
    public static ProfileChangeImpact Impact(DeviceProfile before, DeviceProfile after)
    {
        if(before.UsesExistingEntriesOnly!=after.UsesExistingEntriesOnly||(before.SavedNetworkSettings?.CoordinatorBackup??false)!=(after.SavedNetworkSettings?.CoordinatorBackup??false))return ProfileChangeImpact.RestartNetwork;
        var comparable=Copy(after);
        comparable.DeviceName=before.DeviceName;comparable.LogLevel=before.LogLevel;comparable.LogDirectory=before.LogDirectory;
        comparable.AllowManualQualityRequests=before.AllowManualQualityRequests;
        comparable.RequestedVirtualIp=before.RequestedVirtualIp; // next enrollment only; never silently renumber a live network
        comparable.AutoStart=before.AutoStart;
        comparable.UuTakeover=before.UuTakeover;
        comparable.Coordinator=before.Coordinator; // independent host role; never rebuild healthy data paths
        comparable.CoordinatorRoleVersion=before.CoordinatorRoleVersion;
        comparable.PkarrPublish=before.PkarrPublish;comparable.PkarrSeed=before.PkarrSeed;comparable.PkarrSequence=before.PkarrSequence;
        comparable.PkarrPeers=before.PkarrPeers;
        comparable.PkarrStateVersion=before.PkarrStateVersion;
        comparable.Ddns=before.Ddns;comparable.CloudflareDdnsToken=before.CloudflareDdnsToken;
        comparable.EntryRefreshSeconds=before.EntryRefreshSeconds;
        // Runtime observations and opaque future options are not network start
        // parameters. Keep them without restarting an established path.
        comparable.LastEntry=before.LastEntry;comparable.LastStun=before.LastStun;
        comparable.Enabled=before.Enabled;comparable.AdditionalData=before.AdditionalData;
        comparable.CapabilityIntents=before.CapabilityIntents;
        comparable.SavedNetworkSettings=before.SavedNetworkSettings;
        comparable.SavedPeerEntryNetwork=before.SavedPeerEntryNetwork;
        bool nextAttempt=!before.TcpStun.SequenceEqual(after.TcpStun)||!before.UdpStun.SequenceEqual(after.UdpStun)||
            before.ConnectionSource!=after.ConnectionSource||before.ManualEndpoint!=after.ManualEndpoint||!before.ExistingEntries.SequenceEqual(after.ExistingEntries);
        comparable.TcpStun=before.TcpStun;comparable.UdpStun=before.UdpStun;
        if(before.Mesh!=null||before.Pair==null){comparable.ConnectionSource=before.ConnectionSource;comparable.ManualEndpoint=before.ManualEndpoint;comparable.ExistingEntries=before.ExistingEntries;}
        if(JsonSerializer.Serialize(comparable)!=JsonSerializer.Serialize(before))return ProfileChangeImpact.RestartNetwork;
        if(nextAttempt)return ProfileChangeImpact.NextAttempt;
        return before.AllowManualQualityRequests==after.AllowManualQualityRequests&&before.DeviceName==after.DeviceName&&before.LogLevel==after.LogLevel&&before.LogDirectory==after.LogDirectory&&
            JsonSerializer.Serialize(before.AdditionalData)==JsonSerializer.Serialize(after.AdditionalData)&&JsonSerializer.Serialize(before.CapabilityIntents)==JsonSerializer.Serialize(after.CapabilityIntents)
            ?ProfileChangeImpact.None:ProfileChangeImpact.LiveMetadata;
    }
}
