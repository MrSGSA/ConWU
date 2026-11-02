using System.Text.Json;

namespace StreamLink.Core;

public enum ProfileChangeImpact { None, LiveMetadata, NextAttempt, RestartNetwork }
public static class ProfileChanges
{
    public static DeviceProfile Copy(DeviceProfile value) => JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(value))!;
    public static void PreserveLatestDirectory(DeviceProfile current,DeviceProfile draft)
    {
        if(draft.Mesh is {} next && current.Mesh is {} live && next.Pair.Network==live.Pair.Network &&
           next.OwnerKey==live.OwnerKey && live.Directory is {} latest && latest.Revision>(next.Directory?.Revision??0)){
            MeshIdentity.ValidateDirectory(latest,next.Pair.Network,next.OwnerKey);
            next.Directory=latest;
        }
    }
    public static ProfileChangeImpact Impact(DeviceProfile before, DeviceProfile after)
    {
        var comparable=Copy(after);
        comparable.DeviceName=before.DeviceName;comparable.LogLevel=before.LogLevel;comparable.LogDirectory=before.LogDirectory;
        comparable.AllowManualQualityRequests=before.AllowManualQualityRequests;
        comparable.RequestedVirtualIp=before.RequestedVirtualIp; // next enrollment only; never silently renumber a live network
        comparable.AutoStart=before.AutoStart;
        comparable.EntryRefreshSeconds=before.EntryRefreshSeconds;
        // Runtime observations and opaque future options are not network start
        // parameters. Keep them without restarting an established path.
        comparable.LastEntry=before.LastEntry;comparable.LastStun=before.LastStun;
        comparable.Enabled=before.Enabled;comparable.AdditionalData=before.AdditionalData;
        comparable.CapabilityIntents=before.CapabilityIntents;
        bool nextAttempt=!before.TcpStun.SequenceEqual(after.TcpStun)||!before.UdpStun.SequenceEqual(after.UdpStun);
        comparable.TcpStun=before.TcpStun;comparable.UdpStun=before.UdpStun;
        if(JsonSerializer.Serialize(comparable)!=JsonSerializer.Serialize(before))return ProfileChangeImpact.RestartNetwork;
        if(nextAttempt)return ProfileChangeImpact.NextAttempt;
        return before.AllowManualQualityRequests==after.AllowManualQualityRequests&&before.DeviceName==after.DeviceName&&before.LogLevel==after.LogLevel&&before.LogDirectory==after.LogDirectory&&
            JsonSerializer.Serialize(before.AdditionalData)==JsonSerializer.Serialize(after.AdditionalData)&&JsonSerializer.Serialize(before.CapabilityIntents)==JsonSerializer.Serialize(after.CapabilityIntents)
            ?ProfileChangeImpact.None:ProfileChangeImpact.LiveMetadata;
    }
}
