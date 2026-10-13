using System.Text.Json;

namespace StreamLink.Core;

public enum ProfileChangeImpact { None, LiveMetadata, RestartNetwork }
public static class ProfileChanges
{
    public static DeviceProfile Copy(DeviceProfile value) => JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(value))!;
    public static ProfileChangeImpact Impact(DeviceProfile before, DeviceProfile after)
    {
        var comparable=Copy(after);
        comparable.DeviceName=before.DeviceName;comparable.LogLevel=before.LogLevel;comparable.LogDirectory=before.LogDirectory;
        comparable.AllowManualQualityRequests=before.AllowManualQualityRequests;
        // Runtime observations and opaque future options are not network start
        // parameters. Keep them without restarting an established path.
        comparable.LastEntry=before.LastEntry;comparable.LastStun=before.LastStun;
        comparable.Enabled=before.Enabled;comparable.AdditionalData=before.AdditionalData;
        if(JsonSerializer.Serialize(comparable)!=JsonSerializer.Serialize(before))return ProfileChangeImpact.RestartNetwork;
        return before.AllowManualQualityRequests==after.AllowManualQualityRequests&&before.DeviceName==after.DeviceName&&before.LogLevel==after.LogLevel&&before.LogDirectory==after.LogDirectory&&
            JsonSerializer.Serialize(before.AdditionalData)==JsonSerializer.Serialize(after.AdditionalData)
            ?ProfileChangeImpact.None:ProfileChangeImpact.LiveMetadata;
    }
}
