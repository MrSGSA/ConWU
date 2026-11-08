namespace StreamLink.Core;

// User preferences can be shared. Enrollment, identity, allocated addresses and
// runtime observations always remain in the individual network profile.
public sealed record ConnectionConfiguration(string Id,string Name,long Revision,UiNetworkSettings Settings);
public sealed record UiConfigurationUse(string NetworkId,string Name,bool Enabled,string State,string Error);
public sealed record UiConfigurationDto(string Id,string Name,long Revision,UiNetworkSettings Settings,UiConfigurationUse[] Networks);
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record UiConfigurationAction(string Action,string Id="",string Name="",long ExpectedRevision=0,UiNetworkSettings? Settings=null,bool ConfirmReconnect=false);

public static class ConnectionSettings
{
    public static UiNetworkSettings Normalize(UiNetworkSettings settings)
    {
        if(settings is null||settings.Coordinator is null||settings.ExistingEntries is null||settings.ExistingEntries.Any(e=>e==null||e.Source==null))throw new FormatException("连接配置内容无效");
        if(settings.Ddns is {Enabled:true}||settings.Coordinator is {Enabled:true})throw new FormatException("连接配置不包含 DNS 发布或本机协调服务设置");
        if(settings.CoordinatorBackup&&(settings.ConnectionSource!="existing"||!settings.DirectMode||string.IsNullOrWhiteSpace(settings.Service)))throw new FormatException("备用协调仅用于已有入口直连，请填写 HTTPS 协调服务器");
        if(settings.ExistingEntries.Any(e=>e.PeerSlot is not (0 or ExistingEntry.NetworkOwner)))throw new FormatException("共用配置的入口须明确属于本机或目标主机");
        var normalized=settings with{Coordinator=new(),Ddns=null,ManualEndpoint="",TcpStun=settings.TcpStun is {Length:>0}?settings.TcpStun.ToArray():Stun.TcpServers.ToArray(),UdpStun=settings.UdpStun is {Length:>0}?settings.UdpStun.ToArray():Stun.UdpServers.ToArray(),ExistingEntries=settings.ExistingEntries.Select(e=>e with{Source=ExistingEntryResolver.NormalizeSource(e.Source)}).Distinct().ToArray()};
        if(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(normalized).Length>16384)throw new FormatException("单份连接配置超过 16 KiB，请减少来源或 STUN 列表");
        var basis=new DeviceProfile();Apply(basis,normalized);basis.Validate();basis.RequireFixedTransport();
        return normalized;
    }
    public static void Apply(DeviceProfile profile,UiNetworkSettings settings)
    {
        profile.SelectTransport(settings.PathSelection);profile.AllowManualQualityRequests=settings.AllowManualQualityRequests;
        profile.ConnectionSource=settings.ConnectionSource;profile.DirectMode=settings.DirectMode;
        profile.CoordinationService=settings.Service;profile.CoordinationPin=settings.CertificatePin;
        profile.ExistingEntries=settings.ExistingEntries.ToArray();profile.ManualEndpoint=settings.ManualEndpoint;
        profile.ListenPort=settings.ListenPort;profile.SourcePort=settings.SourcePort;
        profile.RequestedVirtualIp=settings.RequestedVirtualIp;profile.EntryRefreshSeconds=settings.EntryRefreshSeconds;
        profile.TcpStun=settings.TcpStun?.ToArray()??Stun.TcpServers.ToArray();profile.UdpStun=settings.UdpStun?.ToArray()??Stun.UdpServers.ToArray();
        profile.SavedNetworkSettings=settings with{Coordinator=new(),Ddns=null};

    }
}
