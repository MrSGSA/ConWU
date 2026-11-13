namespace StreamLink.Core;

// User preferences can be shared. Enrollment, identity, allocated addresses and
// runtime observations always remain in the individual network profile.
public sealed record ConnectionConfiguration(string Id,string Name,long Revision,UiNetworkSettings Settings)
{
    // Modern WebUI settings belong to their network. Explicit CLI templates
    // retain their own lifecycle, including when their last user is removed.
    public bool RetireWithNetwork {get;init;}
}
public sealed record UiConfigurationUse(string NetworkId,string Name,bool Enabled,string State,string Error);
public sealed record UiConfigurationDto(string Id,string Name,long Revision,UiNetworkSettings Settings,UiConfigurationUse[] Networks);
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record UiConfigurationAction(string Action,string Id="",string Name="",long ExpectedRevision=0,UiNetworkSettings? Settings=null,bool ConfirmReconnect=false,bool Independent=false);

public static class ConnectionSettings
{
    public static (string Service,string Pin) PairingCoordinator(UiNetworkSettings settings)=>settings.DirectMode
        ?settings.ConnectionSource=="existing"?(settings.PairingService,settings.PairingCertificatePin):("","")
        :(settings.Service,settings.CertificatePin);
    public static string Discovery(UiNetworkSettings settings)=>settings.DiscoveryMode.Length>0?settings.DiscoveryMode:
        settings.ConnectionSource=="existing"?"existing":settings.DirectMode?(settings.PkarrPublish?"pkarr":"direct"):"coordinator";
    public static UiNetworkSettings Normalize(UiNetworkSettings settings,bool forGuest=false)
    {
        if(settings is null||settings.Service is null||settings.CertificatePin is null||settings.PairingService is null||settings.PairingCertificatePin is null||settings.ManualEndpoint is null||settings.RequestedVirtualIp is null||settings.Coordinator is null||settings.PkarrGateways is null||settings.PkarrGateways.Any(g=>g is null)||settings.ExistingEntries is null||settings.ExistingEntries.Any(e=>e==null||e.Source==null))throw new FormatException("连接配置内容无效");
        if(Discovery(settings)=="pkarr"){
            try{settings=settings with{PkarrGateways=PkarrClient.NormalizeGateways(settings.PkarrGateways)};}
            catch(ArgumentException ex){throw new FormatException("请填写 1–4 个有效的 HTTPS PKARR 发现网关",ex);}
        }
        if(settings.PairingService.Length>2048||settings.PairingCertificatePin.Length>128||settings.PairingService.Any(char.IsControl))throw new FormatException("配对协调地址或证书指纹无效");
        if(settings.ConnectionSource=="existing"&&settings.PairingService.Length>0){
            if(!Uri.TryCreate(settings.PairingService,UriKind.Absolute,out var uri)||uri.Scheme!="https"||uri.UserInfo.Length>0||uri.Query.Length>0||uri.Fragment.Length>0)throw new FormatException("短配对码需要有效的 HTTPS 协调地址");
            if(settings.PairingCertificatePin.Length>0&&(settings.PairingCertificatePin.Length!=64||!settings.PairingCertificatePin.All(char.IsAsciiHexDigit)))throw new FormatException("配对协调证书指纹需要 64 位十六进制字符");
            settings=settings with{PairingService=uri.AbsoluteUri.EndsWith('/')?uri.AbsoluteUri:uri.AbsoluteUri+"/",PairingCertificatePin=settings.PairingCertificatePin.ToUpperInvariant()};
        }
        if(settings.Ddns is {Enabled:true}||settings.Coordinator is {Enabled:true})throw new FormatException("连接配置不包含 DNS 发布或本机协调服务设置");
        if(settings.DiscoveryMode is null||settings.DiscoveryMode is not ("" or "existing" or "coordinator" or "direct" or "pkarr"))throw new FormatException("请选择有效的主机发现方式");
        if(settings.DiscoveryMode.Length>0){
            string discovery=Discovery(settings);
            if((discovery=="existing")!=(settings.ConnectionSource=="existing")||settings.DirectMode!=(discovery!="coordinator"))throw new FormatException("连接策略与主机发现方式不一致");
            if(discovery=="coordinator"&&string.IsNullOrWhiteSpace(settings.Service))throw new FormatException("使用配对码需要填写 HTTPS 协调服务器");
            settings=settings with{CoordinatorBackup=false,PkarrPublish=discovery=="pkarr"&&!forGuest};
        }
        if(settings.CoordinatorBackup&&(settings.ConnectionSource!="existing"||!settings.DirectMode||string.IsNullOrWhiteSpace(settings.Service)))throw new FormatException("备用协调仅用于已有入口直连，请填写 HTTPS 协调服务器");
        if(settings.ExistingEntries.Any(e=>e.PeerSlot is not (0 or ExistingEntry.NetworkOwner)))throw new FormatException("共用配置的入口须明确属于本机或目标主机");
        if(settings.ExistingEntries.Any(e=>e.Source.Length>2048||e.Source.Any(char.IsControl)))throw new FormatException("入口来源过长或包含无效字符");
        bool autonomous=settings.DiscoveryMode.Length>0&&settings.ConnectionSource=="custom";
        var normalized=settings with{Coordinator=new(),Ddns=null,ManualEndpoint="",TcpStun=settings.TcpStun is {Length:>0}?settings.TcpStun.ToArray():Stun.TcpServers.ToArray(),UdpStun=settings.UdpStun is {Length:>0}?settings.UdpStun.ToArray():Stun.UdpServers.ToArray(),ExistingEntries=settings.ExistingEntries.Select(e=>e with{Source=autonomous&&e.PeerSlot==0?e.Source:ExistingEntryResolver.NormalizeSource(e.Source)}).Distinct().ToArray()};
        if(normalized.ExistingEntries.Length>ExistingEntryResolver.MaximumSources)throw new FormatException("最多保存 12 项入口来源");
        if(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(normalized).Length>16384)throw new FormatException("单份连接配置超过 16 KiB，请减少来源或 STUN 列表");
        var basis=new DeviceProfile();Apply(basis,normalized);basis.Validate();basis.RequireFixedTransport();
        return normalized;
    }
    public static void Apply(DeviceProfile profile,UiNetworkSettings settings)
    {
        if(profile.Mesh is {} paired&&TransportModes.RequiresNewEnrollment(paired.Pair.Mode,TransportModes.Mode(settings.PathSelection)))throw new IOException("切换此传输协议需要重新配对，请新建网络使用；原网络和设置保持不变");
        profile.SelectTransport(settings.PathSelection);profile.AllowManualQualityRequests=settings.AllowManualQualityRequests;
        profile.StreamFlowLanes=settings.StreamFlowLanes;
        profile.PortControlMapping=settings.PortControlMapping;
        profile.ConnectionSource=settings.ConnectionSource;profile.DirectMode=settings.DirectMode;
        profile.PkarrPublish=settings.PkarrPublish;
        bool coordination=settings.DiscoveryMode.Length==0||Discovery(settings)=="coordinator"||settings.CoordinatorBackup;
        profile.CoordinationService=coordination?settings.Service:"";profile.CoordinationPin=coordination?settings.CertificatePin:"";
        profile.ExistingEntries=settings.ExistingEntries.Where(e=>settings.DiscoveryMode.Length==0||settings.ConnectionSource=="existing"||e.PeerSlot!=0).ToArray();profile.ManualEndpoint=settings.ManualEndpoint;
        profile.ListenPort=settings.ListenPort;profile.SourcePort=settings.SourcePort;
        profile.RequestedVirtualIp=settings.RequestedVirtualIp;profile.EntryRefreshSeconds=settings.EntryRefreshSeconds;
        bool useStun=settings.DiscoveryMode.Length==0||settings.ConnectionSource=="custom";
        profile.TcpStun=useStun?settings.TcpStun?.ToArray()??Stun.TcpServers.ToArray():Stun.TcpServers.ToArray();profile.UdpStun=useStun?settings.UdpStun?.ToArray()??Stun.UdpServers.ToArray():Stun.UdpServers.ToArray();
        profile.SavedNetworkSettings=settings with{Coordinator=new(),Ddns=null};

    }
}
