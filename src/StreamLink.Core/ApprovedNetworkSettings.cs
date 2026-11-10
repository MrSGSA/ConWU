namespace StreamLink.Core;

// Only this allowlist crosses the encrypted, user-approved pairing exchange.
// Listener/source ports, device preferences, private keys and server credentials
// remain local. Entries are hints bound to the issuing host's member identity.
public sealed record ApprovedNetworkSettings(string PathSelection,string ConnectionSource,
    ExistingEntry[] Entries,int EntryRefreshSeconds,string[] TcpStun,string[] UdpStun,
    bool CoordinatorBackup,string Service,string CertificatePin,int HostListenPort)
{
    public string NetworkName {get;init;}="";
    public string DiscoveryMode {get;init;}="";
    public string PairingService {get;init;}="";
    public string PairingCertificatePin {get;init;}="";
    public string[] PkarrGateways {get;init;}=PkarrClient.DefaultGateways.ToArray();
    public static ApprovedNetworkSettings Create(MeshProfile host,UiNetworkSettings settings,string networkName="")
        =>new(settings.PathSelection,settings.ConnectionSource,
            settings.ExistingEntries.Where(e=>e.PeerSlot==0&&(settings.ConnectionSource=="existing"||ExistingEntryResolver.Kind(e.Source)=="PKARR")).Select(e=>e with{PeerSlot=host.Self.Slot}).ToArray(),
            settings.EntryRefreshSeconds,settings.TcpStun??[],settings.UdpStun??[],settings.CoordinatorBackup,
            host.Pair.Direct?settings.Service:host.Pair.Service,host.Pair.Direct?settings.CertificatePin:host.Pair.CertificatePin,settings.ListenPort){NetworkName=networkName,DiscoveryMode=settings.DiscoveryMode,PairingService=settings.PairingService,PairingCertificatePin=settings.PairingCertificatePin,PkarrGateways=ConnectionSettings.Discovery(settings)=="pkarr"?settings.PkarrGateways.ToArray():PkarrClient.DefaultGateways.ToArray()};

    public UiNetworkSettings ForGuest(MeshProfile mesh,UiNetworkSettings local)
    {
        if(PathSelection!=(mesh.Pair.Mode=="udp"?"udp-only":"faketcp-only")||ConnectionSource is not ("custom" or "existing")||
            Entries is null||TcpStun is null||UdpStun is null||Service is null||CertificatePin is null||PairingService is null||PairingCertificatePin is null||PkarrGateways is null||
            Entries.Any(e=>e is null||e.PeerSlot!=mesh.IntroducerSlot)||HostListenPort is <1 or >65535||NetworkName is null||NetworkName.Length>64||NetworkName.Any(char.IsControl))
            throw new FormatException("主机提供的网络设置与获准身份不符");
        if(!mesh.Pair.Direct&&(Service!=mesh.Pair.Service||!CertificatePin.Equals(mesh.Pair.CertificatePin,StringComparison.OrdinalIgnoreCase)))
            throw new FormatException("主机设置中的协调身份与入网凭据不符");
        if(DiscoveryMode=="pkarr"&&!Entries.Any(e=>ExistingEntryResolver.Kind(e.Source)=="PKARR"))throw new FormatException("主机未提供 PKARR 发现公钥");
        var settings=local with{PathSelection=PathSelection,ConnectionSource=ConnectionSource,DirectMode=mesh.Pair.Direct,
            ExistingEntries=Entries.Select(e=>e with{PeerSlot=ExistingEntry.NetworkOwner}).ToArray(),ManualEndpoint="",
            EntryRefreshSeconds=EntryRefreshSeconds,TcpStun=TcpStun.ToArray(),UdpStun=UdpStun.ToArray(),
            CoordinatorBackup=CoordinatorBackup,Service=Service,CertificatePin=CertificatePin,PairingService=PairingService,PairingCertificatePin=PairingCertificatePin,RequestedVirtualIp="",
            Coordinator=new(),Ddns=null,PkarrPublish=false,DiscoveryMode=DiscoveryMode,PkarrGateways=PkarrGateways.ToArray()};
        return ConnectionSettings.Normalize(settings,forGuest:true);
    }
}
