using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace StreamLink.Core;

public sealed class DeviceProfile
{
    [JsonExtensionData] public Dictionary<string, JsonElement>? AdditionalData { get; set; }
    // null: legacy default/unknown intent; false: explicit user disable. Runtime
    // capability checks still use effective flags, never this intent alone.
    public Dictionary<string,bool?> CapabilityIntents {get;set;}=new();
    public int Version { get; set; } = 2;
    public string Device { get; set; } = Guid.NewGuid().ToString("N");
    public string AdapterScope {get;set;}="";
    [JsonIgnore] public string ResourceScope=>AdapterScope.Length>0?AdapterScope:Device;
    public string NodeSigningPrivate {get;set;}="";
    public Pairing? Pair { get; set; }
    public MeshProfile? Mesh { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public MeshRejoinCredential? RejoinCredential { get; set; }
    public PendingMembershipChange? PendingMembership {get;set;}
    public MeshRejoinHistory[] RejoinHistory {get;set;}=[];
    public int Slot { get; set; } = 1;
    public bool Enabled { get; set; }
    public bool AutoStart {get;set;}=true;
    public CoordinatorSettings Coordinator {get;set;}=new();
    public int CoordinatorRoleVersion {get;set;}
    public CloudflareDdnsSettings Ddns {get;set;}=new();
    // Protected by the profile store; never included in UiNetworkSettings.
    public string CloudflareDdnsToken {get;set;}="";
    public string Preference { get; set; } = "auto";
    public int LastEntry { get; set; }
    public int ListenPort { get; set; } = PersonalFeature.Enabled ? 44680 : 42680;
    public int SourcePort { get; set; } = PersonalFeature.Enabled ? 44691 : 42691;
    public string ManualEndpoint { get; set; } = "";
    public string ConnectionSource { get; set; } = "custom";
    [System.Text.Json.Serialization.JsonIgnore]
    public bool UsesExistingEntriesOnly => ConnectionSource=="existing"||ManualEndpoint.Length>0;
    public bool DirectMode { get; set; }
    public string CoordinationService { get; set; } = "";
    public string CoordinationPin { get; set; } = "";
    public ExistingEntry[] ExistingEntries { get; set; } = [];
    // User configuration is independent of enrollment and runtime entry bindings.
    // Invitations and directory changes may update ExistingEntries, never this copy.
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public UiNetworkSettings? SavedNetworkSettings { get; set; }
    public bool AutoConfigureJoin {get;set;}
    public ApprovedNetworkSettings? ReceivedNetworkSettings {get;set;}
    public bool PkarrPublish {get;set;}
    public string PkarrSeed {get;set;}="";
    public long PkarrSequence {get;set;}
    public PkarrPeerBinding[] PkarrPeers {get;set;}=[];
    public int PkarrStateVersion {get;set;}
    public string SavedPeerEntryNetwork { get; set; } = "";
    // Enrollment observations are not user settings. A join may learn a seed
    // without overwriting saved sources, and saves must not erase that seed.
    public string JoinedEntryNetwork {get;set;}="";
    public ExistingEntry[] JoinedEntrySources {get;set;}=[];
    public int EntryRefreshSeconds {get;set;}=60;
    public string RequestedVirtualIp { get; set; } = "";
    public long NetworkEstablishedAt { get; set; }
    public bool NetworkCreatedHere { get; set; }
    public string[] TcpStun { get; set; } = Stun.TcpServers.ToArray();
    public string[] UdpStun { get; set; } = Stun.UdpServers.ToArray();
    public string LastStun { get; set; } = "";
    public string DeviceName { get; set; } = Environment.MachineName;
    public string TransportMode { get; set; } = "faketcp";
    public PacketAdapterBackend AdapterBackend { get; set; } = OperatingSystem.IsLinux()?PacketAdapterBackend.LinuxTun:PacketAdapterBackend.OfficialWintun;
    public string MigrationNotice { get; set; } = "";
    // Staged rollout: existing installations retain the verified explicit path.
    // New traversal is opt-in until the independent Windows/WAN gates pass.
    public string TraversalMode { get; set; } = PersonalFeature.Enabled ? "tcp-udp" : "legacy";
    public string PathSelection { get; set; } = "faketcp-only";
    public bool AllowUdpFallback { get; set; }
    // Diagnostics only, off by default. Requires a separately configured raw
    // SYN observer on the authenticated coordinator; never promotes a path.
    public bool TcpSynObservation { get; set; }
    // Independent-source calibration only; does not enable predicted paths.
    // Opt-in and requires the ordinary authenticated observer feature as well.
    public bool TcpPortCalibration { get; set; }
    public bool TcpPortPrediction { get; set; }
    // Experimental same-IP initial TCP source learning; requires bilateral and
    // coordinator capability plus an accounted native IPv4 capture broker.
    public bool TcpPeerReflexive { get; set; }
    public bool UdpExploration { get; set; }
    // Weaker, separately negotiated admission. STUN holdouts never claim to
    // prove arbitrary peer-port stability; keep this experiment opt-in.
    public bool UdpEmpiricalStability { get; set; }
    public bool QualityFeedback { get; set; }
    public bool StandbyPaths { get; set; }
    public bool PathDiagnostics { get; set; }
    public bool AllowManualQualityRequests { get; set; }
    public int DiagnosticMbps { get; set; }=50;
    // Opt-in gateway fallback: TCP after UPnP; alternating later UDP_DIRECT
    // rounds. It does not enable UDP itself or bypass path-quality selection.
    public bool PortControlMapping { get; set; }
    // Experimental native outer IPv6 UDP. Requires both peers and coordinator
    // support, physical IPv6 and the existing explicit UDP fallback policy.
    public bool UdpIpv6 { get; set; }
    public bool FakeTcpIpv6 { get; set; }
    // Outer IP Mbps, shared by all managed paths. Zero keeps existing behavior.
    // Kernel helper/control HTTPS are not part of business egress pacing.
    public int ManagedEgressMbps { get; set; }
    // Explicit experimental admission. Matching native capability is required;
    // shared queue bounds apply even when ManagedEgressMbps is zero.
    public bool LegacyEgressPacing { get; set; }
    public PathSelection Selection() => new(PathSelection switch {
        "prefer-faketcp" => PathPolicy.PreferFakeTcp, "faketcp-only" => PathPolicy.FakeTcpOnly,
        "auto-quality" => PathPolicy.AutoQuality, "udp-only" => PathPolicy.UdpOnly, _ => throw new FormatException("选路策略无效")
    }, AllowUdpFallback);
    public void SelectTransport(string policy)
    {
        if(policy is not ("faketcp-only" or "udp-only")) throw new FormatException("请选择 FakeTCP 或直接 UDP；不支持自动回退");
        PathSelection=policy; AllowUdpFallback=false; TraversalMode="tcp-udp";
        TransportMode=policy=="udp-only"?"udp":"faketcp";
        if(policy=="udp-only") { TcpPeerReflexive=false; TcpPortPrediction=false; TcpPortCalibration=false; TcpSynObservation=false; FakeTcpIpv6=false; LegacyEgressPacing=false; }
        else { UdpExploration=false; UdpEmpiricalStability=false; UdpIpv6=false; }
    }
    public bool MigrateAutomaticTransport()
    {
        bool automatic=PathSelection is "prefer-faketcp" or "auto-quality";
        if(!automatic && !AllowUdpFallback) return false;
        SelectTransport(automatic ? ((Mesh?.Pair.Mode ?? Pair?.Mode ?? TransportMode)=="udp"?"udp-only":"faketcp-only") : PathSelection);
        MigrationNotice="已取消自动协议回退；当前固定使用 "+(PathSelection=="udp-only"?"直接 UDP":"FakeTCP＋HTTP")+"，可在设置中更改。";
        return true;
    }
    // Production persistence/control rejects historical research policies.
    // Low-level isolated comparison fixtures may still exercise those policies.
    public void RequireFixedTransport()
    {
        if(PathSelection is not ("faketcp-only" or "udp-only") || AllowUdpFallback)
            throw new FormatException("请选择固定的 FakeTCP 或直接 UDP 模式；不支持自动协议回退");
        if(TransportMode != (PathSelection=="udp-only"?"udp":"faketcp"))
            throw new FormatException("传输模式与连接策略不一致，请在设置中重新选择传输模式");
        if(Mesh != null && Mesh.Pair.Mode != TransportMode &&
            (TraversalMode=="legacy" || TransportMode=="udp" && TraversalMode!="tcp-udp"))
            throw new FormatException("切换传输模式需要启用对应的受管打洞");
    }
    public string LogLevel { get; set; } = "info";
    public string LogDirectory { get; set; } = "";
    public void Validate()
    {
        if(AdapterScope is null||AdapterScope.Length>0&&!Guid.TryParseExact(AdapterScope,"N",out _))throw new FormatException("网卡所有权身份无效");
        if(NodeSigningPrivate is null||NodeSigningPrivate.Length>512)throw new FormatException("设备身份密钥无效");
        if(NodeSigningPrivate.Length>0&&MeshIdentity.NetworkId(MeshIdentity.PublicSigning(NodeSigningPrivate))!=Device)throw new FormatException("设备身份密钥与标识不符");
        if(Coordinator==null)throw new FormatException("协调角色设置不能为空");Coordinator.Validate();
        if(Ddns is {Enabled:true}||CloudflareDdnsToken.Length>0)throw new FormatException("内置 DNS 发布已移除，请先由新版配置迁移停用旧发布设置");
        if (ConnectionSource is not ("custom" or "existing")) throw new FormatException("公共协调服务尚未提供，请选择自建服务或已有入口");
        if (CoordinationService is null || CoordinationPin is null || RequestedVirtualIp is null) throw new FormatException("本机连接设置无效");
        if (CoordinationService.Length > 0) Pairing.Create(CoordinationService, CoordinationPin).Validate();
        ExistingEntryResolver.Validate(ExistingEntries);
        ExistingEntryResolver.Validate(JoinedEntrySources);
        if(PkarrPublish&&UsesExistingEntriesOnly&&ExistingEntries.Count(e=>e.PeerSlot==0)>=ExistingEntryResolver.MaximumSources)throw new FormatException("启用 PKARR 时最多填写 11 项本机入口，请为自动发现地址保留一项空间");
        if(PkarrSeed is null||PkarrSequence<0)throw new FormatException("PKARR 本机身份无效");
        if(PkarrStateVersion is <0 or >1)throw new FormatException("PKARR 对端状态版本无效");
        if(PkarrPeers is null||PkarrPeers.Length>8||PkarrPeers.Any(p=>p is null||!Guid.TryParseExact(p.Network,"N",out _)||p.Slot is <1 or >254||!Guid.TryParseExact(p.Device,"N",out _)||p.SigningKey is not {Length:>0 and <=512})||PkarrPeers.Select(p=>(p.Network,p.Slot)).Distinct().Count()!=PkarrPeers.Length)throw new FormatException("PKARR 对端绑定无效");
        foreach(var peer in PkarrPeers)PkarrPacket.KeyFromSource(peer.Source);
        if(PkarrSeed.Length>0){try{if(Convert.FromBase64String(PkarrSeed).Length!=32)throw new FormatException();}catch(FormatException){throw new FormatException("PKARR 本机密钥格式无效");}}
        if(JoinedEntryNetwork==null||JoinedEntryNetwork.Length>0&&!Guid.TryParseExact(JoinedEntryNetwork,"N",out _))throw new FormatException("已加入网络的入口身份无效");
        if(EntryRefreshSeconds is <1 or >86400)throw new FormatException("订阅更新间隔需为 1 秒至 24 小时");
        if (RequestedVirtualIp.Length > 0) MeshAddressing.ValidateAddress(RequestedVirtualIp);
        if (MigrationNotice is null || MigrationNotice.Length > 512) throw new FormatException("迁移提示无效");
        if (!Enum.IsDefined(AdapterBackend)) throw new FormatException("虚拟网卡后端无效");
        if (AdapterBackend == PacketAdapterBackend.StreamLinkTun && Pair != null) throw new FormatException("自研 TUN 使用原生 Mesh 网络；不支持旧 EasyTier 配对实例");
        if(CapabilityIntents==null||CapabilityIntents.Count>32||CapabilityIntents.Keys.Any(k=>k.Length is<1 or>64||k.Any(char.IsControl)))throw new FormatException("能力意图配置无效");
        if (Version != 2 || !Guid.TryParseExact(Device, "N", out _) || Slot is < 1 or > 2 || LastEntry is < 0 or > 2 || Preference is not ("auto" or "local" or "peer")) throw new FormatException("设备配置无效");
        if (ListenPort is < 1024 or > 65535 || SourcePort is < 1024 or > 65535 || SourcePort == ListenPort) throw new FormatException("源端口与监听端口必须是不同的 1024–65535 端口");
        ValidateServers(TcpStun); ValidateServers(UdpStun); Pair?.Validate();
        if (DeviceName is null || DeviceName.Length is < 1 or > 64 || DeviceName.Any(char.IsControl)) throw new FormatException("设备名称需为 1–64 个可见字符");
        if (TransportMode is not ("faketcp" or "udp") || LogLevel is not ("off" or "error" or "warn" or "info" or "debug")) throw new FormatException("传输或日志选项无效");
        if (TraversalMode is not ("legacy" or "tcp" or "tcp-udp")) throw new FormatException("打洞试验模式无效");
        if (TcpPortCalibration && (!TcpSynObservation || TraversalMode == "legacy")) throw new FormatException("TCP 端口校准需同时开启受管打洞和 TCP 观察诊断");
        if (TcpPortPrediction && !TcpPortCalibration) throw new FormatException("实验 TCP 预测需启用独立端口校准");
        if (ManagedEgressMbps is < 0 or > 10000) throw new FormatException("实验链路出口上限需为 0–10000 Mbps（0 为关闭）");
        if(LegacyEgressPacing&&TransportMode!="faketcp")throw new FormatException("兼容业务出口实验目前仅支持 FakeTCP");
        Selection().Validate();
        if (QualityFeedback && TraversalMode == "legacy") throw new FormatException("路径送达反馈需要实验受管打洞模式");
        if (StandbyPaths && TraversalMode == "legacy") throw new FormatException("备用路径需要实验受管打洞模式");
        if (DiagnosticMbps is < 1 or > 50) throw new FormatException("诊断目标需为1–50Mbps");
        if (PathDiagnostics && (!StandbyPaths || TraversalMode == "legacy" || ManagedEgressMbps < Math.Ceiling(DiagnosticMbps * 1.4)))
            throw new FormatException("路径诊断需开启独立备用，并设置至少目标1.4倍的共享出口额度；诊断仅在业务空闲时进行");
        if (PathSelection == "auto-quality" && !PathDiagnostics) throw new FormatException("自动质量选路需显式开启独立备用与空闲负载诊断");
        if (UdpExploration && (TraversalMode != "tcp-udp" || !Selection().Allows(TraversalProfile.UdpDirect)))
            throw new FormatException("UDP 多源探索需要 UDP 备用许可与实验 TCP/UDP 打洞");
        if (UdpEmpiricalStability && !UdpExploration) throw new FormatException("经验 UDP 稳定性实验需先启用 UDP 多源探索");
        if (TcpPeerReflexive && (TraversalMode == "legacy" || TransportMode != "faketcp" || Pair?.Mode == "udp"))
            throw new FormatException("TCP 来源学习需要实验 TCP 打洞与 FakeTCP 网络");
        if (PathSelection == "faketcp-only" && (TransportMode == "udp" || Pair?.Mode == "udp"))
            throw new FormatException("仅 FakeTCP 与 UDP 网络不兼容，请使用 FakeTCP 网络或更改选路策略");
        if (PathSelection == "udp-only" && (TransportMode != "udp" || Pair?.Mode == "faketcp"))
            throw new FormatException("仅 UDP 与当前传输配置不兼容，请在设置中选择一致的模式");
        if (LogDirectory is null || LogDirectory.Length > 240 || (LogDirectory.Length > 0 && (!Path.IsPathFullyQualified(LogDirectory) || LogDirectory.StartsWith(@"\\")))) throw new FormatException("日志目录需为本机绝对路径");
        if (ManualEndpoint.Length > 0) Invitation.Create(ManualEndpoint, "faketcp", "").Validate();
        Mesh?.Validate();
        RejoinCredential?.Validate();
        if(PendingMembership is {} pending){
            if(Mesh==null || pending.ExpectedHead.Length is not (0 or 64) || pending.Action is not ("enable" or "create" or "approve" or "revoke" or "leave" or "close") || pending.Ciphertext.Length>MeshGovernance.MaximumCipher || pending.Candidate.Length>32 || pending.RejoinHistory.Length>32)throw new FormatException("待确认网络变更无效");
            MeshIdentity.ValidateDirectory(pending.Proposed,Mesh.Pair.Network,Mesh.OwnerKey);
        }
        if(RejoinHistory is not {Length:<=32} || RejoinHistory.Length>0 && Mesh is not {IsOwner:true} && Mesh?.IsDecentralized!=true)throw new FormatException("重新加入历史无效");
        foreach(var h in RejoinHistory){
            if(h==null||h.Network!=Mesh!.Pair.Network||h.Former is null||h.Former.Slot==1&&!Mesh.IsDecentralized||h.CurrentSlot<=h.Former.Slot||Mesh.Directory?.Members.Any(m=>m.Slot==h.CurrentSlot)!=true)throw new FormatException("重新加入历史成员已改变");
            MeshIdentity.ValidateMember(h.Network,Mesh.OwnerKey,h.Former,Mesh.Directory);
        }
        if (Mesh != null && Pair != null) throw new FormatException("不能同时运行旧版配对和多机网络");
        if (Enabled && Pair == null && Mesh == null) throw new FormatException("请先创建或加入网络");
    }
    public static void ValidateServers(string[]? servers)
    {
        if (servers == null || servers.Length is < 1 or > 256) throw new FormatException("STUN 列表需包含 1–256 项");
        foreach (var server in servers)
        {
            bool literal6 = server != null && server.StartsWith('[') && System.Net.IPEndPoint.TryParse(server, out var ep) && Ipv6Direct.UnscopedUnicast(ep.Address);
            if (server == null || server.Length > 260 || !literal6 && !Regex.IsMatch(server, "^[A-Za-z0-9][A-Za-z0-9.-]*:[0-9]{1,5}$") || !int.TryParse(server[(server.LastIndexOf(':') + 1)..], out int port) || port is < 1 or > 65535) throw new FormatException("STUN 应按每行 主机名:端口 或 [IPv6]:端口 填写");
        }
    }
    public string[] OrderedTcp() => TcpStun.OrderByDescending(s => s == LastStun).ToArray();
}
