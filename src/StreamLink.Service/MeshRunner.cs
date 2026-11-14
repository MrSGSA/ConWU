using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;
public sealed class MeshShutdownException(string[] failures):IOException("网络资源退出未获证实："+string.Join("; ",failures));

public sealed class MeshRunner
{
    int receiverReady;
    public bool ReceiverReady=>Volatile.Read(ref receiverReady)!=0;
    UiEntryPreparation entryPreparation=new("Waiting","等待本机入口准备");
    public UiEntryPreparation EntryPreparation=>Volatile.Read(ref entryPreparation);
    readonly DeviceProfile profile;
    readonly MeshProfile mesh;
    readonly Action<string> log, rememberStun;
    readonly Action<SessionStatus> report;
    readonly Action<MeshDirectory> remember;
    readonly MeshRuntimeServices services;
    public Func<ReadOnlyMemory<byte>,byte[]?>? DirectPairing {get;set;}
    public Action<PkarrPeerBinding>? RememberPkarrPeer {get;set;}
    public PkarrCheckpoints? PkarrCheckpoints {get;set;}
    public Guid PkarrBootId {get;}=Guid.NewGuid();
    PkarrPeerObservation? pkarrPeer;
    sealed record PkarrPublication(Guid Entry);
    PkarrPublication? pkarrPublication;
    string pkarrQueryError="";
    public PkarrPeerObservation? PkarrPeer=>Volatile.Read(ref pkarrPeer);
    public string PkarrQueryError=>Volatile.Read(ref pkarrQueryError);
    public bool HasHealthyPeers {
        get {
            if(router is not {} active||mesh.Directory is not {} directory)return false;
            bool any=false;
            foreach(var member in directory.Members)if(member.Slot!=mesh.Self.Slot){
                any=true;if(!active.HasHealthyPath(member.Slot))return false;
            }
            return any;
        }
    }
    public bool PkarrConfirmed=>PkarrPeer is {} peer&&peer.State.Expires>DateTimeOffset.UtcNow.ToUnixTimeSeconds()&&peer.State.AcknowledgedBoot==PkarrBootId&&Volatile.Read(ref pkarrPublication) is {} publication&&peer.State.AcknowledgedEntry==publication.Entry;
    public void ObservePkarrPublication(Guid entry){if(Volatile.Read(ref pkarrPublication)?.Entry!=entry){Volatile.Write(ref pkarrPublication,new(entry));RequestDiscoveryRefresh();}}
    public MeshRunner(DeviceProfile profile, Action<string> log, Action<SessionStatus> report, Action<MeshDirectory> remember, Action<string>? rememberStun = null)
        : this(profile, log, report, remember, rememberStun ?? (_ => { }), MeshRuntimeServices.Default) { }
    internal MeshRunner(DeviceProfile profile, Action<string> log, Action<SessionStatus> report, Action<MeshDirectory> remember, Action<string> rememberStun, MeshRuntimeServices services)
    { this.profile = profile; mesh = profile.Mesh!; this.log = log; this.report = report; this.remember = remember; this.rememberStun = rememberStun; this.services = services; }
    readonly object gate = new();
    int retryRequested, invitationEntryRequested, runStarted,lookupRefreshRequested;
    public void RequestDiscoveryRefresh()=>Interlocked.Exchange(ref lookupRefreshRequested,1);
    sealed record EntrySettings(string Source,string Manual,ExistingEntry[] Entries,string PkarrSeed,PkarrPeerBinding[] PkarrPeers,UiNetworkSettings? Settings,bool PkarrPublish,int PkarrStateVersion) {
        public override string ToString()=>"EntrySettings (credentials hidden)";
    }
    EntrySettings? pendingEntries;
    public void UpdateEntries(DeviceProfile updated)=>Volatile.Write(ref pendingEntries,new(updated.ConnectionSource,updated.ManualEndpoint,updated.ExistingEntries.ToArray(),updated.PkarrSeed,updated.PkarrPeers.ToArray(),updated.SavedNetworkSettings,updated.PkarrPublish,updated.PkarrStateVersion));
    ExistingEntry[] preparedInvitationEntries=[];
    public ExistingEntry[] PreparedInvitationEntries=>Volatile.Read(ref preparedInvitationEntries).ToArray();
    bool stopping;
    public void RequestRetry() => Interlocked.Exchange(ref retryRequested,1);
    public void RequestInvitationEntry(){if(!profile.UsesExistingEntriesOnly&&mesh.IsOwner)Interlocked.Exchange(ref invitationEntryRequested,1);}
    public async Task NotifyDirectClosure(MeshDirectory closed,CancellationToken token)
    {
        MeshIdentity.ValidateDirectory(closed,mesh.Pair.Network,mesh.OwnerKey,mesh.Directory?.Revision??0);
        if(router is not {} active)return;
        int[] peers=active.Status().Where(p=>p.Connected).Select(p=>p.Slot).ToArray();
        if(peers.Length==0)return;
        var frames=DirectMeshDiscovery.DirectoryFrames(closed);
        // Best effort while old routes still exist. The signature is the
        // authority; receiving an older concurrent snapshot cannot undo it.
        long deadline=Environment.TickCount64+4000;
        for(int round=0;round<3&&Environment.TickCount64<deadline;round++)foreach(var frame in frames){
            var waiting=peers.ToHashSet();
            while(waiting.Count>0&&Environment.TickCount64<deadline){
                foreach(int slot in waiting.ToArray())if(!active.HasHealthyPath(slot)||active.SendSynchronization(slot,frame))waiting.Remove(slot);
                await Task.Delay(120,token);
            }
        }
    }
    internal static bool NeedsEntryProbe(MeshMember[] members, IReadOnlyDictionary<int, MeshAnnouncement> announcements,
        Func<int, bool> healthy, long now)
        => members.Any(m => !healthy(m.Slot) &&
            announcements.TryGetValue(m.Slot, out var node) && node.Device == m.Device && node.Expires > now);
    internal static ExistingEntry[] EntrySources(DeviceProfile profile, MeshProfile mesh) {
        // Local ingress publication is independent of how peers are discovered.
        // A serverless autonomous guest learns authenticated host hints during
        // approval. These must remain resolvable, including the PKARR public key,
        // without treating old LOCAL third-party inputs as autonomous entries.
        var bindings=PkarrRendezvous.Uses(profile)&&profile.PkarrStateVersion==1?profile.PkarrPeers.Where(p=>PkarrRendezvous.Matches(p,mesh)).Select(p=>new ExistingEntry(p.Slot,p.Source)):[];
        // An approved direct exchange can bootstrap a coordinated network too.
        // Keep its network-bound host hints usable while the optional directory
        // service is offline; the transport still authenticates membership.
        bool approvedBootstrap=profile.JoinedEntryNetwork==mesh.Pair.Network;
        var sources=bindings.Concat(profile.ExistingEntries.Where(e=>profile.UsesExistingEntriesOnly||(mesh.Pair.Direct||approvedBootstrap)&&e.PeerSlot!=0)
            .Select(e=>e.PeerSlot==ExistingEntry.NetworkOwner?e with{PeerSlot=mesh.IntroducerSlot}:e)).Distinct().ToArray();
        return sources.Length==0&&profile.ManualEndpoint.Length>0?[new(0,profile.ManualEndpoint)]:sources;
    }
    MeshRouter? router;
    internal object? ExitDiagnostics { get; private set; }
    internal bool CleanupComplete {get;private set;}
    readonly List<object> unprovenOwners=[];
    internal int UnprovenOwnerCount {get{lock(gate)return unprovenOwners.Count;}}
    public void UpdateDirectory(MeshDirectory directory)
    {
        lock (gate) ApplyDirectory(directory);
    }
    // Both local membership changes and coordinator snapshots use the same
    // revision/installation boundary. No user callback is invoked under gate.
    void ApplyDirectory(MeshDirectory directory)
    {
        MeshIdentity.ValidateDirectory(directory, mesh.Pair.Network, mesh.OwnerKey, mesh.Directory?.Revision ?? 0);
        if (mesh.Directory is {} prior) MeshIdentity.ValidateSuccessor(directory, prior);
        if (!directory.Members.Contains(mesh.Self)) throw new MeshRevokedException(directory.Closed);
        if (!stopping) router?.ApplyDirectory(directory);
        mesh.Directory = directory;
    }
    string? QualityKey(IPAddress address)
    {
        lock (gate) {
            var peer = mesh.Directory?.Members.FirstOrDefault(m => m.Slot != mesh.Self.Slot && MeshAddressing.Address(mesh.Pair.Network, m) == address.ToString());
            if (peer == null) return null;
            byte[] key = MeshIdentity.SharedKey(mesh, peer); try { return Convert.ToHexString(key); } finally { CryptographicOperations.ZeroMemory(key); }
        }
    }
    public Task<QualityResult> Measure(int mbps, int slot, CancellationToken token)
    {
        var connected = router?.Status().Where(p => p.Connected).ToArray() ?? [];
        if (slot == 0 && connected.Length == 1) slot = connected[0].Slot;
        var peer = connected.FirstOrDefault(p => p.Slot == slot) ?? throw new IOException("请选择已直连的设备进行测速");
        return Quality.Measure(peer.Ip, QualityKey(IPAddress.Parse(peer.Ip))!, mbps, token, local: mesh.LocalIp);
    }
    public async Task Run(CancellationToken token)
    {
        if (Interlocked.CompareExchange(ref runStarted, 1, 0) != 0) throw new InvalidOperationException("同一网络运行器不能重复或并发启动");
        profile.Validate(); mesh.Validate();
        if (mesh.Directory is {} known && !known.Members.Contains(mesh.Self)) { CleanupComplete = true; throw new MeshRevokedException(known.Closed); }
        // Explicit workers use the user's current fixed protocol, not the mode stored
        // in the original enrollment. This cannot enable an unselected protocol.
        var wireMesh=JsonSerializer.Deserialize<MeshProfile>(JsonSerializer.Serialize(mesh))!;
        wireMesh.Pair=wireMesh.Pair with {Mode=profile.TransportMode};
        bool legacyAllowed=profile.Selection().Allows(TransportModes.Carrier(profile.TransportMode));
        bool existingOnly=profile.UsesExistingEntriesOnly;
        bool streamGuest=TransportModes.OutboundGuest(profile.TransportMode)&&!mesh.IsOwner;
        Volatile.Write(ref entryPreparation,existingOnly?new("Existing","只使用已保存入口；仍需设备认证与双向验证"):new("Preparing","正在准备自主入口，取得候选不代表对端可达"));
        string folder = Path.Combine(services.SessionRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string rule = "StreamLink-" + Guid.NewGuid().ToString("N");
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        CancellationToken stop = cancellation.Token;
        using var sharedEgress=profile.LegacyEgressPacing?new EgressPacer(profile.ManagedEgressMbps):null;
        using var discovery = services.Discovery(mesh);
        bool coordinatorBackup=existingOnly&&mesh.Pair.Direct&&profile.SavedNetworkSettings is {CoordinatorBackup:true};
        long primaryAttemptAt=Environment.TickCount64;
        if(coordinatorBackup&&discovery is DirectMeshDiscovery directBackup){
            var backupSettings=profile.SavedNetworkSettings!;
            directBackup.UseCoordinatorBackup(services.CoordinatorBackup(mesh,backupSettings.Service,backupSettings.CertificatePin),
                ()=>Environment.TickCount64-primaryAttemptAt>=12000&&router!=null&&mesh.Directory!.Members.Any(m=>m.Slot!=mesh.Self.Slot&&!router.HasHealthyPath(m.Slot)),log);
        }
        using var peerSynchronization = discovery is DirectMeshDiscovery ? null : new MeshPeerSynchronization(mesh);
        var synchronization = (discovery as DirectMeshDiscovery)?.Synchronization ?? peerSynchronization!;
        long synchronizedVersion = -1;
        long rememberedDirectory = 0;
        using var networkWake = services.NetworkWake();
        using var entryResolver = services.ResolveEntries == null ? new ExistingEntryResolver(services.PkarrClientFactory) : null;
        Func<ExistingEntry[],string,CancellationToken,Task<EntryResolution[]>> resolveEntries = services.ResolveEntries ?? entryResolver!.Resolve;
        Func<ExistingEntry[],string,CancellationToken,Task<EntryResolution[]>>? recoverEntries=services.ResolveEntriesForRecovery??(entryResolver==null?null:entryResolver.ResolveRecovering);
        var requestBudget = new MeshRequestBudget(profile.TcpPortPrediction ? 8 : 6);
        Task<IMeshCandidateFactory?>? gatheringFactory = null;
        IMeshCandidateFactory? factory = null;
        MeshTraversalManager? traversal = null;
        MeshTraversalMessage[] pendingControl = [];
        IMapping? mapping = null, retiringMapping = null; Task<IMapping>? probe = null; Task? maintain = null, quality = null, releasing = null;
        bool mappingReleaseFailed = false;
        bool entryProbeRequested = false, entryProbeDeferred = false, restoreEstablishedEntry = false,entriesWereHealthy=false;
        Task<IPacketAdapter>? opening = null;
        Task<MeshSnapshot?>? reading = null;
        Task? publishing = null, saving = null;
        IMeshTransport? server = null;
        IPAddress? serverAddress = null;
        var clients = new Dictionary<int, MeshPeerTransports>();
        NetworkEntryConnections? networkEntries=null;
        MeshPeerTransports Paths(int slot) {
            if(router==null)throw new InvalidOperationException("Router not ready");
            if(!clients.TryGetValue(slot,out var paths))clients[slot]=paths=new(router,
                (ep,ct)=>LegacyStartupQueue.Shared.Start(()=>services.Transport(new(folder,wireMesh,IPEndPoint.Parse(ep),false,profile.ListenPort,null,profile.LogLevel){
                    ReserveEndpoint=endpoint=>router.CancelLegacyCandidate(slot,endpoint),Egress=sharedEgress,StreamFlowLanes=profile.StreamFlowLanes||mesh.Self.Slot!=mesh.IntroducerSlot
                }),ct),log);
            return paths;
        }
        var existingPlans=new Dictionary<int,ExistingEntryPlan>();
        var coordinatorEntryPlans=new Dictionary<int,ExistingCoordinatorPlan>();
        var reconnectPlans=new Dictionary<int,PeerReconnectPolicy>();
        int refreshSeconds=profile.EntryRefreshSeconds;
        string resolutionState="";
        var externalSources=EntrySources(profile,mesh);
        Task<EntryResolution[]>? resolving=null;
        ExistingEntry[] resolvingSources=[];
        EntryResolution[] resolved=[];
        long nextResolve=0;
        string[] localExisting=[];
        string[] LocalEntries()=>resolved.Where(r=>r.PeerSlot==0).SelectMany(r=>r.Endpoints).Distinct().Take(8).ToArray();
        var revisions = new Dictionary<int, long>();
        var announcements = new Dictionary<int, MeshAnnouncement>();
        var recoveryReports = new Dictionary<int, (Guid Episode, bool First, bool Stable, bool Path)>();
        var reportedRouterDrops = new Dictionary<int, RouterPeerDrops>();
        var reportedStreamFlows = new Dictionary<int, StreamFlowStatus>();
        var reportedBridgeDrops = new Dictionary<int, (long SendData,long SendControl,long ReceiveData,long ReceiveControl,long Socket)>();
        var qualityReports = new Dictionary<int, (Guid Session,string Result,string Reason)>();
        long revision = DateTime.UtcNow.Ticks, savedDirectory = 0, savingRevision = 0;
        long nextProbe = 0, nextRead = 0, nextSave = 0, lastPublish = 0, nextReport = 0, lastWarning = 0, nextServer = 0, serverStarted = 0, nextEgressReport = 0, nextTrafficReport = 0;
        int probeFailures = 0, readFailures = 0, serverFailures = 0;
        string publishedEndpoint = "\0", publishingEndpoint = "";
        string firewallMembers = "";
        var timeline = new ConnectionTimeline(log);
        var feedback = new MeshConnectionFeedback(log);
        long began = Environment.TickCount64;
        bool coordinatorUnavailable = false;
        AdapterRuntimeStatus adapterStatus = new(profile.AdapterBackend==PacketAdapterBackend.LinuxTun?PacketAdapterProviders.LinuxTun:profile.AdapterBackend==PacketAdapterBackend.OfficialWintun ? PacketAdapterProviders.OfficialWintun : PacketAdapterProviders.NativeExperimental,null,"NotOpened","尚未打开虚拟网卡");
        IPacketAdapter? actualAdapter=null, pendingAdapter=null;
        string adapterPhase = "lifecycle-wait";
        long nextAdapterReport = 0;
        string Candidate() => server != null && !server.Exited ? mapping is { IsValid: false } ? "" : mapping?.PublicEndpoint.ToString() ?? localExisting.FirstOrDefault() ?? "" : "";
        void Warning(Exception ex)
        {
            coordinatorUnavailable = true;
            if (lastWarning == 0 || Environment.TickCount64 - lastWarning >= 30000) { log("协调服务暂不可用，已有直连继续运行：" + ex.Message); lastWarning = Environment.TickCount64; }
        }
        void AcceptSynchronizedState()
        {
            if (synchronizedVersion == synchronization.Version || synchronization.Read() is not {} snapshot) return;
            long previous; bool revoked;
            lock (gate) {
                previous = mesh.Directory?.Revision ?? 0;
                // A UI approval may race an incoming snapshot. Never replace a
                // newer local table; the next loop will publish it to peers.
                if (snapshot.Directory.Revision < previous) return;
                MeshIdentity.ValidateDirectory(snapshot.Directory, mesh.Pair.Network, mesh.OwnerKey, previous);
                if (mesh.Directory is {} prior) MeshIdentity.ValidateSuccessor(snapshot.Directory, prior);
                revoked = !snapshot.Directory.Members.Contains(mesh.Self);
                if (revoked) mesh.Directory = snapshot.Directory;
                else if (snapshot.Directory.Revision > previous) ApplyDirectory(snapshot.Directory);
            }
            if (snapshot.Directory.Revision > rememberedDirectory) {
                try { remember(snapshot.Directory); rememberedDirectory = snapshot.Directory.Revision; }
                catch (Exception) when (revoked) { log("成员撤销记录未能保存；立即停止本机连接，请检查本机存储"); }
            }
            if (revoked) throw new MeshRevokedException(snapshot.Directory.Closed);
            foreach (var envelope in snapshot.Nodes) {
                var member = snapshot.Directory.Members.FirstOrDefault(m => m.Slot == envelope.Slot && m.Slot != mesh.Self.Slot);
                if (member == null) continue;
                MeshAnnouncement announcement;
                try { announcement = MeshMetadata.Open(mesh, member, envelope); }
                catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException) { continue; }
                if (revisions.GetValueOrDefault(member.Slot) >= announcement.Revision) continue;
                if(PkarrRendezvous.Uses(profile)&&announcement.PkarrSource is {} source){
                    var binding=new PkarrPeerBinding(mesh.Pair.Network,member.Slot,member.Device,member.SigningKey,source);
                    try{RememberPkarrPeer?.Invoke(binding);}catch(IOException ex){log("PKARR 对端绑定未保存："+ex.Message);}
                }
                revisions[member.Slot] = announcement.Revision; announcements[member.Slot] = announcement;
            }
            synchronizedVersion = synchronization.Version;
        }
        try {
            if(!existingOnly)gatheringFactory = sharedEgress!=null&&services.CandidatesWithEgress!=null?services.CandidatesWithEgress(profile,folder,log,stop,sharedEgress):services.Candidates(profile, folder, log, stop);
            else log(coordinatorBackup?"已有入口优先，备用协调仅提供地址；不执行 STUN、自动映射或自主打洞":"仅使用已有入口：按已保存的地址或订阅连接，不执行 STUN、自动映射或自主打洞");
            timeline.Mark("原生网络开始启动");
            report(new("正在创建虚拟网卡", mesh.LocalIp, "", mesh.Pair.Mode, false, null, existingOnly?"正在准备虚拟网卡与已有入口":"正在准备原生组网，同时探测公网入口") {Adapter=adapterStatus,Connection=new("StartingAdapter","正在准备虚拟网卡与本机入口。")});
            opening = services.ProfileAdapter is {} create ? create(profile, phase => {
                Volatile.Write(ref adapterPhase, phase); log($"WintunLifecycle elapsedMs={Environment.TickCount64-began} stage={phase}");
            }, stop) : profile.AdapterBackend==PacketAdapterBackend.OfficialWintun ? services.Adapter(mesh) :
                throw new IOException("此运行环境未提供官方 Wintun 准入工厂");
            while (!stop.IsCancellationRequested) {
                long now = Environment.TickCount64;
                if (mesh.Directory is {} localDirectory && synchronization.DirectoryRevision < localDirectory.Revision)
                    synchronization.SetDirectory(localDirectory);
                synchronization.Tick(now);
                AcceptSynchronizedState();
                if(Interlocked.Exchange(ref pendingEntries,null) is {} edited){
                    if((edited.Source=="existing"||edited.Manual.Length>0)!=existingOnly)throw new IOException("连接方式已改变，需要重新建立连接以应用入口策略");
                    profile.ConnectionSource=edited.Source;profile.ManualEndpoint=edited.Manual;profile.ExistingEntries=edited.Entries;
                    if(profile.PkarrSeed!=edited.PkarrSeed){profile.PkarrSeed=edited.PkarrSeed;lastPublish=0;}
                    profile.PkarrPeers=edited.PkarrPeers;profile.SavedNetworkSettings=edited.Settings;profile.PkarrPublish=edited.PkarrPublish;profile.PkarrStateVersion=edited.PkarrStateVersion;
                    if(!PkarrRendezvous.Uses(profile)){Volatile.Write(ref pkarrPeer,null);Volatile.Write(ref pkarrQueryError,"");}
                    var nextSources=EntrySources(profile,mesh);
                    if(!nextSources.SequenceEqual(externalSources)){
                        // Cache by the exact source AND owner, never the reused row index.
                        resolved=nextSources.Select((source,index)=>{
                            int old=Array.IndexOf(externalSources,source);return resolved.FirstOrDefault(r=>r.Index==old) is {} cached?cached with{Index=index}:null;
                        }).OfType<EntryResolution>().ToArray();
                        externalSources=nextSources;localExisting=LocalEntries();
                        nextResolve=0;lastPublish=0;resolutionState="";
                        foreach(var plan in existingPlans.Values)plan.Retry();
                        log("入口设置已更新：重新解析来源，保留已验证的连接与虚拟网卡");
                    }
                }
                localExisting=LocalEntries();
                // A remote restart/NAT change need not raise a LOCAL interface
                // notification. Refresh saved subscriptions on path loss too;
                // a long ordinary polling interval must not pin the old tuple.
                // This only refreshes discovery; proven paths and their owners
                // remain under the router's normal authentication/health rules.
                bool entriesHealthy=HasHealthyPeers;
                if(entriesWereHealthy&&!entriesHealthy&&externalSources.Length>0){
                    nextResolve=now;
                    foreach(var plan in reconnectPlans.Values)plan.Wake();
                    log("原直连路径暂未通过健康检查，正在重新获取已保存的入口；保留网络身份与设置");
                }
                entriesWereHealthy=entriesHealthy;
                if(Interlocked.Exchange(ref lookupRefreshRequested,0)!=0)nextResolve=0;
                if(refreshSeconds!=profile.EntryRefreshSeconds){refreshSeconds=profile.EntryRefreshSeconds;nextResolve=0;}
                if(externalSources.Length>0 && resolving==null && now>=nextResolve){
                    resolvingSources=externalSources;
                    bool recovering=!entriesHealthy&&mesh.Directory?.Members.Any(m=>m.Slot!=mesh.Self.Slot)==true;
                    resolving=recovering&&recoverEntries!=null?recoverEntries(externalSources,profile.TransportMode,stop):resolveEntries(externalSources,profile.TransportMode,stop);
                    // Long user intervals for ordinary subscriptions must not
                    // leave a short-lived signed locator dormant for hours.
                    int interval=externalSources.Any(e=>ExistingEntryResolver.Kind(e.Source) is "DDNS" or "PKARR")?Math.Min(refreshSeconds,60):refreshSeconds;
                    // A third-party mapping/DNS updater can publish only AFTER
                    // the old path is lost. The immediate refresh may still
                    // return its old tuple, so keep recovery reads bounded.
                    // Healthy paths continue to use the configured interval.
                    if(!entriesHealthy&&mesh.Directory?.Members.Any(m=>m.Slot!=mesh.Self.Slot)==true)interval=Math.Min(interval,30);
                    if(PkarrRendezvous.Uses(profile)&&externalSources.Any(e=>ExistingEntryResolver.Kind(e.Source)=="PKARR"))interval=Math.Max(5,Math.Min(refreshSeconds,PkarrConfirmed&&entriesHealthy?60:now-began>=120000?30:5));
                    nextResolve=now+interval*1000L;
                }
                if(resolving?.IsCompleted==true){
                    if(!resolvingSources.SequenceEqual(externalSources)){try{await resolving;}catch(Exception)when(!stop.IsCancellationRequested){}resolving=null;nextResolve=0;continue;}
                    try {var previous=resolved;resolved=(await resolving).Select(item=>{
                            if(item.Pkarr is {} signed){
                                try{
                                    string source=resolvingSources[item.Index].Source,key=PkarrPacket.KeyFromSource(source);
                                    var verified=PkarrPacket.Read(key,signed.Packet,DateTimeOffset.UtcNow);
                                    if(verified.Announcement.Mode!=profile.TransportMode)throw new FormatException("PKARR 公告协议不符");
                                    PkarrCheckpoints?.Remember(key,verified);item=item with{Pkarr=verified};
                                    if(PkarrRendezvous.Uses(profile)&&verified.Announcement.State!=null&&profile.PkarrPeers.FirstOrDefault(p=>p.Source==source&&PkarrRendezvous.Matches(p,mesh)) is {} binding){
                                        var member=mesh.Directory!.Members.Single(m=>m.Slot==binding.Slot);
                                        var state=PkarrRendezvous.Open(mesh,member,source,verified.Announcement);
                                        if(pkarrPeer==null||state.ObservedAt>=pkarrPeer.State.ObservedAt){
                                            Volatile.Write(ref pkarrPeer,new(source,state,DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
                                            // This state is authenticated by the pinned PKARR key
                                            // and the member ECDH key. It never changes membership.
                                            var known=announcements.GetValueOrDefault(member.Slot);
                                            if(known?.Expires<=DateTimeOffset.UtcNow.ToUnixTimeSeconds()||known==null)
                                                announcements[member.Slot]=new(member.Slot,member.Device,verified.Sequence,state.Expires,item.Endpoints.FirstOrDefault()??"",state.Name);
                                        }
                                    }
                                    Volatile.Write(ref pkarrQueryError,"");
                                }catch(Exception ex)when(ex is IOException or FormatException or CryptographicException or JsonException or ArgumentException){
                                    Volatile.Write(ref pkarrQueryError,"PKARR 对端公告未通过本机验证");return item with{Endpoints=[],Pkarr=null,Error="PKARR 公告旧于本机记录、身份不符或状态无效",AllowCached=false};
                                }
                            }else if(item.Kind=="PKARR"&&item.Error.Length>0)Volatile.Write(ref pkarrQueryError,item.Error);
                            return EntryResolutionCache.Merge(item,previous.FirstOrDefault(p=>p.PeerSlot==item.PeerSlot&&p.Index==item.Index),DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                        }).ToArray();localExisting=LocalEntries();
                        string current=string.Join('|',resolved.Select(r=>$"{r.PeerSlot}:{r.Index}:{r.Error}:{string.Join(',',r.Endpoints)}:{r.LookupDetail}"));
                        if(current!=resolutionState){resolutionState=current;foreach(var item in resolved)log($"已有入口 {item.Index+1}（{item.Kind}）查询候选："+(item.Error.Length>0?item.Error+(item.Endpoints.Length>0?"；暂用上次可用候选，继续定时更新":""):$"已解析 {item.Endpoints.Length} 个地址：{string.Join(", ",item.Endpoints)}；"+(entriesHealthy?"当前已验证的直连保持不变":"等待对端认证验证"))+(item.LookupDetail.Length>0?"；"+item.LookupDetail:""));}
                    }catch(Exception ex)when(!stop.IsCancellationRequested){
                        if(externalSources.Any(e=>ExistingEntryResolver.Kind(e.Source)=="PKARR")){Volatile.Write(ref pkarrQueryError,"PKARR 查询暂未完成");resolved=resolved.Select(r=>r.Kind=="PKARR"?r with{Endpoints=[],Pkarr=null,Error="PKARR 查询暂未完成",AllowCached=false}:r).ToArray();localExisting=LocalEntries();}
                        log("入口解析暂未完成："+ex.GetType().Name);
                    }
                    resolving=null;
                }
                // Source polling intervals may exceed a signed record's life.
                // Expiration/withdrawal must stop new dials and publication now,
                // without tearing down an independently authenticated live path.
                long sourceUtc=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if(resolved.Any(r=>r.Endpoints.Length>0&&r.ExpiresAt>0&&r.ExpiresAt<=sourceUtc)) {
                    resolved=resolved.Select(r=>EntryResolutionCache.Current(r,sourceUtc)).ToArray();
                    localExisting=LocalEntries();
                }
                if(Interlocked.Exchange(ref retryRequested,0)!=0) {
                    entryProbeRequested = mapping == null && probe == null;
                    nextProbe = nextRead = nextServer = now; lastPublish = 0;
                    traversal?.RequestRetry();
                    foreach(var plan in existingPlans.Values)plan.Retry();nextResolve=0;
                    foreach(var plan in reconnectPlans.Values)plan.Wake();
                    foreach(var client in clients)if(!router!.HasHealthyPath(client.Key))client.Value.WakeRetry();
                    (mapping as IMappingRefresh)?.RequestRefresh();
                    log("已请求重新探测：保留健康直连、在途验证和虚拟网卡，唤醒等待中的重试");
                }
                if (networkWake.Take(now)) {
                    entryProbeRequested = mapping == null && probe == null;
                    nextProbe = nextRead = nextServer = now;
                    probeFailures = readFailures = serverFailures = 0;
                    lastPublish = 0;
                    foreach (var client in clients) client.Value.InvalidatePreparation(client.Key);
                    foreach(var plan in existingPlans.Values)plan.Retry();nextResolve=0;
                    foreach(var plan in reconnectPlans.Values)plan.Wake();
                    (mapping as IMappingRefresh)?.RequestRefresh();
                    log("网络变化或系统唤醒，正在复核入口和发现信息；保留已验证的直连路径");
                }
                if (gatheringFactory?.IsCompleted == true) {
                    try { factory = await gatheringFactory; } catch (Exception ex) when (!stop.IsCancellationRequested) { log("新增打洞能力暂不可用：" + ex.Message); }
                    gatheringFactory = null;
                    log("CandidateFactoryReady profiles="+string.Join(',',factory?.Profiles??[])+" policy="+profile.PathSelection+" udpAllowed="+profile.Selection().Allows(TraversalProfile.UdpDirect));
                    if (factory is MeshCandidateFactory ownedFactory && discovery is ITcpObservationControl observationControl)
                        ownedFactory.ConfigureObservation(observationControl, requestBudget, log);
                }
                if (opening?.IsCompleted == true) {
                    IPacketAdapter adapter;
                    try { pendingAdapter=adapter=await opening; }
                    catch(Exception ex) { adapterStatus=adapterStatus with {State="Blocked",Reason=ex.Message};report(new("虚拟网卡准入失败",mesh.LocalIp,"",mesh.Pair.Mode,false,null,ex.Message){Adapter=adapterStatus});throw; }
                    opening = null;actualAdapter=adapter;
                    adapterStatus=adapterStatus with {ActualProvider=adapter.Descriptor.Provider,State="Opened",Reason=OperatingSystem.IsLinux()?"已打开 Linux 内核 TUN":"已由实际工厂打开官方 Wintun",Abi=adapter.Descriptor.Abi,Loaded=true};
                    if(OperatingSystem.IsWindows()&&adapter is NativeAdapter official)foreach(var warning in official.RouteWarnings)
                        log($"虚拟网段路由警告：{warning.Reason}；{warning.Prefix}；现有路由未改动，可在诊断中检查其他 VPN/父网段");
                    // Keep startup ownership through descriptor/logging/router
                    // validation. Only a successful Router takes the adapter.
                    lock (gate) {
                        wireMesh.Directory = mesh.Directory;
                        router = new(wireMesh, adapter, (discovery as IMeshTraversalDiscovery)?.BootId, profile.Selection());
                        router.DirectPairing=packet=>DirectPairing?.Invoke(packet);
                        synchronization.Attach(router);
                        pendingAdapter = null;
                    }
                    services.Record(folder, rule);
                    try{quality=services.QualityWithPolicy is {} controlled?controlled(profile,mesh.LocalIp,QualityKey,stop):services.QualityServer(mesh.LocalIp,QualityKey,stop);}
                    catch(Exception ex){log("测速服务不可用，组网继续运行："+ex.Message);}
                    timeline.Mark("原生虚拟网卡就绪");
                }
                if (traversal == null && router != null && factory != null && factory.Profiles.Any(router.Selection.Allows) && discovery is IMeshTraversalDiscovery controlDiscovery) {
                    traversal = new(mesh, router, controlDiscovery, factory, requestBudget, log, stop);
                    log("TraversalReady profiles="+string.Join(',',traversal.Capabilities.Profiles)+" coordinator="+controlDiscovery.SupportsTraversal);
                    traversal.Receive(pendingControl); pendingControl = []; lastPublish = 0;
                }
                if (router?.Completion.IsCompleted == true) await router.Completion;
                if (quality?.IsCompleted == true) {try{await quality;}catch(Exception ex)when(!stop.IsCancellationRequested){log("测速服务不可用，组网继续运行："+ex.Message);}quality=null;}
                if (releasing?.IsCompleted == true && !mappingReleaseFailed) {
                    try { await releasing; releasing = null; retiringMapping = null; }
                    catch (Exception ex) {
                        // Failed completion is not release proof. Keep both the
                        // task and its owner; other healthy paths may continue.
                        mappingReleaseFailed = true;
                        log("本机入口资源退出未获证实，暂停新建入口并保留已有直连：" + ex.Message);
                    }
                }
                if(Interlocked.Exchange(ref invitationEntryRequested,0)!=0&&!existingOnly){entryProbeRequested=mapping==null&&probe==null;nextProbe=0;}
                if (!existingOnly && !streamGuest && legacyAllowed && localExisting.Length==0 && probe == null && mapping == null && releasing == null && now >= nextProbe &&
                    (externalSources.Length==0 || now-began>=5000 && resolving==null && !existingPlans.Values.Any(p=>p.Priority))) {
                    var entryPeers = mesh.Directory?.Members.Where(m => m.Slot != mesh.Self.Slot).ToArray() ?? [];
                    bool needed = mesh.Pair.Direct&&(mesh.IsOwner||PkarrRendezvous.Uses(profile)) || restoreEstablishedEntry || entryProbeRequested || router == null || NeedsEntryProbe(entryPeers, announcements,
                        router.HasHealthyPath, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                    if (needed) {
                        entryProbeRequested = entryProbeDeferred = false;
                        probe = services.Probe(profile, log, stop);
                        Volatile.Write(ref entryPreparation,new("Preparing","正在探测或映射本机入口"));
                    } else if (!entryProbeDeferred) {
                        entryProbeDeferred = true;
                        log(entryPeers.Any(m=>router?.HasHealthyPath(m.Slot)==true)?"现有在线成员已直连，暂停本机备用入口探测；继续维护已有路径，新成员上线或路径失效时恢复探测":"已配对设备暂未在线，暂停额外入口探测；收到上线信息或手动重试后恢复");
                    }
                }
                if (probe?.IsCompleted == true) {
                    try {
                        mapping = await probe;
                        Volatile.Write(ref entryPreparation,new("Candidate","已取得入口候选；尚未确认对端可以连接",mapping.PublicEndpoint.ToString()));
                        Volatile.Write(ref preparedInvitationEntries,mapping.IsValid?[new ExistingEntry(0,mapping.PublicEndpoint.ToString())]:[]);
                        restoreEstablishedEntry = false;
                        if (server != null && serverAddress != null && !serverAddress.Equals(mapping.LocalAddress) && !TransportModes.OutboundGuest(profile.TransportMode)) { server.Dispose(); server = null; }
                        maintain = mapping.Maintain(stop); probeFailures = 0; timeline.Mark("本机候选入口就绪");
                    }
                    catch (Exception ex) {
                        // A completed probe can fault in the same tick as user stop.
                        // Report cancellation; the finally block still proves owner cleanup.
                        stop.ThrowIfCancellationRequested();
                        Volatile.Write(ref entryPreparation,new("Unavailable",ex.Message));
                        log("入口暂不可用，可使用其他成员入口：" + ex.Message); nextProbe = now + Math.Min(45000, 5000L << Math.Min(probeFailures++, 4));
                    }
                    finally { probe = null; }
                }
                string selectedStun=mapping switch {TcpMapping tcp=>tcp.StunServer,StreamMapping stream=>stream.StunServer,_=>""};
                if (selectedStun.Length>0 && profile.LastStun != selectedStun) {
                    profile.LastStun = selectedStun; rememberStun(selectedStun);
                }
                if(mapping is {IsValid:true}){
                    var preparedCandidate=new ExistingEntry(0,mapping.PublicEndpoint.ToString());
                    if(!Volatile.Read(ref preparedInvitationEntries).SequenceEqual([preparedCandidate])){
                        Volatile.Write(ref preparedInvitationEntries,[preparedCandidate]);
                        Volatile.Write(ref entryPreparation,new("Candidate","已取得入口候选；尚未确认对端可以连接",mapping.PublicEndpoint.ToString()));
                    }
                }else if(mapping is {IsValid:false}&&Volatile.Read(ref preparedInvitationEntries).Length>0){
                    Volatile.Write(ref preparedInvitationEntries,[]);
                    Volatile.Write(ref entryPreparation,new("Preparing","正在复核本机入口，已有直连继续由双向保活检查"));
                }
                if (maintain?.IsCompleted == true) {
                    // Previously valid ingress is a resource to restore, even
                    // while an independent outbound peer path stays healthy.
                    Volatile.Write(ref preparedInvitationEntries,[]);
                    restoreEstablishedEntry = true;
                    try { await maintain; } catch (Exception ex) when (!stop.IsCancellationRequested) { log("重新建立映射：" + ex.Message); }
                    // FakeTCP's listening process owns established peer sessions
                    // independently of candidate publication/lease renewal. Keep
                    // it until process failure, a source-address change or stop.
                    // Legacy raw UDP still has a helper-specific shared bind.
                    if (profile.TransportMode == "udp") { server?.Dispose(); server = null; }
                    retiringMapping = mapping!;
                    releasing = ReleaseMapping(retiringMapping); mapping = null; maintain = null; nextProbe = now + 1000;
                }
                if (server?.Exited == true) {
                    log($"本机传输入口失效：{server.FailureReason}；重新建立入口");
                    router?.FailLegacyListener();
                    if (now - serverStarted >= 30000) serverFailures = 0;
                    server.Dispose(); server = null; nextServer = now + Math.Min(15000, 250L << Math.Min(serverFailures++, 6));
                }
                if (legacyAllowed && !streamGuest && router != null && server == null && now >= nextServer) {
                    try { server = services.Transport(new(folder, wireMesh, router.LocalEndpoint, true, profile.ListenPort, mapping, profile.LogLevel){Egress=sharedEgress,RetireEndpoint=router.FailLegacyIngress,StreamFlowLanes=profile.StreamFlowLanes}); serverAddress = mapping?.LocalAddress; serverStarted = now; }
                    catch (Exception ex) { nextServer = now + Math.Min(15000, 1000L << Math.Min(serverFailures++, 4)); log("本机传输入口启动重试：" + ex.Message); }
                }
                // Independent HTTP operations: neither a slow GET/PUT nor adapter
                router?.SetLegacyListenerControl(server?.ControlsWirePackets == true && !server.Exited);
                Volatile.Write(ref receiverReady,server!=null&&!server.Exited?1:0);
                // startup can hold up local child recovery or the other direction.
                if (saving?.IsCompleted == true) {
                    try { await saving; savedDirectory = savingRevision; }
                    catch (Exception ex) when (!stop.IsCancellationRequested) { Warning(ex); }
                    saving = null;
                }
                if (publishing?.IsCompleted == true) {
                    try { await publishing; publishedEndpoint = publishingEndpoint; }
                    catch (Exception ex) when (!stop.IsCancellationRequested) { Warning(ex); }
                    publishing = null;
                }
                if (reading?.IsCompleted == true) {
                    try {
                        var snapshot = await reading; readFailures = 0; coordinatorUnavailable = false;
                        if (snapshot != null) {
                            synchronization.Merge(snapshot,true);
                            AcceptSynchronizedState();
                            if (traversal != null) traversal.Receive(snapshot.Traversal); else pendingControl = snapshot.Traversal ?? [];
                        }
                        // Any authorized replica can restore a missing table.
                        // It forwards the issuer's signature, never signs a new one.
                        else savedDirectory = 0;
                    } catch (Exception ex) when (!stop.IsCancellationRequested && ex is not MeshRevokedException) {
                        Warning(ex); nextRead = now + Math.Min(30000, 2500L << Math.Min(++readFailures, 4));
                    }
                    reading = null;
                }
                if (saving == null && mesh.Directory is {} directory && savedDirectory < directory.Revision && now >= nextSave && (traversal == null || requestBudget.Take())) {
                    savingRevision = directory.Revision; saving = discovery.SaveDirectory(directory, stop); nextSave = now + 5000;
                }
                var statuses = router?.Status() ?? [];
                if (factory is MeshCandidateFactory calibrationFactory) calibrationFactory.UpdateCalibrationStatus(statuses, router != null);
                bool allConnected = statuses.Length > 0 && statuses.All(p => p.Connected);
                if (reading == null && now >= nextRead && (traversal == null || requestBudget.Take(priority: true))) {
                    bool watching = discovery is IMeshChangeDiscovery { SupportsLongPolling: true };
                    reading = watching ? ((IMeshChangeDiscovery)discovery).WaitForChanges(stop) : discovery.Read(stop);
                    // Negotiated traversal uses the shared request bucket, so
                    // Ready/Start need not wait 2.5s. Idle waits still hold 25s.
                    nextRead = now + (watching && traversal != null ? 100 : watching ? 2500 : allConnected ? 5000 : 2500);
                }
                string candidate = Candidate();
                if (publishing == null && (lastPublish == 0 || now - lastPublish >= (candidate != publishedEndpoint ? 2500 : 15000)) && (traversal == null || requestBudget.Take())) {
                    publishingEndpoint = candidate; lastPublish = now;
                    var announcement = new MeshAnnouncement(mesh.Self.Slot, mesh.Self.Device, ++revision, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), candidate, profile.DeviceName, traversal?.Capabilities) {
                        ExistingEndpoints=server!=null&&!server.Exited&&localExisting.Length>0?localExisting:null,
                        ExistingEntryOnly=existingOnly,
                        PkarrSource=PkarrRendezvous.Uses(profile)&&profile.PkarrSeed.Length>0?PkarrPacket.Source(profile.PkarrSeed):null
                    };
                    peerSynchronization?.Publish(announcement);
                    publishing = discovery.Publish(announcement, stop);
                }
                // Negotiated mode shares 40 requests/minute across these HTTP
                // operations and traversal states. Legacy keeps its old cadence.
                if (router == null) {
                    if (now >= nextAdapterReport) {
                        string phase = Volatile.Read(ref adapterPhase);
                        string detail = phase switch {
                            "lifecycle-wait" => "正在申请网卡资源，等待当前设备操作完成。",
                            "previous-interface-wait" or "identity-vacant-wait" => "正在等待旧网卡退出；完成回收后继续连接。",
                            _ when phase.StartsWith("previous-adapter-settle-wait/",StringComparison.Ordinal) => "Windows 仍缓存旧网卡，正在等待网络设备配置稳定，约剩 "+phase[(phase.LastIndexOf('/')+1)..]+" 秒；完成后继续连接。",
                            "previous-device-wait" => "正在等待旧 Wintun 设备退出，尚未创建第二个实例。",
                            "adapter-class-setup-retry" => "Windows 网卡配置未完成，正在回收后进行一次有限重试。",
                            "adapter-create-retry-1" or "adapter-create-retry-2" => "Windows 尚未准备好网卡，正在进行有限重试。",
                            "ipv4-interface-wait" => "网卡已创建，正在等待 Windows 网络接口就绪。",
                            _ when phase.StartsWith("open-rollback/",StringComparison.Ordinal) => "创建未完成，正在安全回收本轮网卡资源。",
                            _ => "正在准备 Wintun 网卡；Windows 设备操作完成后继续连接。"
                        };
                        adapterStatus = adapterStatus with { State="Opening", Reason=detail };
                        report(new("正在创建虚拟网卡",mesh.LocalIp,"",mesh.Pair.Mode,false,null,detail) {
                            Adapter=adapterStatus,Connection=new("StartingAdapter",detail,now-began) });
                        nextAdapterReport = now + 1000;
                    }
                    await Task.Delay(100, stop); continue;
                }
                var members = mesh.Directory?.Members.Where(m => m.Slot != mesh.Self.Slot).ToArray() ?? [];
                if(legacyAllowed){
                    networkEntries??=new(router,(ep,ct)=>LegacyStartupQueue.Shared.Start(()=>services.Transport(new(folder,wireMesh,IPEndPoint.Parse(ep),false,profile.ListenPort,null,profile.LogLevel){Egress=sharedEgress,StreamFlowLanes=profile.StreamFlowLanes||mesh.Self.Slot!=mesh.IntroducerSlot}),ct),Paths,log,stop);
                    var knownEntries=members.SelectMany(m=>resolved.Where(r=>r.PeerSlot==m.Slot).SelectMany(r=>r.Endpoints)).ToHashSet();
                    await networkEntries.Tick(resolved.Where(r=>r.PeerSlot==ExistingEntry.Network).SelectMany(r=>r.Endpoints).Distinct().Take(8).ToArray(),members,now,knownEntries);
                }
                string remoteAddresses = string.Join(',', members.Select(m => MeshAddressing.Address(mesh.Pair.Network, m)));
                if (firewallMembers != remoteAddresses) {
                    services.Firewall(rule, mesh.LocalIp, remoteAddresses); firewallMembers = remoteAddresses;
                }
                foreach (int slot in clients.Keys.Where(s => !members.Any(m => m.Slot == s)).ToArray()) { await clients[slot].DisposeAsync(); clients.Remove(slot); announcements.Remove(slot); }
                foreach(int slot in existingPlans.Keys.Where(s=>!members.Any(m=>m.Slot==s)).ToArray())existingPlans.Remove(slot);
                foreach(int slot in reconnectPlans.Keys.Where(s=>!members.Any(m=>m.Slot==s)).ToArray())reconnectPlans.Remove(slot);
                var selectedEntries=new Dictionary<int,string>();var priorityPeers=new HashSet<int>();var quietPeers=new HashSet<int>();var onlyEntryPeers=new HashSet<int>();
                foreach(var member in members){
                    announcements.TryGetValue(member.Slot,out var remote);
                    bool fresh=remote?.Expires>DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    var networkHints=networkEntries?.ForMember(member)??[];
                    bool hasDiscoveryHint=networkHints.Length>0;
                    bool strictEntry=existingOnly||fresh&&remote!.ExistingEntryOnly||!fresh&&hasDiscoveryHint&&!router.HasHealthyPath(member.Slot);
                    if(strictEntry){onlyEntryPeers.Add(member.Slot);selectedEntries[member.Slot]="";}
                    string[] primaryHints=resolved.Where(r=>r.PeerSlot==member.Slot).SelectMany(r=>r.Endpoints).Concat(networkHints).Distinct().Take(8).ToArray();
                    string[] remoteHints=fresh?remote!.ExistingEndpoints??[]:[];
                    string[] hints=primaryHints.Concat(remoteHints).Distinct().Take(8).ToArray();
                    if(!reconnectPlans.TryGetValue(member.Slot,out var reconnect))reconnectPlans[member.Slot]=reconnect=new();
                    if(!reconnect.Allow(mesh.Pair.Direct||hasDiscoveryHint,router.HasHealthyPath(member.Slot),fresh,hints,now)){
                        quietPeers.Add(member.Slot);selectedEntries[member.Slot]="";traversal?.PauseOffline(member.Slot);continue;
                    }
                    if(hints.Length==0&&localExisting.Length==0&&!strictEntry)continue;
                    if(!existingPlans.TryGetValue(member.Slot,out var plan))existingPlans[member.Slot]=plan=new();
                    bool fellBack=plan.FellBack;
                    string fallback=fresh && !(remote!.ExistingEndpoints??[]).Contains(remote.Endpoint)?remote.Endpoint:"";
                    if(mesh.Pair.Direct){
                        if(coordinatorBackup){
                            if(!coordinatorEntryPlans.TryGetValue(member.Slot,out var backupPlan))coordinatorEntryPlans[member.Slot]=backupPlan=new();
                            bool wasBackup=backupPlan.UsingBackup;
                            selectedEntries[member.Slot]=backupPlan.Select(primaryHints,remoteHints,router.HasHealthyPath(member.Slot),now);
                            if(!wasBackup&&backupPlan.UsingBackup)log($"设备 {member.Slot} 的已配置入口尚未通过认证，改用备用协调提供的已有入口；不执行自主打洞");
                        }else selectedEntries[member.Slot]=router.HasHealthyPath(member.Slot)||hints.Length==0?"":hints[(int)((now-began)/15000%hints.Length)];
                        if(!router.HasHealthyPath(member.Slot))priorityPeers.Add(member.Slot);
                        continue;
                    }
                    selectedEntries[member.Slot]=plan.Select(hints,fallback,localExisting.Length>0,router.HasHealthyPath(member.Slot),now,strictEntry);
                    if(plan.Priority)priorityPeers.Add(member.Slot);
                    if(!fellBack && plan.FellBack)log($"设备 {member.Slot} 已有入口 {string.Join(", ",hints)} 未完成 ConWU 双向认证，请确认映射通向 ConWU {profile.ListenPort} 且协议一致；开始自主打洞，保持 {profile.TransportMode} 协议"+(fallback.Length>0?$"；自主发现入口 {fallback}":""));
                }
                // Locally configured peer entries also count as explicit hints to the scheduler.
                var scheduling=announcements.ToDictionary(p=>p.Key,p=>selectedEntries.TryGetValue(p.Key,out var chosen)&&chosen.Length>0?p.Value with {Endpoint=chosen}:p.Value);
                traversal?.Tick(scheduling, candidate,priorityPeers,onlyEntryPeers);
                foreach (var member in members) {
                    if(TransportModes.OutboundGuest(profile.TransportMode)&&mesh.IsOwner){router.DescribeTraversal(member.Slot,announcements.GetValueOrDefault(member.Slot)?.Name??"","等待从机连接本机入口；通道建立后支持双向传输");continue;}
                    if(quietPeers.Contains(member.Slot)){
                        if(clients.TryGetValue(member.Slot,out var quiet))quiet.Suspend(member.Slot,announcements.GetValueOrDefault(member.Slot)?.Name??"");
                        continue;
                    }
                    if(!legacyAllowed) {
                        router.DescribeTraversal(member.Slot,announcements.GetValueOrDefault(member.Slot)?.Name??"","等待所选传输模式建立直连");
                        continue;
                    }
                    if (traversal?.Owns(member.Slot) == true && router.UsesManagedTransport(member.Slot)) {
                        if (clients.Remove(member.Slot, out var obsolete)) await obsolete.DisposeAsync();
                        traversal.ObserveLegacyPending(member.Slot, false);
                        continue;
                    }
                    announcements.TryGetValue(member.Slot, out var announcement);
                    string endpoint = announcement?.Expires > DateTimeOffset.UtcNow.ToUnixTimeSeconds() ? announcement.Endpoint : "";
                    if(selectedEntries.TryGetValue(member.Slot,out var selected))endpoint=selected;
                    if(networkEntries?.OwnsEndpoint(endpoint)==true)continue;
                    var paths=Paths(member.Slot);
                    bool preferred=priorityPeers.Contains(member.Slot);
                    paths.Update(member.Slot, endpoint, announcement?.Name ?? "", onlyEntryPeers.Contains(member.Slot)?"仅通过已有入口连接；失败时请检查入口或手动切换到自选服务器模式":preferred?"正在优先验证已有入口，失败后自主打洞":traversal?.WaitingDetail(member.Slot) ??
                        (endpoint.Length > 0 ? "正在验证直连" : candidate.Length > 0 ? "等待成员连接本机入口" : "双方暂无可用入口，业务不会转发"),
                        traversal == null ? null : () => preferred?existingPlans[member.Slot].Admit(()=>traversal.BeginLegacyAttempt(member.Slot)):traversal.BeginLegacyAttempt(member.Slot), traversal?.KeepLegacyAttempt(member.Slot) ?? true);
                    traversal?.ObserveLegacyPending(member.Slot, paths.HasPending);
                }
                if (now >= nextReport) {
                    ConnectionProgress? EntryProgress(int slot){
                        if(!onlyEntryPeers.Contains(slot))return null;
                        if(traversal?.Progress(slot,now) is {Phase:"Blocked" or "Releasing"} held)return held;
                        var progress=clients.GetValueOrDefault(slot)?.Progress(now);
                        bool missing=selectedEntries.GetValueOrDefault(slot,"").Length==0&&localExisting.Length==0;
                        if(missing||clients.GetValueOrDefault(slot)?.HasFailedAttempts==true)return new("EntryUnavailable",missing?"没有可用的已有入口。请检查地址或订阅，或手动切换到自选服务器模式进行自主打洞。":"已有入口未通过双向验证，将继续仅重试已有入口。请检查目标在线状态、映射和协议，或手动切换到自选服务器模式进行自主打洞。",CanRetry:true){ReasonCode="ExistingEntryUnreachable"};
                        return selectedEntries.GetValueOrDefault(slot,"").Length==0?new("WaitingPeer","等待对端通过本机已有入口连接；不执行自主打洞",CanRetry:true):progress;
                    }
                    feedback.Retain(members.Select(m=>m.Slot));
                    ConnectionProgress QuietProgress(int slot)=>traversal?.Progress(slot,now) is {Phase:"Blocked" or "Releasing"} held?held:
                        clients.GetValueOrDefault(slot)?.HasPending==true?new("Releasing","对端未响应，正在回收本轮连接资源"):
                        new("Offline",mesh.Pair.Direct?"设备暂无响应，已暂停密集重连；定时复核、入口变化或手动重试后恢复。":"设备未在线，等待新的上线信息后自动连接。");
                    ConnectionProgress? unavailable=!legacyAllowed && gatheringFactory==null && factory==null
                        ? new("Blocked","当前传输模式的连接组件不可用，请检查安装或在设置中选择可用模式；不会自动切换协议。") {ReasonCode="SelectedTransportUnavailable"} : null;
                    MeshPeerStatus EntryEvidence(MeshPeerStatus peer)=>peer.Connected&&peer.EntryDirection=="Outbound"&&clients.GetValueOrDefault(peer.Slot)?.AuthenticatedEndpoint(peer.Slot) is {} endpoint?peer with{OuterTarget=endpoint}:peer;
                    statuses = router.Status().Select(peer=>feedback.Observe(EntryEvidence(peer),
                        quietPeers.Contains(peer.Slot)?QuietProgress(peer.Slot):EntryProgress(peer.Slot)??(priorityPeers.Contains(peer.Slot) ? new ConnectionProgress("Verifying",mesh.Pair.Direct?"正在验证已有入口 "+selectedEntries.GetValueOrDefault(peer.Slot)+"；请确认主机在线，映射转发到 ConWU 且协议一致。":existingPlans[peer.Slot].Detail+"；失败后自主打洞，保持所选协议。",CanRetry:true) : traversal?.Progress(peer.Slot,now) ?? clients.GetValueOrDefault(peer.Slot)?.Progress(now) ?? unavailable),
                        announcements.TryGetValue(peer.Slot,out var remote) && remote.Expires > DateTimeOffset.UtcNow.ToUnixTimeSeconds(),now)).ToArray();
                    foreach(int slot in qualityReports.Keys.Where(slot=>!statuses.Any(p=>p.Slot==slot)).ToArray())qualityReports.Remove(slot);
                    foreach(var peer in statuses)if(peer.Quality is{}assessment){
                        var key=(assessment.SessionId,assessment.Result,assessment.Reason);
                        if(qualityReports.GetValueOrDefault(peer.Slot)!=key){
                            log($"PathQuality peer={peer.Slot} session={assessment.SessionId:N} targetMbps={assessment.TargetMbps} result={assessment.Result} reason={assessment.Reason} candidateQualified={assessment.CandidateQualified} benefit={assessment.StableBenefit}；诊断截止送达与加载往返，不代表应用帧时限");
                            qualityReports[peer.Slot]=key;
                        }
                    }
                    foreach (int slot in recoveryReports.Keys.Where(slot => !statuses.Any(p => p.Slot == slot)).ToArray()) recoveryReports.Remove(slot);
                    foreach (var peer in statuses) if (peer.Recovery is {} recovery) {
                        var prior = recoveryReports.GetValueOrDefault(peer.Slot);
                        if (prior.Episode != recovery.EpisodeId) prior = (recovery.EpisodeId, false, false, false);
                        if (!prior.Path && recovery.StablePathConfirmedMs is {} pathConfirmed) {
                            log($"StablePath peer={peer.Slot} episode={recovery.EpisodeId:N} path={recovery.PathId:N} startMs={recovery.StablePathStartMs} confirmedMs={pathConfirmed} probes={recovery.PathProbes}；普通保活已验证双向路径，不代表业务恢复或负载质量");
                            prior.Path = true;
                        }
                        if (!prior.First && recovery.FirstBusinessMs is {} firstBusiness) {
                            log($"FirstBusiness peer={peer.Slot} episode={recovery.EpisodeId:N} path={recovery.FirstBusinessPathId:N} elapsedMs={firstBusiness}；已收到认证业务包，尚不代表稳定恢复");
                            prior.First = true;
                        }
                        if (!prior.Stable && recovery.StableBusinessConfirmedMs is {} confirmed) {
                            log($"StableBusiness peer={peer.Slot} episode={recovery.EpisodeId:N} path={recovery.PathId:N} startMs={recovery.StableBusinessStartMs} confirmedMs={confirmed} probes={recovery.ConsecutiveProbes} restarts={recovery.WindowRestarts}；本地业务进展与同路径往返验证，不代表目标吞吐或零丢包");
                            prior.Stable = true;
                        }
                        recoveryReports[peer.Slot] = prior;
                    }
                    var egress = sharedEgress?.Snapshot()??factory?.Egress;
                    if (egress != null && now >= nextEgressReport) {
                        log($"实验出口 {egress.Mbps} Mbps：已发外层 {egress.SentBytes} B，突发上限 {egress.BurstBytes} B，排队 {egress.QueuedBytes}/{egress.QueueLimitBytes} B，队列 P95 ≤ {egress.QueueP95Ms:F1} ms，当前最老 {egress.OldestQueuedMs:F1} ms，溢出 {egress.OverflowDrops}，发送失败 {egress.SendFailures}" +
                            (egress.Accounting is {} accounting ? $"；在途 {accounting.InFlight.Bytes} B，拒绝 {accounting.CapacityRejected.Packets + accounting.UnavailableRejected.Packets}，队列账本 {(accounting.Conserved ? "一致" : "异常")}" : "") +
                            (egress.Failure.Length > 0 ? "；调度失败 " + egress.Failure : ""));
                        nextEgressReport = now + 30000;
                    }
                    int count = statuses.Count(p => p.Connected); var first = statuses.FirstOrDefault(p => p.Connected);
                    if (now >= nextTrafficReport) {
                        var pressure = router.Pressure();
                        log($"RouterPressure maintenanceAgeMs={pressure.MaintenanceAgeMs} maximumDelayMs={pressure.MaximumMaintenanceDelayMs} maximumLockWaitMs={pressure.MaximumMaintenanceLockWaitMs} maximumWorkMs={pressure.MaximumMaintenanceWorkMs} receiveYields={pressure.ReceiveYields} legacySendRejected={pressure.LegacySendRejected}");
                        foreach (var peer in statuses) {
                            if (peer.StreamFlows is {} flows && reportedStreamFlows.GetValueOrDefault(peer.Slot) != flows) {
                                reportedStreamFlows[peer.Slot] = flows;
                                log($"StreamFlows slot={peer.Slot} negotiated={flows.Negotiated} splitActive={flows.SplitActive} connections={flows.Connections} queueRejected={flows.RejectedPackets} receiveRejected={flows.ReceiveRejectedPackets}；按流分离，不对同一数据流逐包轮发");
                            }
                            if (peer.LocalDrops is {} drops && reportedRouterDrops.GetValueOrDefault(peer.Slot) != drops) {
                                reportedRouterDrops[peer.Slot] = drops;
                                if (drops.Total > 0)
                                    log($"RouterDrops slot={peer.Slot} noHealthyPath={drops.NoHealthyPath} sendRejected={drops.SendRejected} authenticationRejected={drops.AuthenticationRejected} receivePolicyRejected={drops.ReceivePolicyRejected} adapterWriteRejected={drops.AdapterWriteRejected}；本次运行累计的本机拒绝计数");
                            }
                            if (peer.NativeEvidence is {BridgeSendQueue:{} sendQueue,BridgeReceiveQueue:{} receiveQueue} native) {
                                var counts = (SendData:sendQueue.DataRejected,SendControl:sendQueue.ControlRejected,
                                    ReceiveData:receiveQueue.DataRejected,ReceiveControl:receiveQueue.ControlRejected,Socket:native.BridgeSocketRejected);
                                long total = counts.SendData + counts.SendControl + counts.ReceiveData + counts.ReceiveControl + counts.Socket;
                                if (reportedBridgeDrops.TryGetValue(peer.Slot,out var previous) && previous == counts) continue;
                                reportedBridgeDrops[peer.Slot] = counts;
                                if (total > 0)
                                    log($"NativeBridgeDrops slot={peer.Slot} sendData={sendQueue.DataRejected} sendControl={sendQueue.ControlRejected} receiveData={receiveQueue.DataRejected} receiveControl={receiveQueue.ControlRejected} socketRejected={native.BridgeSocketRejected} queueConserved={sendQueue.Conserved && receiveQueue.Conserved}；本次运行累计的原生桥拒绝计数");
                            }
                        }
                        foreach (var peer in statuses) if (peer.Traffic?.Windows.LastOrDefault(w => w.Complete) is {} window &&
                            (window.AcceptedSendBytes > 0 || window.DeliveredReceiveBytes > 0))
                            log($"设备 {peer.Slot} 路径业务窗口 {window.Seconds:F2} 秒：接受发送 {window.AcceptedSendMbps:F3} Mbps，已交付接收 {window.DeliveredReceiveMbps:F3} Mbps，拒绝 {window.SendRejectedPackets}；" +
                                $"业务活动 RTT 样本 {window.ActivityRtt.Samples}，P95 {(window.ActivityRtt.P95Ms?.ToString("F2") ?? "Unknown")} ms；对端送达/发送损失 Unknown");
                        foreach (var peer in statuses) if (peer.Delivery?.Reports.LastOrDefault() is {} receipt)
                            log($"设备 {peer.Slot} 路径送达反馈：{receipt.Result}；接受 {receipt.AcceptedPackets} 包/{receipt.AcceptedBytes} B，对端交付 " +
                                $"{receipt.PeerDeliveredPackets?.ToString() ?? "Unknown"} 包/{receipt.PeerDeliveredBytes?.ToString() ?? "Unknown"} B；" +
                                $"接收收尾 {receipt.ReceiverSettleMs} ms，截止缺口 {receipt.DeficitAtReceiptPercent?.ToString("F3") ?? "Unknown"}%；此项不代表永久丢失或单向延迟");
                        nextTrafficReport = now + 30000;
                    }
                    int degraded = statuses.Count(p => p.Degraded);
                    var (connectionState, connection) = MeshConnectionFeedback.Summarize(statuses,now-began);
                    if(coordinatorUnavailable)connection=connection with {Detail="协调服务暂不可用，已有直连继续运行；新增连接可能延迟。 "+connection.Detail};
                    if(mappingReleaseFailed)connection=connection with {Detail="本机入口资源回收失败，已暂停入口重建；已有直连继续运行，请保留诊断后重启后台处理。 "+connection.Detail};
                    var adapterStatistics = actualAdapter?.Statistics;
                    report(new(connectionState, mesh.LocalIp, first?.Ip ?? "", mesh.Pair.Mode, count > 0, first?.RttMs,
                        $"{count}/{statuses.Length} 台设备直连 · 业务不经中继" + (degraded > 0 ? $" · {degraded} 台 UDP，质量单独评估" : ""), first?.Name ?? "", statuses) {
                            Connection=connection, RouterPressure=router.Pressure(),
                            Adapter = adapterStatistics is {} observed ? adapterStatus with {ReadPackets=observed.ReadPackets,WrittenPackets=observed.WrittenPackets} : adapterStatus,
                            AdapterStatistics = adapterStatistics,
                            Egress = egress, ControlAdmission = TraversalResources.Shared.Usage(),
                            TcpHelpers = TcpHelperLedger.Shared.Snapshot(),
                            LegacyTransports = LegacyTransportLedger.Shared.Snapshot(),
                            CompatibilityNativeControl = LegacyControlGovernor.Shared.Snapshot(),
                            EnhancementAdmission = TraversalResources.Shared.Enhancements.Usage()
                        });
                    nextReport = now + 1000;
                }
                // Only the bounded, fresh-observation exchange needs this
                // cadence. Idle and established paths retain the normal tick.
                await Task.Delay(traversal?.FreshPredictionInProgress == true ? 25 : 100, stop);
            }
        } catch(Exception ex) when(!stop.IsCancellationRequested && ex is not MeshRevokedException) {
            // Publish loss of connectivity before potentially slow owner cleanup.
            report(new("连接中断",mesh.LocalIp,"",mesh.Pair.Mode,false,null,ex.Message) {
                Adapter=adapterStatus,Connection=new("Recovering","连接组件发生异常，正在安全退出旧资源后重试。",nowElapsed(),CanRetry:false) });
            throw;
        } finally {
            Volatile.Write(ref receiverReady,0);
            lock (gate) stopping = true;
            long shutdownStarted = Environment.TickCount64;
            var cleanupFailures=new List<string>();
            void CleanupFailed(string stage,Exception ex,object? owner=null){if(owner!=null)lock(gate)unprovenOwners.Add(owner);cleanupFailures.Add(stage+":"+ex.GetType().Name+":"+ex.Message);try{log("资源退出未完成："+cleanupFailures[^1]);}catch{}}
            void ShutdownStage(string stage) {
                ExitDiagnostics = new { stage, elapsedMs=Environment.TickCount64-shutdownStarted,
                    cleanupComplete=CleanupComplete,failures=cleanupFailures.ToArray(),
                    tasks=new {factory=gatheringFactory?.Status.ToString(),probe=probe?.Status.ToString(),adapter=opening?.Status.ToString(),
                        maintain=maintain?.Status.ToString(),quality=quality?.Status.ToString(),read=reading?.Status.ToString(),publish=publishing?.Status.ToString(),save=saving?.Status.ToString(),release=releasing?.Status.ToString(),router=router?.Completion.Status.ToString()} };
                try { log($"ShutdownStage={stage}; elapsedMs={Environment.TickCount64-shutdownStarted}; tasks="+System.Text.Json.JsonSerializer.Serialize(ExitDiagnostics)); } catch { }
            }
            ShutdownStage("cancel");
            try{cancellation.Cancel();}catch(Exception ex){CleanupFailed("cancel",ex);}
            ShutdownStage("factory-startup");
            if (gatheringFactory != null) try { factory = await gatheringFactory; } catch { }
            ShutdownStage("traversal");
            if (traversal != null) try { await traversal.DisposeAsync(); } catch (Exception ex) { CleanupFailed("traversal",ex,traversal); }
            ShutdownStage("mapping-probe");
            if (probe != null) { try { mapping = await probe; } catch { } }
            ShutdownStage("adapter-startup");
            if (opening != null) try { pendingAdapter=await opening; } catch { }
            if (pendingAdapter != null) try { pendingAdapter.Dispose(); } catch (Exception ex) { CleanupFailed("adapter-startup",ex,pendingAdapter); }
            ShutdownStage("maintenance-and-http");
            foreach (var task in new Task?[] { maintain, quality, reading, publishing, saving, releasing,resolving }) if (task != null) {
                try { await task; }
                catch (Exception ex) {
                    // Even a cancelled release is unproven ownership. An HTTP
                    // or maintenance cancellation is only an operation ending.
                    if (ReferenceEquals(task,releasing)) CleanupFailed("mapping-release",ex,retiringMapping);
                    else if (ex is not OperationCanceledException) try { log("退出任务已结束："+ex.Message); } catch { }
                }
            }
            ShutdownStage("network-entry-probes");
            if(networkEntries!=null)try{await networkEntries.DisposeAsync();}catch(Exception ex){CleanupFailed("network-entry",ex,networkEntries);}
            ShutdownStage("legacy-clients");
            foreach (var client in clients.Values) { try { await client.DisposeAsync(); } catch (Exception ex) { CleanupFailed("legacy-client",ex,client); } }
            ShutdownStage("listener");
            try { server?.Dispose(); } catch (Exception ex) { CleanupFailed("listener",ex,server); }
            ShutdownStage("mapping");
            if (mapping != null) { try { await mapping.DisposeAsync(); } catch (Exception ex) { CleanupFailed("mapping",ex,mapping); } }
            ShutdownStage("router");
            if (router != null) { try { await router.DisposeAsync(); } catch (Exception ex) { CleanupFailed("router",ex,router); } router = null; }
            ShutdownStage("factory");
            if (factory is IAsyncDisposable ownedFactory) try { await ownedFactory.DisposeAsync(); } catch (Exception ex) { CleanupFailed("factory",ex,ownedFactory); }
            ShutdownStage("owned-rule-and-record");
            try { services.Firewall(rule, mesh.LocalIp, ""); File.Delete(Path.Combine(folder, "owner.json")); } catch (Exception ex) { CleanupFailed("owned-rule-and-record",ex); }
            CleanupComplete=cleanupFailures.Count==0;
            ShutdownStage(CleanupComplete?"complete":"incomplete");
            if(!CleanupComplete)throw new MeshShutdownException(cleanupFailures.ToArray());
        }
        long nowElapsed() => Environment.TickCount64-began;
        static async Task ReleaseMapping(IMapping owner) => await owner.DisposeAsync();
    }
}
