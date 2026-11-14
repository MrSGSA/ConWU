using System.Collections.Concurrent;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

internal sealed class NetworkAddressConflictException(string message):IOException(message);

// Owns independent two-device contexts. A view selection never changes which
// workers run, and a failed/slow worker cannot hold the device status lock.
internal sealed partial class PairNetworkWorkspace : IDisposable
{
    sealed record Information(string Id,string Name,bool Removed=false,Guid CreationOperation=default,bool PendingEnrollment=false,string ConfigurationId="",long AppliedConfigurationRevision=0);
    sealed class Context(Information info,ControlWorker worker,ProfileStore store)
    {
        public Information Info=info;
        public ControlWorker Worker {get;}=worker;
        public ProfileStore Store {get;}=store;
        public SemaphoreSlim Actions {get;}=new(1,1);
    }
    readonly ControlWorker device;
    readonly ProfileStore store;
    readonly MeshRuntimeServices? services;
    readonly SharedMeshReceiver receivers;
    readonly SharedEntryResolver entryQueries=new();
    readonly ConcurrentDictionary<string,Context> networks=new(StringComparer.Ordinal);
    readonly ConcurrentDictionary<Guid,string> operationNetworks=new();
    readonly SemaphoreSlim creating=new(1,1);
    readonly ConcurrentDictionary<long,TaskCompletionSource> mutations=new();
    readonly ConcurrentDictionary<Guid,WorkspaceOperation> controlOperations=new();
    readonly object admissionGate=new();
    sealed class WorkspaceOperation(string digest,Guid id,string command)
    {
        public string Digest {get;}=digest;
        public ControlOperationStatus State=new(id,command,"等待此网络的其他操作完成",false,true);
        public CancellationTokenSource Stop {get;}=new();
        public bool Delegated;
        public bool Executing=true;
        public UiControlReply? Result;
        public string Selected="";
    }
    long mutationSequence;
    volatile bool accepting=true;
    bool started;
    const int MaximumNetworks=16;
    string Folder=>Path.Combine(store.DirectoryPath,"networks");

    public PairNetworkWorkspace(ControlWorker device,ProfileStore store,MeshRuntimeServices? services)
    {
        this.device=device;this.store=store;this.services=services;
        receivers=new(Path.Combine(store.DirectoryPath,"sessions","shared-receivers"));
        if(device.ProfileSnapshot().Mesh!=null||device.ProfileSnapshot().Pair!=null)
            throw new IOException("此版本使用双机多网络配置，请先按全新安装流程重新设置；旧配置尚未修改");
        LoadConfigurations();
        if(!Directory.Exists(Folder)){EnsureInitialConfiguration();return;}
        if((File.GetAttributes(Folder)&FileAttributes.ReparsePoint)!=0)throw new IOException("网络配置目录不能是链接");
        try{foreach(string folder in Directory.EnumerateDirectories(Folder).Order(StringComparer.Ordinal)){
            string id=Path.GetFileName(folder);if(!Guid.TryParseExact(id,"N",out _))continue;
            if((File.GetAttributes(folder)&FileAttributes.ReparsePoint)!=0)throw new IOException("网络配置不能是链接");
            string path=Path.Combine(folder,"network-info.json");if(!File.Exists(path))continue;
            if(new FileInfo(path).Length>4096||(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("网络索引无效");
            var info=JsonSerializer.Deserialize<Information>(File.ReadAllBytes(path))??throw new IOException("网络索引为空");
            ValidateName(info.Name);if(info.Id!=id)throw new IOException("网络配置身份不符");if(info.Removed){if(info.ConfigurationId.Length>0)retiredConfigurations[info.ConfigurationId]=0;continue;}
            if(networks.Count>=MaximumNetworks)throw new IOException("本机网络数量超过限制");
            Context? opened=null;
            try{
                var context=opened=Open(info,folder);
                if(info.PendingEnrollment){
                    bool completed=context.Worker.ProfileSnapshot().Mesh!=null;
                    var received=context.Worker.ProfileSnapshot();context.Info=context.Info with{PendingEnrollment=false,Removed=!completed,Name=completed&&received.AutoConfigureJoin&&received.ReceivedNetworkSettings?.NetworkName.Length>0?received.ReceivedNetworkSettings.NetworkName:context.Info.Name};context.Worker.NetworkDisplayName=context.Info.Name;WriteInfo(context);
                    if(!completed){context.Worker.Dispose();opened=null;continue;}
                }
                EnsureConfiguration(context);networks[id]=context;if(info.CreationOperation!=Guid.Empty)operationNetworks[info.CreationOperation]=id;
                opened=null;
            }catch{opened?.Worker.Dispose();throw;}
        }}catch{foreach(var context in networks.Values)context.Worker.Dispose();receivers.Dispose();throw;}
        PruneRetiredConfigurations();EnsureInitialConfiguration();
    }
    Context Open(Information info,string folder)
    {
        var networkStore=new ProfileStore(folder,store);
        var basis=services??MeshRuntimeServices.Default;ControlWorker? worker=null;
        var runtime=basis with{SessionRoot=Path.Combine(folder,"sessions"),ResolveEntries=basis.ResolveEntries??entryQueries.Resolve,
            ResolveEntriesForRecovery=basis.ResolveEntriesForRecovery??basis.ResolveEntries??entryQueries.ResolveRecovering,
            Transport=r=>receivers.Acquire(r,basis.Transport,p=>worker?.AcceptsDirectPairing(p)==true,p=>worker?.AuthenticatedNetworkFrame(p)==true,p=>worker?.DirectPairPriority(p)??0)};
        PrepareConfigurationAtStartup(info,networkStore);
        if(info.ConfigurationId.Length>0&&configurations.TryGetValue(info.ConfigurationId,out var loaded))info=info with{AppliedConfigurationRevision=loaded.Revision};
        networkStore.ValidateNetworkProfile=p=>ValidateNetwork(info.Id,p);
        worker=new ControlWorker(networkStore,runtime,isolatedNetwork:true){NetworkDisplayName=info.Name};var opened=new Context(info,worker,networkStore);try{WriteInfo(opened);return opened;}catch{worker.Dispose();throw;}
    }
    void ValidateNetwork(string id,DeviceProfile candidate)
    {
        if(candidate.Mesh is not {} mesh)return;
        if(mesh.Directory?.Pairwise!=true)throw new IOException("此版本仅接入新版双机网络，请让两端重新创建连接");
        if(mesh.IsDecentralized)throw new IOException("本版双机网络由主机审批，不接入成员平等管理网络；原配置保留，请重新配对");
        if(mesh.Self.Device!=candidate.Device)throw new IOException("网络凭据不属于本机的设备身份，不能导入其他设备的配置");
        var others=validatingConfigurations is {} planned?planned.Where(n=>n.Key!=id).Select(n=>n.Value).ToArray():networks.Values.Where(n=>n.Info.Id!=id).Select(n=>n.Store.LoadForMaintenance()).ToArray();
        if(candidate.Enabled&&others.Count(p=>p.Enabled&&p.Mesh!=null)>=8)throw new IOException("本机最多同时运行 8 条双机网络，请先暂停一条连接");
        foreach(var other in others){
            if(other.Mesh is not {} known)continue;
            if(known.Pair.Network==mesh.Pair.Network)throw new IOException("本机已保存此网络，请使用已有配置重新连接");
            var peer=mesh.Directory?.Members.FirstOrDefault(m=>m.Slot!=mesh.Self.Slot);var knownPeer=known.Directory?.Members.FirstOrDefault(m=>m.Slot!=known.Self.Slot);
            if(peer!=null&&knownPeer?.Device==peer.Device)throw new IOException("本机已保存与此设备的连接，请使用已有配置或先移除它");
            if(MeshAddressing.Prefix(known.LocalIp)==MeshAddressing.Prefix(mesh.LocalIp))throw new NetworkAddressConflictException("虚拟网段与本机另一条网络冲突："+MeshAddressing.Prefix(mesh.LocalIp)+".0/24，请重新创建或调整固定地址");
            if(other.Enabled&&candidate.Enabled&&(other.ListenPort==candidate.SourcePort||other.SourcePort==candidate.ListenPort||other.SourcePort==candidate.SourcePort))throw new IOException("端口与另一条运行网络冲突，请在此网络设置独立端口");
            if(other.Enabled&&candidate.Enabled&&other.ListenPort==candidate.ListenPort&&!CanShareListener(other,candidate))throw new IOException("此接收端口正被不兼容的网络策略使用，请为本网络设置独立端口");
        }
    }
    static UiNetworkSettings AutoJoinSettings(UiNetworkAction action,DeviceProfile local)
    {
        bool direct=action.Action!="join";string mode=action.Mode;
        ExistingEntry[] entries=[];
        if(action.Action=="join-invitation")mode=DirectPairInvitation.Import(action.Code).Mode;
        else if(action.Action=="join-compact"){var compact=CompactDirectCode.Import(action.Code);mode=compact.Mode;entries=[new(ExistingEntry.NetworkOwner,compact.Endpoint)];}
        else if(direct){
            if(string.IsNullOrWhiteSpace(action.Entry))throw new FormatException("请提供目标主机入口，或使用包含入口的直连邀请");
            entries=[new(ExistingEntry.NetworkOwner,action.Entry)];
        }
        return ConnectionSettings.Normalize(new(action.Service,action.CertificatePin,PathSelection:TransportModes.Policy(mode),ListenPort:local.ListenPort,SourcePort:local.SourcePort){
            DirectMode=direct,ConnectionSource=direct?"existing":"custom",ExistingEntries=entries
        });
    }
    static bool CanShareListener(DeviceProfile left,DeviceProfile right)=>left.TransportMode==right.TransportMode&&(left.SavedNetworkSettings?.ConnectionSource??left.ConnectionSource)==(right.SavedNetworkSettings?.ConnectionSource??right.ConnectionSource)&&
        (left.TransportMode!="udp"||left.UsesExistingEntriesOnly&&right.UsesExistingEntriesOnly)&&left.ManagedEgressMbps==0&&right.ManagedEgressMbps==0;
    static void ValidateName(string name){if(name is null||name.Length is <1 or >64||name.Any(char.IsControl))throw new FormatException("网络名称需为 1–64 个可见字符");}
    static void WriteInfo(Context context)
    {
        string path=Path.Combine(context.Store.DirectoryPath,"network-info.json");byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(context.Info);
        if(OperatingSystem.IsLinux())LinuxPlatform.PrivateWrite(path,bytes);
        else{string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";try{File.WriteAllBytes(temp,bytes);File.Move(temp,path,true);}finally{if(File.Exists(temp))File.Delete(temp);}}
    }
    public void Start(){accepting=true;started=true;foreach(var network in networks.Values)network.Worker.StartLocal();}
    public async Task Stop(CancellationToken token){
        Task[] ending;lock(admissionGate){accepting=false;ending=mutations.Values.Select(m=>m.Task).ToArray();}
        foreach(var network in networks.Values)network.Worker.BeginApplicationStop();
        await Task.WhenAll(ending).WaitAsync(token);
        await Task.WhenAll(networks.Values.Select(n=>n.Worker.StopLocal(token)));started=false;
    }
    public bool HasOutstandingOwnership=>mutations.Values.Any(m=>!m.Task.IsCompleted)||networks.Values.Any(n=>n.Worker.HasOutstandingOwnership);
    public UuTakeoverNetwork[] TakeoverNetworks()=>networks.Values.Select(n=>n.Worker.TakeoverNetwork(n.Info.Id,n.Info.Name)).ToArray();
    public UpdateNetworkState[] UpdateNetworks()=>networks.Values.Select(n=>n.Worker.UpdateNetwork(n.Info.Id)).ToArray();
    public void Dispose(){lock(admissionGate)accepting=false;foreach(var context in networks.Values)context.Worker.Dispose();receivers.Dispose();entryQueries.Dispose();}

    public UiStatusDto Snapshot(string selected="")
    {
        var defaults=device.SingleUiSnapshot();
        var rows=networks.Values.OrderBy(n=>n.Info.Id,StringComparer.Ordinal).Select(n=>new UiNetworkDto(n.Info.Id,n.Info.Name,n.Worker.SingleUiSnapshot()){ConfigurationId=n.Info.ConfigurationId,AppliedConfigurationRevision=n.Info.AppliedConfigurationRevision}).ToArray();
        var chosen=rows.FirstOrDefault(n=>n.Id==selected)?.Status??defaults;
        var peers=rows.SelectMany(n=>n.Status.Peers.Select(p=>new UiAggregatePeerDto(n.Id,p.DeviceId,n.Status.IsOwner?"host":"guest",p,p.ConnectedSince))).ToArray();
        int connected=rows.Count(n=>n.Status.DirectPeers>0),connecting=rows.Count(n=>n.Status.DirectPeers==0&&n.Status.NetworkEnabled);
        var aggregate=new UiAggregateDto(rows.Length,connected,connecting,rows.Length-connected-connecting,
            peers.Select(p=>p.DeviceId.Length>0?p.DeviceId:p.NetworkId+":"+p.Peer.Slot).Distinct(StringComparer.Ordinal).Count(),
            peers.Sum(p=>p.Peer.SentBytes),peers.Sum(p=>p.Peer.ReceivedBytes),peers);
        return chosen with{Configurations=ConfigurationSnapshot(),WorkspaceVersion=2,SelectedNetworkId=selected,Networks=rows,Aggregate=aggregate,
            NetworkDefaults=new(){DirectMode=true,DiscoveryMode="pkarr",PkarrPublish=true,TcpStun=Stun.TcpServers.ToArray(),UdpStun=Stun.UdpServers.ToArray()},
            DeviceSettings=defaults.Settings,DeviceSettingsRevision=defaults.SettingsRevision,Coordinator=defaults.Coordinator,Desktop=defaults.Desktop,Update=defaults.Update,LocalUpdate=defaults.LocalUpdate,UuTakeover=defaults.UuTakeover,
            DeviceName=defaults.DeviceName,LogLevel=defaults.LogLevel,ServiceReady=defaults.ServiceReady,
            Logs=defaults.Logs,LogEntries=defaults.LogEntries};
    }
    public async Task<UiControlReply> Handle(UiControlRequest request,string sid,CancellationToken token)
    {
        if(store.AuthorizedUiUser()!=sid)return new(false,"当前用户没有本机控制权限",null);
        if(request.Method=="status")return await HandleCore(request,sid,token);
        if(!accepting)return new(false,"后台正在停止，请稍后重试",Snapshot(),Operation:new(request.OperationId,request.Method,"未完成",true,false,"后台正在停止"));
        request=request.OperationId==Guid.Empty?request with{OperationId=Guid.NewGuid()}:request;
        string digest=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new{request,sid})));
        long id;TaskCompletionSource completion;WorkspaceOperation operation;
        lock(admissionGate){
            if(!accepting)return new(false,"后台正在停止，请稍后重试",Snapshot(),Operation:new(request.OperationId,request.Method,"未完成",true,false,"后台正在停止"));
            if(controlOperations.TryGetValue(request.OperationId,out var existing)){
                if(existing.Digest!=digest)return new(false,"操作ID已被不同请求使用",Snapshot());
                return existing.Result is {} completed?completed with{Status=Snapshot(existing.Selected)}:new(true,"",Snapshot(existing.Selected) with{Operation=existing.State},Operation:existing.State);
            }
            if(mutations.Count>=32)return new(false,"本机已有太多操作，请等待当前操作完成",Snapshot(),Operation:new(request.OperationId,request.Method,"未完成",true,false,"本机操作队列已满"));
            operation=new(digest,request.OperationId,request.Network?.Action??request.Method){Selected=request.NetworkId};controlOperations[request.OperationId]=operation;
            id=Interlocked.Increment(ref mutationSequence);completion=new(TaskCreationOptions.RunContinuationsAsynchronously);mutations[id]=completion;
        }
        try{
            var reply=!accepting?new UiControlReply(false,"后台正在停止",Snapshot(),Operation:new(request.OperationId,request.Method,"未完成",true,false,"后台正在停止")):await HandleCore(request,sid,token);
            operation.Selected=reply.Status?.SelectedNetworkId??operation.Selected;
            if(request.Method=="cancel")reply=reply with{Operation=new(request.OperationId,"cancel",reply.Ok?"已请求取消":"未完成",true,false,reply.Error)};
            operation.State=reply.Operation??new(request.OperationId,request.Network?.Action??request.Method,reply.Ok?"已完成":"未完成",true,false,reply.Error);
            if(operation.State.Completed)operation.Result=reply with{Status=null,Operation=operation.State};
            return reply;
        }finally{
            lock(admissionGate){operation.Executing=false;operation.Stop.Dispose();mutations.TryRemove(id,out _);completion.TrySetResult();}
            if(operationNetworks.Count>256)foreach(var retired in operationNetworks.Where(p=>!networks.ContainsKey(p.Value)&&(!controlOperations.TryGetValue(p.Key,out var savedOperation)||savedOperation.Result!=null)).ToArray())operationNetworks.TryRemove(retired.Key,out _);
            if(controlOperations.Count>256)foreach(var old in controlOperations.Where(p=>p.Key!=request.OperationId&&(p.Value.Result!=null||!p.Value.Executing&&p.Value.Delegated&&
                (!operationNetworks.TryGetValue(p.Key,out var targetId)||!networks.TryGetValue(targetId,out var context)||context.Worker.IsOperationComplete(p.Key)))).Take(64))controlOperations.TryRemove(old.Key,out _);
        }
    }
    async Task WaitGate(SemaphoreSlim gate,Guid operationId,CancellationToken serviceToken)
    {
        var tracked=controlOperations.GetValueOrDefault(operationId);
        using var waiting=tracked==null?CancellationTokenSource.CreateLinkedTokenSource(serviceToken):CancellationTokenSource.CreateLinkedTokenSource(serviceToken,tracked.Stop.Token);
        try{if(!await gate.WaitAsync(TimeSpan.FromSeconds(90),waiting.Token))throw new IOException("等待其他操作超过 90 秒，请查看当前进度后重试");}
        catch(OperationCanceledException)when(!serviceToken.IsCancellationRequested){throw new IOException("已取消排队中的操作");}
    }
    void ActiveOperation(Guid id,bool delegated=false)
    {
        lock(admissionGate)if(controlOperations.TryGetValue(id,out var operation)){operation.Delegated=delegated;operation.State=operation.State with{Phase="正在执行",Cancelable=delegated};}
    }
    async Task<UiControlReply> HandleCore(UiControlRequest request,string sid,CancellationToken token)
    {
        if(store.AuthorizedUiUser()!=sid)return new(false,"当前用户没有本机控制权限",null);
        string selected=request.NetworkId;
        try{
            if(request.Method=="status"&&controlOperations.TryGetValue(request.OperationId,out var finished)&&finished.Result is {} cached)return cached with{Status=Snapshot(finished.Selected)};
            if(request.Method=="cancel")lock(admissionGate){
                if(controlOperations.TryGetValue(request.CancelOperationId,out var queued)&&!queued.Delegated&&queued.Result==null&&queued.Executing){
                    if(!queued.State.Cancelable)throw new IOException("操作已进入资源或设置提交阶段，不能撤销；可以关闭界面等待");
                    queued.Stop.Cancel();return new(true,"",Snapshot(queued.Selected),Operation:queued.State);
                }
            }
            if(selected is null||selected.Length>0&&!Guid.TryParseExact(selected,"N",out _))throw new FormatException("网络配置 ID 无效");
            Guid lookup=request.Method=="cancel"?request.CancelOperationId:request.OperationId;
            if(lookup!=Guid.Empty&&operationNetworks.TryGetValue(lookup,out var operationTarget)){
                if(selected.Length>0&&selected!=operationTarget)throw new IOException("操作 ID 已绑定另一条网络");
                selected=operationTarget;
            }
            selected??="";
            if(request.Method=="configuration")return await HandleConfiguration(request with{NetworkId=selected},sid,token);
            if(request.Method=="save-settings")return await SaveBatch(request with{NetworkId=selected},sid,token);
            if(request.Network!=null&&(request.Network.ConfigurationId==null||request.Network.RequestedVirtualIp==null))throw new FormatException("连接配置 ID 不能为空");
            if(request.Method=="network"&&request.Network is {Action:"join-target"} joinTargetAction){
                using var lookupStop=CancellationTokenSource.CreateLinkedTokenSource(token,controlOperations[request.OperationId].Stop.Token);
                var resolvedJoin=await JoinTarget.Resolve(joinTargetAction,(url,pin,ct)=>MeshCoordinatorPreflight.Probe(url,pin,null,ct),lookupStop.Token);
                request=request with{Network=resolvedJoin};
            }
            bool enrollment=request.Method=="network"&&request.Network?.Action is "create" or "create-direct" or "join" or "join-entry" or "join-invitation" or "join-compact" or "join-direct-short" or "join-direct";
            if(enrollment&&selected.Length==0){
                await WaitGate(creating,request.OperationId,token);
                try{
                    if(request.OperationId!=Guid.Empty&&operationNetworks.TryGetValue(request.OperationId,out var existing))selected=existing;
                    else{
                        await WaitGate(sharedSettings,request.OperationId,token);
                        try{
                        if(networks.Count>=MaximumNetworks)throw new IOException("最多保留 16 条网络配置，请先移除不用的配置");
                        if(networks.Values.Count(n=>n.Worker.ProfileSnapshot() is {Enabled:true,Mesh:not null})>=8)throw new IOException("本机最多同时运行 8 条双机网络，请先暂停一条连接");
                        string name=request.Network!.Name.Trim();if(name.Length==0)name="连接 "+(networks.Count+1);ValidateName(name);
                        string id=Guid.NewGuid().ToString("N"),folder=Path.Combine(Folder,id);
                        bool automatic=request.Network.AutoConfigure;
                        if(automatic&&request.Network.Action is not ("join" or "join-direct-short" or "join-entry" or "join-invitation" or "join-compact"))throw new FormatException("自动获取设置仅用于申请加入网络");
                        var configurationId=request.Network.ConfigurationId;
                        if(!automatic&&configurationId.Length==0&&configurations.Count==1)configurationId=configurations.Keys.Single();
                        ConnectionConfiguration? configuration=null;
                        if(!automatic&&!configurations.TryGetValue(configurationId,out configuration))throw new IOException("请先选择或保存本次连接配置");
                        var template=device.ProfileSnapshot();
                        var settings=automatic?AutoJoinSettings(request.Network,template):configuration!.Settings;
                        if(automatic&&request.Network.Action is ("join-invitation" or "join-compact"))request=request with{Network=request.Network with{Mode=TransportModes.Mode(settings.PathSelection)}};
                        ConnectionSettings.Apply(template,settings);
                        template.AutoConfigureJoin=automatic;template.ReceivedNetworkSettings=null;template.PkarrSeed="";template.PkarrSequence=0;
                        template.PkarrPeers=[];template.PkarrStateVersion=0;
                        if(request.Network.RequestedVirtualIp.Length>0){MeshAddressing.ValidateAddress(request.Network.RequestedVirtualIp);template.RequestedVirtualIp=request.Network.RequestedVirtualIp;template.SavedNetworkSettings=template.SavedNetworkSettings! with{RequestedVirtualIp=template.RequestedVirtualIp};}
                        template.Mesh=null;template.Pair=null;template.Enabled=false;template.PendingMembership=null;template.RejoinCredential=null;template.RejoinHistory=[];
                        template.AdapterScope=id;
                        template.NetworkCreatedHere=false;template.NetworkEstablishedAt=0;template.JoinedEntryNetwork="";template.JoinedEntrySources=[];
                        template.Coordinator=new();
                        if(request.Network.Action is "create-direct" or "join-entry" or "join-invitation" or "join-compact" or "join-direct-short" or "join-direct"){
                            if(!settings.DirectMode)throw new IOException("此操作需要使用无协调的已有入口配置，请先选择并保存对应配置");
                        }
                        // A published address may be a fixed NAT mapping or an
                        // opaque subscription. Never silently move its receiver.
                        // Only the private outgoing source port may be allocated.
                        var used=networks.Values.Select(n=>n.Worker.ProfileSnapshot()).ToArray();
                        if(automatic)while(used.Any(p=>p.SourcePort==template.ListenPort||p.ListenPort==template.ListenPort&&!CanShareListener(p,template))){
                            if(template.ListenPort>=65533)throw new IOException("没有可用的本机接收端口");template.ListenPort+=2;
                        }
                        if(used.Any(p=>p.SourcePort==template.ListenPort||p.ListenPort==template.ListenPort&&!CanShareListener(p,template)))
                            throw new IOException($"接收端口 {template.ListenPort} 与另一条已保存的网络配置冲突；请先在连接配置中为新网络选择独立接收端口，并核对已有入口的映射或订阅。现有端口和入口未更改");
                        while(used.Any(p=>p.ListenPort==template.SourcePort||p.SourcePort==template.SourcePort)){
                            if(template.SourcePort>65500)throw new IOException("没有空闲的网络源端口，请调整连接配置的源端口");
                            template.SourcePort+=2;
                        }
                        if(template.SavedNetworkSettings is {} saved)template.SavedNetworkSettings=saved with{ListenPort=template.ListenPort,SourcePort=template.SourcePort,Coordinator=new()};
                        var networkStore=new ProfileStore(folder,store);
                        // An unfinished reservation is never loaded as an active
                        // network after a crash between its configuration writes.
                        var reservation=new Information(id,name,Removed:true,CreationOperation:request.OperationId,ConfigurationId:configuration?.Id??"",AppliedConfigurationRevision:configuration?.Revision??0);
                        string marker=Path.Combine(folder,"network-info.json");
                        if(OperatingSystem.IsLinux())LinuxPlatform.PrivateWrite(marker,JsonSerializer.SerializeToUtf8Bytes(reservation));else File.WriteAllBytes(marker,JsonSerializer.SerializeToUtf8Bytes(reservation));
                        networkStore.Save(template);
                        bool pending=request.Network.Action is not ("create" or "create-direct");
                        var context=Open(new(id,name,CreationOperation:request.OperationId,PendingEnrollment:pending,ConfigurationId:configuration?.Id??"",AppliedConfigurationRevision:configuration?.Revision??0),folder);
                        try{WriteInfo(context);if(!networks.TryAdd(id,context))throw new IOException("网络配置创建冲突");}
                        catch{context.Worker.Dispose();throw;}
                        selected=id;if(request.OperationId!=Guid.Empty)operationNetworks[request.OperationId]=id;
                        if(controlOperations.TryGetValue(request.OperationId,out var tracked))tracked.Selected=id;
                        if(started)context.Worker.StartLocal();
                        }finally{sharedSettings.Release();}
                    }
                }finally{creating.Release();}
            }
            if(request.Method=="status"){
                if(selected.Length>0&&!networks.TryGetValue(selected,out _)){
                    var tracked=controlOperations.GetValueOrDefault(request.OperationId);
                    return new(true,"",Snapshot(),Operation:tracked?.State);
                }
                var worker=selected.Length>0&&networks.TryGetValue(selected,out var selectedContext)?selectedContext.Worker:device;
                var status=await worker.HandleSingleUi(request with{NetworkId=""},sid,token);
                if(request.OperationId!=Guid.Empty&&settingOperations.TryGetValue(request.OperationId,out var settingOperation)){
                    var current=settingOperation.State;return status with{Ok=!current.Completed||current.Error.Length==0,Error=current.Error,Operation=current,Status=Snapshot(selected) with{Operation=current}};
                }
                if(status.Operation==null&&controlOperations.TryGetValue(request.OperationId,out var pending))return status with{Operation=pending.State,Status=Snapshot(selected) with{Operation=pending.State}};
                if(status.Operation is {Completed:true} terminal&&controlOperations.TryGetValue(request.OperationId,out var completedOperation)){
                    completedOperation.State=terminal;completedOperation.Selected=selected;completedOperation.Result=status with{Status=null};
                }
                return status with{Status=Snapshot(selected)};
            }
            if(selected.Length==0){
                if(request.Method is "start" or "stop" or "retry" or "quality"||request.Network?.Action is "forget-network" or "delete-network" or "invite" or "invite-code" or "invite-direct" or "invite-compact" or "refresh-pkarr" or "approve" or "reject")
                    throw new IOException("请先选择要操作的网络");
                bool saving=request.Method=="patch"||request.Network?.Action=="settings";
                if(saving)await WaitGate(sharedSettings,request.OperationId,token);
                try{
                    ActiveOperation(request.OperationId,delegated:true);
                    var result=await device.HandleSingleUi(request with{NetworkId=""},sid,token);
                    if(result.Ok&&saving)foreach(var context in networks.Values)context.Worker.RefreshSharedSettings();
                    return result with{Status=Snapshot()};
                }finally{if(saving)sharedSettings.Release();}
            }
            if(!networks.TryGetValue(selected,out var target))throw new IOException("此网络配置已被移除");
            if(request.Method=="cancel"){
                var canceled=await target.Worker.HandleSingleUi(request with{NetworkId=""},sid,token);return canceled with{Status=Snapshot(selected)};
            }
            await WaitGate(target.Actions,request.OperationId,token);
            try{
            if(!networks.TryGetValue(selected,out var live)||!ReferenceEquals(live,target))throw new IOException("此网络配置已被移除");
            ActiveOperation(request.OperationId);
            if(request.Network?.Action=="settings"){if(target.Info.ConfigurationId.Length>0)throw new IOException("此网络使用已保存配置，请在设置中编辑该配置；保存会更新全部关联网络");return await SaveSettings(target,request,sid,token);}
            if(request.Network?.Action is "rename-network" or "remove-network"){
                if(request.Network.ExpectedNetwork!=target.Worker.SingleUiSnapshot().NetworkId)throw new IOException("网络身份已变化，请刷新后重试");
                if(request.Network.Action=="rename-network"){
                    ValidateName(request.Network.Name);var previous=target.Info;target.Info=previous with{Name=request.Network.Name};try{WriteInfo(target);target.Worker.NetworkDisplayName=target.Info.Name;}catch{target.Info=previous;throw;}
                }else{
                    if(!request.Network.ConfirmReplace)throw new IOException("移除配置需要明确确认");
                    await target.Worker.StopLocal(token);target.Info=target.Info with{Removed=true};WriteInfo(target);
                    networks.TryRemove(selected,out _);configurationErrors.TryRemove(selected,out _);if(target.Info.ConfigurationId.Length>0)retiredConfigurations[target.Info.ConfigurationId]=0;target.Worker.Dispose();selected="";
                }
                return new(true,"",Snapshot(selected),Operation:new(request.OperationId,request.Network.Action,"已完成",true,false));
            }
            if(request.OperationId!=Guid.Empty){
                if(operationNetworks.Count>256)foreach(var route in operationNetworks.ToArray()){
                    if(settingOperations.TryGetValue(route.Key,out var saving)&&!saving.State.Completed)continue;
                    if(networks.TryGetValue(route.Value,out var context)&&context.Info.CreationOperation!=route.Key&&context.Worker.IsOperationComplete(route.Key))operationNetworks.TryRemove(route.Key,out _);
                }
                if(operationNetworks.Count>1024)throw new IOException("本机操作记录已满，请等待当前操作完成后重试");
                operationNetworks[request.OperationId]=selected;
            }
            var handling=target.Worker.HandleSingleUi(request with{NetworkId=""},sid,token);ActiveOperation(request.OperationId,delegated:true);
            var reply=await handling;
            if(target.Info.PendingEnrollment&&target.Worker.ProfileSnapshot() is {Mesh:not null} completedProfile){
                string inheritedName=completedProfile.AutoConfigureJoin?completedProfile.ReceivedNetworkSettings?.NetworkName??"":"";
                if(inheritedName.Length>0)ValidateName(inheritedName);
                target.Info=target.Info with{PendingEnrollment=false,Name=inheritedName.Length>0?inheritedName:target.Info.Name};
                target.Worker.NetworkDisplayName=target.Info.Name;WriteInfo(target);
            }
            if((enrollment&&!reply.Ok||request.Network?.Action is "forget-network" or "delete-network" or "leave"||request.Network?.Action=="pair-cancel"&&target.Worker.ProfileSnapshot().RejoinCredential==null)&&target.Worker.SingleUiSnapshot() is {NetworkId:"",Pairing:null or {Active:false}}){
                await target.Worker.StopLocal(token);target.Info=target.Info with{Removed=true};WriteInfo(target);
                networks.TryRemove(selected,out _);configurationErrors.TryRemove(selected,out _);if(target.Info.ConfigurationId.Length>0)retiredConfigurations[target.Info.ConfigurationId]=0;target.Worker.Dispose();selected="";
            }
            return reply with{Status=Snapshot(selected)};
            }finally{target.Actions.Release();}
        }catch(Exception ex)when(ex is IOException or FormatException or UnauthorizedAccessException or OperationCanceledException){
            string message=ex is OperationCanceledException?"操作已取消，请查看当前状态":ex.Message;
            return new(false,message,Snapshot(selected??""),Operation:new(request.OperationId,request.Network?.Action??request.Method,"未完成",true,false,message));
        }
    }
}
