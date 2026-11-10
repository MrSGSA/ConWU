using Microsoft.Extensions.Hosting;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker : BackgroundService
{
    readonly ProfileStore store;
    readonly bool networkContext;
    PairNetworkWorkspace? workspace;
    bool automaticCoordinator;
    readonly object sync = new();
    readonly Queue<string> logs = new();
    DeviceProfile profile;
    SessionStatus? status;
    CancellationTokenSource? runStop;
    Task? running, measuring;
    NetworkRunner? runner;
    MeshRunner? meshRunner;
    DeviceProfile? runningProfile;
    CancellationTokenSource? measureStop;
    ControlReply? snapshot;
    string quality = "";
    QualityResult? lastQuality;
    UiStageLedger? stageLedger;
    bool initialized;
    bool applicationStopping;
    bool stoppingNetwork;
    bool resourceShutdownUnproven;
    TaskCompletionSource? retryWake;
    long lastManualRetry;
    readonly SemaphoreSlim requests = new(1, 1);
    readonly FileStream lease;
    readonly MeshRuntimeServices? meshRuntime;
    internal ControlWorker(MeshRuntimeServices services):this(new ProfileStore(),services) { }
    public ControlWorker():this(new ProfileStore()){}
    public ControlWorker(bool pairNetworks):this(new ProfileStore(),enableWorkspace:pairNetworks){}
    internal ControlWorker(ProfileStore profileStore,MeshRuntimeServices? services=null,bool isolatedNetwork=false,bool enableWorkspace=false)
    {
        store=profileStore;meshRuntime=services;networkContext=isolatedNetwork;
        pkarrCheckpoints=new(()=>new(()=>store.ReadPrivate<PkarrCheckpoint[]>("pkarr-checkpoints.protected")??[],value=>store.WritePrivate("pkarr-checkpoints.protected",value)));
        uiEntryResolver=new(()=>new(CreatePkarrClient));
        lease = new FileStream(Path.Combine(store.DirectoryPath, "runtime.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try {
            if(enableWorkspace&&store.LoadForMaintenance() is { } old&&(old.Mesh!=null||old.Pair!=null))throw new IOException("旧版网络配置与双机多网络不兼容，请使用全新安装流程重新设置；配置尚未迁移");
            if(OperatingSystem.IsLinux()&&!networkContext)LinuxFirewall.Recover();
            profile = store.Load();
            bool changed=false;
            var platformAdapter=OperatingSystem.IsLinux()?PacketAdapterBackend.LinuxTun:PacketAdapterBackend.OfficialWintun;
            if (profile.AdapterBackend != platformAdapter) {
                store.BackupResearchProfile();
                profile.AdapterBackend = platformAdapter;
                profile.Enabled = false;
                profile.MigrationNotice = OperatingSystem.IsLinux()?"网卡配置已在本机备份并迁移到 Linux TUN；网络保持停止，请核对后连接。":"原自研网卡配置已在本机备份并迁移到官方 Wintun；网络保持停止，请核对后连接。";
                changed=true;
            }
            if(profile.SavedNetworkSettings==null){
                var existingSettings=LegacyPublicSettings(profile);
                profile.SavedNetworkSettings=existingSettings with {
                    ExistingEntries=SavedEntries(existingSettings.ExistingEntries,profile.Mesh!=null&&profile.Mesh.IntroducerSlot!=profile.Mesh.Self.Slot,profile.Mesh?.IntroducerSlot??1)
                };
                profile.SavedPeerEntryNetwork=profile.Mesh?.Pair.Network??"";
                changed=true;
            }
            if(changed)store.Save(profile);
            PublishReply();
            if(enableWorkspace)EnablePairNetworks();
        } catch { lease.Dispose(); throw; }
    }
    public void EnablePairNetworks()
    {
        if(initialized||workspace!=null)throw new InvalidOperationException("多网络模式只能在启动前配置");
        if(profile.Mesh!=null||profile.Pair!=null)throw new IOException("旧版网络配置需要全新安装，不能自动改变管理权限");
        PairSettingsTransaction.Recover(store);PairBatchSettingsTransaction.Recover(store);profile=store.Load();PublishReply();
        if(profile.NodeSigningPrivate.Length==0){profile.NodeSigningPrivate=NodeIdentityProof.GeneratePrivate();profile.Device=MeshIdentity.NetworkId(MeshIdentity.PublicSigning(profile.NodeSigningPrivate));store.Save(profile);PublishReply();}
        workspace=new(this,store,meshRuntime);
        // Injected transport fixtures own their listener explicitly. The
        // installed device host provisions its independent coordinator once.
        automaticCoordinator=meshRuntime==null;
    }
    internal DeviceProfile ProfileSnapshot()=>ProfileChanges.Copy(Volatile.Read(ref snapshot)!.Profile!);
    internal bool IsOperationComplete(Guid id)=>OperationState(id)?.Completed!=false;
    internal bool HasOutstandingOwnership{get{lock(operationGate)return Volatile.Read(ref resourceShutdownUnproven)||running?.IsCompleted==false||measuring?.IsCompleted==false||acceptingEntries?.IsCompleted==false||publishingPkarr?.IsCompleted==false||operations.Values.Any(o=>!o.Completed);}}
    internal void BeginApplicationStop()=>Volatile.Write(ref applicationStopping,true);
    internal async Task RestoreSettings(DeviceProfile before,CancellationToken token)
    {
        await requests.WaitAsync(token);
        try{
            DeviceProfile restored;bool restart;
            lock(sync){restored=PairSettingsTransaction.SettingsOnly(profile,before);restart=ProfileChanges.Impact(profile,restored)==ProfileChangeImpact.RestartNetwork;}
            if(restart)await End(token);
            // Shutdown may await resources while discovery independently commits
            // a newer identity, binding or sequence. Merge again at the write.
            lock(sync){restored=PairSettingsTransaction.SettingsOnly(profile,before);store.Save(restored);profile=restored;PublishReply();}
            if(restart&&restored.Enabled&&!Volatile.Read(ref applicationStopping))Begin();else meshRunner?.UpdateEntries(restored);
        }finally{requests.Release();}
    }
    internal void RefreshSharedSettings()
    {
        lock(sync){var shared=store.Load();profile.DeviceName=shared.DeviceName;profile.LogLevel=shared.LogLevel;
            profile.Ddns=shared.Ddns;profile.CloudflareDdnsToken=shared.CloudflareDdnsToken;
            meshRunner?.UpdateEntries(profile);PublishReply();}
    }
    void Log(string text)
    {
        lock (sync)
        {
            text=SensitiveText.Redact(text,profile);
            bool error=text.Contains("失败")||text.Contains("异常");
            bool warning=text.Contains("未完成")||text.Contains("不可用")||text.Contains("重试")||text.Contains("拒绝");
            bool debug=text.StartsWith("ShutdownStage=")||text.StartsWith("CandidateFactoryReady")||text.StartsWith("TraversalReady")||text.StartsWith("RouterPressure")||text.StartsWith("WintunLifecycle");
            string level=error?"ERROR":warning?"WARN":debug?"DEBUG":"INFO";
            if(profile.LogLevel=="off" || profile.LogLevel=="error"&&!error || profile.LogLevel=="warn"&&!error&&!warning || profile.LogLevel!="debug"&&debug&&!error&&!warning)return;
            string line = $"{DateTime.Now:HH:mm:ss} [{level}] {text}"; logs.Enqueue(line); while (logs.Count > 80) logs.Dequeue();
            PublishReply();
            {
                try {
                    string folder = profile.LogDirectory.Length > 0 ? profile.LogDirectory : Path.Combine(store.DirectoryPath, "logs");
                    Directory.CreateDirectory(folder);
                    if ((File.GetAttributes(folder) & FileAttributes.ReparsePoint) != 0) throw new IOException("日志目录不能是链接");
                    string path = Path.Combine(folder, "streamlink.log");
                    if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("日志文件不能是链接");
                    if (File.Exists(path) && new FileInfo(path).Length > 2_000_000) File.Move(path, path + ".previous", true);
                    File.AppendAllText(path, line + Environment.NewLine);
                } catch (Exception ex) { if (logs.Count < 80) logs.Enqueue("日志写入失败：" + ex.Message); }
            }
        }
    }
    void Begin()
    {
        if(Volatile.Read(ref applicationStopping))throw new OperationCanceledException("后台正在停止");
        RequireResourceOwnership();
        if (running != null && !running.IsCompleted) return;
        Volatile.Write(ref stoppingNetwork,false);
        if (profile.Mesh == null && profile.Pair != null && !File.Exists(Path.Combine(AppContext.BaseDirectory, "components", "easytier-core.exe"))) {
            lock (sync) status = new("旧网络需要迁移", "", "", profile.Pair.Mode, false, null, "此轻量包仅包含原生组网。原配对已保留；请在双方新版上创建并加入多机网络，或使用旧版恢复连接。");
            return;
        }
        runStop?.Dispose(); runStop = new();
        var copy = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(profile))!;
        runningProfile=copy;
        var token = runStop.Token;
        running = Task.Run(async () => {
            int attempt=0;
            while (!token.IsCancellationRequested)
            {
                TaskCompletionSource wake;
                lock(sync){
                    if(token.IsCancellationRequested||Volatile.Read(ref stoppingNetwork))break;
                    retryWake=wake=new(TaskCreationOptions.RunContinuationsAsynchronously);
                    status=new(attempt++==0?"正在启动":"正在恢复网络",copy.Mesh?.LocalIp??"","","faketcp",false,null,"正在启动连接组件") {
                        Connection=new("StartingAdapter","正在准备网卡、入口与设备发现。",Attempt:attempt) };
                    PublishReply();
                }
                if (copy.Mesh != null) meshRunner = new(copy, Log, ReportRuntimeStatus, directory => { lock (sync) { if (profile.Mesh != null && directory.Network==profile.Mesh.Pair.Network && directory.OwnerKey==profile.Mesh.OwnerKey && directory.Revision > (profile.Mesh.Directory?.Revision ?? 0)) { var remembered=ProfileChanges.Copy(profile);if(remembered.Mesh!.Directory is {} priorDirectory)MeshIdentity.ValidateSuccessor(directory,priorDirectory);remembered.Mesh.Directory=directory;remembered.RejoinHistory=remembered.RejoinHistory.Where(h=>directory.Members.Any(m=>m.Slot==h.CurrentSlot)).ToArray();if(remembered.Mesh.IsDecentralized)remembered.ExistingEntries=RuntimeEntries(remembered);store.Save(remembered);profile=remembered;if(remembered.Mesh.IsDecentralized)meshRunner?.UpdateEntries(remembered);PublishReply();} } }, stun => { lock (sync) { profile.LastStun = stun; store.Save(profile); PublishReply();} },(meshRuntime??MeshRuntimeServices.Default) with{PkarrClientFactory=CreatePkarrClient}){DirectPairing=HandleDirectPairing,PkarrCheckpoints=pkarrCheckpoints.Value,RememberPkarrPeer=RememberPkarrPeer};
                else runner = new(copy, Log, ReportRuntimeStatus, (entry, stun) => { lock (sync) { profile.LastEntry = entry; profile.LastStun = stun; store.Save(profile); PublishReply();} });
                try { if (meshRunner != null) await meshRunner.Run(token); else await runner!.Run(token); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
                catch (MeshRevokedException ex) {
                    lock (sync) {
                        // Retry persistence with the disabled state if the
                        // runner's first save failed. Never save an old table
                        // over the verified revocation retained by the runner.
                        if (profile.Mesh is {} current && copy.Mesh?.Directory is {} revoked &&
                            revoked.Network == current.Pair.Network && revoked.OwnerKey == current.OwnerKey &&
                            revoked.Revision > (current.Directory?.Revision ?? 0)) current.Directory = revoked;
                        profile.Enabled = false; store.Save(profile);
                        status = new(profile.Mesh?.Directory?.Closed==true?"网络已解散":"已移出网络", "", "", "faketcp", false, null, ex.Message);
                    }
                    Log(ex.Message); break;
                }
                catch (MeshShutdownException ex) { Volatile.Write(ref resourceShutdownUnproven,true);lock(sync){status=new("资源退出未完成","","","faketcp",false,null,ex.Message);PublishReply();}Log(ex.Message);break; }
                catch (Exception ex) {
                    lock(sync){status=new("连接中断，等待重试",copy.Mesh?.LocalIp??"","","faketcp",false,null,ex.Message) {
                        Connection=new("Retrying","连接组件异常："+ex.Message,Attempt:attempt,RetryInSeconds:10,CanRetry:true) };PublishReply();}
                    Log("后台连接将重试：" + ex.Message);
                }
                long retryAt=Environment.TickCount64+10000;
                try {
                    while(!wake.Task.IsCompleted && Environment.TickCount64<retryAt) {
                        lock(sync){if(status?.Connection is {} progress)status=status with {Connection=progress with {RetryInSeconds=(int)Math.Max(0,(retryAt-Environment.TickCount64+999)/1000)}};PublishReply();}
                        await Task.WhenAny(Task.Delay(1000,token),wake.Task);token.ThrowIfCancellationRequested();
                    }
                } catch (OperationCanceledException) { break; }
            }
        });
    }
    void ReportRuntimeStatus(SessionStatus next){lock(sync){
        if(Volatile.Read(ref stoppingNetwork))return;
        var active=next.Peers?.Where(p=>p.Connected).Select(p=>p.Slot).ToHashSet()??[];
        foreach(var slot in connectedSince.Keys)if(!active.Contains(slot))connectedSince.TryRemove(slot,out _);
        foreach(var slot in active)connectedSince.TryAdd(slot,DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        status=next;PublishReply();
    }}
    async Task End(CancellationToken token = default,Action<string>? progress=null)
    {
        Volatile.Write(ref stoppingNetwork,true);
        if(running?.IsCompleted==false){
            const string detail="正在停止本机网络并回收资源，后台服务仍在运行。";
            lock(sync){if(status is {} current){status=current with{State="正在停止网络",Connected=false,Connection=new("Releasing",detail),Peers=current.Peers?.Select(p=>p with{Connected=false,Connection=new("Releasing",detail)}).ToArray()};PublishReply();}}
        }
        if(uiPairClient is DirectPairHost)ResetUiPair("连接已停止，请重新生成配对码");
        uiDirectHost.Clear();
        ClearEntryAdmission();
        runStop?.Cancel();measureStop?.Cancel();
        Task[] ending=new[]{running,measuring}.Where(t=>t!=null).Cast<Task>().ToArray();
        var completion=Task.WhenAll(ending.Select(ObserveShutdown));
        var clock=System.Diagnostics.Stopwatch.StartNew();
        try {
            while(!completion.IsCompleted){
                var remaining=TimeSpan.FromSeconds(60)-clock.Elapsed;
                if(remaining<=TimeSpan.Zero)throw new TimeoutException();
                try {await completion.WaitAsync(remaining<TimeSpan.FromSeconds(5)?remaining:TimeSpan.FromSeconds(5),token);}
                catch(TimeoutException)when(!completion.IsCompleted&&clock.Elapsed<TimeSpan.FromSeconds(60)){
                    string detail=$"正在等待旧网络安全退出（{(int)clock.Elapsed.TotalSeconds} 秒）"+(progress!=null?"，完成后自动应用设置":"");
                    progress?.Invoke(detail);
                    Log(detail+"；退出阶段："+JsonSerializer.Serialize(meshRunner?.ExitDiagnostics));
                }
            }
            await completion;
        }
        catch(TimeoutException)when(!completion.IsCompleted) {
            string resource=running?.IsCompleted==false?"网络 worker/捕获/租约":"测速";
            lock(sync){status=new("停止未完成","","","faketcp",false,null,$"{resource} 尚未退出；所有权仍保留，拒绝启动第二实例");PublishReply();}
            throw new IOException(resource+" 退出超过60秒；已保留资源所有权，请查看退出阶段日志"+(progress!=null?"。设置尚未应用":""));
        }
        RequireResourceOwnership(); // completed task is not proof that its owners closed
        running = null; runner = null; meshRunner = null;runningProfile=null;
        measureStop?.Dispose();measureStop=null;measuring=null;
        lock (sync) { connectedSince.Clear();quality = ""; lastQuality=null; status = new("已停止", "", "", "faketcp", false, null, "后台网络已停止，配对仍保留"); PublishReply();}
    }
    static async Task ObserveShutdown(Task task){try{await task;}catch(OperationCanceledException){} }
    void RequireResourceOwnership(){
        if(!Volatile.Read(ref resourceShutdownUnproven))return;
        const string reason="上次原生资源退出未获证实，不能释放所有权或启动第二后台；请保留日志并重启个人后台进程，原 0.3.2 不受影响";
        lock(sync){status=new("资源退出未完成","","","faketcp",false,null,reason);PublishReply();}
        throw new IOException(reason);
    }
    void PublishReply()
    {
        lock(sync) Volatile.Write(ref stageLedger,new(status?.AdapterStatistics,status?.Egress,
            status?.LegacyTransports?.Resources.Take(15).Select(x=>new UiLegacyStage(x.ResourceId,x.ProcessId,x.Mode,x.Listener,x.Target,x.BusinessHandoff,x.BusinessEgress,x.Route?.Witnesses.Take(2).ToArray()??[])).ToArray()??[]) { RouterPressure=status?.RouterPressure });
        lock (sync) Volatile.Write(ref snapshot,new(true, "", ProfileChanges.Copy(profile), DisplayStatus(status), profile.Slot == 1 ? profile.Pair?.Invite() ?? "" : "", logs.ToArray(), quality, typeof(ControlWorker).Assembly.GetName().Version!.ToString(3), 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1,1,1,Volatile.Read(ref operationStatus),1,2,1,initialized,1));
    }
    ControlReply Reply(string error = "") {var current=Volatile.Read(ref snapshot)!;return current with{Ok=error.Length==0,Error=SensitiveText.Redact(error,current.Profile!),Profile=ProfileChanges.Copy(current.Profile!),Logs=(string[])current.Logs.Clone()};}
    // Full per-window evidence stays in the runner; the legacy pipe remains
    // 64KiB. This display copy cannot change evidence used for selection.
    static SessionStatus? DisplayStatus(SessionStatus? source) => source == null ? null : source with {
        TcpHelpers = source.TcpHelpers is {} tcp ? tcp with { Resources = [] } : null,
        LegacyTransports = source.LegacyTransports is {} legacy ? legacy with { Resources = [] } : null,
        Peers = source.Peers?.Select(p => p with {
            Diagnostics = p.Diagnostics is {} d ? d with { Windows = [] } : null,
            Traffic = null, Delivery = null, SendQueue = null
        }).ToArray()
    };
    public Task<ControlReply> Handle(ControlRequest request,CancellationToken token=default)
        => workspace!=null&&request.Command!="status"?Task.FromResult(Reply("多网络操作请使用 WebUI 或 conwu network 命令并指定网络")):HandleCore(request,token,null);

    // UI requests carry their original patch until AFTER the shared mutation gate.
    async Task<ControlReply> HandleCore(ControlRequest request,CancellationToken token,UiOperation? ui)
    {
        if(request.Command=="status")return Reply();
        if(request.Command=="cancel")return CancelOperation(request.CancelOperationId);
        Operation operation;bool duplicate;
        try{operation=OpenOperation(request,token,out duplicate,ui);}
        catch(Exception ex){return Reply(OperationError(ex));}
        if(duplicate)return Reply(operation.State.Completed?operation.State.Error:"") with{Operation=operation.State};
        bool acquired=false,background=false;
        try
        {
            await requests.WaitAsync(operation.Stop.Token);acquired=true;
            operation.Stop.Token.ThrowIfCancellationRequested();
            if(ui!=null && store.AuthorizedUiUser()!=ui.CallerSid)
                throw new IOException("该本机用户的UI控制授权已改变");
            SetOperation(operation,"执行中",true);
            if(profile.PendingMembership!=null && request.Command is not ("membership-resume" or "ui-network" or "ui-patch" or "stop" or "start" or "retry" or "personal-check"))throw new IOException("请先在 WebUI 继续确认待处理的网络变更");
            string issued = "";
            switch (request.Command)
            {
                case "status": break;
                case "membership-resume":await ResumeMembership(operation);break;
                case "ui-network":
                    if(ui?.Network==null)throw new FormatException("网络操作需要已认证的UI请求");
                    await ApplyUiNetwork(ui.Network,operation);
                    break;
                case "mesh-create":
                case "mesh-join":
                    var mesh = request.Command == "mesh-create" ? MeshIdentity.Create(request.Service, request.Pin, request.Mode) : MeshIdentity.Import(request.Invite);
                    SetOperation(operation,"停止旧网络",false);await End(operation.Stop.Token); lock (sync) { store.BackupLegacy(profile); profile.Enabled = false; profile.Pair = null; profile.Mesh = mesh; profile.RejoinHistory=[];profile.Slot = 1; profile.LastEntry = 0;
                        profile.SelectTransport(mesh.Pair.Mode=="udp"?"udp-only":"faketcp-only");
                        if(PersonalFeature.Enabled)profile=PersonalFeature.EnhancedPreset(profile);
                        store.Save(profile); } break;
                case "personal-preset":
                    if(running?.IsCompleted==false)throw new IOException("请先停止个人实例再应用增强预设；已有健康连接未重建");
                    var enhanced=PersonalFeature.EnhancedPreset(profile);
                    lock(sync){store.Save(enhanced);profile=enhanced;}break;
                case "personal-check":
                    if(!PersonalFeature.Enabled)throw new IOException("新方法验证需要个人功能包");
                    if(profile.Mesh is not {} configured)throw new IOException("请先创建或加入个人多机网络，再检查新方法与协调服务的准备状态");
                    profile.Validate();await PersonalPacketAdapters.Preflight(profile,operation.Stop.Token);
                    await MeshCoordinatorPreflight.Check(configured.Pair,operation.Stop.Token);
                    Log("个人新方法准备检查通过："+profile.TraversalMode+"；实际打洞、资格和承载状态在连接后报告，不以开关宣称成功");break;
                case "mesh-invite":
                    if(profile.Mesh?.IsDecentralized==true)throw new IOException("成员平等网络请通过 WebUI 生成配对码并审批");
                    lock (sync) {
                        var network = profile.Mesh ?? throw new IOException("请先创建多机网络");
                        issued = MeshIdentity.Export(MeshIdentity.Issue(network)); store.Save(profile);
                        meshRunner?.UpdateDirectory(network.Directory!);
                    } break;
                case "mesh-revoke":
                    if(profile.Mesh?.IsDecentralized==true){await ApplyUiNetwork(new("revoke",ExpectedNetwork:profile.Mesh.Pair.Network,PeerSlot:request.PeerSlot),operation);break;}
                    lock (sync) {
                        var network = profile.Mesh ?? throw new IOException("请先创建多机网络");
                        MeshIdentity.Revoke(network, request.PeerSlot);profile.RejoinHistory=profile.RejoinHistory.Where(h=>h.CurrentSlot!=request.PeerSlot).ToArray();store.Save(profile); meshRunner?.UpdateDirectory(network.Directory!);
                    } break;
                case "create":
                case "join":
                    var pair = request.Command == "create" ? Pairing.Create(request.Service, request.Pin, request.Mode) : Pairing.Import(request.Invite);
                    SetOperation(operation,"停止旧网络",false);await End(operation.Stop.Token); lock (sync) { profile.Enabled = false; profile.Pair = pair; profile.Mesh = null;profile.RejoinHistory=[];profile.Slot = request.Command == "create" ? 1 : 2; profile.LastEntry = 0; profile.SelectTransport(pair.Mode=="udp"?"udp-only":"faketcp-only"); store.Save(profile); } break;
                case "ui-patch":
                    if(ui?.Patch==null)throw new FormatException("此命令需要已认证的UI补丁");
                    lock(sync) {
                        // Background directory/STUN updates also use sync. Never
                        // reconstitute a stale whole profile outside this lock.
                        var patched=ui.Patch.ApplyTo(profile);
                        if(ui.Patch.RequestedVirtualIp!=null)patched.SavedNetworkSettings=PublicSettings(patched) with{RequestedVirtualIp=patched.RequestedVirtualIp};
                        store.Save(patched);profile=patched;
                        if(runningProfile is {} activeUi) {
                            activeUi.DeviceName=patched.DeviceName;
                            activeUi.LogLevel=patched.LogLevel;
                        }
                    }
                    break;
                case "save":
                    var updated = request.Profile ?? throw new FormatException("配置为空"); updated.Validate();
                    if(PersonalFeature.Enabled) updated.RequireFixedTransport();
                    if (updated.Device != profile.Device || updated.Pair != profile.Pair || updated.Slot != profile.Slot || JsonSerializer.Serialize(updated.Mesh) != JsonSerializer.Serialize(profile.Mesh)) throw new FormatException("不能通过设置修改配对身份");
                    bool resume = profile.Enabled;
                    updated=ProfileChanges.Copy(updated);
                    var userSettings=LegacyPublicSettings(updated);
                    updated.SavedNetworkSettings=userSettings with{ExistingEntries=SavedEntries(userSettings.ExistingEntries,updated.Mesh!=null&&updated.Mesh.IntroducerSlot!=updated.Mesh.Self.Slot,updated.Mesh?.IntroducerSlot??1)};
                    updated.SavedPeerEntryNetwork=updated.Mesh?.Pair.Network??"";
                    updated.Enabled=resume;updated.LastEntry=profile.LastEntry;updated.LastStun=profile.LastStun;
                    if(profile.AdditionalData!=null){updated.AdditionalData??=new();foreach(var extra in profile.AdditionalData)updated.AdditionalData.TryAdd(extra.Key,extra.Value.Clone());}
                    bool restart=ProfileChanges.Impact(profile,updated)==ProfileChangeImpact.RestartNetwork;
                    // Admission failure must precede End; never tear down a
                    // healthy official adapter to discover an unsigned backend.
                    if(updated.AdapterBackend!=profile.AdapterBackend)await PersonalPacketAdapters.Preflight(updated,operation.Stop.Token);
                    if(restart){SetOperation(operation,"重建受影响网络资源",false);await End(operation.Stop.Token,phase=>SetOperation(operation,phase,false));}
                    try {lock (sync) {PreserveLatestDirectory(updated);store.Save(updated);profile=updated; if(!restart&&runningProfile is {} active){active.DeviceName=updated.DeviceName;active.LogLevel=updated.LogLevel;active.LogDirectory=updated.LogDirectory;active.AllowManualQualityRequests=updated.AllowManualQualityRequests;active.EntryRefreshSeconds=updated.EntryRefreshSeconds;active.TcpStun=updated.TcpStun.ToArray();active.UdpStun=updated.UdpStun.ToArray();active.ConnectionSource=updated.ConnectionSource;active.ManualEndpoint=updated.ManualEndpoint;active.ExistingEntries=updated.ExistingEntries.ToArray();}}}
                    catch{if(restart&&resume)Begin();throw;}
                    if(!restart)meshRunner?.UpdateEntries(updated);
                    if(restart&&resume)Begin();break;
                case "start":
                    RequireResourceOwnership();
                    if(running?.IsCompleted==false&&runStop?.IsCancellationRequested==true)throw new IOException("先前网络正在退出，不能启动第二实例");
                    await PersonalPacketAdapters.Preflight(profile,operation.Stop.Token);
                    lock (sync) { if (profile.Pair == null && profile.Mesh == null) throw new IOException("请先创建或加入网络"); profile.Enabled = true; profile.Validate(); store.Save(profile); } Begin(); break;
                case "stop":
                    SetOperation(operation,"停止网络",false);lock (sync) { profile.Enabled = false; store.Save(profile); } await End(operation.Stop.Token); break;
                case "retry":
                    RequireResourceOwnership();
                    if(!profile.Enabled || running?.IsCompleted != false || runStop?.IsCancellationRequested == true)
                        throw new IOException("网络未运行，请先连接网络");
                    long retryNow=Environment.TickCount64;
                    if(lastManualRetry!=0 && retryNow-lastManualRetry<10000)throw new IOException("已请求重新探测，请稍候 10 秒再试");
                    lastManualRetry=retryNow;
                    Interlocked.Exchange(ref pkarrRefreshRequested,1);
                    meshRunner?.RequestRetry();lock(sync)retryWake?.TrySetResult();
                    Log("用户请求重新探测；健康直连与虚拟网卡保持运行");break;
                case "quality":
                    if (status?.Connected != true || runner == null && meshRunner == null) throw new IOException("请先连接对端");
                    if (request.Mbps is < 1 or > 60) throw new FormatException("测试速率需为 1–60 Mbps");
                    if (measuring != null && !measuring.IsCompleted) throw new IOException("已有质量测试在运行");
                    quality = "正在测试，20 秒后显示结果";
                    Volatile.Write(ref lastQuality,null);
                    measureStop?.Dispose();measureStop=CancellationTokenSource.CreateLinkedTokenSource(runStop!.Token,operation.Stop.Token);
                    var current = runner; var currentMesh = meshRunner; var measurementToken = measureStop.Token;
                    background=true;SetOperation(operation,"测速中",true);
                    measuring = Task.Run(async () => { string error="";try { var r = currentMesh != null ? await currentMesh.Measure(request.Mbps, request.PeerSlot, measurementToken) : await current!.Measure(request.Mbps, measurementToken); Volatile.Write(ref lastQuality,r); lock (sync) quality = $"收到 {r.ReceivedMbps:F2} Mbps，丢包 {r.LossPercent:F3}%，{r.ReceivedPackets}/{r.SentPackets} 包"; } catch (Exception ex) { error=ex is OperationCanceledException?"操作已取消":ex.Message;lock (sync) quality = "测试未完成：" + error; } finally {CompleteOperation(operation,error);PublishReply();} }); break;
                default: throw new FormatException("未知控制命令");
            }
            if(!background)CompleteOperation(operation);PublishReply();return issued.Length > 0 ? Reply() with { Invite = issued,Operation=operation.State } : Reply() with {Operation=operation.State};
        }
        catch (Exception ex) { var error=operation.Superseded?"":OperationError(ex,operation);if(!operation.Superseded)Log("控制操作 "+operation.DisplayCommand+" 未完成："+error);CompleteOperation(operation,error);PublishReply();return Reply(error) with {Operation=operation.State}; }
        finally { if(acquired)requests.Release(); }
    }
    public void StartLocal()
    {
        Volatile.Write(ref applicationStopping,false);
        Recovery.Recover(Log, Path.Combine(store.DirectoryPath, "sessions"));
        if(!networkContext)StartCoordinator();else StartPkarr();
        Log("ConWU 已启动");
        if(workspace!=null)workspace.Start();
        else{if (profile.Enabled) Begin();StartEntryAdmission();}
        initialized=true;
        PublishReply();
    }
    public async Task StopLocal(CancellationToken token=default) { BeginApplicationStop();if(workspace!=null)await workspace.Stop(token);await StopEntryAdmission();await StopPkarr();await StopCoordinator();await End(token); runStop?.Dispose();runStop=null; }
    public override void Dispose() {BeginApplicationStop();if(workspace?.HasOutstandingOwnership==true)Volatile.Write(ref resourceShutdownUnproven,true);workspace?.Dispose();base.Dispose();DisposeControlResources();}
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StartLocal();
        if(OperatingSystem.IsLinux()){try{await RunLinuxControl(stoppingToken);}finally{await StopLocal();}return;}
        var uiServing=RunUiControl(stoppingToken);
        var recovering=profile.PendingMembership==null?Task.CompletedTask:Task.Run(async()=>{var recovered=await HandleCore(new("membership-resume"),stoppingToken,null);if(!recovered.Ok)Log("待确认网络变更需要继续确认："+recovered.Error);},CancellationToken.None);
        using var clientsLimit=new SemaphoreSlim(8,8);var clients=new List<Task>();bool first=true;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await clientsLimit.WaitAsync(stoppingToken);
                System.IO.Pipes.NamedPipeServerStream pipe;
                try{pipe=LocalControlPipe.Create(first);first=false;}
                catch{clientsLimit.Release();throw;}
                try{await pipe.WaitForConnectionAsync(stoppingToken);}
                catch{pipe.Dispose();clientsLimit.Release();throw;}
                clients.RemoveAll(t=>t.IsCompleted);clients.Add(ServeClient(pipe,clientsLimit,stoppingToken));
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally {try{await Task.WhenAll(clients.Append(uiServing).Append(recovering)).WaitAsync(TimeSpan.FromSeconds(21));}finally{await StopLocal();}}
    }
}
