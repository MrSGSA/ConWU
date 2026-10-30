using Microsoft.Extensions.Hosting;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker : BackgroundService
{
    readonly ProfileStore store = new();
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
    bool resourceShutdownUnproven;
    TaskCompletionSource? retryWake;
    long lastManualRetry;
    readonly SemaphoreSlim requests = new(1, 1);
    readonly FileStream lease;
    readonly MeshRuntimeServices? meshRuntime;
    internal ControlWorker(MeshRuntimeServices services):this() { meshRuntime=services; }
    public ControlWorker()
    {
        lease = new FileStream(Path.Combine(ProfileStore.Root, "runtime.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try {
            profile = store.Load();
            if (profile.AdapterBackend != PacketAdapterBackend.OfficialWintun) {
                store.BackupResearchProfile();
                profile.AdapterBackend = PacketAdapterBackend.OfficialWintun;
                profile.Enabled = false;
                profile.MigrationNotice = "原自研网卡配置已在本机备份并迁移到官方 Wintun；网络保持停止，请核对后连接。";
                store.Save(profile);
            }
            PublishReply();
        } catch { lease.Dispose(); throw; }
    }
    void Log(string text)
    {
        lock (sync)
        {
            text=SensitiveText.Redact(text,profile);
            string line = $"{DateTime.Now:HH:mm:ss} {text}"; logs.Enqueue(line); while (logs.Count > 80) logs.Dequeue();
            PublishReply();
            bool error = text.Contains("失败") || text.Contains("未完成") || text.Contains("不可用") || text.Contains("重试") || text.Contains("异常");
            if (profile.LogLevel != "off" && (profile.LogLevel != "error" || error)) {
                try {
                    string folder = profile.LogDirectory.Length > 0 ? profile.LogDirectory : Path.Combine(ProfileStore.Root, "logs");
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
        RequireResourceOwnership();
        if (running != null && !running.IsCompleted) return;
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
                    retryWake=wake=new(TaskCreationOptions.RunContinuationsAsynchronously);
                    status=new(attempt++==0?"正在启动":"正在恢复网络",copy.Mesh?.LocalIp??"","","faketcp",false,null,"正在启动连接组件") {
                        Connection=new("StartingAdapter","正在准备网卡、入口与设备发现。",Attempt:attempt) };
                    PublishReply();
                }
                if (copy.Mesh != null) meshRunner = new(copy, Log, s => { lock (sync) {status = s;PublishReply();} }, directory => { lock (sync) { if (profile.Mesh != null && directory.Revision > (profile.Mesh.Directory?.Revision ?? 0)) { profile.Mesh.Directory = directory; store.Save(profile); PublishReply();} } }, stun => { lock (sync) { profile.LastStun = stun; store.Save(profile); PublishReply();} },meshRuntime??MeshRuntimeServices.Default);
                else runner = new(copy, Log, s => { lock (sync) {status = s;PublishReply();} }, (entry, stun) => { lock (sync) { profile.LastEntry = entry; profile.LastStun = stun; store.Save(profile); PublishReply();} });
                try { if (meshRunner != null) await meshRunner.Run(token); else await runner!.Run(token); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
                catch (MeshRevokedException ex) { lock (sync) { profile.Enabled = false; store.Save(profile); status = new("已移出网络", "", "", "faketcp", false, null, ex.Message); } Log(ex.Message); break; }
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
    async Task End(CancellationToken token = default)
    {
        runStop?.Cancel();measureStop?.Cancel();
        Task[] ending=new[]{running,measuring}.Where(t=>t!=null).Cast<Task>().ToArray();
        try {await Task.WhenAll(ending.Select(ObserveShutdown)).WaitAsync(TimeSpan.FromSeconds(15),token);}
        catch(TimeoutException) {
            string resource=running?.IsCompleted==false?"网络 worker/捕获/租约":"测速";
            lock(sync){status=new("停止未完成","","","faketcp",false,null,$"{resource} 尚未退出；所有权仍保留，拒绝启动第二实例");PublishReply();}
            throw new IOException(resource+" 退出超过15秒，未提前释放仍被使用的资源");
        }
        RequireResourceOwnership(); // completed task is not proof that its owners closed
        running = null; runner = null; meshRunner = null;runningProfile=null;
        measureStop?.Dispose();measureStop=null;measuring=null;
        lock (sync) { quality = ""; lastQuality=null; status = new("已停止", "", "", "faketcp", false, null, "后台网络已停止，配对仍保留"); PublishReply();}
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
            status?.LegacyTransports?.Resources.Take(15).Select(x=>new UiLegacyStage(x.ResourceId,x.ProcessId,x.Mode,x.Listener,x.Target,x.BusinessHandoff,x.BusinessEgress,x.Route?.Witnesses.Take(2).ToArray()??[])).ToArray()??[]));
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
        => HandleCore(request,token,null);

    // UI requests carry their original patch until AFTER the shared mutation gate.
    async Task<ControlReply> HandleCore(ControlRequest request,CancellationToken token,UiOperation? ui)
    {
        if(request.Command=="status")return Reply();
        if(request.Command=="cancel")return CancelOperation(request.CancelOperationId);
        Operation operation;bool duplicate;
        try{operation=OpenOperation(request,token,out duplicate,ui);}
        catch(Exception ex){return Reply(ex is OperationCanceledException?"操作已取消":ex.Message);}
        if(duplicate)return Reply(operation.State.Completed?operation.State.Error:"") with{Operation=operation.State};
        bool acquired=false,background=false;
        try
        {
            await requests.WaitAsync(operation.Stop.Token);acquired=true;
            operation.Stop.Token.ThrowIfCancellationRequested();
            if(ui!=null && store.AuthorizedUiUser()!=ui.CallerSid)
                throw new IOException("该本机用户的UI控制授权已改变");
            SetOperation(operation,"执行中",true);
            string issued = "";
            switch (request.Command)
            {
                case "status": break;
                case "ui-network":
                    if(ui?.Network==null)throw new FormatException("网络操作需要已认证的UI请求");
                    await ApplyUiNetwork(ui.Network,operation);
                    break;
                case "mesh-create":
                case "mesh-join":
                    var mesh = request.Command == "mesh-create" ? MeshIdentity.Create(request.Service, request.Pin, request.Mode) : MeshIdentity.Import(request.Invite);
                    if (profile.Selection().Policy == PathPolicy.FakeTcpOnly && mesh.Pair.Mode != "faketcp") throw new IOException("仅 FakeTCP 策略不能创建或加入 UDP 网络，请先更改选路策略");
                    SetOperation(operation,"停止旧网络",false);await End(operation.Stop.Token); lock (sync) { store.BackupLegacy(profile); profile.Enabled = false; profile.Pair = null; profile.Mesh = mesh; profile.Slot = 1; profile.LastEntry = 0;
                        if(PersonalFeature.Enabled && mesh.Pair.Mode=="faketcp")profile=PersonalFeature.EnhancedPreset(profile);
                        if(mesh.Pair.Mode=="udp")profile.TcpPeerReflexive=false;
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
                    lock (sync) {
                        var network = profile.Mesh ?? throw new IOException("请先创建多机网络");
                        issued = MeshIdentity.Export(MeshIdentity.Issue(network)); store.Save(profile);
                        meshRunner?.UpdateDirectory(network.Directory!);
                    } break;
                case "mesh-revoke":
                    lock (sync) {
                        var network = profile.Mesh ?? throw new IOException("请先创建多机网络");
                        MeshIdentity.Revoke(network, request.PeerSlot); store.Save(profile); meshRunner?.UpdateDirectory(network.Directory!);
                    } break;
                case "create":
                case "join":
                    var pair = request.Command == "create" ? Pairing.Create(request.Service, request.Pin, request.Mode) : Pairing.Import(request.Invite);
                    if (profile.Selection().Policy == PathPolicy.FakeTcpOnly && pair.Mode != "faketcp") throw new IOException("仅 FakeTCP 策略不能创建或加入 UDP 网络，请先更改选路策略");
                    SetOperation(operation,"停止旧网络",false);await End(operation.Stop.Token); lock (sync) { profile.Enabled = false; profile.Pair = pair; profile.Mesh = null; profile.Slot = request.Command == "create" ? 1 : 2; profile.LastEntry = 0; store.Save(profile); } break;
                case "ui-patch":
                    if(ui?.Patch==null)throw new FormatException("此命令需要已认证的UI补丁");
                    lock(sync) {
                        // Background directory/STUN updates also use sync. Never
                        // reconstitute a stale whole profile outside this lock.
                        var patched=ui.Patch.ApplyTo(profile);
                        store.Save(patched);profile=patched;
                        if(runningProfile is {} activeUi) {
                            activeUi.DeviceName=patched.DeviceName;
                            activeUi.LogLevel=patched.LogLevel;
                        }
                    }
                    break;
                case "save":
                    var updated = request.Profile ?? throw new FormatException("配置为空"); updated.Validate();
                    if (updated.Device != profile.Device || updated.Pair != profile.Pair || updated.Slot != profile.Slot || JsonSerializer.Serialize(updated.Mesh) != JsonSerializer.Serialize(profile.Mesh)) throw new FormatException("不能通过设置修改配对身份");
                    bool resume = profile.Enabled;
                    updated=ProfileChanges.Copy(updated);
                    updated.Enabled=resume;updated.LastEntry=profile.LastEntry;updated.LastStun=profile.LastStun;
                    if(profile.AdditionalData!=null){updated.AdditionalData??=new();foreach(var extra in profile.AdditionalData)updated.AdditionalData.TryAdd(extra.Key,extra.Value.Clone());}
                    bool restart=ProfileChanges.Impact(profile,updated)==ProfileChangeImpact.RestartNetwork;
                    // Admission failure must precede End; never tear down a
                    // healthy official adapter to discover an unsigned backend.
                    if(updated.AdapterBackend!=profile.AdapterBackend)await PersonalPacketAdapters.Preflight(updated,operation.Stop.Token);
                    if(restart){SetOperation(operation,"重建受影响网络资源",false);await End(operation.Stop.Token);}
                    try {lock (sync) {store.Save(updated);profile=updated; if(!restart&&runningProfile is {} active){active.DeviceName=updated.DeviceName;active.LogLevel=updated.LogLevel;active.LogDirectory=updated.LogDirectory;active.AllowManualQualityRequests=updated.AllowManualQualityRequests;active.TcpStun=updated.TcpStun.ToArray();active.UdpStun=updated.UdpStun.ToArray();}}}
                    catch{if(restart&&resume)Begin();throw;}
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
        catch (Exception ex) { CompleteOperation(operation,ex is OperationCanceledException?"操作已取消":ex.Message);PublishReply();return Reply(ex is OperationCanceledException?"操作已取消":ex.Message) with {Operation=operation.State}; }
        finally { if(acquired)requests.Release(); }
    }
    public void StartLocal()
    {
        Recovery.Recover(Log, Path.Combine(ProfileStore.Root, "sessions"));
        Log("StreamLink 已启动"); if (profile.Enabled) Begin();
        initialized=true;
        PublishReply();
    }
    public async Task StopLocal(CancellationToken token=default) { await End(token); runStop?.Dispose();runStop=null; }
    public override void Dispose() {base.Dispose();DisposeControlResources();}
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StartLocal();
        var uiServing=RunUiControl(stoppingToken);
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
        finally {try{await Task.WhenAll(clients.Append(uiServing)).WaitAsync(TimeSpan.FromSeconds(21));}finally{await End();runStop?.Dispose();runStop=null;}}
    }
}
