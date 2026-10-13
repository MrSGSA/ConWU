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
    readonly SemaphoreSlim requests = new(1, 1);
    readonly FileStream lease;
    public ControlWorker()
    {
        lease = new FileStream(Path.Combine(ProfileStore.Root, "runtime.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try { profile = store.Load(); PublishReply(); } catch { lease.Dispose(); throw; }
    }
    void Log(string text)
    {
        lock (sync)
        {
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
            while (!token.IsCancellationRequested)
            {
                if (copy.Mesh != null) meshRunner = new(copy, Log, s => { lock (sync) {status = s;PublishReply();} }, directory => { lock (sync) { if (profile.Mesh != null && directory.Revision > (profile.Mesh.Directory?.Revision ?? 0)) { profile.Mesh.Directory = directory; store.Save(profile); PublishReply();} } }, stun => { lock (sync) { profile.LastStun = stun; store.Save(profile); PublishReply();} });
                else runner = new(copy, Log, s => { lock (sync) {status = s;PublishReply();} }, (entry, stun) => { lock (sync) { profile.LastEntry = entry; profile.LastStun = stun; store.Save(profile); PublishReply();} });
                try { if (meshRunner != null) await meshRunner.Run(token); else await runner!.Run(token); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
                catch (MeshRevokedException ex) { lock (sync) { profile.Enabled = false; store.Save(profile); status = new("已移出网络", "", "", "faketcp", false, null, ex.Message); } Log(ex.Message); break; }
                catch (Exception ex) { Log("后台连接将重试：" + ex.Message); }
                try { await Task.Delay(10000, token); } catch (OperationCanceledException) { break; }
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
        running = null; runner = null; meshRunner = null;runningProfile=null;
        measureStop?.Dispose();measureStop=null;measuring=null;
        lock (sync) { quality = ""; status = new("已停止", "", "", "faketcp", false, null, "后台网络已停止，配对仍保留"); PublishReply();}
    }
    static async Task ObserveShutdown(Task task){try{await task;}catch(OperationCanceledException){} }
    void PublishReply()
    {
        lock (sync) Volatile.Write(ref snapshot,new(true, "", ProfileChanges.Copy(profile), DisplayStatus(status), profile.Slot == 1 ? profile.Pair?.Invite() ?? "" : "", logs.ToArray(), quality, typeof(ControlWorker).Assembly.GetName().Version!.ToString(3), 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1,1,1,Volatile.Read(ref operationStatus),1));
    }
    ControlReply Reply(string error = "") {var current=Volatile.Read(ref snapshot)!;return current with{Ok=error.Length==0,Error=error,Profile=ProfileChanges.Copy(current.Profile!),Logs=(string[])current.Logs.Clone()};}
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
    public async Task<ControlReply> Handle(ControlRequest request,CancellationToken token=default)
    {
        if(request.Command=="status")return Reply();
        if(request.Command=="cancel")return CancelOperation(request.CancelOperationId);
        Operation operation;bool duplicate;
        try{operation=OpenOperation(request,token,out duplicate);}
        catch(Exception ex){return Reply(ex is OperationCanceledException?"操作已取消":ex.Message);}
        if(duplicate)return Reply() with{Operation=operation.State};
        bool acquired=false,background=false;
        try
        {
            await requests.WaitAsync(operation.Stop.Token);acquired=true;
            operation.Stop.Token.ThrowIfCancellationRequested();
            SetOperation(operation,"执行中",true);
            string issued = "";
            switch (request.Command)
            {
                case "status": break;
                case "mesh-create":
                case "mesh-join":
                    var mesh = request.Command == "mesh-create" ? MeshIdentity.Create(request.Service, request.Pin, request.Mode) : MeshIdentity.Import(request.Invite);
                    if (profile.Selection().Policy == PathPolicy.FakeTcpOnly && mesh.Pair.Mode != "faketcp") throw new IOException("仅 FakeTCP 策略不能创建或加入 UDP 网络，请先更改选路策略");
                    SetOperation(operation,"停止旧网络",false);await End(operation.Stop.Token); lock (sync) { store.BackupLegacy(profile); profile.Enabled = false; profile.Pair = null; profile.Mesh = mesh; profile.Slot = 1; profile.LastEntry = 0; store.Save(profile); } break;
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
                case "save":
                    var updated = request.Profile ?? throw new FormatException("配置为空"); updated.Validate();
                    if (updated.Device != profile.Device || updated.Pair != profile.Pair || updated.Slot != profile.Slot || JsonSerializer.Serialize(updated.Mesh) != JsonSerializer.Serialize(profile.Mesh)) throw new FormatException("不能通过设置修改配对身份");
                    bool resume = profile.Enabled;
                    updated=ProfileChanges.Copy(updated);
                    updated.Enabled=resume;updated.LastEntry=profile.LastEntry;updated.LastStun=profile.LastStun;
                    if(profile.AdditionalData!=null){updated.AdditionalData??=new();foreach(var extra in profile.AdditionalData)updated.AdditionalData.TryAdd(extra.Key,extra.Value.Clone());}
                    bool restart=ProfileChanges.Impact(profile,updated)==ProfileChangeImpact.RestartNetwork;
                    if(restart){SetOperation(operation,"重建受影响网络资源",false);await End(operation.Stop.Token);}
                    try {lock (sync) {store.Save(updated);profile=updated; if(!restart&&runningProfile is {} active){active.DeviceName=updated.DeviceName;active.LogLevel=updated.LogLevel;active.LogDirectory=updated.LogDirectory;}}}
                    catch{if(restart&&resume)Begin();throw;}
                    if(restart&&resume)Begin();break;
                case "start":
                    if(running?.IsCompleted==false&&runStop?.IsCancellationRequested==true)throw new IOException("先前网络正在退出，不能启动第二实例");
                    lock (sync) { if (profile.Pair == null && profile.Mesh == null) throw new IOException("请先创建或加入网络"); profile.Enabled = true; profile.Validate(); store.Save(profile); } Begin(); break;
                case "stop":
                    SetOperation(operation,"停止网络",false);lock (sync) { profile.Enabled = false; store.Save(profile); } await End(operation.Stop.Token); break;
                case "quality":
                    if (status?.Connected != true || runner == null && meshRunner == null) throw new IOException("请先连接对端");
                    if (request.Mbps is < 1 or > 60) throw new FormatException("测试速率需为 1–60 Mbps");
                    if (measuring != null && !measuring.IsCompleted) throw new IOException("已有质量测试在运行");
                    quality = "正在测试，20 秒后显示结果";
                    measureStop?.Dispose();measureStop=CancellationTokenSource.CreateLinkedTokenSource(runStop!.Token,operation.Stop.Token);
                    var current = runner; var currentMesh = meshRunner; var measurementToken = measureStop.Token;
                    background=true;SetOperation(operation,"测速中",true);
                    measuring = Task.Run(async () => { try { var r = currentMesh != null ? await currentMesh.Measure(request.Mbps, request.PeerSlot, measurementToken) : await current!.Measure(request.Mbps, measurementToken); lock (sync) quality = $"收到 {r.ReceivedMbps:F2} Mbps，丢包 {r.LossPercent:F3}%，{r.ReceivedPackets}/{r.SentPackets} 包"; } catch (Exception ex) { lock (sync) quality = "测试未完成：" + ex.Message; } finally {CompleteOperation(operation);PublishReply();} }); break;
                default: throw new FormatException("未知控制命令");
            }
            if(!background)CompleteOperation(operation);PublishReply();return issued.Length > 0 ? Reply() with { Invite = issued } : Reply();
        }
        catch (Exception ex) { CompleteOperation(operation,ex is OperationCanceledException?"操作已取消":ex.Message);PublishReply();return Reply(ex is OperationCanceledException?"操作已取消":ex.Message); }
        finally { if(acquired)requests.Release(); }
    }
    public void StartLocal()
    {
        Recovery.Recover(Log, Path.Combine(ProfileStore.Root, "sessions"));
        Log("StreamLink 已启动"); if (profile.Enabled) Begin();
        PublishReply();
    }
    public async Task StopLocal(CancellationToken token=default) { await End(token); runStop?.Dispose();runStop=null; }
    public override void Dispose() {base.Dispose();DisposeControlResources();}
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StartLocal();
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
        finally {try{await Task.WhenAll(clients).WaitAsync(TimeSpan.FromSeconds(16));}finally{await End();runStop?.Dispose();runStop=null;}}
    }
}
