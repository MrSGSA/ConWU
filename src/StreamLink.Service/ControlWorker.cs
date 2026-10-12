using Microsoft.Extensions.Hosting;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed class ControlWorker : BackgroundService
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
    string quality = "";
    readonly SemaphoreSlim requests = new(1, 1);
    readonly FileStream lease;
    public ControlWorker()
    {
        lease = new FileStream(Path.Combine(ProfileStore.Root, "runtime.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try { profile = store.Load(); } catch { lease.Dispose(); throw; }
    }
    void Log(string text)
    {
        lock (sync)
        {
            string line = $"{DateTime.Now:HH:mm:ss} {text}"; logs.Enqueue(line); while (logs.Count > 80) logs.Dequeue();
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
        var token = runStop.Token;
        running = Task.Run(async () => {
            while (!token.IsCancellationRequested)
            {
                if (copy.Mesh != null) meshRunner = new(copy, Log, s => { lock (sync) status = s; }, directory => { lock (sync) { if (profile.Mesh != null && directory.Revision > (profile.Mesh.Directory?.Revision ?? 0)) { profile.Mesh.Directory = directory; store.Save(profile); } } }, stun => { lock (sync) { profile.LastStun = stun; store.Save(profile); } });
                else runner = new(copy, Log, s => { lock (sync) status = s; }, (entry, stun) => { lock (sync) { profile.LastEntry = entry; profile.LastStun = stun; store.Save(profile); } });
                try { if (meshRunner != null) await meshRunner.Run(token); else await runner!.Run(token); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
                catch (MeshRevokedException ex) { lock (sync) { profile.Enabled = false; store.Save(profile); status = new("已移出网络", "", "", "faketcp", false, null, ex.Message); } Log(ex.Message); break; }
                catch (Exception ex) { Log("后台连接将重试：" + ex.Message); }
                try { await Task.Delay(10000, token); } catch (OperationCanceledException) { break; }
            }
        });
    }
    async Task End()
    {
        runStop?.Cancel(); if (running != null) { try { await running; } catch (OperationCanceledException) { } }
        if (measuring != null) { try { await measuring; } catch { } }
        running = null; runner = null; meshRunner = null; lock (sync) { quality = ""; status = new("已停止", "", "", "faketcp", false, null, "后台网络已停止，配对仍保留"); }
    }
    ControlReply Reply(string error = "")
    {
        lock (sync) return new(error.Length == 0, error, profile, status, profile.Slot == 1 ? profile.Pair?.Invite() ?? "" : "", logs.ToArray(), quality, typeof(ControlWorker).Assembly.GetName().Version!.ToString(3), 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1,1);
    }
    public async Task<ControlReply> Handle(ControlRequest request)
    {
        await requests.WaitAsync();
        try
        {
            string issued = "";
            switch (request.Command)
            {
                case "status": break;
                case "mesh-create":
                case "mesh-join":
                    var mesh = request.Command == "mesh-create" ? MeshIdentity.Create(request.Service, request.Pin, request.Mode) : MeshIdentity.Import(request.Invite);
                    if (profile.Selection().Policy == PathPolicy.FakeTcpOnly && mesh.Pair.Mode != "faketcp") throw new IOException("仅 FakeTCP 策略不能创建或加入 UDP 网络，请先更改选路策略");
                    await End(); lock (sync) { store.BackupLegacy(profile); profile.Enabled = false; profile.Pair = null; profile.Mesh = mesh; profile.Slot = 1; profile.LastEntry = 0; store.Save(profile); } break;
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
                    await End(); lock (sync) { profile.Enabled = false; profile.Pair = pair; profile.Mesh = null; profile.Slot = request.Command == "create" ? 1 : 2; profile.LastEntry = 0; store.Save(profile); } break;
                case "save":
                    var updated = request.Profile ?? throw new FormatException("配置为空"); updated.Validate();
                    if (updated.Device != profile.Device || updated.Pair != profile.Pair || updated.Slot != profile.Slot || JsonSerializer.Serialize(updated.Mesh) != JsonSerializer.Serialize(profile.Mesh)) throw new FormatException("不能通过设置修改配对身份");
                    bool resume = profile.Enabled; await End(); lock (sync) { updated.Enabled = resume; profile = updated; store.Save(profile); } if (resume) Begin(); break;
                case "start":
                    lock (sync) { if (profile.Pair == null && profile.Mesh == null) throw new IOException("请先创建或加入网络"); profile.Enabled = true; profile.Validate(); store.Save(profile); } Begin(); break;
                case "stop":
                    lock (sync) { profile.Enabled = false; store.Save(profile); } await End(); break;
                case "quality":
                    if (status?.Connected != true || runner == null && meshRunner == null) throw new IOException("请先连接对端");
                    if (request.Mbps is < 1 or > 60) throw new FormatException("测试速率需为 1–60 Mbps");
                    if (measuring != null && !measuring.IsCompleted) throw new IOException("已有质量测试在运行");
                    quality = "正在测试，20 秒后显示结果";
                    var current = runner; var currentMesh = meshRunner; var token = runStop!.Token;
                    measuring = Task.Run(async () => { try { var r = currentMesh != null ? await currentMesh.Measure(request.Mbps, request.PeerSlot, token) : await current!.Measure(request.Mbps, token); lock (sync) quality = $"收到 {r.ReceivedMbps:F2} Mbps，丢包 {r.LossPercent:F3}%，{r.ReceivedPackets}/{r.SentPackets} 包"; } catch (Exception ex) { lock (sync) quality = "测试未完成：" + ex.Message; } }); break;
                default: throw new FormatException("未知控制命令");
            }
            return issued.Length > 0 ? Reply() with { Invite = issued } : Reply();
        }
        catch (Exception ex) { return Reply(ex.Message); }
        finally { requests.Release(); }
    }
    public void StartLocal()
    {
        Recovery.Recover(Log, Path.Combine(ProfileStore.Root, "sessions"));
        Log("StreamLink 已启动"); if (profile.Enabled) Begin();
    }
    public async Task StopLocal() { await End(); runStop?.Dispose(); }
    public override void Dispose() { lease.Dispose(); requests.Dispose(); base.Dispose(); }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        StartLocal();
        using var pipe = LocalControlPipe.Create();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await pipe.WaitForConnectionAsync(stoppingToken);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken); timeout.CancelAfter(45000);
                try
                {
                    var request = await ServiceProtocol.Read<ControlRequest>(pipe, timeout.Token);
                    await ServiceProtocol.Write(pipe, await Handle(request), timeout.Token);
                    // DisconnectNamedPipe discards unread bytes. Wait until the
                    // client has consumed the framed response before reusing it.
                    byte[] ack = new byte[1]; await pipe.ReadAtLeastAsync(ack, 1, false, timeout.Token);
                }
                catch (Exception ex) when (!stoppingToken.IsCancellationRequested) { Log("控制请求未完成：" + ex.GetType().Name + " " + ex.Message); }
                finally { if (pipe.IsConnected) pipe.Disconnect(); }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { await End(); runStop?.Dispose(); }
    }
}
