using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "StreamLink");
builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(45));
builder.Services.AddHostedService<ControlWorker>();
await builder.Build().RunAsync();

sealed class ControlWorker : BackgroundService
{
    readonly ProfileStore store = new();
    readonly object sync = new();
    readonly Queue<string> logs = new();
    DeviceProfile profile;
    SessionStatus? status;
    CancellationTokenSource? runStop;
    Task? running, measuring;
    NetworkRunner? runner;
    string quality = "";
    public ControlWorker() { profile = store.Load(); }
    void Log(string text)
    {
        lock (sync)
        {
            string line = $"{DateTime.Now:HH:mm:ss} {text}"; logs.Enqueue(line); while (logs.Count > 80) logs.Dequeue();
            string path = Path.Combine(ProfileStore.Root, "service.log");
            if (File.Exists(path) && new FileInfo(path).Length > 2_000_000) File.Move(path, path + ".previous", true);
            File.AppendAllText(path, line + Environment.NewLine);
        }
    }
    void Begin()
    {
        if (running != null && !running.IsCompleted) return;
        runStop?.Dispose(); runStop = new();
        var copy = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(profile))!;
        var token = runStop.Token;
        running = Task.Run(async () => {
            while (!token.IsCancellationRequested)
            {
                runner = new(copy, Log, s => { lock (sync) status = s; }, (entry, stun) => { lock (sync) { profile.LastEntry = entry; profile.LastStun = stun; store.Save(profile); } });
                try { await runner.Run(token); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
                catch (Exception ex) { Log("后台连接将重试：" + ex.Message); }
                try { await Task.Delay(10000, token); } catch (OperationCanceledException) { break; }
            }
        });
    }
    async Task End()
    {
        runStop?.Cancel(); if (running != null) { try { await running; } catch (OperationCanceledException) { } }
        if (measuring != null) { try { await measuring; } catch { } }
        running = null; runner = null; lock (sync) { quality = ""; status = new("已停止", "", "", "faketcp", false, null, "后台网络已停止，配对仍保留"); }
    }
    ControlReply Reply(string error = "")
    {
        lock (sync) return new(error.Length == 0, error, profile, status, profile.Slot == 1 ? profile.Pair?.Invite() ?? "" : "", logs.ToArray(), quality);
    }
    async Task<ControlReply> Handle(ControlRequest request)
    {
        try
        {
            switch (request.Command)
            {
                case "status": break;
                case "create":
                case "join":
                    var pair = request.Command == "create" ? Pairing.Create(request.Service, request.Pin) : Pairing.Import(request.Invite);
                    await End(); lock (sync) { profile.Enabled = false; profile.Pair = pair; profile.Slot = request.Command == "create" ? 1 : 2; profile.LastEntry = 0; store.Save(profile); } break;
                case "save":
                    var updated = request.Profile ?? throw new FormatException("配置为空"); updated.Validate();
                    if (updated.Device != profile.Device || updated.Pair != profile.Pair || updated.Slot != profile.Slot) throw new FormatException("不能通过设置修改配对身份");
                    bool resume = profile.Enabled; await End(); lock (sync) { updated.Enabled = resume; profile = updated; store.Save(profile); } if (resume) Begin(); break;
                case "start":
                    lock (sync) { if (profile.Pair == null) throw new IOException("请先创建或加入网络"); profile.Enabled = true; profile.Validate(); store.Save(profile); } Begin(); break;
                case "stop":
                    lock (sync) { profile.Enabled = false; store.Save(profile); } await End(); break;
                case "quality":
                    if (status?.Connected != true || runner == null) throw new IOException("请先连接对端");
                    if (request.Mbps is < 1 or > 60) throw new FormatException("测试速率需为 1–60 Mbps");
                    if (measuring != null && !measuring.IsCompleted) throw new IOException("已有质量测试在运行");
                    quality = "正在测试，20 秒后显示结果";
                    var current = runner; var token = runStop!.Token;
                    measuring = Task.Run(async () => { try { var r = await current.Measure(request.Mbps, token); lock (sync) quality = $"收到 {r.ReceivedMbps:F2} Mbps，丢包 {r.LossPercent:F3}%，{r.ReceivedPackets}/{r.SentPackets} 包"; } catch (Exception ex) { lock (sync) quality = "测试未完成：" + ex.Message; } }); break;
                default: throw new FormatException("未知控制命令");
            }
            return Reply();
        }
        catch (Exception ex) { return Reply(ex.Message); }
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Recovery.Recover(Log, Path.Combine(ProfileStore.Root, "sessions"));
        Log("StreamLink 服务已启动；关闭界面不会停止网络"); if (profile.Enabled) Begin();
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
