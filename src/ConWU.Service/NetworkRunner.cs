using StreamLink.Core;

namespace StreamLink.Service;

public sealed class NetworkRunner
{
    readonly DeviceProfile profile;
    readonly Action<string> log;
    readonly Action<SessionStatus> report;
    readonly Action<int, string> remember;
    readonly RunnerServices services;
    IStreamSession? session;
    public NetworkRunner(DeviceProfile profile, Action<string> log, Action<SessionStatus> report, Action<int, string> remember)
        : this(profile, log, report, remember, RunnerServices.Default) { }
    internal NetworkRunner(DeviceProfile profile, Action<string> log, Action<SessionStatus> report, Action<int, string> remember, RunnerServices services)
    { this.profile = profile; this.log = log; this.report = report; this.remember = remember; this.services = services; }
    public Task<QualityResult> Measure(int mbps, CancellationToken token) => session?.Measure(mbps, token) ?? throw new IOException("尚未启动连接");
    public async Task Run(CancellationToken token)
    {
        var pair = profile.Pair!;
        using var discovery = services.OpenDiscovery(pair);
        using var networkWake = services.NetworkWake();
        using var mappingStop = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var sessionStop = CancellationTokenSource.CreateLinkedTokenSource(token);
        IMapping? mapping = null; Task<IMapping>? pendingMapping = null; Task? maintain = null;
        Task? pendingStart = null, publishing = null; Task<NodeAnnouncement?>? reading = null;
        long nextProbe = 0, lastWarning = 0, connectingSince = Environment.TickCount64, nextPublish = 0, nextRead = 0;
        NodeAnnouncement? peer = null;
        int selected = 0, failed = 0; string activeEndpoint = ""; long revision = DateTime.UtcNow.Ticks;
        bool remembered = false, mappingFailed = false;
        var timeline = new ConnectionTimeline(log);
        timeline.Mark("开始连接协商");
        string Candidate() => mappingFailed || mapping is { IsValid: false } ? "" : mapping?.PublicEndpoint.ToString() ?? profile.ManualEndpoint;
        NodeAnnouncement Own() => new(profile.Device, profile.Slot, ++revision, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), Candidate(), profile.Preference, profile.LastEntry, profile.Slot == 1 ? selected : 0, session?.IsConnected == true, profile.DeviceName);
        Task<IMapping> Probe() => services.Probe(profile, log, mappingStop.Token);
        async Task Publish(NodeAnnouncement value) => await discovery.Publish(value, token);
        async Task<NodeAnnouncement?> Read() => await discovery.Read(3 - profile.Slot, token);
        void Warn(Exception ex) {
            long now = Environment.TickCount64;
            if (lastWarning == 0 || now - lastWarning >= 30000) { log("发现服务暂不可用，保留已有直连：" + ex.Message); lastWarning = now; }
        }
        try
        {
            while (!token.IsCancellationRequested)
            {
                long now = Environment.TickCount64;
                if (networkWake.Take(now)) {
                    nextProbe = nextPublish = nextRead = now;
                    (mapping as IMappingRefresh)?.RequestRefresh();
                    log("网络变化或系统唤醒，正在复核双机入口和发现信息；保留已验证的直连路径");
                }
                if (session?.IsConnected != true && mapping == null && pendingMapping == null && profile.ManualEndpoint.Length == 0 && now >= nextProbe)
                {
                    pendingMapping = Probe();
                    log("正在探测本机入口能力，同时等待对端公告");
                }
                if (pendingMapping?.IsCompleted == true)
                {
                    try { mapping = await pendingMapping; mappingFailed = false; maintain = mapping.Maintain(mappingStop.Token); if (mapping is TcpMapping tcp) profile.LastStun = tcp.StunServer; remember(profile.LastEntry, profile.LastStun); timeline.Mark("本机候选映射就绪"); }
                    catch (Exception ex) when (!token.IsCancellationRequested) { mappingFailed = mapping != null; log("本机入口暂不可用：" + ex.Message); nextProbe = now + 45000; }
                    pendingMapping = null;
                }
                if (maintain?.IsCompleted == true)
                {
                    try { await maintain; } catch (Exception ex) when (!token.IsCancellationRequested) { log("映射需要重建：" + ex.Message); }
                    // A failed helper query stops advertising its candidate;
                    // it does not release a mapping still used by a healthy path.
                    mappingFailed = true; maintain = null; nextPublish = now;
                }
                if (pendingStart?.IsCompleted == true)
                {
                    try { await pendingStart; timeline.Mark("本机会话组件就绪"); }
                    catch (Exception ex) when (!token.IsCancellationRequested)
                    {
                        if (session != null) await session.DisposeAsync(); session = null; activeEndpoint = "";
                        log("组件启动重试：" + ex.Message);
                    }
                    pendingStart = null;
                }
                // Each direction has one outstanding request. Slow HTTPS must
                // not block process recovery, mapping completion or OS hints.
                if (publishing?.IsCompleted == true) {
                    try { await publishing; } catch (Exception ex) when (!token.IsCancellationRequested) { Warn(ex); }
                    publishing = null;
                }
                if (reading?.IsCompleted == true) {
                    try { peer = await reading; } catch (Exception ex) when (!token.IsCancellationRequested) { Warn(ex); }
                    reading = null;
                }
                bool fresh = peer != null && peer.Expires > DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                bool connected = session?.IsConnected == true;
                // Measure recovery from the last healthy observation, not from
                // initial startup (which may have happened several hours ago).
                if (connected) connectingSince = now;
                int previousSelection = selected;
                if (profile.Slot == 1 && !connected)
                {
                    var own = Own(); var usablePeer = fresh ? peer : null;
                    if (selected == 0 || now - connectingSince > 50000)
                    {
                        if (selected != 0) failed = selected;
                        int choice = EntryElection.Choose(own, usablePeer, failed);
                        if (choice == 0) { failed = 0; choice = EntryElection.Choose(own, usablePeer); }
                        if (selected != choice) { selected = choice; connectingSince = now; }
                    }
                }
                else if (profile.Slot == 2 && fresh) selected = peer!.SelectedEntry;
                if (profile.Slot == 1 && selected != previousSelection)
                {
                    // Send the decision before slow adapter/process startup.
                    // Previously the peer learned it only on the next loop.
                    nextPublish = now;
                    timeline.Mark("入口方向已确定");
                }
                string endpoint = selected == profile.Slot ? Candidate() : selected != 0 && fresh ? peer!.Endpoint : "";
                // Discovery loss alone must not tear down an established path.
                if (session != null && pendingStart == null && !connected && ((endpoint.Length > 0 && activeEndpoint != selected + "/" + endpoint) || now - connectingSince > 90000 || mappingFailed && selected == profile.Slot))
                {
                    await session.DisposeAsync(); session = null; activeEndpoint = ""; remembered = false; connectingSince = now;
                }
                if (mappingFailed && session == null && pendingStart == null) {
                    if (mapping != null) await mapping.DisposeAsync();
                    mapping = null; mappingFailed = false; nextProbe = now + 5000;
                }
                if (session == null && selected != 0 && endpoint.Length > 0)
                {
                    bool host = selected == profile.Slot;
                    var ticket = new Invitation(1, pair.Network, pair.Secret, endpoint, pair.Mode, pair.Mode == "faketcp" ? "test.ustc.edu.cn" : "", DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeSeconds());
                    var starting = services.NewSession(log);
                    starting.StatusChanged += s => report(s with { PeerName = peer?.Name ?? "" });
                    log($"协商入口为设备 {selected}，本机固定地址 10.129.129.{profile.Slot}");
                    var options = new SessionOptions { Host = host, LocalSlot = profile.Slot, ListenPort = profile.ListenPort, PersistentTicket = ticket, Mode = pair.Mode, LogLevel = profile.LogLevel, LogDirectory = profile.LogDirectory.Length > 0 ? profile.LogDirectory : Path.Combine(ProfileStore.Root, "logs"),AllowManualQualityRequests=profile.AllowManualQualityRequests };
                    var prepared = host ? mapping : null;
                    session = starting; activeEndpoint = selected + "/" + endpoint; connectingSince = now;
                    report(new("正在启动", $"10.129.129.{profile.Slot}", $"10.129.129.{3 - profile.Slot}", pair.Mode, false, null, "本机组件正在初始化，同时同步对端连接信息", peer?.Name ?? ""));
                    // Start may synchronously initialize COM, processes or a
                    // virtual adapter. Never block discovery/heartbeats on it.
                    pendingStart = Task.Run(() => starting.Start(options, sessionStop.Token, prepared));
                }
                if (session?.IsConnected == true && !remembered)
                {
                    profile.LastEntry = selected; remember(selected, profile.LastStun); remembered = true; log("实际直连握手成功，已记忆入口方向"); timeline.Mark("连接可用");
                }
                if (session == null) report(new("等待自动协商", $"10.129.129.{profile.Slot}", $"10.129.129.{3 - profile.Slot}", pair.Mode, false, null, Candidate().Length > 0 ? "本机已有候选映射，等待配对端上线" : "正在寻找可用入口；任一端需有可达映射", peer?.Name ?? ""));
                long interval = (long)(session?.IsConnected == true ? services.ConnectedPoll : services.ConnectingPoll).TotalMilliseconds;
                if (publishing == null && now >= nextPublish) { publishing = Publish(Own()); nextPublish = now + interval; }
                if (reading == null && now >= nextRead) { reading = Read(); nextRead = now + interval; }
                await Task.Delay((int)Math.Clamp(interval, 10, 100), token);
            }
        }
        finally
        {
            mappingStop.Cancel();
            sessionStop.Cancel();
            if (pendingStart != null) { try { await pendingStart; } catch { } }
            if (session != null) { await session.DisposeAsync(); session = null; }
            if (pendingMapping != null) { try { mapping = await pendingMapping; } catch { } }
            if (maintain != null) { try { await maintain; } catch { } }
            if (mapping != null) await mapping.DisposeAsync();
            if (publishing != null) { try { await publishing; } catch { } }
            if (reading != null) { try { await reading; } catch { } }
            try { using var timeout = new CancellationTokenSource(2000); await discovery.Publish(Own() with { Endpoint = "", SelectedEntry = 0, Connected = false }, timeout.Token); } catch { }
        }
    }
}
