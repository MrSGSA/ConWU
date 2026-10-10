using StreamLink.Core;

namespace StreamLink.Service;

public sealed class NetworkRunner(DeviceProfile profile, Action<string> log, Action<SessionStatus> report, Action<int, string> remember)
{
    StreamSession? session;
    public Task<QualityResult> Measure(int mbps, CancellationToken token) => session?.Measure(mbps, token) ?? throw new IOException("尚未启动连接");
    public async Task Run(CancellationToken token)
    {
        var pair = profile.Pair!;
        using var discovery = new DiscoveryClient(pair);
        using var mappingStop = CancellationTokenSource.CreateLinkedTokenSource(token);
        IMapping? mapping = null; Task<TcpMapping>? pendingMapping = null; Task? maintain = null;
        DateTime nextProbe = DateTime.MinValue, lastWarning = DateTime.MinValue, connectingSince = DateTime.UtcNow;
        NodeAnnouncement? peer = null;
        int selected = 0, failed = 0; string activeEndpoint = ""; long revision = DateTime.UtcNow.Ticks;
        bool remembered = false;
        string Candidate() => mapping?.PublicEndpoint.ToString() ?? profile.ManualEndpoint;
        NodeAnnouncement Own() => new(profile.Device, profile.Slot, ++revision, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), Candidate(), profile.Preference, profile.LastEntry, profile.Slot == 1 ? selected : 0, session?.IsConnected == true);
        try
        {
            while (!token.IsCancellationRequested)
            {
                if (session?.IsConnected != true && mapping == null && pendingMapping == null && profile.ManualEndpoint.Length == 0 && DateTime.UtcNow >= nextProbe)
                {
                    pendingMapping = TcpMapping.Create(profile.SourcePort, profile.ListenPort, log, mappingStop.Token, profile.OrderedTcp(), profile.Device);
                    log("正在探测本机入口能力，同时等待对端公告");
                }
                if (pendingMapping?.IsCompleted == true)
                {
                    try { mapping = await pendingMapping; maintain = mapping.Maintain(mappingStop.Token); profile.LastStun = ((TcpMapping)mapping).StunServer; remember(profile.LastEntry, profile.LastStun); }
                    catch (Exception ex) when (!token.IsCancellationRequested) { log("本机入口暂不可用：" + ex.Message); nextProbe = DateTime.UtcNow.AddSeconds(45); }
                    pendingMapping = null;
                }
                if (maintain?.IsCompleted == true)
                {
                    try { await maintain; } catch (Exception ex) when (!token.IsCancellationRequested) { log("映射需要重建：" + ex.Message); }
                    if (mapping != null) await mapping.DisposeAsync(); mapping = null; maintain = null; nextProbe = DateTime.UtcNow.AddSeconds(5);
                }
                bool fresh = false;
                try
                {
                    await discovery.Publish(Own(), token);
                    peer = await discovery.Read(3 - profile.Slot, token); fresh = peer != null;
                }
                catch (Exception ex) when (!token.IsCancellationRequested)
                {
                    if ((DateTime.UtcNow - lastWarning).TotalSeconds > 30) { log("发现服务暂不可用，保留已有直连：" + ex.Message); lastWarning = DateTime.UtcNow; }
                }
                bool connected = session?.IsConnected == true;
                if (profile.Slot == 1 && !connected)
                {
                    var own = Own(); var usablePeer = fresh ? peer : null;
                    if (selected == 0 || (DateTime.UtcNow - connectingSince).TotalSeconds > 50)
                    {
                        if (selected != 0) failed = selected;
                        int choice = EntryElection.Choose(own, usablePeer, failed);
                        if (choice == 0) { failed = 0; choice = EntryElection.Choose(own, usablePeer); }
                        if (selected != choice) { selected = choice; connectingSince = DateTime.UtcNow; }
                    }
                }
                else if (profile.Slot == 2 && fresh) selected = peer!.SelectedEntry;
                string endpoint = selected == profile.Slot ? Candidate() : selected != 0 && fresh ? peer!.Endpoint : "";
                // Discovery loss alone must not tear down an established path.
                if (session != null && ((endpoint.Length > 0 && activeEndpoint != selected + "/" + endpoint) || (!connected && (DateTime.UtcNow - connectingSince).TotalSeconds > 90)))
                {
                    await session.DisposeAsync(); session = null; activeEndpoint = ""; remembered = false; connectingSince = DateTime.UtcNow;
                }
                if (session == null && selected != 0 && endpoint.Length > 0)
                {
                    bool host = selected == profile.Slot;
                    var ticket = new Invitation(1, pair.Network, pair.Secret, endpoint, "faketcp", "test.ustc.edu.cn", DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeSeconds());
                    var starting = new StreamSession(Path.Combine(AppContext.BaseDirectory, "components"), log, Path.Combine(ProfileStore.Root, "sessions"));
                    starting.StatusChanged += report;
                    try
                    {
                        log($"协商入口为设备 {selected}，本机固定地址 10.129.129.{profile.Slot}");
                        await starting.Start(new SessionOptions { Host = host, LocalSlot = profile.Slot, ListenPort = profile.ListenPort, PersistentTicket = ticket }, token, host ? mapping : null);
                        session = starting; activeEndpoint = selected + "/" + endpoint; connectingSince = DateTime.UtcNow;
                    }
                    catch (Exception ex) when (!token.IsCancellationRequested) { await starting.DisposeAsync(); log("组件启动重试：" + ex.Message); }
                }
                if (session?.IsConnected == true && !remembered)
                {
                    profile.LastEntry = selected; remember(selected, profile.LastStun); remembered = true; log("实际直连握手成功，已记忆入口方向");
                }
                if (session == null) report(new("等待自动协商", $"10.129.129.{profile.Slot}", $"10.129.129.{3 - profile.Slot}", "faketcp", false, null, Candidate().Length > 0 ? "本机已有候选映射，等待配对端上线" : "正在寻找可用入口；任一端需有可达映射"));
                await Task.Delay(5000, token);
            }
        }
        finally
        {
            mappingStop.Cancel();
            if (session != null) { await session.DisposeAsync(); session = null; }
            if (pendingMapping != null) { try { mapping = await pendingMapping; } catch { } }
            if (maintain != null) { try { await maintain; } catch { } }
            if (mapping != null) await mapping.DisposeAsync();
            try { using var timeout = new CancellationTokenSource(2000); await discovery.Publish(Own() with { Endpoint = "", SelectedEntry = 0, Connected = false }, timeout.Token); } catch { }
        }
    }
}
