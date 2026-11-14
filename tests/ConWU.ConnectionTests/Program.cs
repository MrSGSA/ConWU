using System.Collections.Concurrent;
using System.Diagnostics;
using StreamLink.Core;
using StreamLink.Service;

int checks = 0;
void Check(bool condition, string message) { if (!condition) throw new Exception(message); checks++; }
async Task Until(Func<bool> condition)
{
    using var timeout = new CancellationTokenSource(5000);
    while (!condition()) await Task.Delay(10, timeout.Token);
}
async Task Stop(Task running, CancellationTokenSource stop)
{
    stop.Cancel();
    try { await running.WaitAsync(TimeSpan.FromSeconds(5)); } catch (OperationCanceledException) { }
}
DeviceProfile Profile(int slot = 1) => new()
{
    Pair = Pairing.Create("https://example.invalid/", ""), Slot = slot,
    ManualEndpoint = slot == 1 ? "203.0.113.1:1234" : "", LogLevel = "off"
};
NodeAnnouncement Peer(int slot = 2, int entry = 0) => new(Guid.NewGuid().ToString("N"), slot, 1,
    DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), "203.0.113.2:2345", "auto", 0, entry, false);
var testsRoot = Path.Combine(Path.GetTempPath(), "streamlink-connection-" + Guid.NewGuid().ToString("N"));
Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT", testsRoot);
try
{
    // Real coordinator flow shared by two runners: both machines must begin
    // their slow adapter initialization before either machine finishes it.
    using (var stop = new CancellationTokenSource())
    using (var release = new ManualResetEventSlim())
    {
        var shared = new ConcurrentDictionary<int, NodeAnnouncement>();
        var leftDiscovery = new FakeDiscovery { Shared = shared };
        var rightDiscovery = new FakeDiscovery { Shared = shared };
        FakeSession Pending() => new((s, ct) => { release.Wait(ct); s.Connect(); return Task.CompletedTask; });
        var leftSession = Pending(); var rightSession = Pending();
        var left = new NetworkRunner(Profile(), _ => { }, _ => { }, (_, _) => { }, Services(leftDiscovery, () => leftSession));
        var right = new NetworkRunner(Profile(2), _ => { }, _ => { }, (_, _) => { }, Services(rightDiscovery, () => rightSession));
        Task first = left.Run(stop.Token), second = right.Run(stop.Token);
        try
        {
            await Until(() => leftSession.Started && rightSession.Started);
            Check(!leftSession.StartExited && !rightSession.StartExited, "Peer startup waited for the other adapter to finish");
            Check(leftSession.Options!.Host && !rightSession.Options!.Host, "Both runners failed to agree on entry direction");
            release.Set(); await Until(() => leftSession.IsConnected && rightSession.IsConnected);
            Check(shared[1].SelectedEntry == 1, "Creator did not publish its entry decision");
        }
        finally { stop.Cancel(); await Stop(first, stop); await Stop(second, stop); }
        Check(leftSession.Disposed && rightSession.Disposed, "Paired runner cleanup leaked a session");
    }
    // Block *synchronously* inside Start, like COM/driver initialization. Both
    // the initial election and later metadata must still reach the other peer.
    using (var stop = new CancellationTokenSource())
    using (var unblock = new ManualResetEventSlim())
    {
        var discovery = new FakeDiscovery { Peer = Peer() };
        var session = new FakeSession((s, ct) => { unblock.Wait(ct); return Task.CompletedTask; });
        var services = Services(discovery, () => session);
        var runner = new NetworkRunner(Profile(), _ => { }, _ => { }, (_, _) => { }, services);
        Task running = runner.Run(stop.Token);
        try
        {
            await Until(() => session.Started);
            Check(discovery.Published.Any(n => n.SelectedEntry == 1), "Entry decision was not sent before blocked startup");
            int before = discovery.Published.Count;
            await Until(() => discovery.Published.Count >= before + 3);
            Check(!session.Disposed && !session.StartExited, "Blocking startup fixture did not stay pending");
            Check(discovery.Reads >= 3, "Peer discovery stopped during local startup");
        }
        finally { await Stop(running, stop); }
        Check(session.StartExited && session.Disposed, "Cancellation must await startup before disposing its session");
        Check(discovery.Disposed, "Discovery client leaked after cancellation");
    }

    // A usable remote entry must not wait for our own impossible mapping.
    using (var stop = new CancellationTokenSource())
    {
        var profile = Profile(); profile.ManualEndpoint = "";
        var discovery = new FakeDiscovery { Peer = Peer() };
        var sessions = new ConcurrentQueue<FakeSession>(); int remembered = 0;
        var services = Services(discovery, () => { var s = ConnectedSession(); sessions.Enqueue(s); return s; });
        var runner = new NetworkRunner(profile, _ => { }, _ => { }, (entry, _) => remembered = entry, services);
        Task running = runner.Run(stop.Token);
        try
        {
            await Until(() => remembered == 2);
            Check(sessions.Count == 1 && sessions.Single().IsConnected, "Remote entry blocked on unfinished local mapping");
            Check(sessions.Single().Options is { Host: false, LocalSlot: 1 }, "Endpoint direction changed the persistent address slot");
            discovery.Fail = true; int before = discovery.Reads;
            await Task.Delay(160);
            Check(sessions.Count == 1 && !sessions.Single().Disposed, "Coordination outage destroyed a working direct path");
            discovery.Fail = false;
            discovery.Peer = discovery.Peer! with { Endpoint = "203.0.113.3:3456", Revision = 2 };
            await Task.Delay(180);
            Check(sessions.Count == 1 && !sessions.First().Disposed && sessions.First().IsConnected,
                "A new announcement destroyed an authenticated healthy old path");
            sessions.First().Disconnect();
            await Until(() => sessions.Count == 2 && sessions.Last().IsConnected);
            Check(sessions.First().Disposed, "Failed old path did not adopt the latest candidate and release its session");
            Check(sessions.Last().Options?.LocalSlot == 1, "Reconnect changed the virtual address identity");
        }
        finally { await Stop(running, stop); }
        Check(sessions.All(s => s.Disposed), "Reconnect cleanup leaked a session");
    }
    // The default two-slot compatibility runner must respond to the same OS
    // wake as MeshRunner, even when one HTTPS request never finishes. It must
    // neither issue duplicate outstanding requests nor dispose a healthy path
    // merely because its mapping helper failed.
    using (var stop = new CancellationTokenSource())
    using (var wake = new MeshNetworkWake(false))
    {
        var profile = Profile(); profile.ManualEndpoint = "";
        var discovery = new FakeDiscovery { BlockPublish = true };
        var mapping = new FakeMapping(); var sessions = new ConcurrentQueue<FakeSession>();
        int probes = 0; var logs = new ConcurrentQueue<string>();
        var services = Services(discovery, () => { var s = ConnectedSession(); sessions.Enqueue(s); return s; }) with {
            NetworkWake = () => wake,
            Probe = (_, _, _) => Interlocked.Increment(ref probes) == 1
                ? Task.FromException<IMapping>(new IOException("interface not ready"))
                : Task.FromResult<IMapping>(mapping)
        };
        var runner = new NetworkRunner(profile, logs.Enqueue, _ => { }, (_, _) => { }, services);
        Task running = runner.Run(stop.Token);
        try {
            await Until(() => logs.Any(l => l.StartsWith("本机入口暂不可用")) && discovery.PublishStarted > 0);
            Check(probes == 1 && discovery.PublishStarted == 1, "Blocked discovery introduced extra probe or publishing requests");
            wake.Signal(true);
            await Until(() => probes == 2 && sessions.Count == 1 && sessions.First().IsConnected);
            Check(discovery.PublishStarted == 1 && discovery.Reads > 1 && !mapping.Disposed,
                "Slow HTTPS blocked the wake retry, opposite discovery direction or local component startup");
            mapping.FailHelper();
            await Until(() => logs.Any(l => l.StartsWith("映射需要重建")));
            Check(!mapping.Disposed && sessions.First().IsConnected && !sessions.First().Disposed,
                "Helper failure released a mapping still referenced by a healthy business path");
            await Task.Delay(2100); wake.Signal(true);
            await Until(() => mapping.Refreshes == 1);
            Check(probes == 2 && sessions.Count == 1 && discovery.PublishStarted == 1,
                "Wake rebuilt healthy components or bypassed outstanding-request ownership");
            for (int i = 0; i < 500; i++) wake.Signal(false);
            await Task.Delay(300);
            Check(mapping.Refreshes == 1 && !mapping.Disposed, "Notification storm generated repeated helper operations");
            sessions.First().Disconnect();
            await Until(() => sessions.First().Disposed && mapping.Disposed);
        } finally { await Stop(running, stop); }
        Check(discovery.PublishCancelled && discovery.Disposed && sessions.All(s => s.Disposed),
            "Runner stop did not join its pending HTTP request and owned components");
    }

    // A failed initialization must be observed and replaced, not left in a
    // permanently pending state or reported as an established connection.
    using (var stop = new CancellationTokenSource())
    {
        var discovery = new FakeDiscovery { Peer = Peer(1, 1) };
        var sessions = new ConcurrentQueue<FakeSession>(); int remembered = 0;
        var services = Services(discovery, () => {
            var s = sessions.IsEmpty ? new FakeSession((_, _) => throw new IOException("synthetic initialization failure")) : ConnectedSession();
            sessions.Enqueue(s); return s;
        });
        var runner = new NetworkRunner(Profile(2), _ => { }, _ => { }, (entry, _) => remembered = entry, services);
        Task running = runner.Run(stop.Token);
        try
        {
            await Until(() => remembered == 1);
            Check(sessions.Count == 2 && sessions.First().Disposed, "Failed session was not disposed and retried");
            Check(sessions.Last().IsConnected, "Retry was remembered before a real session reported connected");
        }
        finally { await Stop(running, stop); }
    }
    Check(60 / RunnerServices.Default.ConnectingPoll.TotalSeconds * 4 <= 96,
        "Regular connecting polls exceed the deployed metadata rate-limit budget");
    var lines = new List<string>(); var timeline = new ConnectionTimeline(lines.Add);
    timeline.Mark("fixture ready"); await Task.Delay(10); timeline.Mark("fixture connected");
    Check(lines.Count == 2 && lines.All(s => s.Contains("阶段") && s.Contains("累计")), "Stage/total timing evidence missing");
    Console.WriteLine($"PASS {checks}: startup/discovery independence, network wake, retained helper ownership, cancellation, outage, candidate changes, retry and metadata budget. In-memory coordination/sessions and injected OS hints only; no drivers, adapters, firewall rules, live profiles or public traffic.");
}
finally { Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT", null); }

static RunnerServices Services(FakeDiscovery discovery, Func<IStreamSession> create) => new(
    _ => discovery, _ => create(),
    async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new InvalidOperationException(); },
    TimeSpan.FromMilliseconds(30), TimeSpan.FromMilliseconds(30));
static FakeSession ConnectedSession() => new((session, _) => { session.Connect(); return Task.CompletedTask; });

sealed class FakeDiscovery : IDiscoveryClient
{
    public readonly ConcurrentQueue<NodeAnnouncement> Published = new();
    public NodeAnnouncement? Peer;
    public ConcurrentDictionary<int, NodeAnnouncement>? Shared;
    public volatile bool Fail, Disposed;
    public volatile bool BlockPublish, PublishCancelled;
    public int Reads, PublishStarted;
    public async Task Publish(NodeAnnouncement node, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); Interlocked.Increment(ref PublishStarted);
        if (BlockPublish) { try { await Task.Delay(Timeout.Infinite, token); } catch (OperationCanceledException) { PublishCancelled = true; throw; } }
        if (Fail) throw new IOException("synthetic discovery outage"); Published.Enqueue(node); if (Shared != null) Shared[node.Slot] = node;
    }
    public Task<NodeAnnouncement?> Read(int slot, CancellationToken token)
    { token.ThrowIfCancellationRequested(); Interlocked.Increment(ref Reads); if (Fail) throw new IOException("synthetic discovery outage"); return Task.FromResult(Shared?.GetValueOrDefault(slot) ?? Peer); }
    public void Dispose() => Disposed = true;
}
sealed class FakeSession(Func<FakeSession, CancellationToken, Task> start) : IStreamSession
{
    public volatile bool Started, StartExited, Disposed;
    volatile bool connected;
    public bool IsConnected => connected;
    public SessionOptions? Options;
    public event Action<SessionStatus>? StatusChanged;
    public async Task Start(SessionOptions options, CancellationToken cancellation = default, IMapping? preparedMapping = null)
    {
        Options = options; Started = true;
        try { await start(this, cancellation); } finally { StartExited = true; }
    }
    public void Connect() { connected = true; StatusChanged?.Invoke(new("已直连", "", "", "faketcp", true, 1, "fixture")); }
    public void Disconnect() { connected = false; }
    public Task<QualityResult> Measure(int mbps, CancellationToken token) => throw new NotSupportedException();
    public ValueTask DisposeAsync() { if (Started && !StartExited) throw new Exception("Disposed concurrently with Start"); Disposed = true; connected = false; return ValueTask.CompletedTask; }
}
sealed class FakeMapping : IMapping, IMappingRefresh
{
    readonly TaskCompletionSource helper = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public System.Net.IPAddress LocalAddress => System.Net.IPAddress.Parse("192.0.2.10");
    public System.Net.IPEndPoint PublicEndpoint => new(System.Net.IPAddress.Parse("203.0.113.10"), 12345);
    public event Action<System.Net.IPEndPoint>? Changed { add { } remove { } }
    public volatile bool Disposed;
    public int Refreshes;
    public Task Maintain(CancellationToken token) => helper.Task.WaitAsync(token);
    public void FailHelper() => helper.TrySetException(new IOException("helper transaction unusable"));
    public void RequestRefresh() => Interlocked.Increment(ref Refreshes);
    public ValueTask DisposeAsync() { Disposed = true; return ValueTask.CompletedTask; }
}
