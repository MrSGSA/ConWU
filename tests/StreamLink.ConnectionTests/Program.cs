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
            await Until(() => sessions.Count == 2 && sessions.Last().IsConnected);
            Check(sessions.First().Disposed, "Changed endpoint did not release the previous session");
            Check(sessions.Last().Options?.LocalSlot == 1, "Reconnect changed the virtual address identity");
        }
        finally { await Stop(running, stop); }
        Check(sessions.All(s => s.Disposed), "Reconnect cleanup leaked a session");
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
    Console.WriteLine($"PASS {checks}: startup does not block election/heartbeats, mapping independence, cancellation, discovery outage, endpoint changes, startup retry and metadata budget. In-memory coordination/sessions only; no drivers, adapters, firewall rules, live profiles or public traffic.");
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
    public volatile bool Fail, Disposed;
    public int Reads;
    public Task Publish(NodeAnnouncement node, CancellationToken token)
    { token.ThrowIfCancellationRequested(); if (Fail) throw new IOException("synthetic discovery outage"); Published.Enqueue(node); return Task.CompletedTask; }
    public Task<NodeAnnouncement?> Read(int slot, CancellationToken token)
    { token.ThrowIfCancellationRequested(); Interlocked.Increment(ref Reads); if (Fail) throw new IOException("synthetic discovery outage"); return Task.FromResult(Peer); }
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
    public Task<QualityResult> Measure(int mbps, CancellationToken token) => throw new NotSupportedException();
    public ValueTask DisposeAsync() { if (Started && !StartExited) throw new Exception("Disposed concurrently with Start"); Disposed = true; connected = false; return ValueTask.CompletedTask; }
}
