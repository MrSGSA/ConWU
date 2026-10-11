using System.Diagnostics;
using StreamLink.Core;
using StreamLink.Service;

static class OpportunityTests
{
    public static async Task<object> Run(Action<bool, string> check, CancellationToken token)
    {
        var window = new MeshPairOpportunity(); var boot = Guid.NewGuid(); long now = 1000;
        TraversalProfile[] profiles = [TraversalProfile.FakeTcpHttpSo, TraversalProfile.UdpDirect, TraversalProfile.LegacyExplicit];
        check(window.Observe(boot, false, now), "first eligible peer opens one monotonic opportunity before resource admission");
        long deadline = window.Deadline; Guid id = window.Id;
        check(window.Begin(TraversalProfile.FakeTcpHttpSo, now) && window.Next(profiles.Take(2), now + 1) == TraversalProfile.UdpDirect,
            "a failed native collection leaves the first UDP round immediately eligible");
        for (int i = 0; i < 2; i++) foreach (var profile in profiles) if (window.Count(profile) < 2) check(window.Begin(profile, now + 100), "bounded profile allocation " + profile);
        check(profiles.All(p => window.Count(p) == 2 && !window.CanBegin(p, now + 500)) && window.Next(profiles, now + 500) == null,
            "each method stops at two rounds, including compatible entry attempts");
        check(!window.Observe(boot, false, now + 10000) && window.Id == id && window.Deadline == deadline,
            "repeated observations do not renew an open opportunity or reset its counters");
        check(window.End(now + 11000, 1000) && window.Outcome == "NoDirectPathWithinBudget" && window.RetryAt == now + 42000,
            "only the completed opportunity starts the first 30-second background backoff plus jitter");
        check(!window.Observe(boot, false, window.RetryAt - 1) && window.Observe(boot, false, window.RetryAt) && window.Id != id,
            "background retry is a new visible opportunity after its cooldown");
        long tail = window.Deadline - TraversalLimits.SoRoundMs + 1;
        check(!window.CanBegin(TraversalProfile.FakeTcpHttpSo, tail) && window.CanBegin(TraversalProfile.UdpDirect, tail),
            "remaining shared time must fit the chosen complete handshake budget");
        for (int i = 0; i < 5; i++) { window.End(window.Deadline, 0); check(window.RetryAt - window.Deadline <= 300000, "background backoff remains capped"); window.Observe(boot, false, window.RetryAt); }
        check(window.Failures == 5, "repeated unsuccessful opportunities retain their backoff history");
        window.Observe(boot, true, window.Began + 1);
        check(window.Connected && !window.Open && window.Failures == 0, "a proven path ends the foreground operation without killing its resource");
        window.Observe(boot, false, window.Began + 2);
        check(window.Open && window.Count(TraversalProfile.UdpDirect) == 0, "a later path failure opens a fresh bounded recovery opportunity");
        window.End(window.Began + 3, 0); window.Observe(Guid.NewGuid(), false, window.Began + 4);
        check(window.Open && window.Failures == 0, "authenticated peer boot change may invalidate old backoff");

        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var guest = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner))); guest.Directory = owner.Directory;
        await SupersedingOffer(owner, guest, check, token);
        await FastFailures(owner, guest, check, token);
        await Legacy(owner, guest, check, token);
        return await QueuedDeadline(check, token);
    }
    static Dictionary<int, MeshAnnouncement> Announce(MeshProfile peer, MeshTraversalCapabilities caps, string endpoint = "") => new() {
        [peer.Self.Slot] = new(peer.Self.Slot, peer.Self.Device, 1, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), endpoint, "fixture", caps)
    };
    static async Task SupersedingOffer(MeshProfile owner, MeshProfile guest, Action<bool,string> check, CancellationToken token)
    {
        var discovery = new Discovery(); var factory = new Factory();
        await using var router = new MeshRouter(guest, new EmptyAdapter(), discovery.BootId, new(AllowUdpFallback: true));
        await using var manager = new MeshTraversalManager(guest, router, discovery, factory, new(), _ => { }, token);
        var remote = new MeshTraversalCapabilities(1, 1, Guid.NewGuid(), factory.Profiles); var announcements = Announce(owner, remote);
        long sequence = 0, utc = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await using var first = MeshTraversalAttempt.Offer(owner, guest.Self, remote, manager.Capabilities, TraversalProfile.FakeTcpHttpSo,
            new(Guid.NewGuid(), 1, "192.0.2.1:40001", null, utc, utc + 120, CandidatePurpose.Host), 1, () => ++sequence);
        manager.Receive([first.Outbound!]); manager.Tick(announcements, "");
        await using var next = MeshTraversalAttempt.Offer(owner, guest.Self, remote, manager.Capabilities, TraversalProfile.UdpDirect,
            new(Guid.NewGuid(), 1, "192.0.2.1:40002", null, utc, utc + 120, CandidatePurpose.Host), 2, () => ++sequence);
        manager.Receive([next.Outbound!]);
        var watch = Stopwatch.StartNew();
        while (factory.Visited.Count < 2 && watch.ElapsedMilliseconds < 3000) { manager.Tick(announcements, ""); await Task.Delay(10, token); }
        check(factory.Visited.Select(x => x.Kind).SequenceEqual(new[] { TraversalProfile.FakeTcpHttpSo, TraversalProfile.UdpDirect }) && factory.Peak == 1 && factory.Closed == 1,
            "new authenticated Offer supersedes a still-gathering attempt only after its delayed cleanup, even with no Cancel delivery");
        manager.Receive([first.Outbound!]); manager.Tick(announcements, "");
        check(factory.Visited.Count == 2, "old Offer replay cannot reopen the retired attempt");
        await manager.DisposeAsync(); check(factory.Live == 0 && factory.Closed == 2, "superseded and pending resources both join on shutdown");
    }
    static async Task FastFailures(MeshProfile owner, MeshProfile guest, Action<bool,string> check, CancellationToken token)
    {
        var discovery = new Discovery(); var factory = new Factory(fail: true); var logs = new List<string>();
        await using var router = new MeshRouter(owner, new EmptyAdapter(), discovery.BootId, new(AllowUdpFallback: true));
        await using var manager = new MeshTraversalManager(owner, router, discovery, factory, new(), logs.Add, token);
        var announcements = Announce(guest, new(1, 1, Guid.NewGuid(), factory.Profiles));
        var watch = Stopwatch.StartNew();
        while (manager.WaitingDetail(2) == null && watch.ElapsedMilliseconds < 5000) { manager.Tick(announcements, ""); await Task.Delay(10, token); }
        check(factory.Visited.Select(x => x.Kind).SequenceEqual(new[] { TraversalProfile.FakeTcpHttpSo, TraversalProfile.UdpDirect, TraversalProfile.FakeTcpHttpSo, TraversalProfile.UdpDirect }),
            "actual scheduler advances alternating failed methods without per-method background sleep");
        check(manager.WaitingDetail(2)?.Contains("NoDirectPathWithinBudget") == true && logs.Count(s => s.Contains("进入后台退避")) == 1,
            "exhausted pair reports one bounded outcome instead of extending or silently resetting its operation");
        for (int i = 0; i < 20; i++) { manager.Tick(announcements, ""); await Task.Delay(10, token); }
        check(factory.Visited.Count == 4 && factory.Live == 0 && !manager.Owns(2), "cooldown and resource cleanup prevent an immediate fifth attempt");
    }
    static async Task Legacy(MeshProfile owner, MeshProfile guest, Action<bool,string> check, CancellationToken token)
    {
        var discovery = new Discovery(); var factory = new Factory();
        await using var router = new MeshRouter(owner, new EmptyAdapter(), discovery.BootId);
        await using var manager = new MeshTraversalManager(owner, router, discovery, factory, new(), _ => { }, token);
        var announcements = Announce(guest, new(1, 1, Guid.NewGuid(), factory.Profiles), "192.0.2.10:40000");
        manager.Tick(announcements, ""); int creations = 0;
        using var paths = new MeshPeerTransports(router, _ => { creations++; throw new IOException("fixture legacy creation failure"); }, _ => { });
        for (int i = 0; i < 3; i++) paths.Update(2, "192.0.2.10:" + (40000 + i), "fixture", "test", () => manager.BeginLegacyAttempt(2));
        check(creations == 2, "endpoint refresh cannot bypass the compatible method's two-round allocation");
        manager.Tick(announcements, "");
        check(factory.Visited.Count == 1 && factory.Visited[0].Kind == TraversalProfile.FakeTcpHttpSo,
            "exhausted failed explicit entries yield promptly to native traversal instead of idling for 15 seconds");
    }
    static async Task<object> QueuedDeadline(Action<bool,string> check, CancellationToken token)
    {
        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var peers = Enumerable.Range(0, 7).Select(_ => MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)))).ToArray();
        var discovery = new Discovery(); var factory = new Factory(udpOnly: true); var logs = new List<string>();
        await using var router = new MeshRouter(owner, new EmptyAdapter(), discovery.BootId, new(AllowUdpFallback: true));
        await using var manager = new MeshTraversalManager(owner, router, discovery, factory, new(), logs.Add, token);
        var announcements = peers.ToDictionary(p => p.Self.Slot, p => Announce(p, new(1, 0, Guid.NewGuid(), factory.Profiles)).Single().Value);
        var clock = Stopwatch.StartNew(); manager.Tick(announcements, "");
        check(factory.Live == 2 && factory.Visited.Count == 2, "two occupied slots leave five peers queued inside their own already-running deadlines");
        while (clock.ElapsedMilliseconds < 65000 && (logs.Count(s => s.Contains("进入后台退避")) < 7 || factory.Live != 0)) {
            manager.Tick(announcements, ""); await Task.Delay(25, token);
        }
        for (int i = 0; i < 12; i++) { manager.Tick(announcements, ""); await Task.Delay(25, token); }
        check(logs.Count(s => s.Contains("进入后台退避")) == 7 && peers.All(p => manager.WaitingDetail(p.Self.Slot) != null),
            "all seven real scheduler opportunities finish within their original deadline; queued peers stop when a complete round no longer fits");
        check(factory.Visited.Count == 2 && factory.Closed == 2 && factory.Live == 0 && peers.All(p => !manager.Owns(p.Self.Slot)),
            "expiry cancels and joins the held preparations without starting fresh work beyond the opportunity");
        return new { scenario = "bounded-foreground-opportunities", wallMs = clock.ElapsedMilliseconds, peers = 7, realTimer = true,
            gathered = factory.Visited.Count, closed = factory.Closed, outcomes = logs.Where(s => s.Contains("进入后台退避")).ToArray(),
            realNat = false, nativeDriver = false, scope = "production scheduler and legacy client admission with controlled failing/held preparation; no real 8-device claim" };
    }
    sealed class Factory(bool fail = false, bool udpOnly = false) : IMeshCandidateFactory {
        public readonly List<(int Slot, TraversalProfile Kind)> Visited = []; public int Live, Peak, Closed;
        public TraversalProfile[] Profiles => udpOnly ? [TraversalProfile.UdpDirect] : [TraversalProfile.FakeTcpHttpSo, TraversalProfile.UdpDirect];
        public async Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile profile, Guid attempt, CancellationToken token) {
            Visited.Add((peer.Slot, profile)); int live = Interlocked.Increment(ref Live); Peak = Math.Max(Peak, live);
            try { if (fail) throw new IOException("fixture gather failure"); await Task.Delay(Timeout.Infinite, token); throw new InvalidOperationException(); }
            finally { await Task.Delay(150); Interlocked.Increment(ref Closed); Interlocked.Decrement(ref Live); }
        }
    }
    sealed class Discovery : IMeshTraversalDiscovery {
        public Guid BootId { get; } = Guid.NewGuid(); public bool SupportsTraversal => true;
        public Task PublishTraversal(MeshTraversalMessage[] messages, CancellationToken token) => Task.CompletedTask;
    }
    sealed class EmptyAdapter : IPacketAdapter {
        public int Read(byte[] buffer) { Thread.Sleep(10); return 0; }
        public bool Write(byte[] packet) => true;
        public void Dispose() { }
    }
}
