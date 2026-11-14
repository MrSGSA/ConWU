using System.Diagnostics;
using StreamLink.Core;

namespace StreamLink.Discovery;

public sealed partial class MeshRegistry
{
    sealed class Account
    {
        public double Tokens = 8;
        public long Tick = Stopwatch.GetTimestamp();
        public bool Waiting;
        public readonly Dictionary<Guid, long> Requests = [];
    }
    sealed class Feed
    {
        public long Cursor;
        public readonly Queue<MeshChange> Changes = [];
        public readonly Dictionary<int, Account> Accounts = [];
        public readonly Dictionary<ControlKey, ControlState> Control = [];
        public readonly Dictionary<Guid, SeenControl> ControlIds = [];
        public TaskCompletionSource Changed = NewSignal();
    }
    static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly Guid serverEpoch = Guid.NewGuid();
    readonly Dictionary<string, Feed> feeds = [];
    int waiters;
    Feed State(string network)
    {
        if (!feeds.TryGetValue(network, out var feed)) feeds[network] = feed = new();
        return feed;
    }
    Account MemberAccount(string network, int slot)
    {
        var feed = State(network);
        if (!feed.Accounts.TryGetValue(slot, out var account)) feed.Accounts[slot] = account = new();
        return account;
    }
    // Invoked under the registry gate, after authentication. The network-wide
    // 512/minute HTTP limit remains independent of this 48/minute + 8 burst cap.
    bool TakeRequest(string network, int slot)
    {
        var account = MemberAccount(network, slot); long now = Stopwatch.GetTimestamp();
        account.Tokens = Math.Min(8, account.Tokens + Stopwatch.GetElapsedTime(account.Tick, now).TotalSeconds * .8);
        account.Tick = now;
        if (account.Tokens < 1) return false;
        account.Tokens--; return true;
    }
    void Changed(string network, string kind, int slot, int targetSlot = 0)
    {
        var feed = State(network);
        feed.Changes.Enqueue(new(++feed.Cursor, kind, slot, targetSlot));
        while (feed.Changes.Count > TraversalLimits.EventQueueSize) feed.Changes.Dequeue();
        var signal = feed.Changed; feed.Changed = NewSignal(); signal.TrySetResult();
        if (kind == "directory") {
            var slots = networks[network].Directory.Members.Select(m => m.Slot).ToHashSet();
            foreach (int removed in feed.Accounts.Keys.Where(s => !slots.Contains(s)).ToArray()) feed.Accounts.Remove(removed);
            foreach (var key in feed.Control.Keys.Where(k => !slots.Contains(k.From) || !slots.Contains(k.To)).ToArray()) feed.Control.Remove(key);
        }
    }
    MeshSnapshot Snapshot(string network, Registration registration, int slot, Guid boot)
    {
        var found = registration.Directory.Members.Select(m => nodes.GetValueOrDefault(network + "/" + m.Slot))
            .Where(n => n.Envelope != null && n.Expires > DateTimeOffset.UtcNow).Select(n => n.Envelope).ToArray();
        var feed = State(network); PruneControl(feed);
        var messages = feed.Control.Where(p => p.Key.To == slot && p.Key.ToBoot == boot).Select(p => p.Value.Message).ToArray();
        return new(registration.Directory, found, messages, MeshTraversal.Version, UdpIpv6: 1, FakeTcpIpv6: 1, TcpPrediction: 1, TcpPeerReflexive: 1, UdpExploration: 1, QualityFeedback: 1, StandbyPaths: 1,PathDiagnostics:1,AutoQuality:1,DiagnosticTiming:1);
    }
    public async Task<IResult> Watch(HttpContext context, string network, MeshWatchRequest request)
    {
        Account account; Feed feed;
        lock (gate) {
            // A missing network on a new server is not an unsupported API.
            if (!networks.TryGetValue(network, out var registration)) return Results.StatusCode(412);
            if (!Equal(Auth(context), registration.AuthHash)) return Results.Unauthorized();
            var member = registration.Directory.Members.FirstOrDefault(m => m.Slot == request.Slot);
            if (member == null) return Results.StatusCode(403);
            try { if (!MeshWatch.Validate(network, member, request)) return Results.StatusCode(403); }
            catch { return Results.BadRequest(); }
            account = MemberAccount(network, request.Slot); feed = State(network);
            if (!TakeRequest(network, request.Slot)) return Results.StatusCode(429);
            clients?.Observe(member.Device,"",network,"网络发现");
            long utc = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            foreach (Guid id in account.Requests.Where(p => p.Value <= utc).Select(p => p.Key).ToArray()) account.Requests.Remove(id);
            if (account.Requests.ContainsKey(request.RequestId)) return Results.Conflict();
            if (account.Waiting) return Results.Conflict();
            if (waiters >= TraversalLimits.GlobalWaiters) return Results.StatusCode(503);
            if (account.Requests.Count >= TraversalLimits.EventQueueSize) return Results.StatusCode(429);
            account.Requests[request.RequestId] = request.Expires; account.Waiting = true; waiters++;
        }
        var watch = Stopwatch.StartNew(); bool elapsed = false, batched = false;
        try {
            while (true) {
                Task signal; MeshWatchResponse? response = null;
                lock (gate) {
                    var registration = networks[network];
                    if (!registration.Directory.Members.Any(m => m.Slot == request.Slot && m.Device == request.Device)) return Results.StatusCode(403);
                    bool reset = request.ServerEpoch != serverEpoch || request.After > feed.Cursor ||
                        feed.Changes.TryPeek(out var first) && request.After < first.Cursor - 1;
                    var changes = feed.Changes.Where(c => c.Cursor > request.After &&
                        (c.TargetSlot != 0 ? c.TargetSlot == request.Slot : c.Slot == 0 || c.Slot != request.Slot)).ToArray();
                    if (reset || elapsed || changes.Length > 0)
                        response = new(serverEpoch, feed.Cursor, reset, changes, Snapshot(network, registration, request.Slot, request.BootId));
                    signal = feed.Changed.Task;
                }
                if (response != null) {
                    // Coalesce nearby member publications into one bounded reply.
                    if (!response.Reset && !elapsed && !batched && !response.Changes.Any(c => c.Kind == "traversal")) { batched = true; await Task.Delay(100, context.RequestAborted); continue; }
                    return Results.Json(response);
                }
                TimeSpan remaining = TimeSpan.FromSeconds(TraversalLimits.LongPollHoldSeconds) - watch.Elapsed;
                if (remaining <= TimeSpan.Zero) { elapsed = true; continue; }
                try { await signal.WaitAsync(remaining, context.RequestAborted); }
                catch (TimeoutException) { elapsed = true; }
            }
        } finally { lock (gate) { account.Waiting = false; waiters--; } }
    }
}
