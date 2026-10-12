using System.Net;
using System.Text.Json;
using StreamLink.Core;

static partial class Program
{
    sealed class EnhancementClock : TimeProvider
    {
        long stamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref stamp);
        public void Advance(TimeSpan value) => Interlocked.Add(ref stamp, value.Ticks);
    }
    static async Task EnhancementAdmission(string output)
    {
        var rows = new List<object>();
        try {
            var scheduler = new TraversalEnhancementScheduler(); var generation = Guid.NewGuid();
            TraversalEnhancementScope Scope(int peer) => new("network", "local", "peer-" + peer, generation);
            var first = scheduler.TryEnter(Scope(0), TraversalEnhancementKind.TcpCalibration)!;
            var tokens = Enumerable.Range(1, 7).Select(_ => new CancellationTokenSource()).ToArray();
            var pending = Enumerable.Range(1, 7).Select(i => scheduler.Enter(Scope(i), i % 2 == 0 ? TraversalEnhancementKind.UdpExploration : TraversalEnhancementKind.TcpPrediction, tokens[i - 1].Token)).ToArray();
            Check(scheduler.Usage() is { Active: 1, Waiting: 7, PeakWaiting: 7 } && pending.All(p => !p.IsCompleted), "seven peers across TCP/UDP queue behind one calibration owner");
            Check(scheduler.TryEnter(Scope(99), TraversalEnhancementKind.TcpPrediction) == null, "fresh prediction cannot jump an existing FIFO queue");
            tokens[2].Cancel(); bool canceled = false; try { using var ignored = await pending[2]; } catch (OperationCanceledException) { canceled = true; }
            Check(canceled && scheduler.Usage().Waiting == 6, "queued cancellation removes the peer immediately without owning an endpoint");
            first.Dispose();
            for (int i = 0; i < pending.Length; i++) {
                if (i == 2) continue;
                using var current = await pending[i].WaitAsync(TimeSpan.FromSeconds(1));
                Check(scheduler.Usage().Active == 1 && pending.Skip(i + 1).Where((_, j) => i + 1 + j != 2).All(t => !t.IsCompleted), "one FIFO owner completes before the next TCP/UDP peer is admitted");
            }
            Check(scheduler.Usage() is { Active: 0, Waiting: 0, Granted: 7 }, "all peer operations release the single shared owner");
            rows.Add(new { scenario = "seven-peer-fairness", usage = scheduler.Usage() });
            foreach (var token in tokens) token.Dispose();

            using (var occupied = scheduler.TryEnter(Scope(0), TraversalEnhancementKind.TcpPrediction)!) {
                using var cancellation = new CancellationTokenSource();
                var waiting = Enumerable.Range(0, TraversalEnhancementScheduler.MaximumWaiters).Select(i => scheduler.Enter(Scope(i + 20), TraversalEnhancementKind.TcpCalibration, cancellation.Token)).ToArray();
                bool bounded = false; try { using var ignored = await scheduler.Enter(Scope(99), TraversalEnhancementKind.TcpPrediction, None); } catch (IOException) { bounded = true; }
                Check(bounded && scheduler.Usage().Waiting == 16, "bounded global queue refuses a seventeenth waiter without taking resource quota");
                cancellation.Cancel(); foreach (var task in waiting) try { using var ignored = await task; } catch (OperationCanceledException) { }
                Check(scheduler.Usage() is { Active: 1, Waiting: 0 }, "cancelling a full waiting queue preserves the active operation");
            }
            for (int i = 0; i < 200; i++) {
                var owner = scheduler.TryEnter(Scope(0), TraversalEnhancementKind.TcpCalibration)!;
                using var cancellation = new CancellationTokenSource();
                var waiter = scheduler.Enter(Scope(1), TraversalEnhancementKind.TcpPrediction, cancellation.Token);
                await Task.WhenAll(Task.Run(owner.Dispose), Task.Run(cancellation.Cancel));
                try { using var handedOff = await waiter; } catch (OperationCanceledException) { }
                if (scheduler.Usage() is not { Active: 0, Waiting: 0 }) throw new Exception("grant/cancel leaked admission at iteration " + i);
            }
            Check(true, "200 release/cancel races never leak the awarded lease or leave a queued owner");
            rows.Add(new { scenario = "bounded-queue-cancel-race", iterations = 200, usage = scheduler.Usage() });

            var time = new EnhancementClock(); var cooldown = new TraversalEnhancementScheduler(time);
            var failed = cooldown.TryEnter(Scope(1), TraversalEnhancementKind.UdpExploration)!;
            var alreadyWaiting = cooldown.Enter(Scope(1), TraversalEnhancementKind.UdpExploration, None);
            failed.Failed(); failed.Dispose();
            bool queuedRejected = false; try { using var ignored = await alreadyWaiting; } catch (IOException e) { queuedRejected = e.Message.StartsWith("EnhancementCoolingDown"); }
            Check(queuedRejected && cooldown.Usage().Active == 0, "a UDP attempt queued before failure cannot bypass cooldown at grant time");
            bool Rejected(TraversalEnhancementScope scope) { try { using var ignored = cooldown.TryEnter(scope, TraversalEnhancementKind.UdpExploration); return false; } catch (IOException e) { return e.Message.StartsWith("EnhancementCoolingDown"); } }
            Check(Rejected(Scope(1)), "failed UDP attempt starts five-minute cooldown for the same authenticated pair/generation");
            using (var tcp = cooldown.TryEnter(Scope(1), TraversalEnhancementKind.TcpPrediction)) Check(tcp != null, "UDP failure never substitutes for TCP behavior or blocks independent TCP prediction");
            using (var different = cooldown.TryEnter(Scope(2), TraversalEnhancementKind.UdpExploration)) Check(different != null, "another peer has its own failure history");
            using (var changed = cooldown.TryEnter(Scope(1) with { NetworkGeneration = Guid.NewGuid() }, TraversalEnhancementKind.UdpExploration)) Check(changed != null, "new local egress generation does not reuse an old failure history");
            time.Advance(TimeSpan.FromSeconds(299)); Check(Rejected(Scope(1)), "cooldown does not expire early");
            time.Advance(TimeSpan.FromSeconds(1));
            using (var elapsed = cooldown.TryEnter(Scope(1), TraversalEnhancementKind.UdpExploration)) Check(elapsed != null, "monotonic five-minute expiry permits a new bounded attempt");
            using (var noFailure = cooldown.TryEnter(Scope(1), TraversalEnhancementKind.UdpExploration)) Check(noFailure != null, "releasing an unfailed preparation does not manufacture a NAT failure");
            rows.Add(new { scenario = "protocol-pair-generation-cooldown", clock = "controlled monotonic TimeProvider, not wall-clock waiting", usage = cooldown.Usage() });

            var machine = new TraversalResources(); var context = ProbabilityContext(); int opened = 0;
            using (var tcp = machine.Enhancements.TryEnter(new(context.NetworkId, context.LocalNodeId, context.RemoteNodeId, generation), TraversalEnhancementKind.TcpPrediction)!) {
                bool rejected = false;
                try {
                    await using var udp = new UdpProbabilityPreparation(machine, context, generation, Key(), true, IPAddress.Loopback, null, [40000], 1,
                        _ => { opened++; return new TraversalSocket(new(IPAddress.Loopback, 0)); });
                } catch (IOException) { rejected = true; }
                Check(rejected && opened == 0 && machine.Usage().OpenUdpResources == 0, "actual UDP preparation observes TCP admission before opening any source or expanding its pool");
            }
            await using (var udp = new UdpProbabilityPreparation(machine, context, generation, Key(), true, IPAddress.Loopback, null, [40000], 1,
                _ => { opened++; return new TraversalSocket(new(IPAddress.Loopback, 0)); })) {
                Check(opened == 1 && machine.Enhancements.Usage().Active == 1 && machine.Usage().OpenUdpResources == 1, "actual UDP preparation owns its endpoint and the same cross-protocol admission");
                Check(machine.Enhancements.TryEnter(Scope(9), TraversalEnhancementKind.TcpCalibration) == null, "UDP exploration prevents a simultaneous TCP calibration window");
            }
            Check(machine.Enhancements.Usage() is { Active: 0, Waiting: 0 } && machine.Usage().OpenUdpResources == 0, "unstarted preparation releases high-cost admission and exact socket ownership together");
            foreach (bool cancel in new[] { true, false }) {
                var holder = machine.Enhancements.TryEnter(Scope(0), TraversalEnhancementKind.TcpPrediction)!;
                using var stop = new CancellationTokenSource(); int bound = 0;
                var preparing = UdpProbabilityPreparation.Create(machine, context, generation, Key(), true, IPAddress.Loopback, null, [40000], 1,
                    _ => { bound++; return new TraversalSocket(new(IPAddress.Loopback, 0)); }, stop.Token);
                Check(!preparing.IsCompleted && bound == 0 && machine.Usage().OpenUdpResources == 0 && machine.Enhancements.Usage().Waiting == 1,
                    "actual async UDP preparation queues without binding any socket");
                if (cancel) {
                    stop.Cancel(); bool removed = false;
                    try { await using var ignored = await preparing; } catch (OperationCanceledException) { removed = true; }
                    Check(removed && bound == 0 && machine.Enhancements.Usage() is { Active: 1, Waiting: 0 }, "queued UDP cancellation leaves the active TCP owner and opens no endpoint");
                    holder.Dispose();
                } else {
                    holder.Dispose();
                    await using (var prepared = await preparing.WaitAsync(TimeSpan.FromSeconds(1)))
                        Check(prepared.Armed && bound == 1 && machine.Enhancements.Usage() is { Active: 1, Waiting: 0, Running: TraversalEnhancementKind.UdpExploration },
                            "FIFO handoff transfers the same grant into UDP preparation without a second admission");
                }
                Check(machine.Enhancements.Usage() is { Active: 0, Waiting: 0 } && machine.Usage().OpenUdpResources == 0,
                    "async creation and cancellation release all admission and socket references");
            }
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows, scope = "shared scheduler and real UDP preparation, no public probing, native driver, installed service or configuration change" }, new JsonSerializerOptions { WriteIndented = true }));
        } catch (Exception ex) {
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() }, new JsonSerializerOptions { WriteIndented = true })); throw;
        }
    }
}
