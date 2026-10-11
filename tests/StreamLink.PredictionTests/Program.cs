using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

if (args is not ["--output", _]) throw new ArgumentException("--output result.json");
string output = Path.GetFullPath(args[1]); Directory.CreateDirectory(Path.GetDirectoryName(output)!);
var clock = new Clock(); int checks = 0; var rows = new List<object>();
void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
var scope = new PortPredictionScope(Guid.NewGuid(), "controlled-interface", "10.200.0.2", TraversalProfile.FakeTcpHttpSo);
PortAllocationWindow[] Windows(Func<int, (int Before, int After)> allocation, PortPredictionScope? selected = null)
{
    var context = selected ?? scope;
    return Enumerable.Range(0, 20).Select(i => {
        var ports = allocation(i); Guid resource = Guid.NewGuid(), owner = context.Profile == TraversalProfile.FakeTcpHttpSo ? Guid.NewGuid() : Guid.Empty;
        var kind = context.Profile == TraversalProfile.FakeTcpHttpSo ? PortAllocationEvidence.NativeSynObserved : PortAllocationEvidence.UdpStunObserved;
        var before = new PortAllocationSample(resource, Guid.NewGuid(), context.SourceAddress + ":" + (42000 + i), "198.51.100.10:47221", "192.0.2.2:" + ports.Before,
            clock.GetUtcNow().AddSeconds(-80 + i * 3), true, kind, owner);
        return new PortAllocationWindow(Guid.NewGuid(), context, before, before with { ObservationId = Guid.NewGuid(), Target = "198.51.100.10:47222", Mapped = "192.0.2.2:" + ports.After, ObservedAt = before.ObservedAt.AddMilliseconds(500) }, i % 3 == 0 ? 1 : 0);
    }).ToArray();
}
NatPortPrediction Fit(PortAllocationWindow[] windows, string expected)
{
    var model = NatPortPrediction.Fit(windows, out var assessment, clock);
    Check(model != null && assessment.Model == expected && assessment.ValidationWindows >= 10 && assessment.ValidationHits * 10 >= assessment.ValidationWindows * 9,
        "frozen " + expected + " model passes independent chronological holdout including interference");
    rows.Add(assessment); return model!;
}
void Reject(PortAllocationWindow[] windows, string why)
{
    Check(NatPortPrediction.Fit(windows, out var report, clock) == null && report.State == "PredictionNotSupported", why);
}
PortAllocationSample Anchor(int number = 0) => new(Guid.NewGuid(), Guid.NewGuid(), scope.SourceAddress + ":" + (44000 + number), "198.51.100.11:47221", "192.0.2.2:46000", clock.GetUtcNow(), true, PortAllocationEvidence.NativeSynObserved, Guid.NewGuid(), clock.GetTimestamp());
try {
    var regular = Windows(i => (40000 + i * 14, 40007 + i * 14));
    var model = Fit(regular, "fixed-step");
    Fit(Windows(i => (42000 + i, 42000 + i)), "preserved-local-port");
    Fit(Windows(i => (43000, 43000)), "stable-observed-port");
    var block = Fit(Windows(i => (40000 + i % 8, 40000 + (i * 5 + 3) % 8)), "observed-port-block");
    var noisy = Fit(Windows(i => (40000 + i * 30, 40000 + i * 30 + (i % 3 == 0 ? 14 : 7))), "fixed-step");
    Check(noisy.Assessment.MaximumPorts == 2, "background-consumption envelope is bounded to two trained step candidates");
    Reject(regular.Take(19).ToArray(), "nineteen windows cannot enable a predictor");
    Reject(regular.Concat(regular).ToArray(), "replayed window IDs cannot inflate independent sample count");
    Reject(regular.Select((w, i) => i == 19 ? w with { Scope = w.Scope with { Profile = TraversalProfile.UdpDirect } } : w).ToArray(), "TCP and UDP evidence cannot be pooled");
    Reject(regular.Select((w, i) => i == 19 ? w with { Scope = w.Scope with { NetworkGeneration = Guid.NewGuid() } } : w).ToArray(), "route generation cannot be pooled");
    Reject(regular.Select(w => w with { ObservedBackgroundAllocations = 0 }).ToArray(), "training without an interference experiment stays disabled");
    Reject(regular.Select((w, i) => i >= 10 ? w with { ObservedBackgroundAllocations = 0 } : w).ToArray(), "interference must also appear in the held-out half");
    Reject(regular.Select(w => w with { ObservedBackgroundAllocations = 1 }).ToArray(), "interference-only fitting cannot claim a quiet-baseline model");
    Reject(regular.Select(w => w with { Before = w.Before with { Evidence = PortAllocationEvidence.KernelTcpStun } }).ToArray(), "kernel TCP STUN cannot substitute for native allocation evidence");
    Reject(regular.Select((w, i) => i == 19 ? w with { Before = w.Before with { NewDestination = false } } : w).ToArray(), "a reused mapping does not measure a fresh allocation");
    Reject(regular.Select((w, i) => i == 19 ? w with { After = w.After with { ResourceId = Guid.NewGuid() } } : w).ToArray(), "one sample transition requires the same held resource");
    Reject(regular.Select((w, i) => i == 19 ? w with { After = w.After with { Mapped = "192.0.2.3:45000" } } : w).ToArray(), "changing public IP rejects single-pool prediction");
    Reject(regular.Select((w, i) => i == 19 ? w with { After = w.After with { ObservedAt = w.Before.ObservedAt.AddSeconds(3) } } : w).ToArray(), "a delayed transition cannot train a two-second forecast");
    Reject(Windows(i => (40000 + i * 100, 40000 + i * 100 + (i < 10 ? 7 : 19))), "perfect training fit with a changed held-out step cannot enable or refit on holdout");
    var atThreshold = Windows(i => (40000 + i * 100, 40000 + i * 100 + (i == 19 ? 100 : 7)));
    Fit(atThreshold, "fixed-step");
    Reject(atThreshold.Select((w, i) => i == 18 ? w with { After = w.After with { Mapped = "192.0.2.2:62000" } } : w).ToArray(), "eight of ten held-out hits fail the 90 percent threshold");

    var anchor = Anchor(); bool alive = true;
    Check(!model.TryForecast(scope, anchor, () => alive, false, out _, out var why) && why == "PredictionDisabled", "explicit experiment opt-in is required even for a qualified model");
    Check(!model.TryForecast(scope, anchor with { ProbeStartedAt = clock.GetTimestamp() - 3 * clock.TimestampFrequency }, () => alive, true, out _, out why) && why == "StaleOrInvalidAnchor", "fresh-looking server timestamps cannot rejuvenate an old local probe");
    Check(!model.TryForecast(scope, anchor with { ProbeStartedAt = 0 }, () => alive, true, out _, out _), "legacy observations without a local monotonic start cannot authorize a forecast");
    Check(!model.TryForecast(scope, anchor with { ObservedAt = clock.GetUtcNow().AddMilliseconds(1) }, () => alive, true, out _, out _), "future observations are rejected instead of extending prediction lifetime");
    Check(model.TryForecast(scope, anchor, () => alive, true, out var forecast, out _) && forecast!.Ports.SequenceEqual(new[] { 46007 }), "forecast preserves public address and predicts only the learned next port");
    Check(!model.TryClaim(Guid.NewGuid()) && model.TryClaim(forecast!.Id) && !model.TryClaim(forecast.Id), "forecast can be claimed only once by its exact ID");
    model.Finish(forecast!.Id, PredictionOutcome.Failed);
    Check(!model.TryForecast(scope, anchor, () => alive, true, out _, out _), "the same anchor cannot repeatedly scan the same window");
    Check(model.TryForecast(scope, Anchor(1), () => alive, true, out forecast, out _) && model.TryClaim(forecast!.Id), "one failed actual attempt permits a second fresh forecast");
    model.Finish(forecast!.Id, PredictionOutcome.Failed);
    Check(!model.TryForecast(scope, Anchor(2), () => alive, true, out _, out why) && why == "PredictionInvalidated", "two consecutive failed actual attempts disable this model");

    var edge = Fit(regular, "fixed-step");
    Check(!edge.TryForecast(scope, Anchor(8) with { Mapped = "192.0.2.2:65535" }, () => true, true, out _, out why) && why == "PredictionOutOfRange",
        "port range overflow never invents an unobserved modulo or port pool");
    var reset = Fit(regular, "fixed-step");
    int trialNumber = 100;
    foreach (var outcome in new[] { PredictionOutcome.Failed, PredictionOutcome.PathAuthenticated, PredictionOutcome.Failed, PredictionOutcome.Cancelled }) {
        if (!reset.TryForecast(scope, Anchor(trialNumber++), () => true, true, out var trial, out _) || !reset.TryClaim(trial!.Id)) throw new Exception("success/cancel reset admission");
        reset.Finish(trial.Id, outcome); reset.Finish(trial.Id, PredictionOutcome.Failed);
    }
    Check(reset.TryForecast(scope, Anchor(10), () => true, true, out _, out _), "authenticated success resets consecutive failure count; cancellation and duplicate results do not add failures");

    model = Fit(regular, "fixed-step");
    Check(model.TryForecast(scope, Anchor(3), () => alive, true, out forecast, out _), "fresh predictor creates a resource-bound pending forecast");
    alive = false; Check(!model.TryClaim(forecast!.Id), "source closure prevents claim even if address and port digits are unchanged"); alive = true;
    Check(model.TryForecast(scope, Anchor(4), () => alive, true, out forecast, out _), "closed unused forecast releases its pending slot");
    clock.Advance(TimeSpan.FromSeconds(3)); Check(!model.TryClaim(forecast!.Id), "monotonic expiry forbids delayed attempts");
    clock.ShiftUtc(TimeSpan.FromMinutes(-1));
    Check(!model.TryClaim(forecast.Id), "wall-clock rollback cannot revive an expired forecast");
    clock.ShiftUtc(TimeSpan.FromMinutes(1));
    Check(model.TryForecast(scope, Anchor(5), () => alive, true, out forecast, out _), "expired unused forecasts allow a new fresh observation");
    model.Invalidate(); Check(!model.TryClaim(forecast!.Id), "explicit network invalidation revokes a pending forecast");
    model = Fit(regular, "fixed-step");
    Check(!model.TryForecast(scope with { NetworkGeneration = Guid.NewGuid() }, Anchor(6), () => alive, true, out _, out _) &&
        !model.TryForecast(scope, Anchor(7), () => alive, true, out _, out _), "observing a route generation change permanently retires the old model");

    // Independent seeded negative allocations: this checks false model admission,
    // not birthday-hole-punch success. No public traffic or mapping claims.
    int acceptedRandom = 0;
    for (int seed = 0; seed < 1000; seed++) {
        var rng = new Random(seed);
        var random = Windows(_ => (rng.Next(1024, 65536), rng.Next(1024, 65536)));
        if (NatPortPrediction.Fit(random, out _, clock) != null) acceptedRandom++;
    }
    Check(acceptedRandom == 0, "1000 independent random allocation seeds do not meet the held-out model gate");
    rows.Add(new { randomAllocationSeeds = 1000, admittedModels = acceptedRandom, interpretation = "predictor false admission fixture, not NAT traversal success probability" });

    var nativeWindow = regular[0];
    TcpShapeObservation Native(PortAllocationSample s) => new(s.ResourceId, scope.NetworkGeneration, s.Local, "198.51.100.12:3478", s.ObservationId,
        s.Target, s.Mapped, s.ObservedAt.ToUnixTimeMilliseconds(), nativeWindow.Before.ObservedAt.AddSeconds(68).ToUnixTimeMilliseconds(), "SynObserved",
        CaptureOwnerId: s.CaptureOwnerId, InterfaceId: scope.InterfaceId, ProbeWindowEndsAt: nativeWindow.Before.ObservedAt.AddSeconds(8).ToUnixTimeMilliseconds());
    var native = new[] { Native(nativeWindow.Before), Native(nativeWindow.After),
        Native(nativeWindow.After with { ObservationId = Guid.NewGuid(), Target = "198.51.100.11:47221", ObservedAt = nativeWindow.After.ObservedAt.AddMilliseconds(400) }),
        Native(nativeWindow.After with { ObservationId = Guid.NewGuid(), Target = "198.51.100.11:47222", ObservedAt = nativeWindow.After.ObservedAt.AddMilliseconds(800) }) };
    var converted = TcpPredictionEvidence.Windows(native);
    Check(converted.Length == 1 && converted[0].ObservedBackgroundAllocations == 0, "four destinations in one native observer ticket count as one window, without invented interference evidence");
    Check(TcpPredictionEvidence.Windows(native.Select(o => o with { InterfaceId = "Unknown" }).ToArray()).Length == 0 &&
        TcpPredictionEvidence.Windows(native.Select(o => o with { State = "Ambiguous" }).ToArray()).Length == 0, "unknown interface and ambiguous SYN correlation cannot train a predictor");
    Check(TcpPredictionEvidence.Windows(native.Select((o, i) => i == 0 ? o with { CaptureOwnerId = Guid.NewGuid() } : o).ToArray()).Length == 0,
        "native evidence from different capture owners cannot form one allocation window");
    await UdpModel.Run(Check, rows);
    await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows,
        scope = "deterministic allocation evidence and in-memory NAT running real UdpTraversal/MeshLink; no public NAT, native TCP I/O, physical Windows or Wintun" }, new JsonSerializerOptions { WriteIndented = true }));
} catch (Exception ex) { await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() }, new JsonSerializerOptions { WriteIndented = true })); throw; }

sealed class Clock : TimeProvider
{
    DateTimeOffset utc = new(2026, 10, 12, 0, 0, 0, TimeSpan.Zero); long ticks = 1000000000;
    public override DateTimeOffset GetUtcNow() => utc;
    public override long GetTimestamp() => ticks;
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public void Advance(TimeSpan delta) { utc += delta; ticks += delta.Ticks; }
    public void ShiftUtc(TimeSpan delta) { utc += delta; }
}
