using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// These are allocation observations, not NAT labels or reachability proofs.
// TCP kernel/STUN samples must not be passed off as native FakeTCP samples.
public sealed record PortPredictionScope(Guid NetworkGeneration, string InterfaceId, string SourceAddress, TraversalProfile Profile);
public enum PortAllocationEvidence { Unknown, NativeSynObserved, UdpStunObserved, KernelTcpStun }
public sealed record PortAllocationSample(Guid ResourceId, Guid ObservationId, string Local, string Target, string Mapped,
    DateTimeOffset ObservedAt, bool NewDestination, PortAllocationEvidence Evidence, Guid CaptureOwnerId = default, long ProbeStartedAt = 0);
public sealed record PortAllocationWindow(Guid WindowId, PortPredictionScope Scope, PortAllocationSample Before,
    PortAllocationSample After, int ObservedBackgroundActivity);
public sealed record PortPredictionAssessment(string State, string Reason, string Model, int TrainingWindows,
    int ValidationWindows, int TrainingHits, int ValidationHits, int TrainingInterference, int ValidationInterference,
    int MaximumPorts, Guid ModelId);
public enum PredictionOutcome { PathAuthenticated, Failed, Cancelled }

// Immutable, local-only forecast. Publishing guesses requires a separately
// negotiated authenticated candidate extension; this is not a public endpoint.
public sealed class PortForecast
{
    public Guid Id { get; } = Guid.NewGuid();
    public Guid ModelId { get; }
    public Guid ResourceId { get; }
    public string Address { get; }
    public IReadOnlyList<int> Ports { get; }
    internal PortForecast(Guid model, PortAllocationSample sample, int[] ports)
    { ModelId = model; ResourceId = sample.ResourceId; Address = IPEndPoint.Parse(sample.Mapped).Address.ToString(); Ports = Array.AsReadOnly((int[])ports.Clone()); }
}

public sealed class NatPortPrediction
{
    public const int MinimumWindows = TraversalLimits.PredictionWindows, MaximumWindows = TraversalLimits.PredictionWindowLimit,
        MaximumPorts = TraversalLimits.PredictionPorts, MaximumAgeMs = TraversalLimits.PredictionAgeMs;
    readonly object gate = new();
    readonly TimeProvider time;
    readonly PortPredictionScope scope;
    readonly Rule rule;
    readonly string publicAddress;
    readonly HashSet<Guid> consumedObservations = [];
    readonly HashSet<string> knownTuples;
    bool retired;
    int failed;
    Pending? pending;
    public PortPredictionAssessment Assessment { get; }
    sealed record Pending(PortForecast Forecast, Func<bool> ResourceAlive, long Began, TimeSpan Life) { public bool Consumed; }
    sealed record Rule(string Kind, int Step = 0, int Width = 1, int Offset = 0, int[]? Blocks = null)
    {
        public int[] Ports(PortAllocationSample sample)
        {
            int current = IPEndPoint.Parse(sample.Mapped).Port;
            if (Kind == "preserved-local-port") return [IPEndPoint.Parse(sample.Local).Port];
            if (Kind == "stable-observed-port") return [current];
            if (Kind == "fixed-step") return Enumerable.Range(1, Width).Select(n => current + n * Step).Where(p => p is >= 1024 and <= 65535).ToArray();
            int block = (current - Offset) / Width * Width + Offset;
            // A learned block is a local allocation range, not proof of a
            // device-wide port pool or a pattern at an unobserved boundary.
            return Blocks!.Contains(block) ? Enumerable.Range(block, Width).Where(p => p is >= 1024 and <= 65535).ToArray() : [];
        }
    }
    NatPortPrediction(PortPredictionScope scope, Rule rule, string address, PortPredictionAssessment assessment,
        IEnumerable<PortAllocationWindow> windows, TimeProvider time)
    {
        this.scope = scope; this.rule = rule; publicAddress = address; Assessment = assessment; this.time = time;
        knownTuples = windows.SelectMany(w => new[] { TupleKey(w.Before), TupleKey(w.After) }).ToHashSet();
    }
    static string TupleKey(PortAllocationSample sample) => sample.Local + "/" + sample.Target;
    static bool Endpoint(string? text, out IPEndPoint ep)
    {
        ep = null!;
        return text is { Length: >= 3 and <= 64 } && IPEndPoint.TryParse(text, out ep!) && ep.AddressFamily == AddressFamily.InterNetwork &&
            ep.Port is >= 1024 and <= 65535 && ep.Address.GetAddressBytes()[0] is > 0 and < 224 && !ep.Address.Equals(IPAddress.Broadcast);
    }
    static bool ValidScope(PortPredictionScope? s) => s != null && s.NetworkGeneration != Guid.Empty && s.InterfaceId is { Length: >= 1 and <= 128 } &&
        !s.InterfaceId.Any(char.IsControl) && Endpoint(s.SourceAddress + ":1024", out _) && s.Profile is TraversalProfile.FakeTcpHttpSo or TraversalProfile.UdpDirect;
    static bool ValidSample(PortAllocationSample? s, PortPredictionScope scope, DateTimeOffset now) => s != null &&
        s.ResourceId != Guid.Empty && s.ObservationId != Guid.Empty && s.NewDestination &&
        (scope.Profile == TraversalProfile.FakeTcpHttpSo ? s.Evidence == PortAllocationEvidence.NativeSynObserved && s.CaptureOwnerId != Guid.Empty
            : s.Evidence == PortAllocationEvidence.UdpStunObserved && s.CaptureOwnerId == Guid.Empty) &&
        Endpoint(s.Local, out var local) && local.Address.ToString() == scope.SourceAddress && Endpoint(s.Target, out _) && Endpoint(s.Mapped, out _) &&
        s.ObservedAt > DateTimeOffset.UnixEpoch && s.ObservedAt <= now;
    public static NatPortPrediction? Fit(IReadOnlyList<PortAllocationWindow> windows, out PortPredictionAssessment assessment, TimeProvider? clock = null)
    {
        clock ??= TimeProvider.System;
        PortPredictionAssessment Reject(string reason) => new("PredictionNotSupported", reason, "", 0, 0, 0, 0, 0, 0, 0, Guid.Empty);
        assessment = Reject("insufficient-independent-windows");
        if (windows.Count < MinimumWindows) return null;
        if (windows.Count > MaximumWindows) { assessment = Reject("window-limit"); return null; }
        var first = windows[0];
        if (first == null || !ValidScope(first.Scope)) { assessment = Reject("invalid-scope"); return null; }
        var scope = first.Scope; var now = clock.GetUtcNow();
        var windowIds = new HashSet<Guid>(); var observations = new HashSet<Guid>(); var tuples = new HashSet<string>();
        DateTimeOffset previous = DateTimeOffset.MinValue; string? address = null;
        foreach (var w in windows) {
            if (w == null || w.Scope != scope || w.WindowId == Guid.Empty || !windowIds.Add(w.WindowId) ||
                !ValidSample(w.Before, scope, now) || !ValidSample(w.After, scope, now) ||
                w.Before.ResourceId != w.After.ResourceId || w.Before.CaptureOwnerId != w.After.CaptureOwnerId || w.Before.Local != w.After.Local || w.Before.Target == w.After.Target ||
                w.Before.ObservedAt <= previous || w.After.ObservedAt <= w.Before.ObservedAt ||
                (w.After.ObservedAt - w.Before.ObservedAt).TotalMilliseconds > MaximumAgeMs ||
                w.ObservedBackgroundActivity is < 0 or > 1024 ||
                !observations.Add(w.Before.ObservationId) || !observations.Add(w.After.ObservationId) ||
                !tuples.Add(TupleKey(w.Before)) || !tuples.Add(TupleKey(w.After))) {
                assessment = Reject("mixed-replayed-reused-or-unordered-evidence"); return null;
            }
            string before = IPEndPoint.Parse(w.Before.Mapped).Address.ToString(), after = IPEndPoint.Parse(w.After.Mapped).Address.ToString();
            address ??= before;
            if (before != address || after != address) { assessment = Reject("public-address-pool-changed"); return null; }
            previous = w.After.ObservedAt;
        }
        // Chronological split. No held-out value chooses a model, parameter,
        // window size or a second model after a failed validation result.
        int count = windows.Count / 2;
        var train = windows.Take(count).ToArray(); var validation = windows.Skip(count).ToArray();
        int trainNoise = train.Count(w => w.ObservedBackgroundActivity > 0), validationNoise = validation.Count(w => w.ObservedBackgroundActivity > 0);
        if (trainNoise == 0 || validationNoise == 0 || trainNoise == train.Length || validationNoise == validation.Length) { assessment = Reject("missing-baseline-or-interference-observations"); return null; }
        var rules = new List<Rule> { new("preserved-local-port"), new("stable-observed-port") };
        foreach (int step in train.Select(w => IPEndPoint.Parse(w.After.Mapped).Port - IPEndPoint.Parse(w.Before.Mapped).Port).Where(d => d != 0 && Math.Abs(d) <= 4096).Distinct().Order())
            for (int width = 1; width <= MaximumPorts; width++) rules.Add(new("fixed-step", step, width));
        foreach (int width in new[] { 2, 4, 8 }) for (int offset = 0; offset < width; offset++) {
            int[] blocks = train.Select(w => (IPEndPoint.Parse(w.Before.Mapped).Port - offset) / width * width + offset).Distinct().ToArray();
            rules.Add(new("observed-port-block", Width: width, Offset: offset, Blocks: blocks));
        }
        int Hits(Rule r, IEnumerable<PortAllocationWindow> data) => data.Count(w => r.Ports(w.Before).Contains(IPEndPoint.Parse(w.After.Mapped).Port));
        var best = rules.Select(r => (Rule: r, Hits: Hits(r, train))).OrderByDescending(r => r.Hits).ThenBy(r => r.Rule.Width).First();
        int held = Hits(best.Rule, validation); bool supported = best.Hits * 10 >= train.Length * 9 && held * 10 >= validation.Length * 9;
        assessment = new(supported ? "QualifiedLocalModel" : "PredictionNotSupported", supported ? "held-out-coverage-only-not-path-success" : "held-out-or-training-coverage-below-90-percent",
            best.Rule.Kind, count, validation.Length, best.Hits, held, trainNoise, validationNoise, best.Rule.Width, supported ? Guid.NewGuid() : Guid.Empty);
        return supported ? new(scope, best.Rule, address!, assessment, windows, clock) : null;
    }
    public bool TryForecast(PortPredictionScope current, PortAllocationSample anchor, Func<bool> resourceAlive, bool enabled,
        out PortForecast? forecast, out string reason)
    {
        forecast = null;
        lock (gate) {
            reason = "PredictionDisabled"; if (!enabled) return false;
            if (current.NetworkGeneration != scope.NetworkGeneration) retired = true;
            if (current.Profile != scope.Profile) { reason = "ProtocolMismatch"; return false; }
            if (current != scope) retired = true;
            reason = "PredictionInvalidated"; if (retired || failed >= TraversalLimits.PredictionFailedAttempts) return false;
            if (pending is { Consumed: false } p && time.GetElapsedTime(p.Began) >= p.Life) pending = null;
            reason = "PredictionBusy"; if (pending != null) return false;
            var now = time.GetUtcNow(); long stamp = time.GetTimestamp(); reason = "StaleOrInvalidAnchor";
            if (!ValidSample(anchor, scope, now) || anchor.ProbeStartedAt <= 0 || anchor.ProbeStartedAt > stamp ||
                time.GetElapsedTime(anchor.ProbeStartedAt, stamp).TotalMilliseconds >= MaximumAgeMs ||
                IPEndPoint.Parse(anchor.Mapped).Address.ToString() != publicAddress || knownTuples.Contains(TupleKey(anchor))) return false;
            reason = "ResourceClosed"; if (!resourceAlive()) return false;
            reason = "AnchorAlreadyConsumed"; if (consumedObservations.Contains(anchor.ObservationId)) return false;
            reason = "RecalibrationRequired"; if (consumedObservations.Count >= TraversalLimits.PredictionForecastLimit) return false;
            int[] ports = rule.Ports(anchor); reason = "PredictionOutOfRange"; if (ports.Length == 0) return false;
            consumedObservations.Add(anchor.ObservationId); knownTuples.Add(TupleKey(anchor));
            forecast = new(Assessment.ModelId, anchor, ports);
            pending = new(forecast, resourceAlive, stamp, TimeSpan.FromMilliseconds(MaximumAgeMs) - time.GetElapsedTime(anchor.ProbeStartedAt, stamp));
            reason = "ReadyForAuthenticatedCoordination"; return true;
        }
    }
    // Claim once, immediately before an already-budgeted coordinated attempt.
    // A claim doesn't allocate a socket, scan ports, or authenticate a peer.
    public bool TryClaim(Guid forecastId)
    {
        lock (gate) {
            if (retired || failed >= TraversalLimits.PredictionFailedAttempts || pending == null || pending.Forecast.Id != forecastId || pending.Consumed) return false;
            if (time.GetElapsedTime(pending.Began) >= pending.Life || !pending.ResourceAlive()) { pending = null; return false; }
            pending.Consumed = true; return true;
        }
    }
    public void Finish(Guid forecastId, PredictionOutcome outcome)
    {
        if (!Enum.IsDefined(outcome)) throw new ArgumentException("Invalid prediction outcome");
        lock (gate) {
            if (pending == null || pending.Forecast.Id != forecastId) return;
            if (pending.Consumed) {
                if (outcome == PredictionOutcome.Failed) failed++;
                else if (outcome == PredictionOutcome.PathAuthenticated) failed = 0;
            }
            pending = null;
        }
    }
    public void Invalidate() { lock (gate) { retired = true; pending = null; } }
}
