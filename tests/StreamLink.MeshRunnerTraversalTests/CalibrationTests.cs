using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Threading.Channels;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

static partial class PredictionQualificationTests
{
    static async Task<object> Calibration(string binary, string root, Action<bool, string> check, CancellationToken token)
    {
        var rows = new List<object>();
        foreach (string scenario in new[] { "twenty-windows", "business-return", "waiting-cancel", "interval-cancel", "interval-business", "missing-observer" }) {
            await using var helper = new Reflector();
            var mesh = MeshIdentity.Create("https://example.com", "", "faketcp"); var peer = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(mesh)));
            var profile = new DeviceProfile { Mesh = mesh, TraversalMode = "tcp", TcpSynObservation = true, TcpPortCalibration = true, TcpStun = ["fixture.invalid:3478"] };
            var control = new CalibrationObserver(helper.Endpoint.Port, scenario == "missing-observer" ? 2 : 4);
            string directory = Path.Combine(root, "calibration-" + scenario); var ios = new ConcurrentBag<CalibrationIo>();
            var messages = new ConcurrentQueue<string>();
            await using var factory = new MeshCandidateFactory(profile, binary, directory, [TraversalProfile.FakeTcpHttpSo], captureBroker: true) {
                ResolveTarget = (_, _, _) => Task.FromResult(helper.Endpoint), RouteCheckForTest = (_, _, _) => { },
                OpenCaptureForTest = (_, _) => { var io = new CalibrationIo(control); ios.Add(io); return io; },
                CalibrationIntervalForTest = scenario == "twenty-windows" ? TimeSpan.Zero : null
            };
            factory.ConfigureObservation(control, new(), messages.Enqueue);
            await using var resource = await factory.Gather(peer.Self, TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), token);
            await Task.Delay(150, token);
            check(control.Calls == 0 && helper.Accepted == 1, "calibration waits for target path status without reserving extra endpoints");
            if (scenario != "waiting-cancel") factory.UpdateCalibrationStatus([
                new(peer.Self.Slot, "", "target", false, null, "pending"), new(7, "", "another healthy peer", true, 1, "connected")], true);
            if (scenario == "business-return") {
                var wait = Stopwatch.StartNew();
                while (control.Sent == 0) { if (wait.Elapsed.TotalSeconds > 8) throw new TimeoutException("calibration did not send"); await Task.Delay(10, token); }
                factory.SetCalibrationBusy(true);
            }
            if (scenario == "waiting-cancel") await factory.DisposeAsync();
            if (scenario is "interval-cancel" or "interval-business") {
                var wait = Stopwatch.StartNew();
                while (!messages.Any(s => s.StartsWith("TCP 端口校准 1/"))) { if (wait.Elapsed.TotalSeconds > 14) throw new TimeoutException("calibration first window did not finish"); await Task.Delay(20, token); }
                await Task.Delay(300, token);
                check(helper.Accepted == 2 && control.Calls == 3 && ios.Count(i => !i.Closed) == 1,
                    "default 31-second ticket spacing releases the calibration resource before waiting for another window");
                if (scenario == "interval-cancel") await factory.DisposeAsync();
                else factory.SetCalibrationBusy(true);
            }
            await factory.CalibrationCompletion.WaitAsync(TimeSpan.FromSeconds(230), token);
            var model = factory.CalibratedTcpModel;
            using var report = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(directory, "tcp-port-calibration.json"), token));
            var r = report.RootElement; string? state = r.GetProperty("state").GetString();
            if (scenario == "twenty-windows") {
                check(model != null && model.Assessment.ValidationWindows == 10 && model.Assessment.ValidationHits == 10 &&
                    model.Assessment.MaximumPorts == 2 && model.Assessment.Model == "fixed-step", "formal collector fits one frozen two-port model after twenty new-source windows including held-out interference");
                var windows = r.GetProperty("windows").EnumerateArray().ToArray();
                check(windows.Length == 20 && windows.Select(w => w.GetProperty("Before").GetProperty("ResourceId").GetGuid()).Distinct().Count() == 20 &&
                    control.Sources.Count == 20 && helper.Accepted == 21, "calibration source continuity holds within each window and resources are independent across windows");
                check(control.Sent == 141 && control.Calls == 60 && control.Mappings == 47 && ios.Count(i => !i.Closed) == 1,
                    "twenty-window inventory is 141 raw SYNs, 47 distinct destination mappings, sixty control calls and only original capture retained");
                check(windows.Count(w => w.GetProperty("ObservedBackgroundActivity").GetInt32() == 1) == 7 &&
                    !r.GetProperty("candidateEnabled").GetBoolean(), "observed interference is recorded without turning calibration into a predicted candidate");
                rows.Add(new { scenario, state, windows = windows.Length, model = model!.Assessment, control.Sent, control.Calls,
                    control.Mappings, actualHelperConnections = helper.Accepted, serverQuotaEmulated = false, spacingMsForFixture = 0 });
            } else {
                string expected = scenario is "business-return" or "interval-business" ? "BusinessPathAvailable" : scenario is "waiting-cancel" or "interval-cancel" ? "Cancelled" : "PredictionNotSupported";
                check(state == expected && model == null && r.GetProperty("windows").GetArrayLength() == (scenario is "interval-cancel" or "interval-business" ? 1 : 0),
                    "collector terminates " + scenario + " without promoting incomplete evidence");
                rows.Add(new { scenario, state, control.Sent, control.Calls });
            }
            if (scenario is not ("waiting-cancel" or "interval-cancel")) {
                await using var retained = await factory.Gather(peer.Self, TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), token);
                check(IPEndPoint.Parse(retained.Candidate.Endpoint).Equals(IPEndPoint.Parse(resource.Candidate.Endpoint)), "original helper remains queryable after calibration resources are released");
            }
            await resource.DisposeAsync(); await factory.DisposeAsync();
            check(ios.All(i => i.Closed), "calibration and original capture teardown join on factory shutdown");
        }
        rows.Add(await CalibrationAdmission(binary, root, check, token));
        return new { rows, scope = "actual factory, exclusive loopback helpers and raw SYN creation; allocation/observer are controlled memory fixtures; no authenticated observer service, native worker, WinDivert, Wintun or WAN" };
    }
    static async Task<object> CalibrationAdmission(string binary, string root, Action<bool, string> check, CancellationToken token)
    {
        await using var helper = new Reflector(); var factories = new List<MeshCandidateFactory>();
        var resources = new List<IMeshCandidateResource>(); var controls = new List<CalibrationObserver>(); var ios = new ConcurrentBag<CalibrationIo>();
        async Task Wait(Func<bool> predicate) {
            var clock = Stopwatch.StartNew(); while (!predicate()) { if (clock.Elapsed.TotalSeconds > 10) throw new TimeoutException("machine calibration admission"); await Task.Delay(20, token); }
        }
        try {
            for (int i = 0; i < 2; i++) {
                var mesh = MeshIdentity.Create("https://example.com", "", "faketcp"); var peer = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(mesh)));
                var profile = new DeviceProfile { Mesh = mesh, TraversalMode = "tcp", TcpSynObservation = true, TcpPortCalibration = true, TcpStun = ["fixture.invalid:3478"] };
                var control = new CalibrationObserver(helper.Endpoint.Port, 4); controls.Add(control);
                var factory = new MeshCandidateFactory(profile, binary, Path.Combine(root, "calibration-admission-" + i), [TraversalProfile.FakeTcpHttpSo], captureBroker: true) {
                    ResolveTarget = (_, _, _) => Task.FromResult(helper.Endpoint), RouteCheckForTest = (_, _, _) => { },
                    OpenCaptureForTest = (_, _) => { var io = new CalibrationIo(control); ios.Add(io); return io; }
                };
                factories.Add(factory); factory.ConfigureObservation(control, new(), _ => { });
                resources.Add(await factory.Gather(peer.Self, TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), token));
            }
            factories[0].SetCalibrationBusy(false); await Wait(() => controls[0].Sent > 0);
            factories[1].SetCalibrationBusy(false); await Task.Delay(250, token);
            check(controls[1].Calls == 0 && helper.Accepted == 3, "second calibration queues globally without an extra source or observer request");
            factories[0].SetCalibrationBusy(true); await factories[0].CalibrationCompletion;
            await Wait(() => controls[1].Sent > 0);
            check(helper.Accepted == 4, "machine calibration admission moves to the next waiting factory after first-owner cleanup");
            factories[1].SetCalibrationBusy(true); await factories[1].CalibrationCompletion;
            check(factories.All(f => f.CalibratedTcpModel == null) && ios.Count(i => !i.Closed) == 2,
                "interrupted queued calibrations retain original helpers only and cannot expose a fitted model");
            return new { helpers = helper.Accepted, rawSends = controls.Sum(c => c.Sent), scope = "two isolated factories share one calibration admission; controlled observer and raw I/O" };
        } finally {
            foreach (var resource in resources) await resource.DisposeAsync();
            foreach (var factory in factories) await factory.DisposeAsync();
            check(ios.All(i => i.Closed), "machine admission negative cases release every capture on shutdown");
        }
    }
    sealed class CalibrationObserver : ITcpObservationControl
    {
        readonly Guid epoch = Guid.NewGuid(); readonly TcpObserverPoint[] points; readonly object gate = new();
        TcpProbeSpec[] specs = []; Guid ticket; long expires; int nextPort = 40000;
        readonly Dictionary<string, int> mappings = []; readonly Dictionary<Guid, TcpSynEvidence> evidence = [];
        public readonly HashSet<string> Sources = [];
        public int Calls, Sent;
        public int Mappings { get { lock (gate) return mappings.Count; } }
        public CalibrationObserver(int helperPort, int count) {
            var ports = Enumerable.Range(47221, 5).Where(p => p != helperPort).Take(2).ToArray();
            TcpObserverPoint[] all = [new("a1", "127.0.0.1:" + ports[0]), new("a2", "127.0.0.1:" + ports[1]), new("b1", "127.0.0.2:" + ports[0]), new("b2", "127.0.0.2:" + ports[1])];
            points = all.Take(count).ToArray();
        }
        public void Packet(ReadOnlySpan<byte> packet) {
            if (!TcpShapeSyn.Read(packet, out var source, out var target, out uint iss)) throw new IOException("Invalid calibration SYN");
            lock (gate) {
                Sent++; Sources.Add(source.ToString());
                var point = points.Single(p => p.Endpoint == target.ToString()); var spec = specs.Single(s => s.ObserverId == point.Id && s.Iss == iss);
                string key = source + "/" + target;
                if (!mappings.TryGetValue(key, out int port)) { port = nextPort += 7; mappings[key] = port; }
                if (evidence.TryGetValue(spec.ProbeId, out var old)) evidence[spec.ProbeId] = old with { Retransmissions = old.Retransmissions + 1 };
                else evidence[spec.ProbeId] = new(spec.ProbeId, point.Id, point.Endpoint, "SynObserved", "192.0.2.2:" + port, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), 0);
            }
        }
        public Task<TcpObserverReply> TcpObservation(string operation, Guid id, TcpProbeSpec[]? supplied, CancellationToken token) {
            token.ThrowIfCancellationRequested(); lock (gate) {
                Calls++;
                if (operation == "catalog") return Task.FromResult(new TcpObserverReply(1, epoch, Guid.Empty, 0, points, []));
                if (operation == "register") { ticket = id; specs = supplied!; expires = DateTimeOffset.UtcNow.AddSeconds(8).ToUnixTimeMilliseconds(); }
                if (id != ticket) throw new IOException("Wrong calibration ticket");
                return Task.FromResult(new TcpObserverReply(1, epoch, ticket, expires, [], specs.Select(p => evidence.GetValueOrDefault(p.ProbeId) ??
                    new(p.ProbeId, p.ObserverId, points.Single(s => s.Id == p.ObserverId).Endpoint, "Pending", null, null, 0)).ToArray()));
            }
        }
    }
    sealed class CalibrationIo(CalibrationObserver control) : IEndpointPacketIo
    {
        readonly Channel<EndpointPacket> input = Channel.CreateBounded<EndpointPacket>(8);
        public bool Closed;
        public bool Inject(ReadOnlySpan<byte> packet) { control.Packet(packet); return true; }
        public ValueTask<EndpointPacket> Receive(CancellationToken token) => input.Reader.ReadAsync(token);
        public bool Reinject(EndpointPacket packet) => true;
        public void Shutdown() => input.Writer.TryComplete();
        public void Dispose() { Closed = true; Shutdown(); }
    }
}
