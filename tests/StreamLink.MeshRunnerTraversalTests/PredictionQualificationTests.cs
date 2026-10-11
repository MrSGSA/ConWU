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
    public static async Task<object> Run(string binary, string root, Action<bool, string> check, CancellationToken token)
    {
        var rows = new List<object>();
        foreach (bool enabled in new[] { false, true }) {
            await using var helper = new Reflector();
            var mesh = MeshIdentity.Create("https://example.com", "", "faketcp"); var peer = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(mesh)));
            var profile = new DeviceProfile { Mesh = mesh, TraversalMode = "tcp", TcpSynObservation = enabled, TcpStun = ["fixture.invalid:3478"] };
            string directory = Path.Combine(root, "prediction-qualification-" + enabled);
            var control = new Observer(helper.Endpoint.Port); var logs = new ConcurrentQueue<string>(); Io? io = null;
            await using var factory = new MeshCandidateFactory(profile, binary, directory, [TraversalProfile.FakeTcpHttpSo], captureBroker: true) {
                ResolveTarget = (_, _, _) => Task.FromResult(helper.Endpoint), RouteCheckForTest = (_, _, _) => { },
                OpenCaptureForTest = (_, _) => io = new(control)
            };
            factory.ConfigureObservation(new Control(control), new(), logs.Enqueue);
            await using var resource = await factory.Gather(peer.Self, TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), token);
            string file = Path.Combine(directory, "tcp-port-prediction-qualification.json");
            if (enabled) {
                var watch = Stopwatch.StartNew();
                while (!logs.Any(s => s.StartsWith("TCP 端口预测保持关闭"))) {
                    if (watch.Elapsed.TotalSeconds > 13) throw new TimeoutException(string.Join('\n', logs));
                    await Task.Delay(20, token);
                }
                using var result = JsonDocument.Parse(await File.ReadAllTextAsync(file, token)); var r = result.RootElement;
                check(!r.GetProperty("candidateEnabled").GetBoolean() && r.GetProperty("qualification").GetProperty("State").GetString() == "PredictionNotSupported",
                    "formal factory persists prediction qualification without turning diagnostic observations into a candidate");
                check(r.GetProperty("independentWindows").GetInt32() <= 1 && control.Calls == 3 && io!.Sent == 12,
                    "one bounded native observation ticket cannot inflate four target replies into twenty windows");
                rows.Add(r.Clone());
            } else {
                await Task.Delay(100, token);
                check(!File.Exists(file) && control.Calls == 0 && io?.Sent == 0, "default-off factory never starts prediction calibration or extra native probes");
            }
            await resource.DisposeAsync(); await factory.DisposeAsync();
            check(io?.Closed == true && helper.Accepted == 1, "qualification reporting retains one helper then joins capture teardown without a second bind");
        }
        rows.Add(await Calibration(binary, root, check, token));
        return new { rows, scope = "formal factory and TcpShapeProbe; real loopback TCP helpers; controlled observer API/NAT raw I/O, no native worker, Wintun or public NAT; calibration scheduling interval accelerated only in fixture" };
    }
    sealed class Observer
    {
        readonly Guid epoch = Guid.NewGuid(); readonly TcpObserverPoint[] points;
        readonly object gate = new(); TcpProbeSpec[] specs = []; Guid registered; long expires;
        readonly Dictionary<Guid, TcpSynEvidence> seen = [];
        public int Calls;
        public Observer(int excludedPort)
        {
            var ports = Enumerable.Range(47221, 5).Where(p => p != excludedPort).Take(2).ToArray();
            points = [new("a1", "127.0.0.1:" + ports[0]), new("a2", "127.0.0.1:" + ports[1]), new("b1", "127.0.0.2:" + ports[0]), new("b2", "127.0.0.2:" + ports[1])];
        }
        public void Packet(ReadOnlySpan<byte> packet)
        {
            if (!TcpShapeSyn.Read(packet, out var source, out var target, out uint iss)) throw new IOException("bad fixture SYN");
            lock (gate) {
                var p = points.Single(p => p.Endpoint == target.ToString()); var probe = specs.Single(s => s.ObserverId == p.Id && s.Iss == iss);
                if (seen.TryGetValue(probe.ProbeId, out var old)) seen[probe.ProbeId] = old with { Retransmissions = old.Retransmissions + 1 };
                else seen[probe.ProbeId] = new(probe.ProbeId, p.Id, p.Endpoint, "SynObserved", source.ToString(), DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), 0);
            }
        }
        public Task<TcpObserverReply> Request(string op, Guid ticket, TcpProbeSpec[]? supplied)
        {
            lock (gate) {
                Calls++;
                if (op == "catalog") return Task.FromResult(new TcpObserverReply(1, epoch, Guid.Empty, 0, points, []));
                if (op == "register") { registered = ticket; specs = supplied!; expires = DateTimeOffset.UtcNow.AddSeconds(8).ToUnixTimeMilliseconds(); }
                if (ticket != registered) throw new IOException("wrong fixture ticket");
                return Task.FromResult(new TcpObserverReply(1, epoch, ticket, expires, points, specs.Select(s => seen.GetValueOrDefault(s.ProbeId)
                    ?? new(s.ProbeId, s.ObserverId, points.Single(p => p.Id == s.ObserverId).Endpoint, op == "read" ? "NotObserved" : "Pending", null, null, 0)).ToArray()));
            }
        }
    }
    sealed class Io(Observer observer) : IEndpointPacketIo
    {
        readonly Channel<EndpointPacket> incoming = Channel.CreateUnbounded<EndpointPacket>();
        public int Sent; public bool Closed;
        public ValueTask<EndpointPacket> Receive(CancellationToken token) => incoming.Reader.ReadAsync(token);
        public bool Inject(ReadOnlySpan<byte> packet) { observer.Packet(packet); Sent++; return true; }
        public bool Reinject(EndpointPacket packet) => true;
        public void Shutdown() => incoming.Writer.TryComplete();
        public void Dispose() { Closed = true; Shutdown(); }
    }
    // Explicit interface wrapper keeps the controlled observer separate from
    // the production authenticated HTTPS client, which has its own test suite.
    sealed class Control(Observer inner) : ITcpObservationControl
    { public Task<TcpObserverReply> TcpObservation(string op, Guid ticket, TcpProbeSpec[]? probes, CancellationToken token) { token.ThrowIfCancellationRequested(); return inner.Request(op, ticket, probes); } }
}
