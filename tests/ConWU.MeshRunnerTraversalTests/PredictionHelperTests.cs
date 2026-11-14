using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

static partial class PredictionRunnerTests
{
    static async Task HelperFallback(string binary, string root, Action<bool, string> check, CancellationToken token)
    {
        foreach (string failure in new[] { "dns", "refused", "silent", "cancelled", "all-failed", "capture" }) {
            await using var first = new Reflector { Silent = true };
            await using var good = new Reflector();
            using var closed = new TcpListener(IPAddress.Loopback, 0); closed.Start();
            var refused = (IPEndPoint)closed.LocalEndpoint; closed.Stop();
            var mesh = MeshIdentity.Create("https://example.com/", "", "faketcp");
            var peer = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(mesh))).Self;
            var config = new DeviceProfile { Mesh = mesh, TraversalMode = "tcp", TcpSynObservation = true,
                TcpPortCalibration = true, TcpPortPrediction = true,
                TcpStun = ["bad.fixture:3478", "good.fixture:3478", "third.fixture:3478", "fourth.fixture:3478"] };
            var names = new ConcurrentQueue<string>(); var ios = new ConcurrentBag<HelperIo>();
            var control = new Catalog(); var admission = new TraversalEnhancementScheduler();
            await using var factory = new MeshCandidateFactory(config, binary, root, [TraversalProfile.FakeTcpHttpSo], captureBroker: true, wireControl: true) {
                ResolveTarget = (name, _, _) => {
                    names.Enqueue(name);
                    if (failure == "all-failed" || failure == "dns" && name.StartsWith("bad"))
                        throw new SocketException((int)SocketError.HostNotFound);
                    return Task.FromResult(name.StartsWith("bad") ? failure == "refused" ? refused : first.Endpoint : good.Endpoint);
                }, RouteCheckForTest = (_, _, _) => { }, EnhancementAdmissionForTest = admission,
                OpenCaptureForTest = (_, _) => { if (failure == "capture") throw new IOException("DriverUnavailable fixture"); var io = new HelperIo(); ios.Add(io); return io; }
            };
            factory.ConfigureObservation(control, new(8), _ => { });
            factory.SetPredictionModelForTest(Model(factory.GenerationForTest, 0, 0));
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var remote = new MeshTraversalCandidate(Guid.NewGuid(), 1, "192.0.2.20:40000", null, now, now + 120,
                CandidatePurpose.SimultaneousOpen, new(Guid.NewGuid(), true, ""));
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
            if (failure == "cancelled") stop.CancelAfter(150);
            IMeshCandidateResource? resource = null; Exception? result = null;
            try { resource = await factory.GatherCoordinated(peer, TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), false, remote, 2, true, stop.Token); }
            catch (Exception ex) when (ex is IOException or OperationCanceledException) { result = ex; }
            try {
            if (failure == "capture") {
                check(result is IOException && names.Count == 1 && control.Calls == 0 && good.Accepted == 0 && ios.Count == 0,
                    "capture setup failure is preserved and does not retry unrelated STUN servers");
            } else if (failure == "all-failed") {
                check(result is IOException && names.Count == 3 && control.Calls == 0 && ios.Count == 0,
                    "prediction helper failures try at most three distinct configured servers and never probe the observer");
            } else if (failure == "cancelled") {
                check(result is OperationCanceledException && names.Count == 1 && control.Calls == 0 && good.Accepted == 0,
                    "cancelled in-flight reflection does not open the next server or consume observer requests");
            } else {
                check(result == null && resource?.PredictionReady == true && resource.Candidate.ObservationTarget == good.Endpoint.ToString() &&
                    names.SequenceEqual(new[] { "bad.fixture:3478", "good.fixture:3478" }) && good.Accepted == 1 && good.Requests == 1 && control.Calls == 1,
                    failure + ": formal prediction recovers through second helper and retains its exact observation target");
                check(ios.Where(i => i.Closed).Count() == (failure == "silent" ? 1 : 0) && ios.All(i => i.Sent == 0),
                    failure + ": losing capture closes before reservation and no predicted SYN is sent during helper preparation");
            }
            } finally { if (resource != null) await resource.DisposeAsync(); await factory.DisposeAsync(); }
            check(ios.All(i => i.Closed) && admission.Usage() is { Active: 0, Waiting: 0 },
                failure + ": helper fallback releases capture/source ownership and the shared enhancement grant");
        }
    }
    sealed class Catalog : ITcpObservationControl
    {
        public int Calls;
        public Task<TcpObserverReply> TcpObservation(string operation, Guid ticket, TcpProbeSpec[]? probes, CancellationToken token)
        {
            if (operation != "catalog") throw new IOException("No predicted observation authorized during helper preparation");
            Calls++; return Task.FromResult(new TcpObserverReply(1, Guid.NewGuid(), Guid.Empty, 0, Points, [], FreshWindowMs: TcpObserverProtocol.FreshWindowMs));
        }
    }
    sealed class HelperIo : IEndpointPacketIo
    {
        readonly Channel<EndpointPacket> queue = Channel.CreateUnbounded<EndpointPacket>();
        public bool Closed; public int Sent;
        public ValueTask<EndpointPacket> Receive(CancellationToken token) => queue.Reader.ReadAsync(token);
        public bool Inject(ReadOnlySpan<byte> packet) { Sent++; return true; }
        public bool Reinject(EndpointPacket packet) => true;
        public void Shutdown() => queue.Writer.TryComplete();
        public void Dispose() { Closed = true; Shutdown(); }
    }
}
