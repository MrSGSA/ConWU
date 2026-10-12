using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Channels;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.EndpointPoc;
using StreamLink.Service;

static class PredictionRunnerTests
{
    public static readonly TcpObserverPoint[] Points = [new("a", "127.0.0.2:47221"), new("b", "127.0.0.3:47221")];
    public static async Task Admission(string binary, string root, Action<bool, string> check, CancellationToken token)
    {
        var a = MeshIdentity.Create("https://example.com/", "", "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));
        var p = new DeviceProfile { Mesh = a, TraversalMode = "tcp", TcpSynObservation = true, TcpPortCalibration = true, TcpPortPrediction = true, TcpStun = ["fixture.invalid:3478"] };
        await using var helper = new Reflector(); var control = new NeverObserver(); var budget = new MeshRequestBudget(8); var admission = new TraversalEnhancementScheduler();
        await using var factory = new MeshCandidateFactory(p, binary, root, [TraversalProfile.FakeTcpHttpSo], captureBroker: true, wireControl: true) {
            ResolveTarget = (_, _, _) => Task.FromResult(helper.Endpoint), RouteCheckForTest = (_, _, _) => { }, EnhancementAdmissionForTest = admission
        };
        factory.ConfigureObservation(control, budget, _ => { });
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var remote = new MeshTraversalCandidate(Guid.NewGuid(), 1, "192.0.2.20:40000", null, now, now + 120,
            CandidatePurpose.SimultaneousOpen, new(Guid.NewGuid(), true, ""));
        async Task Reject(bool allowed, string why) {
            bool rejected = false;
            try { await using var r = await factory.GatherCoordinated(b.Self, TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), false, remote, 2, allowed, token); }
            catch (IOException) { rejected = true; }
            check(rejected && helper.Accepted == 0 && control.Calls == 0, why);
        }
        await Reject(true, "formal prediction rejects missing calibration without allocating or probing");
        factory.SetPredictionModelForTest(Model(factory.GenerationForTest, 0, 1));
        await Reject(false, "old server or bilateral capability absence rejects prediction before source allocation");
        p.TcpPortPrediction = false; await Reject(true, "local opt-out rejects even an authenticated prediction offer"); p.TcpPortPrediction = true;
        remote = remote with { Prediction = remote.Prediction! with { StableModel = false } };
        await Reject(true, "formal gather rejects two unstable models before any network probe");
        remote = remote with { Prediction = remote.Prediction! with { StableModel = true } };
        using (var other = admission.TryEnter(new("fixture", "holder", "peer", Guid.NewGuid()), TraversalEnhancementKind.UdpExploration)) {
            using var queuedStop = CancellationTokenSource.CreateLinkedTokenSource(token);
            var queued = factory.GatherCoordinated(b.Self, TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), false, remote, 2, true, queuedStop.Token);
            check(admission.Usage() is { Active: 1, Waiting: 1 } && helper.Accepted == 0 && control.Calls == 0,
                "formal TCP prediction waits behind UDP admission before opening a helper or making observer calls");
            queuedStop.Cancel(); bool removed = false; try { await using var ignored = await queued; } catch (OperationCanceledException) { removed = true; }
            check(removed && admission.Usage() is { Active: 1, Waiting: 0 }, "cancelled prediction leaves the active UDP owner and removes its queued request");
        }
        while (budget.Take(true)) { }
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token); stop.CancelAfter(150);
        bool cancelled = false;
        try { await using var r = await factory.GatherCoordinated(b.Self, TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), false, remote, 2, true, stop.Token); }
        catch (OperationCanceledException) { cancelled = true; }
        check(cancelled && helper.Accepted == 0 && control.Calls == 0 && admission.Usage() is { Active: 0, Waiting: 0 },
            "cancelling queued HTTP admission releases the heavy slot and never allocates a source");
    }
    sealed class NeverObserver : ITcpObservationControl {
        public int Calls;
        public Task<TcpObserverReply> TcpObservation(string operation, Guid ticket, TcpProbeSpec[]? probes, CancellationToken token) { Calls++; throw new IOException("No observation should be issued"); }
    }
    public static async Task<object> Run(string binary, string root, string url, string pin, TcpSynObserver observer, Action<bool, string> check, CancellationToken token, int stablePeer = 0, bool changedStableMapping = false)
    {
        var a = MeshIdentity.Create(url, pin, "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var logs = new ConcurrentQueue<string>(); var wire = new NatWire(observer, stablePeer, changedStableMapping);
        await using var ah = new Reflector { MapForTest = _ => new(NatWire.Public[0], 35000) };
        await using var bh = new Reflector { MapForTest = _ => new(NatWire.Public[1], 35000) };
        var helpers = new[] { ah, bh };
        var profiles = new[] { a, b }.Select(m => new DeviceProfile { Mesh = m, TraversalMode = "tcp", PathSelection = "faketcp-only",
            TcpSynObservation = true, TcpPortCalibration = true, TcpPortPrediction = true, TcpStun = ["fixture.invalid:3478"] }).ToArray();
        var factories = profiles.Select((p, i) => new MeshCandidateFactory(p, binary, Path.Combine(root, "prediction-" + i), [TraversalProfile.FakeTcpHttpSo],
            captureBroker: true, wireControl: true, diagnostic: logs.Enqueue) {
                ResolveTarget = (_, _, _) => Task.FromResult(helpers[i].Endpoint), RouteCheckForTest = (_, _, _) => { },
                OpenCaptureForTest = (local, _) => wire.Open(i, local), EnhancementAdmissionForTest = new()
            }).ToArray();
        for (int i = 0; i < 2; i++) factories[i].SetPredictionModelForTest(Model(factories[i].GenerationForTest, i, stablePeer));
        var adapters = new[] { new NativeIpv6RunnerTests.Adapter(), new NativeIpv6RunnerTests.Adapter() }; var states = new SessionStatus?[2];
        using var running = CancellationTokenSource.CreateLinkedTokenSource(token);
        MeshRuntimeServices Services(int i) => new(m => new MeshDiscoveryClient(m), _ => Task.FromResult<IPacketAdapter>(adapters[i]),
            async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new IOException(); }, _ => throw new IOException("No legacy entry"),
            (_, _, ct) => Task.Delay(Timeout.Infinite, ct), (_, _, _) => { }, (_, _) => { }, Path.Combine(root, "sessions")) {
                Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(factories[i])
            };
        var tasks = Enumerable.Range(0, 2).Select(i => new MeshRunner(profiles[i], s => { logs.Enqueue(i + " " + s); Console.WriteLine(DateTimeOffset.UtcNow.ToString("HH:mm:ss.fff") + " " + i + " " + s); },
            s => states[i] = s, _ => { }, _ => { }, Services(i)).Run(running.Token)).ToArray();
        var clock = Stopwatch.StartNew();
        try {
            while (!states.All(s => s?.Connected == true)) {
                if (changedStableMapping && logs.Any(s => s.Contains("新鲜映射不再符合稳定模型"))) {
                    check(wire.ObservedSources.Count == 2 && wire.Ios.Where(io => io.Observed).All(io => io.PeerSends == 0),
                        "changed port-preservation evidence rejects the stable assumption before any predicted peer SYN");
                    check(states.All(s => s?.Connected != true), "conflicting fresh model cannot select a business path");
                    return new { negative = "stable-preservation-changed", scope = "actual fresh HTTPS observation; controlled NAT stopped preserving local source port" };
                }
                foreach (var task in tasks) if (task.IsCompleted) await task;
                if (clock.Elapsed.TotalSeconds > 70) throw new TimeoutException(string.Join('\n', logs));
                await Task.Delay(20, token);
            }
            if (changedStableMapping) throw new Exception("Mismatched stable model unexpectedly connected");
            check(logs.Any(s => s.Contains("候选失败")) && wire.Refused > 0, "ordinary helper endpoints fail before enhanced traversal under the controlled mapping rules");
            check(wire.ObservedSources.Count >= 2 && wire.PeerMappings.Any(p => p.Peer != stablePeer && p.Port == 40014), "fresh native observation and subsequent peer SYN create the predicted hard-side mapping");
            check(states.All(s => s!.Connected && !s.Degraded), "production Runner selects the authenticated predicted FakeTCP path");
            long connectedMs = clock.ElapsedMilliseconds;
            await Task.Delay(8500, token); // resource survives Measure's shared deadline
            adapters[0].Outgoing.Add(NativeIpv6RunnerTests.Packet(a.LocalIp, b.LocalIp)); adapters[1].Outgoing.Add(NativeIpv6RunnerTests.Packet(b.LocalIp, a.LocalIp));
            var data = Stopwatch.StartNew(); while (adapters.Any(ad => ad.Incoming.Count == 0)) { if (data.Elapsed.TotalSeconds > 3) throw new TimeoutException("predicted Runner business absent"); await Task.Delay(10, token); }
            check(states.All(s => s?.Connected == true), "full-size bidirectional MeshLink business continues after the predicted attempt ends");
            return new { connectedMs, stablePeer, wire.Refused, wire.Packets, observations = wire.ObservedSources.Count, mappings = wire.PeerMappings.Select(p => new { p.Peer, p.Port }).ToArray(),
                training = "twenty synthetic independent windows injected into each actual factory; raw fresh observations and HTTPS signatures are exercised",
                scope = "EIM/APDF stable side and sequential APDM/APDF hard side, controlled memory mapping/filtering, actual C++ and formal Runner" };
        } finally {
            running.Cancel(); foreach (var task in tasks) try { await task.WaitAsync(TimeSpan.FromSeconds(12)); } catch (OperationCanceledException) { }
            check(wire.Ios.All(io => io.Closed) && adapters.All(ad => ad.Disposed), "formal prediction shutdown closes capture sources and adapters");
        }
    }
    static NatPortPrediction Model(Guid generation, int peer, int stablePeer)
    {
        string nic = NetworkInterface.GetAllNetworkInterfaces().First(n => n.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(IPAddress.Loopback))).Id;
        var scope = new PortPredictionScope(generation, nic, IPAddress.Loopback.ToString(), TraversalProfile.FakeTcpHttpSo);
        var windows = Enumerable.Range(0, 20).Select(i => {
            var resource = Guid.NewGuid(); var owner = Guid.NewGuid(); int local = 21000 + i; int before = peer == stablePeer ? local : 40000 + i * 100;
            int noise = i % 3 == 1 ? 1 : 0; int after = peer == stablePeer ? before : before + 7 * (noise + 1);
            var at = DateTimeOffset.UtcNow.AddSeconds(-60 + i * 2);
            PortAllocationSample Sample(int port, string target, DateTimeOffset time) => new(resource, Guid.NewGuid(), "127.0.0.1:" + local, target,
                new IPEndPoint(NatWire.Public[peer], port).ToString(), time, true, PortAllocationEvidence.NativeSynObserved, owner);
            return new PortAllocationWindow(Guid.NewGuid(), scope, Sample(before, Points[0].Endpoint, at), Sample(after, Points[1].Endpoint, at.AddMilliseconds(100)), noise);
        }).ToArray();
        return NatPortPrediction.Fit(windows, out var report) ?? throw new IOException(report.Reason);
    }
    sealed class NatWire(TcpSynObserver observer, int stablePeer, bool changedStableMapping)
    {
        public static readonly IPAddress[] Public = [IPAddress.Parse("192.0.2.10"), IPAddress.Parse("192.0.2.20")];
        readonly object gate = new();
        readonly Dictionary<string, Io> inbound = [];
        public readonly List<Io> Ios = [];
        public readonly HashSet<string> ObservedSources = [];
        public readonly List<(int Peer, int Port)> PeerMappings = [];
        public int Refused, Packets;
        public Io Open(int peer, IPEndPoint local) { lock (gate) { var io = new Io(this, peer, local); Ios.Add(io); return io; } }
        public bool Send(Io source, ReadOnlySpan<byte> packet) {
            lock (gate) {
                if (!TcpCaptureOwner.Tuple(packet, out _, out var target, true)) throw new IOException("Bad raw fixture packet");
                Packets++;
                string key = target.ToString(); source.Allowed.Add(key);
                if (!source.Mappings.TryGetValue(key, out var outside)) {
                    int stablePort = changedStableMapping ? 1024 + (source.Local.Port - 1024 + 1) % 64512 : source.Local.Port;
                    outside = new(Public[source.Peer], source.Peer == stablePeer ? stablePort : source.Next += 7); source.Mappings[key] = outside;
                    inbound[outside.ToString()] = source;
                    if (Public.Contains(target.Address)) PeerMappings.Add((source.Peer, outside.Port));
                }
                var frame = packet.ToArray(); Rewrite(frame, outside, target);
                if (Points.Any(p => p.Endpoint == target.ToString())) { source.Observed = true; ObservedSources.Add(source.Local.ToString()); observer.Observe(frame); return true; }
                if (Public.Contains(target.Address)) source.PeerSends++;
                if (!inbound.TryGetValue(target.ToString(), out var destination) || !destination.Allowed.Contains(outside.ToString()) ||
                    destination.Peer != stablePeer && (!destination.Mappings.TryGetValue(outside.ToString(), out var reverse) || reverse.ToString() != target.ToString())) { Refused++; return true; }
                Rewrite(frame, outside, destination.Local); destination.Input.Writer.TryWrite(new(frame, false)); return true;
            }
        }
        static void Rewrite(byte[] packet, IPEndPoint source, IPEndPoint target) {
            int ip = (packet[0] & 15) * 4; source.Address.GetAddressBytes().CopyTo(packet, 12); target.Address.GetAddressBytes().CopyTo(packet, 16);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ip), (ushort)source.Port); BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ip + 2), (ushort)target.Port);
            packet[10] = packet[11] = packet[ip + 16] = packet[ip + 17] = 0;
            static ushort Sum(ReadOnlySpan<byte> p, uint sum = 0) { for (int i = 0; i < p.Length; i += 2) sum += i + 1 < p.Length ? BinaryPrimitives.ReadUInt16BigEndian(p[i..]) : (uint)p[i] << 8;
                while (sum > 65535) sum = (sum & 65535) + (sum >> 16); return (ushort)~sum; }
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), Sum(packet.AsSpan(0, ip)));
            uint pseudo = 6 + (uint)(packet.Length - ip); for (int i = 12; i < 20; i += 2) pseudo += BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(i));
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ip + 16), Sum(packet.AsSpan(ip), pseudo));
        }
        public sealed class Io(NatWire owner, int peer, IPEndPoint local) : IEndpointPacketIo {
            public int Peer => peer; public IPEndPoint Local => local;
            public readonly HashSet<string> Allowed = []; public readonly Dictionary<string, IPEndPoint> Mappings = []; public int Next = 40000;
            public bool Observed; public int PeerSends;
            public readonly Channel<EndpointPacket> Input = Channel.CreateBounded<EndpointPacket>(1024); public bool Closed;
            public ValueTask<EndpointPacket> Receive(CancellationToken token) => Input.Reader.ReadAsync(token);
            public bool Inject(ReadOnlySpan<byte> p) => owner.Send(this, p); public bool Reinject(EndpointPacket p) => true;
            public void Shutdown() => Input.Writer.TryComplete(); public void Dispose() { Closed = true; Shutdown(); }
        }
    }
}
