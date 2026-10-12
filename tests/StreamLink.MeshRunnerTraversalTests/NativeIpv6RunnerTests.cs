using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

static class NativeIpv6RunnerTests
{
    public static async Task<object> Run(string binary, string root, string url, string pin, Action<bool, string> check, CancellationToken token, bool paced = false)
    {
        CaptureFilterTests.Run(Path.Combine(Path.GetDirectoryName(binary)!, "..", "downloads", "WinDivert-2.2.2-A", "x64", "WinDivert.dll"), check);
        await Contract(check);
        var rows = new List<object>();
        foreach (string mode in new[] { "ipv6", "ipv6-unreachable", "old-native-abi", "old-service" }) rows.Add(await Pair(binary, root, url, pin, mode, check, token, paced));
        return new { rows, actualNative = true, realTcpHelpers = true, realHttps = true, rawCaptureSimulated = true, realWinDivertIo = false, realNat = false, wintun = false };
    }
    static async Task Contract(Action<bool, string> check)
    {
        var a = MeshIdentity.Create("https://localhost", "", "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var ca = new MeshTraversalCapabilities(1, 1, Guid.NewGuid(), [TraversalProfile.FakeTcpHttpSo, TraversalProfile.UdpDirect], UdpIpv6: 1, FakeTcpIpv6: 1);
        var cb = ca with { BootId = Guid.NewGuid() }; long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), seq = 0;
        var c = new MeshTraversalCandidate(Guid.NewGuid(), 1, "[::1]:40001", "[::1]:3478", now, now + 120, CandidatePurpose.SimultaneousOpen);
        await using var offer = MeshTraversalAttempt.Offer(a, b.Self, ca, cb, TraversalProfile.FakeTcpHttpSo, c, 1, () => ++seq);
        MeshTraversalAttempt.ValidateOffer(b, a.Self, cb, ca, offer.Outbound!);
        check(true, "FakeTCP IPv6 candidate is covered by authenticated bilateral capability negotiation");
        bool rejected = false; try { MeshTraversalAttempt.ValidateOffer(b, a.Self, cb with { FakeTcpIpv6 = 0 }, ca, offer.Outbound!); } catch (CryptographicException) { rejected = true; }
        check(rejected, "UDP IPv6 capability cannot authorize a FakeTCP IPv6 Offer");
        check(!new DeviceProfile().FakeTcpIpv6, "FakeTCP IPv6 remains disabled in default/existing device profiles");
    }
    static async Task<object> Pair(string binary, string root, string url, string pin, string mode, Action<bool, string> check, CancellationToken token, bool paced)
    {
        await using var v4 = new Reflector(); await using var v6 = new Reflector(new(IPAddress.IPv6Loopback, 0));
        var a = MeshIdentity.Create(url, pin, "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var profiles = new[] { a, b }.Select(m => new DeviceProfile { Mesh = m, TraversalMode = "tcp", PathSelection = "faketcp-only", FakeTcpIpv6 = true, TcpStun = ["fixture.invalid:3478"], ManagedEgressMbps = paced ? 50 : 0 }).ToArray();
        var wire = new Wire(mode == "ipv6-unreachable"); var logs = new ConcurrentQueue<string>();
        var factories = profiles.Select((p, i) => new Inspect(new MeshCandidateFactory(p, binary, root, [TraversalProfile.FakeTcpHttpSo], captureBroker: true,
            diagnostic: logs.Enqueue, ipv6Native: mode != "old-native-abi" || i == 0, wireControl: true) {
            Ipv6AvailableForTest = () => true,
            ResolveTarget = (_, family, _) => Task.FromResult(family == AddressFamily.InterNetworkV6 ? v6.Endpoint : v4.Endpoint),
            OpenCaptureForTest = (local, _) => wire.Open(local),
            RouteCheckForTest = (remote, expected, _) => {
                if (!IPAddress.IsLoopback(remote.Address) || expected != null && (!IPAddress.IsLoopback(expected) || expected.AddressFamily != remote.AddressFamily)) throw new IOException("fixture remains family-matched loopback");
            }
        })).ToArray();
        var adapters = new[] { new Adapter(), new Adapter() }; var states = new SessionStatus?[2];
        using var running = CancellationTokenSource.CreateLinkedTokenSource(token); int legacy = 0;
        MeshRuntimeServices Services(int i) => new(m => mode == "old-service" ? new OldService(new MeshDiscoveryClient(m)) : new MeshDiscoveryClient(m),
            _ => Task.FromResult<IPacketAdapter>(adapters[i]), async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new IOException(); },
            _ => { Interlocked.Increment(ref legacy); throw new IOException("no legacy entry"); }, (_, _, ct) => Task.Delay(Timeout.Infinite, ct), (_, _, _) => { }, (_, _) => { }, Path.Combine(root, "native-ipv6")) {
                Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(factories[i])
            };
        var clock = Stopwatch.StartNew(); long connected;
        var tasks = profiles.Select((p, i) => new MeshRunner(p, logs.Enqueue, s => states[i] = s, _ => { }, _ => { }, Services(i)).Run(running.Token)).ToArray();
        try {
            while (!states.All(s => s?.Connected == true)) {
                foreach (var task in tasks) if (task.IsCompleted) await task;
                if (clock.Elapsed.TotalSeconds > 55) throw new TimeoutException(string.Join('\n', logs));
                await Task.Delay(20, token);
            }
            connected = clock.ElapsedMilliseconds;
            var family = mode == "ipv6" ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            check(legacy == 0 && factories.All(f => f.Paths.Count == 1 && f.Paths.Single().ActualLocal.AddressFamily == family && f.Paths.Single().ActualRemote.AddressFamily == family), mode + ": actual production candidate factory and Runner agree on the FakeTCP address family");
            check(states.All(s => s!.Degraded == false) && factories.All(f => f.Paths.Single().Profile == TraversalProfile.FakeTcpHttpSo), mode + ": only FakeTCP policy never substitutes UDP or relay");
            check(mode == "ipv6-unreachable" ? factories.All(f => f.Gathers == 2) && v6.Accepted == 2 && v4.Accepted == 2 : factories.All(f => f.Gathers == 1), mode + ": automatic fallback uses the second existing TCP round");
            if (mode.StartsWith("old-")) check(v6.Accepted == 0, mode + ": missing ABI/server capability prevents IPv6 helper allocation");
            adapters[0].Outgoing.Add(Packet(a.LocalIp, b.LocalIp)); adapters[1].Outgoing.Add(Packet(b.LocalIp, a.LocalIp));
            while (adapters.Any(x => x.Incoming.Count == 0)) await Task.Delay(20, token);
            check(adapters[0].Incoming.Single().SequenceEqual(Packet(b.LocalIp, a.LocalIp)) && adapters[1].Incoming.Single().SequenceEqual(Packet(a.LocalIp, b.LocalIp)), mode + ": authenticated MeshLink transports full inner IPv4 through actual native workers in both directions");
            check(wire.Packets > 0 && wire.MaximumBytes >= 1392, mode + ": native serialized packet length is measured separately from UDP framing");
            check(factories.All(f => f.Transports.Single().WireControl is { Selected: true, HandshakePackets: > 0, BusinessPackets: > 0 }), mode + ": formal factory enables native wire accounting and only selected business bypasses control limits");
            if (paced) check(factories.All(f => f.Egress is { SentBytes: > 0, Failure: "" } && f.Egress.Peers.Length == 1) && states.All(s => s?.Egress?.Mbps == 50), mode + ": formal native broker uses shared per-member pacing and reports it through Runner status");
        } finally {
            running.Cancel(); foreach (var task in tasks) try { await task.WaitAsync(TimeSpan.FromSeconds(10)); } catch (OperationCanceledException) { }
        }
        check(wire.Endpoints.Values.All(io => io.Closed) && adapters.All(ad => ad.Disposed), mode + ": shutdown joins actual capture/worker owners before resource release");
        if (paced) check(factories.All(f => f.Egress?.QueuedBytes == 0), mode + ": pacing closes without retaining a worker or queued packet");
        return new { mode, connectedMs = connected, elapsedMs = clock.ElapsedMilliseconds, wire.Packets, wire.MaximumBytes,
            paths = factories.Select(f => f.Paths.Select(p => new { p.LeaseId, p.AttachId, local = p.ActualLocal.ToString(), remote = p.ActualRemote.ToString() })).ToArray(),
            wireControl = factories.Select(f => f.Transports.Select(p => p.WireControl)).ToArray(), egress = factories.Select(f => f.Egress).ToArray() };
    }
    internal sealed class Inspect(MeshCandidateFactory inner) : IMeshCandidateFactory, IAsyncDisposable
    {
        public int Gathers; public readonly ConcurrentQueue<ValidatedPathIdentity> Paths = [];
        public readonly ConcurrentQueue<NativeDatagramPath> Transports = [];
        public TraversalProfile[] Profiles => inner.Profiles; public bool SupportsFakeTcpIpv6 => inner.SupportsFakeTcpIpv6;
        public bool SupportsTcpPeerReflexive => inner.SupportsTcpPeerReflexive;
        public readonly ConcurrentQueue<MeshTraversalCandidate> Candidates = [];
        public EgressStats? Egress => inner.Egress;
        public Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile p, Guid a, CancellationToken t) => GatherForPeer(peer, p, a, false, null, 1, t);
        public async Task<IMeshCandidateResource> GatherForPeer(MeshMember peer, TraversalProfile p, Guid a, bool v6, IPEndPoint? r, int round, CancellationToken t)
        { Interlocked.Increment(ref Gathers); return new Resource(await inner.GatherForPeer(peer, p, a, v6, r, round, t), this); }
        public async Task<IMeshCandidateResource> GatherSourceAware(MeshMember peer, TraversalProfile p, Guid attempt, bool v6, MeshTraversalCandidate? remote,
            int round, bool prediction, bool source, CancellationToken t)
        { Interlocked.Increment(ref Gathers); var gathered = await inner.GatherSourceAware(peer, p, attempt, v6, remote, round, prediction, source, t); Candidates.Enqueue(gathered.Candidate); return new Resource(gathered, this); }
        sealed class Resource(IMeshCandidateResource inner, Inspect owner) : IMeshCandidateResource {
            public MeshTraversalCandidate Candidate => inner.Candidate;
            public async Task<IPreparedMeshPath> Prepare(TraversalAttemptContext c, IPEndPoint r, CancellationToken t) => new Prepared(await inner.Prepare(c, r, t), owner);
            public ValueTask DisposeAsync() => inner.DisposeAsync();
        }
        sealed class Prepared(IPreparedMeshPath inner, Inspect owner) : IPreparedMeshPath {
            public TraversalAttemptContext Context => inner.Context; public bool Armed => inner.Armed; public TimeSpan RemainingAttemptTime => inner.RemainingAttemptTime;
            public async Task<IMeshDatagramPath> Activate(CancellationToken t) { var p = await inner.Activate(t); owner.Paths.Enqueue(p.Identity); if (p is NativeDatagramPath native) owner.Transports.Enqueue(native); return p; }
            public ValueTask DisposeAsync() => inner.DisposeAsync();
        }
        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }
    internal sealed class Wire(bool dropIpv6)
    {
        public readonly ConcurrentDictionary<string, Io> Endpoints = []; public int Packets, MaximumBytes;
        public Io Open(IPEndPoint endpoint) { var io = new Io(this); if (!Endpoints.TryAdd(endpoint.ToString(), io)) throw new IOException("duplicate capture"); return io; }
        public bool Send(ReadOnlySpan<byte> p) {
            if (!TcpCaptureOwner.Tuple(p, out _, out var target, true)) throw new IOException("malformed native output");
            Interlocked.Increment(ref Packets); MaximumBytes = Math.Max(MaximumBytes, p.Length);
            if (dropIpv6 && target.AddressFamily == AddressFamily.InterNetworkV6) return true;
            return Endpoints.TryGetValue(target.ToString(), out var io) && io.Packets.Writer.TryWrite(new(p.ToArray(), false));
        }
    }
    internal sealed class Io(Wire wire) : IEndpointPacketIo {
        public readonly Channel<EndpointPacket> Packets = Channel.CreateBounded<EndpointPacket>(512); public bool Closed;
        public ValueTask<EndpointPacket> Receive(CancellationToken t) => Packets.Reader.ReadAsync(t);
        public bool Inject(ReadOnlySpan<byte> p) => wire.Send(p);
        public bool Reinject(EndpointPacket p) => true;
        public void Shutdown() => Packets.Writer.TryComplete();
        public void Dispose() { Closed = true; Shutdown(); }
    }
    sealed class OldService(MeshDiscoveryClient inner) : IMeshDiscovery, IMeshChangeDiscovery, IMeshTraversalDiscovery {
        public Guid BootId => inner.BootId; public bool SupportsTraversal => inner.SupportsTraversal; public bool SupportsFakeTcpIpv6 => false;
        public bool SupportsLongPolling => inner.SupportsLongPolling;
        public Task SaveDirectory(MeshDirectory d, CancellationToken t) => inner.SaveDirectory(d, t);
        public Task Publish(MeshAnnouncement a, CancellationToken t) => inner.Publish(a, t);
        public Task<MeshSnapshot?> Read(CancellationToken t) => inner.Read(t);
        public Task<MeshSnapshot?> WaitForChanges(CancellationToken t) => inner.WaitForChanges(t);
        public Task PublishTraversal(MeshTraversalMessage[] m, CancellationToken t) => inner.PublishTraversal(m, t);
        public void Dispose() => inner.Dispose();
    }
    internal static byte[] Packet(string from, string to) {
        byte[] p = new byte[1280]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), 1280);
        IPAddress.Parse(from).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(p, 16);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
    }
    internal sealed class Adapter : IPacketAdapter {
        public readonly BlockingCollection<byte[]> Outgoing = new(); public readonly ConcurrentQueue<byte[]> Incoming = new(); public bool Disposed;
        public int Read(byte[] p) { if (!Outgoing.TryTake(out var b, 25)) return 0; b.CopyTo(p, 0); return b.Length; }
        public bool Write(byte[] p) { Incoming.Enqueue(p); return true; }
        public void Dispose() { Disposed = true; Outgoing.Dispose(); }
    }
}
