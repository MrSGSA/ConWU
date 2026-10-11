using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

static class UdpGatewayTests
{
    public static async Task<object> Run(string root, string url, string pin, Action<bool, string> check, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromMinutes(3)); token = deadline.Token;
        await SharedBudget(check, token);
        await RetainedWinner(check, token);
        await StaleCandidate(root, url, pin, check, token);
        return await Runners(root, url, pin, check, token);
    }
    static async Task Wait(Func<bool> ready, CancellationToken token) { while (!ready()) await Task.Delay(20, token); }
    static UdpTraversal Socket(TraversalResources budget, Guid attempt, int local, int remote, byte[] key, Guid generation)
        => UdpTraversal.Create(new(IPAddress.Loopback, 0), generation, attempt, local, remote, key, budget);
    static async Task SharedBudget(Action<bool, string> check, CancellationToken token)
    {
        await using var gateway = new Gateway(); await using var reflector = new Reflector();
        var budget = new TraversalResources(8); var sockets = new List<UdpTraversal>(); byte[] key = RandomNumberGenerator.GetBytes(32);
        try {
            for (int i = 0; i < 7; i++) sockets.Add(Socket(budget, Guid.NewGuid(), 1, i + 2, key, Guid.NewGuid()));
            foreach (var socket in sockets) socket.AttachGateway(await gateway.Map(socket.Local.Port, token, budget));
            check(gateway.ControlSources.Distinct().Count() == 1 && gateway.Leases.Count == 7, "seven mapped UDP sockets share one serial control socket within the eight-socket machine budget");
            bool full = false; try { using var excess = budget.Acquire(); } catch (IOException) { full = true; }
            check(full, "all active data sockets and the shared gateway control owner consume the global quota");
            int controls = gateway.ControlSources.Count; bool ledger = false;
            try { await using var foreign = await PortControlLease.Open(gateway.Route, 41079, 41079, PortMappingProtocol.Udp, () => true, token, new TraversalResources()); }
            catch (IOException) { ledger = true; }
            check(ledger && gateway.ControlSources.Count == controls, "shared control socket cannot be acquired through a different machine resource ledger");
            var observed = await sockets[0].Observe(reflector.Endpoint, token);
            check(observed.SocketId == sockets[0].SocketId && observed.Local.Equals(sockets[0].Local) &&
                observed.Mapped.Equals(sockets[0].Local) && sockets[0].GatewaySnapshot!.SocketResourceId == observed.SocketId,
                "STUN and gateway attachment refer to the same held real data socket");
            await sockets[0].DisposeAsync();
            check(gateway.Leases.Count(l => l.Snapshot.State == "Closed") == 1 && sockets.Skip(1).All(s => !s.Closed), "retiring one peer leaves the shared control owner and other mapped sockets alive");
            using var free = budget.Acquire();
        } finally { foreach (var socket in sockets) await socket.DisposeAsync(); CryptographicOperations.ZeroMemory(key); }
        check(gateway.Deletes == 7 && gateway.Leases.All(l => l.Snapshot.Cleanup == "DeleteConfirmed"), "last data owner closes all exact UDP mapping leases without wildcard deletion");
        var reclaimed = new List<IDisposable>(); try { for (int i = 0; i < 8; i++) reclaimed.Add(budget.Acquire()); check(true, "all eight quota slots return after the final shared-control reference closes"); }
        finally { foreach (var item in reclaimed) item.Dispose(); }
    }
    static async Task RetainedWinner(Action<bool, string> check, CancellationToken token)
    {
        await using var gateway = new Gateway(); var budget = new TraversalResources(8);
        byte[] key = RandomNumberGenerator.GetBytes(32); var attempt = Guid.NewGuid(); var ga = Guid.NewGuid(); var gb = Guid.NewGuid();
        await using var a = Socket(budget, attempt, 1, 2, key, ga); await using var b = Socket(budget, attempt, 2, 1, key, gb); CryptographicOperations.ZeroMemory(key);
        var wrong = await PortControlLease.Open(gateway.Route, a.Local.Port, a.Local.Port, PortMappingProtocol.Tcp, () => true, token, budget);
        bool rejected = false; try { a.AttachGateway(wrong); } catch (IOException) { rejected = true; }
        check(rejected && a.GatewaySnapshot == null, "TCP mapping cannot be attached to a UDP data socket"); await wrong.DisposeAsync();
        var mappingB = await gateway.Map(b.Local.Port, token, budget); bool otherPort = false;
        try { a.AttachGateway(mappingB); } catch (IOException) { otherPort = true; }
        check(otherPort && a.GatewaySnapshot == null, "a UDP mapping for another local port cannot be transferred to this socket");
        b.AttachGateway(mappingB); a.AttachGateway(await gateway.Map(a.Local.Port, token, budget));
        var result = await Task.WhenAll(a.Punch([b.Local], null, token), b.Punch([a.Local], null, token));
        check(result.All(r => r.Success), "mapped real sockets complete authenticated checks and full-size UDP qualification");
        await using var pa = a.RetainPath(ga, Guid.NewGuid()); await using var pb = b.RetainPath(gb, Guid.NewGuid());
        await a.DisposeAsync(); await b.DisposeAsync(); int deleted = gateway.Deletes;
        byte[] data = RandomNumberGenerator.GetBytes(1344); var received = pb.Receive(token).AsTask();
        check(pa.TrySend(data) && (await received).Span.SequenceEqual(data), "ending the original Attempt owner leaves the exact winning socket carrying 1344-byte datagrams");
        check(!a.Closed && !b.Closed && gateway.Deletes == deleted && a.GatewaySnapshot!.Mapping.State == "Granted",
            "gateway maintenance belongs to retained paths, not the disposed Attempt reference");
        await pa.DisposeAsync(); await pb.DisposeAsync();
        check(a.Closed && b.Closed && gateway.Deletes == deleted + 2, "final path release joins gateway maintenance and deletes only its mappings before releasing data ports");
    }
    static DeviceProfile Profile(MeshProfile mesh, string stun) => new() { Mesh = mesh, TraversalMode = "tcp-udp", AllowUdpFallback = true, PortControlMapping = true, UdpStun = [stun] };
    static MeshCandidateFactory Factory(DeviceProfile profile, string root, Gateway gateway, Action<string>? log = null)
        => new(profile, "unused-native", root, [TraversalProfile.UdpDirect], diagnostic: log) {
            OpenUdpGateway = (_, port, token) => gateway.Map(port, token),
            RouteCheckForTest = (endpoint, expected, _) => {
                if (!IPAddress.IsLoopback(endpoint.Address) || expected != null && !IPAddress.IsLoopback(expected)) throw new IOException("fixture must stay loopback");
            }
        };
    static async Task StaleCandidate(string root, string url, string pin, Action<bool, string> check, CancellationToken token)
    {
        await using var gateway = new Gateway { Lifetime = 10, ChangePort = true }; await using var reflector = new Reflector();
        var a = MeshIdentity.Create(url, pin, "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));
        var disabled = Profile(a, reflector.Endpoint.ToString()); disabled.PortControlMapping = false;
        await using (var noGateway = Factory(disabled, root, gateway)) {
            for (int i = 0; i < 2; i++) { await using var ordinary = await noGateway.Gather(b.Self, TraversalProfile.UdpDirect, Guid.NewGuid(), token); }
            check(gateway.Leases.Count == 0, "disabled gateway option leaves both ordinary UDP rounds free of mapping requests");
        }
        await using var factory = Factory(Profile(a, reflector.Endpoint.ToString()), root, gateway);
        await using (var ordinary = await factory.Gather(b.Self, TraversalProfile.UdpDirect, Guid.NewGuid(), token))
            check(gateway.Leases.Count == 0 && reflector.Count > 0, "first production UDP gather uses ordinary same-socket STUN without waiting for gateway discovery");
        var attempt = Guid.NewGuid(); await using var candidate = await factory.Gather(b.Self, TraversalProfile.UdpDirect, attempt, token);
        var frozen = candidate.Candidate;
        var context = new TraversalAttemptContext(a.Pair.Network, a.Self.Device, Guid.NewGuid(), b.Self.Device, Guid.NewGuid(), attempt,
            frozen.Id, frozen.Version, Guid.NewGuid(), 1, TraversalProfile.UdpDirect, true, true, Guid.NewGuid());
        await using var prepared = await candidate.Prepare(context, new(IPAddress.Loopback, 44001), token);
        check(prepared.Armed && frozen.ObservationTarget == gateway.Route.Gateway.ToString(), "later production UDP gather publishes the actual gateway endpoint and transfers its same socket to Prepared");
        await Wait(() => gateway.Leases.Single().External.Port != IPEndPoint.Parse(frozen.Endpoint).Port, token);
        bool stale = false; try { _ = candidate.Candidate; } catch (IOException) { stale = true; }
        bool activation = false; try { await prepared.Activate(token); } catch (IOException) { activation = true; }
        check(stale && !prepared.Armed && activation, "mapping changes invalidate the frozen Offer and prevent old Ready/Start from activating a different endpoint");
    }
    static async Task<object> Runners(string root, string url, string pin, Action<bool, string> check, CancellationToken token)
    {
        await using var ga = new Gateway { Lifetime = 30 }; await using var gb = new Gateway { Lifetime = 30, Pmp = true }; await using var reflector = new Reflector { BlackholeMappings = true };
        var a = MeshIdentity.Create(url, pin, "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var profiles = new[] { Profile(a, reflector.Endpoint.ToString()), Profile(b, reflector.Endpoint.ToString()) }; var gateways = new[] { ga, gb };
        var logs = new ConcurrentQueue<string>(); var inners = profiles.Select((p, i) => Factory(p, root, gateways[i], logs.Enqueue)).ToArray();
        var factories = inners.Select(i => new Inspect(i)).ToArray(); var adapters = new[] { new Adapter(), new Adapter() }; var states = new SessionStatus?[2];
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(token); int legacy = 0;
        MeshRuntimeServices Services(int i) => new(mesh => new MeshDiscoveryClient(mesh), _ => Task.FromResult<IPacketAdapter>(adapters[i]),
            async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new IOException(); },
            _ => { Interlocked.Increment(ref legacy); throw new IOException("legacy disabled in fixture"); },
            (_, _, ct) => Task.Delay(Timeout.Infinite, ct), (_, _, _) => { }, (_, _) => { }, Path.Combine(root, "gateway-sessions")) {
                Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(factories[i])
            };
        var runners = profiles.Select((p, i) => new MeshRunner(p, logs.Enqueue, s => states[i] = s, _ => { }, _ => { }, Services(i))).ToArray();
        var clock = Stopwatch.StartNew(); var tasks = runners.Select(r => r.Run(stopping.Token)).ToArray(); long connected;
        try {
            while (!states.All(s => s?.Connected == true)) {
                foreach (var task in tasks) if (task.IsCompleted) await task;
                if (clock.Elapsed.TotalSeconds > 55) throw new IOException(string.Join('\n', logs));
                await Task.Delay(20, token);
            }
            connected = clock.ElapsedMilliseconds;
            check(legacy == 0 && factories.All(f => f.Paths.Count == 1 && f.Gathers == 2) && states.All(s => s!.Degraded), "after real checks to an unreachable STUN candidate fail, production Runners automatically retry using gateway UDP candidates, without legacy or relay");
            check(ga.Leases.Single().Snapshot.Provider == PortControlKind.Pcp && gb.Leases.Single().Snapshot.Provider == PortControlKind.NatPmp,
                "formal UDP data path works across one PCP grant and one explicitly negotiated NAT-PMP grant");
            for (int i = 0; i < 2; i++) {
                var path = factories[i].Paths.Single(); var lease = gateways[i].Leases.Single();
                check(path.ActualLocal.ToString() == lease.Snapshot.Local && path.ActualRemote.Port == gateways[1-i].Leases.Single().External.Port && path.Profile == TraversalProfile.UdpDirect,
                    "actual winning UDP path uses the data endpoint owned by its gateway lease");
            }
            adapters[0].Outgoing.Add(Packet(a.LocalIp, b.LocalIp)); adapters[1].Outgoing.Add(Packet(b.LocalIp, a.LocalIp));
            await Wait(() => adapters.All(x => x.Incoming.Count >= 1), token);
            check(true, "gateway candidates carry full 1280-byte inner IP through formal MeshRunner and MeshLink");
            ga.DropRenewals = gb.DropRenewals = true;
            await Wait(() => ga.Leases.Concat(gb.Leases).All(l => !l.Valid), token);
            adapters[0].Outgoing.Add(Packet(a.LocalIp, b.LocalIp)); adapters[1].Outgoing.Add(Packet(b.LocalIp, a.LocalIp));
            await Wait(() => adapters.All(x => x.Incoming.Count >= 2), token);
            check(states.All(s => s?.Connected == true) && factories.All(f => f.Paths.Count == 1),
                "expiry of mapping metadata does not close or replace an authenticated UDP path still passing actual traffic");
        } finally {
            stopping.Cancel(); foreach (var task in tasks) try { await task.WaitAsync(TimeSpan.FromSeconds(10)); } catch (OperationCanceledException) { }
        }
        check(gateways.All(g => g.Leases.All(l => l.Snapshot.State == "Closed")) && adapters.All(a => a.Disposed), "Runner shutdown joins final UDP path, gateway and adapter owners");
        check(gb.Deletes == 0 && gb.Leases.Single().Snapshot.Cleanup == "NaturalExpiry", "formal NAT-PMP path shutdown never sends an unowned deletion request");
        return new { connectedMs = connected, elapsedMs = clock.ElapsedMilliseconds, realHttps = true, realUdp = true, realPcpDatagrams = true, realNatPmpDatagrams = true,
            realNat = false, wintun = false, peers = factories.Select(f => f.Paths.Select(p => new { socketId = p.LeaseId, local = p.ActualLocal.ToString(), remote = p.ActualRemote.ToString() })).ToArray() };
    }
    sealed class Inspect(MeshCandidateFactory inner) : IMeshCandidateFactory, IAsyncDisposable
    {
        public readonly ConcurrentQueue<ValidatedPathIdentity> Paths = [];
        public int Gathers;
        public TraversalProfile[] Profiles => inner.Profiles;
        public async Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile kind, Guid attempt, CancellationToken token)
        { Interlocked.Increment(ref Gathers); return new Resource(await inner.Gather(peer, kind, attempt, token), this); }
        sealed class Resource(IMeshCandidateResource inner, Inspect owner) : IMeshCandidateResource
        {
            public MeshTraversalCandidate Candidate => inner.Candidate;
            public async Task<IPreparedMeshPath> Prepare(TraversalAttemptContext c, IPEndPoint r, CancellationToken token) => new Prepared(await inner.Prepare(c, r, token), owner);
            public ValueTask DisposeAsync() => inner.DisposeAsync();
        }
        sealed class Prepared(IPreparedMeshPath inner, Inspect owner) : IPreparedMeshPath
        {
            public TraversalAttemptContext Context => inner.Context; public bool Armed => inner.Armed; public TimeSpan RemainingAttemptTime => inner.RemainingAttemptTime;
            public async Task<IMeshDatagramPath> Activate(CancellationToken token) { var p = await inner.Activate(token); owner.Paths.Enqueue(p.Identity); return p; }
            public ValueTask DisposeAsync() => inner.DisposeAsync();
        }
        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }
    static byte[] Packet(string from, string to)
    {
        byte[] p = new byte[1280]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), 1280);
        IPAddress.Parse(from).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(p, 16);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
    }
    sealed class Adapter : IPacketAdapter
    {
        public readonly BlockingCollection<byte[]> Outgoing = new(); public readonly ConcurrentQueue<byte[]> Incoming = new(); public bool Disposed;
        public int Read(byte[] p) { if (!Outgoing.TryTake(out var b, 25)) return 0; b.CopyTo(p, 0); return b.Length; }
        public bool Write(byte[] p) { Incoming.Enqueue(p); return true; }
        public void Dispose() { Disposed = true; Outgoing.Dispose(); }
    }
    sealed class Reflector : IAsyncDisposable
    {
        readonly UdpClient udp = new(new IPEndPoint(IPAddress.Loopback, 0)); readonly CancellationTokenSource stop = new(); readonly Task run;
        readonly UdpClient blackhole = new(new IPEndPoint(IPAddress.Loopback, 0));
        public bool BlackholeMappings;
        public int Count; public IPEndPoint Endpoint => (IPEndPoint)udp.Client.LocalEndPoint!;
        public Reflector() { run = Run(); }
        async Task Run() { try { while (true) {
            var p = await udp.ReceiveAsync(stop.Token); if (p.Buffer.Length != 20) continue; Interlocked.Increment(ref Count);
            byte[] reply = new byte[32]; p.Buffer.CopyTo(reply, 0); reply[0] = 1; reply[3] = 12; reply[21] = 0x20; reply[23] = 8; reply[25] = 1;
            int mapped = BlackholeMappings ? ((IPEndPoint)blackhole.Client.LocalEndPoint!).Port : p.RemoteEndPoint.Port;
            BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(26), (ushort)(mapped ^ 0x2112));
            BinaryPrimitives.WriteUInt32BigEndian(reply.AsSpan(28), BinaryPrimitives.ReadUInt32BigEndian(p.RemoteEndPoint.Address.GetAddressBytes()) ^ 0x2112a442);
            await udp.SendAsync(reply, p.RemoteEndPoint, stop.Token);
        } } catch (OperationCanceledException) when (stop.IsCancellationRequested) { } }
        public async ValueTask DisposeAsync() { stop.Cancel(); await run; udp.Dispose(); blackhole.Dispose(); stop.Dispose(); }
    }
    sealed class Gateway : IAsyncDisposable
    {
        readonly UdpClient udp = new(new IPEndPoint(IPAddress.Loopback, 0)); readonly CancellationTokenSource stop = new(); readonly Task run;
        readonly Stopwatch clock = Stopwatch.StartNew(); readonly Dictionary<string, int> grants = [];
        public readonly ConcurrentQueue<PortControlLease> Leases = []; public readonly ConcurrentQueue<string> ControlSources = [];
        public uint Lifetime = 60; public bool ChangePort, DropRenewals, Pmp; public int Deletes;
        public PortControlRoute Route { get; }
        public Gateway() { Route = new("gateway-fixture", IPAddress.Loopback, (IPEndPoint)udp.Client.LocalEndPoint!, Guid.NewGuid().ToString()); run = Run(); }
        public async Task<PortControlLease> Map(int port, CancellationToken token, TraversalResources? budget = null)
        { var lease = await PortControlLease.Open(Route, port, port, PortMappingProtocol.Udp, () => true, token, budget); Leases.Enqueue(lease); return lease; }
        async Task Run() { try { while (true) {
            var p = await udp.ReceiveAsync(stop.Token); byte[] b = p.Buffer; ControlSources.Enqueue(p.RemoteEndPoint.ToString());
            uint epoch = (uint)(100 + clock.Elapsed.TotalSeconds);
            if (Pmp) {
                byte[] answer;
                if (b.Length == 60 && b[0] == 2) { answer = new byte[8]; answer[3] = 1; }
                else if (b.Length == 2 && b[0] == 0 && b[1] == 0) { answer = new byte[12]; answer[1] = 128; IPAddress.Loopback.GetAddressBytes().CopyTo(answer, 8); }
                else if (b.Length == 12 && b[0] == 0 && b[1] == 1) {
                    int port = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(4)); string key = "pmp-" + port;
                    if (DropRenewals && grants.ContainsKey(key)) continue;
                    grants[key] = 1; if (BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(8)) == 0) Interlocked.Increment(ref Deletes);
                    answer = new byte[16]; answer[1] = 129; b.AsSpan(4, 2).CopyTo(answer.AsSpan(8)); b.AsSpan(4, 2).CopyTo(answer.AsSpan(10));
                    BinaryPrimitives.WriteUInt32BigEndian(answer.AsSpan(12), Lifetime);
                } else continue;
                BinaryPrimitives.WriteUInt32BigEndian(answer.AsSpan(4), epoch); await udp.SendAsync(answer, p.RemoteEndPoint, stop.Token); continue;
            }
            if (b.Length != 60 || b[0] != 2 || b[1] != 1) continue;
            string nonce = Convert.ToHexString(b.AsSpan(24, 12));
            bool remove = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(4)) == 0; bool renewal = grants.ContainsKey(nonce);
            if (remove) Interlocked.Increment(ref Deletes); else { if (renewal && DropRenewals) continue; grants[nonce] = grants.GetValueOrDefault(nonce) + 1; }
            byte[] response = b.ToArray(); response[1] = 0x81; response.AsSpan(12, 12).Clear();
            BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(4), remove ? 0 : Lifetime);
            BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(8), (uint)(100 + clock.Elapsed.TotalSeconds));
            int assigned = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(40)); if (ChangePort && renewal && !remove) assigned = assigned == 65535 ? 65534 : assigned + 1;
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(42), (ushort)assigned); IPAddress.Loopback.MapToIPv6().GetAddressBytes().CopyTo(response, 44);
            await udp.SendAsync(response, p.RemoteEndPoint, stop.Token);
        } } catch (OperationCanceledException) when (stop.IsCancellationRequested) { } }
        public async ValueTask DisposeAsync() { stop.Cancel(); await run; udp.Dispose(); stop.Dispose(); }
    }
}
