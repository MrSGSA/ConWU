using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Channels;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

static class SharedBrokerRunner
{
    public static async Task Run(string binary, string root, string url, string pin, Action<bool, string> check, CancellationToken token)
    {
        var a = MeshIdentity.Create(url, pin, "faketcp");
        var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));
        var c = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = c.Directory = a.Directory;
        var mesh = new[] { a, b, c }; var wire = new Wire();
        await using var reflector = new Reflector();
        var adapters = mesh.Select(_ => new Adapter()).ToArray(); var statuses = new SessionStatus?[3];
        var factories = mesh.Select(m => new Factory(m, binary, root, reflector.Endpoint, wire)).ToArray();
        var stops = mesh.Select(_ => CancellationTokenSource.CreateLinkedTokenSource(token)).ToArray();
        var logs = new ConcurrentQueue<string>(); int legacy = 0;
        var tasks = Enumerable.Range(0, 3).Select(i => {
            var services = new MeshRuntimeServices(m => new MeshDiscoveryClient(m), _ => Task.FromResult<IPacketAdapter>(adapters[i]),
                async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new InvalidOperationException(); },
                _ => { Interlocked.Increment(ref legacy); throw new IOException("No explicit fixture entry"); },
                (_, _, ct) => Task.Delay(Timeout.Infinite, ct), (_, _, _) => { }, (_, _) => { }, Path.Combine(root, "broker-runner")) {
                    Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(factories[i])
                };
            return new MeshRunner(new() { Mesh = mesh[i], TraversalMode = "tcp" }, s => logs.Enqueue(i + " " + s), s => statuses[i] = s, _ => { }, _ => { }, services).Run(stops[i].Token);
        }).ToArray();
        async Task Until(Func<bool> condition, string label, int ms = 45000) {
            var watch = Stopwatch.StartNew();
            while (!condition()) {
                foreach (var task in tasks) if (task.IsFaulted) await task;
                if (watch.ElapsedMilliseconds > ms) throw new TimeoutException(label + "\n" + string.Join('\n', logs));
                await Task.Delay(20, token);
            }
            check(true, label);
        }
        try {
            await Until(() => statuses.All(s => s?.Connected == true && s.Peers?.Length == 2 && s.Peers.All(p => p.Connected)), "three production Runners automatically negotiate full mesh through shared source owners");
            check(legacy == 0 && factories.All(f => f.Leases.Distinct().Count() == 1 && f.Owners.Distinct().Count() == 1) && reflector.Accepted == 3,
                "each Runner's two peers use one real TCP helper/capture, no legacy or member relay");
            for (int from = 0; from < 3; from++) for (int to = 0; to < 3; to++) if (from != to) adapters[from].Outgoing.Add(Packet(mesh[from].LocalIp, mesh[to].LocalIp));
            await Until(() => adapters.All(a => a.Incoming.Count == 2), "three Runners carry authenticated full-MTU business over every direct pair");
            stops[1].Cancel(); try { await tasks[1].WaitAsync(TimeSpan.FromSeconds(8), token); } catch (OperationCanceledException) { }
            int before = adapters[2].Incoming.Count; adapters[0].Outgoing.Add(Packet(a.LocalIp, c.LocalIp));
            await Until(() => adapters[2].Incoming.Count == before + 1, "exiting one Runner leaves the other shared-source pair transporting", 2500);
        } finally {
            foreach (var stop in stops) stop.Cancel();
            foreach (var task in tasks) try { await task.WaitAsync(TimeSpan.FromSeconds(10), token); } catch (OperationCanceledException) { }
            foreach (var stop in stops) stop.Dispose();
        }
        check(factories.All(f => f.Closed) && adapters.All(a => a.Disposed), "production Runner shutdown joins shared capture pool after native workers and adapters");
    }
    sealed class Factory(MeshProfile mesh, string binary, string root, IPEndPoint reflector, Wire wire) : IMeshCandidateFactory, IAsyncDisposable
    {
        readonly Guid generation = Guid.NewGuid(); readonly TraversalResources budget = new();
        readonly MeshProfile profile = mesh;
        readonly string executable = binary, folder = root;
        MeshTcpEndpointPool? pool;
        public readonly List<Guid> Leases = [], Owners = []; readonly List<TcpEndpointLease> actual = [];
        public bool Closed => actual.All(l => l.Closed);
        public TraversalProfile[] Profiles => [TraversalProfile.FakeTcpHttpSo];
        public async Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile kind, Guid attempt, CancellationToken token) {
            pool ??= new(generation, (local, _) => wire.Open(local), budget);
            var use = await pool.Acquire(IPAddress.Loopback, reflector, token);
            lock (actual) { actual.Add(use.Lease); Leases.Add(use.Lease.Id); Owners.Add(use.Owner.OwnerId); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return new Resource(this, peer, use, new(Guid.NewGuid(), 1, use.Observed.ToString(), reflector.ToString(), now, now + 120, CandidatePurpose.Host));
        }
        public async ValueTask DisposeAsync() { if (pool != null) await pool.DisposeAsync(); }
        sealed class Resource(Factory owner, MeshMember peer, MeshTcpEndpointPool.Use use, MeshTraversalCandidate candidate) : IMeshCandidateResource {
            public MeshTraversalCandidate Candidate => candidate;
            public async Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context, IPEndPoint remote, CancellationToken token) {
                byte[] key = MeshIdentity.SharedKey(owner.profile, peer);
                try { return await NativeDatagramPath.Prepare(owner.executable, owner.folder, use.Lease, owner.generation, context, remote, key, token, owner.budget, captureOwner: use.Owner); }
                finally { CryptographicOperations.ZeroMemory(key); }
            }
            public ValueTask DisposeAsync() { use.Dispose(); return ValueTask.CompletedTask; }
        }
    }
    sealed class Wire {
        readonly ConcurrentDictionary<string, Io> endpoints = new();
        public Io Open(IPEndPoint local) { var io = new Io(this); if (!endpoints.TryAdd(local.ToString(), io)) throw new IOException("Duplicate capture"); return io; }
        public bool Send(ReadOnlySpan<byte> p) {
            int ip = (p[0] & 15) * 4; var target = new IPEndPoint(new IPAddress(p.Slice(16, 4)), BinaryPrimitives.ReadUInt16BigEndian(p[(ip + 2)..]));
            return endpoints.TryGetValue(target.ToString(), out var io) && io.Packets.Writer.TryWrite(new(p.ToArray(), false));
        }
    }
    sealed class Io(Wire wire) : IEndpointPacketIo {
        public readonly Channel<EndpointPacket> Packets = Channel.CreateBounded<EndpointPacket>(512);
        public ValueTask<EndpointPacket> Receive(CancellationToken token) => Packets.Reader.ReadAsync(token);
        public bool Inject(ReadOnlySpan<byte> packet) => wire.Send(packet);
        public bool Reinject(EndpointPacket packet) => true;
        public void Shutdown() => Packets.Writer.TryComplete();
        public void Dispose() => Shutdown();
    }
    sealed class Adapter : IPacketAdapter {
        public readonly BlockingCollection<byte[]> Outgoing = new(); public readonly ConcurrentQueue<byte[]> Incoming = new(); public bool Disposed;
        public int Read(byte[] buffer) { if (!Outgoing.TryTake(out var p, 30)) return 0; p.CopyTo(buffer, 0); return p.Length; }
        public bool Write(byte[] p) { Incoming.Enqueue(p); return true; }
        public void Dispose() { Disposed = true; Outgoing.Dispose(); }
    }
    static byte[] Packet(string from, string to) {
        byte[] p = new byte[1280]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), 1280);
        IPAddress.Parse(from).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(p, 16);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
    }
}
