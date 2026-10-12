using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using StreamLink.Core;

namespace StreamLink.EndpointPoc;

// Controlled full MeshLink/C++ workload on this Windows host. In-memory outer
// IP delivery removes WAN/QoS; actual pipes, processes and loopback bridges remain.
static class BrokerLoadPoc
{
    const int Size = 1280;
    public static async Task<int> Run(string binary, int mbps, int seconds, int rounds, string output, bool countWireControl = false, int egressMbps = 0, bool feedback = false)
    {
        if (mbps is < 1 or > 60 || seconds is < 3 or > 20 || rounds is < 1 or > 5) throw new ArgumentException("bounded load: 1..60 Mbps, 3..20 seconds, 1..5 rounds");
        if (egressMbps is < 0 or > 100) throw new ArgumentException("controlled outer pacing: 0..100 Mbps");
        string root = Path.Combine(Path.GetDirectoryName(output)!, Path.GetFileNameWithoutExtension(output) + "-logs"); Directory.CreateDirectory(root);
        var rows = new List<object>(); using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(12)); var token = deadline.Token;
        var leases = new List<TcpEndpointLease>(); var owners = new List<TcpCaptureOwner>(); var paths = new List<NativeDatagramPath>();
        var routers = new List<MeshRouter>(); var adapters = new List<Adapter>(); var wire = new Wire();
        var pacers = new List<EgressPacer>();
        var machineBudgets = Enumerable.Range(0, 3).Select(_ => new TraversalResources()).ToArray();
        var a = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); var c = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));
        b.Directory = c.Directory = a.Directory; var profiles = new[] { a, b, c };
        string failure = "";
        try {
            await using var reflector = new Reflector(); var generation = Guid.NewGuid();
            for (int i = 0; i < 3; i++) {
                var lease = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, token); leases.Add(lease);
                using var query = lease.AcquireAttempt(generation); await query.Observe(token);
                EgressPacer? pacer = egressMbps == 0 ? null : new(egressMbps); if (pacer != null) pacers.Add(pacer);
                owners.Add(new(lease, generation, (local, _) => wire.Open(local), pacer)); await owners[^1].Ready;
                adapters.Add(new()); routers.Add(new(profiles[i], adapters[i]));
            }
            var contexts = new List<TraversalAttemptContext>();
            for (int peer = 1; peer <= 2; peer++) {
                var context = new TraversalAttemptContext(a.Pair.Network, a.Self.Device, routers[0].BootId, profiles[peer].Self.Device, routers[peer].BootId,
                    Guid.NewGuid(), Guid.NewGuid(), 1, Guid.NewGuid(), 1, TraversalProfile.FakeTcpHttpSo, true, true, Guid.NewGuid());
                var reverse = context with { LocalNodeId = context.RemoteNodeId, LocalBootId = context.RemoteBootId, RemoteNodeId = context.LocalNodeId,
                    RemoteBootId = context.LocalBootId, LocalCandidateId = context.RemoteCandidateId, RemoteCandidateId = context.LocalCandidateId, ProtocolClient = false, Nominator = false };
                contexts.Add(context); contexts.Add(reverse);
                foreach (var side in new[] { (Local: 0, Remote: peer, Context: context), (Local: peer, Remote: 0, Context: reverse) }) {
                    byte[] key = MeshIdentity.SharedKey(profiles[side.Local], profiles[side.Remote].Self);
                    try { paths.Add(await NativeDatagramPath.Prepare(binary, root, leases[side.Local], generation, side.Context, leases[side.Remote].Local, key, token, machineBudgets[side.Local], captureOwner: owners[side.Local], countWireControl: countWireControl)); }
                    finally { CryptographicOperations.ZeroMemory(key); }
                }
            }
            await Task.WhenAll(paths.Select(p => p.StartAndQualify(token)));
            for (int peer = 1; peer <= 2; peer++) {
                int index = (peer - 1) * 2;
                routers[0].RegisterPath(peer + 1, paths[index], contexts[index], 1, paths[index].RemainingAttemptTime, 1, feedback ? 1 : 0);
                routers[peer].RegisterPath(1, paths[index + 1], contexts[index + 1], 1, paths[index + 1].RemainingAttemptTime, 1, feedback ? 1 : 0);
            }
            var wait = Stopwatch.StartNew();
            while (!routers[0].Status().All(p => p.Connected) || !routers.Skip(1).All(r => r.Status().Single(p => p.Slot == 1).Connected)) {
                if (wait.ElapsedMilliseconds > 6000) throw new TimeoutException("load fixture nomination"); await Task.Delay(10, token);
            }
            await Task.Delay(500, token);
            using var self = Process.GetCurrentProcess();
            var children = paths.Select(p => Process.GetProcessById(p.ProcessId)).ToArray();
            try {
                foreach (int round in Enumerable.Range(1, rounds)) foreach (bool fanIn in new[] { false, true }) {
                    int run = round * 2 + (fanIn ? 1 : 0); var sink = new Sink(run); foreach (var adapter in adapters) adapter.Sink = sink;
                    var templates = Enumerable.Range(1, 2).Select(i => Packet(profiles[fanIn ? i : 0].LocalIp, profiles[fanIn ? 0 : i].LocalIp, run)).ToArray();
                    var startOwners = owners.Select(o => o.Status).ToArray(); long wireDrops = wire.Drops;
                    var egressStart = pacers.Select(p => p.Snapshot()).ToArray();
                    var initialRouterDrops = routers.Sum(r => r.Status().Sum(p => p.DroppedPackets));
                    long allocated = GC.GetTotalAllocatedBytes(true); var cpu = self.TotalProcessorTime; var childCpu = children.Select(p => p.TotalProcessorTime).ToArray();
                    int offered = 0, accepted = 0; var clock = Stopwatch.StartNew();
                    while (clock.Elapsed.TotalSeconds < seconds) {
                        int target = (int)(clock.Elapsed.TotalSeconds * mbps * 1e6 / (Size * 8));
                        // Match the existing short Quality workload's bounded
                        // 128-packet catch-up bursts; report actual offered rate.
                        for (int n = 0; n < 128 && offered < target; n++) {
                            int peer = offered % 2; byte[] packet = (byte[])templates[peer].Clone();
                            BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(36), offered);
                            BinaryPrimitives.WriteInt64BigEndian(packet.AsSpan(40), Stopwatch.GetTimestamp());
                            if (adapters[fanIn ? peer + 1 : 0].Outgoing.TryAdd(packet)) accepted++;
                            offered++;
                        }
                        await Task.Delay(1, token);
                    }
                    double elapsed = clock.Elapsed.TotalSeconds;
                    await Task.Delay(500, token); // bounded drain, one-host delay samples include it
                    self.Refresh(); foreach (var child in children) child.Refresh();
                    var sample = sink.Snapshot(); var finalOwners = owners.Select(o => o.Status).ToArray();
                    var row = new { round, direction = fanIn ? "two-peers-to-owner" : "owner-to-two-peers", requestedMbps = mbps, seconds, elapsed,
                        offered, accepted, received = sample.Count, offeredMbps = offered * Size * 8 / elapsed / 1e6,
                        receivedMbps = sample.Count * Size * 8 / elapsed / 1e6, lossPercent = offered == 0 ? 100 : (offered - sample.Count) * 100d / offered,
                        fixtureQueueDrops = offered - accepted, fixtureWireDrops = wire.Drops - wireDrops,
                        captureQueueDrops = finalOwners.Select((s, i) => s.QueueDrops - startOwners[i].QueueDrops).ToArray(),
                        captureReceived = finalOwners.Select((s, i) => s.Received - startOwners[i].Received).ToArray(),
                        captureQueuesCumulative = finalOwners.Select(s => s.Queues).ToArray(),
                        routerDrops = routers.Sum(r => r.Status().Sum(p => p.DroppedPackets)) - initialRouterDrops,
                        sample.Duplicates, sample.Reordered, sample.P50Ms, sample.P95Ms, sample.P99Ms, sample.MaximumMs,
                        managedAllocatedBytes = GC.GetTotalAllocatedBytes(true) - allocated,
                        managedCpuMs = (self.TotalProcessorTime - cpu).TotalMilliseconds,
                        nativeCpuMs = children.Select((p, i) => (p.TotalProcessorTime - childCpu[i]).TotalMilliseconds).ToArray(),
                        managedWorkingSet = self.WorkingSet64, nativeWorkingSet = children.Select(p => p.WorkingSet64).ToArray(),
                        egressMbps, egressStart, egressEnd = pacers.Select(p => p.Snapshot()).ToArray(),
                        recovery = routers.Select(r => r.Status().Select(p => new { p.Slot, p.Connected, p.Recovery, p.Traffic, p.Delivery }).ToArray()).ToArray(),
                        allPairsHealthy = routers[0].Status().All(p => p.Connected) && routers.Skip(1).All(r => r.Status().Single(p => p.Slot == 1).Connected) };
                    rows.Add(row); Console.WriteLine(JsonSerializer.Serialize(row));
                    foreach (var adapter in adapters) adapter.Sink = null;
                    await Task.Delay(300, token);
                }
            } finally { foreach (var child in children) child.Dispose(); }
        } catch (Exception ex) { failure = ex.ToString(); }
        finally {
            foreach (var router in routers) await router.DisposeAsync(); foreach (var path in paths) await path.DisposeAsync();
            foreach (var owner in owners) await owner.DisposeAsync(); foreach (var lease in leases) lease.Dispose();
            foreach (var pacer in pacers) pacer.Dispose();
        }
        bool completed = failure.Length == 0 && rows.Count == rounds * 2 && owners.All(o => o.Closed.IsCompletedSuccessfully) && leases.All(l => l.Closed) && pacers.All(p => p.Snapshot() is { Failure: "", QueuedBytes: 0 });
        await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = completed ? "Completed" : "Fail", rows, failure, countWireControl, egressMbps, feedback, egressFinal = pacers.Select(p => p.Snapshot()).ToArray(), wireControl = paths.Select(p => p.WireControl).ToArray(),
            hashes = new { core = Hash(typeof(MeshRouter).Assembly.Location), native = Hash(binary), harness = Hash(typeof(BrokerLoadPoc).Assembly.Location) },
            scope = "One Windows host: real protocol workers/pipes/UDP bridge/MeshRouter; synthetic bounded IP adapters and memory raw I/O; no driver, WAN, QoS or Wintun. Completion is not a quality pass. Delay uses one shared monotonic host clock." }, new JsonSerializerOptions { WriteIndented = true }));
        if (!completed) throw new IOException(failure); return 0;
    }
    static string Hash(string file) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)));
    static byte[] Packet(string from, string to, int run) {
        byte[] p = new byte[Size]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), Size);
        IPAddress.Parse(from).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(p, 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), 49001); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), 49002); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(24), Size - 20);
        "SLB1"u8.CopyTo(p.AsSpan(28)); BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(32), run);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
    }
    sealed class Sink(int run) {
        readonly object gate = new(); readonly HashSet<int> seen = []; readonly List<double> delay = []; readonly Dictionary<ulong, int> last = []; int duplicates, reordered;
        public void Accept(byte[] p) {
            if (p.Length != Size || !p.AsSpan(28, 4).SequenceEqual("SLB1"u8) || BinaryPrimitives.ReadInt32BigEndian(p.AsSpan(32)) != run) return;
            int sequence = BinaryPrimitives.ReadInt32BigEndian(p.AsSpan(36)); double ms = Stopwatch.GetElapsedTime(BinaryPrimitives.ReadInt64BigEndian(p.AsSpan(40))).TotalMilliseconds;
            ulong pair = BinaryPrimitives.ReadUInt64BigEndian(p.AsSpan(12));
            lock (gate) { if (!seen.Add(sequence)) { duplicates++; return; } int previous = last.GetValueOrDefault(pair, -1); if (sequence < previous) reordered++; last[pair] = Math.Max(previous, sequence); delay.Add(ms); }
        }
        public Sample Snapshot() { lock (gate) { var sorted = delay.Order().ToArray(); double At(double p) => sorted.Length == 0 ? 0 : sorted[Math.Min(sorted.Length - 1, (int)Math.Ceiling(p * sorted.Length) - 1)]; return new(seen.Count, duplicates, reordered, At(.5), At(.95), At(.99), sorted.LastOrDefault()); } }
    }
    sealed record Sample(int Count, int Duplicates, int Reordered, double P50Ms, double P95Ms, double P99Ms, double MaximumMs);
    sealed class Adapter : IPacketAdapter {
        public readonly BlockingCollection<byte[]> Outgoing = new(512); public volatile Sink? Sink;
        public int Read(byte[] buffer) { if (!Outgoing.TryTake(out var p, 30)) return 0; p.CopyTo(buffer, 0); return p.Length; }
        public bool Write(byte[] p) { Sink?.Accept(p); return true; }
        public void Dispose() => Outgoing.Dispose();
    }
    sealed class Wire {
        readonly ConcurrentDictionary<int, Io> endpoints = new(); public long Drops;
        public Io Open(IPEndPoint local) { var io = new Io(this); if (!endpoints.TryAdd(local.Port, io)) throw new IOException("duplicate source capture"); return io; }
        public bool Send(ReadOnlySpan<byte> p) { int ip = (p[0] & 15) * 4; int port = BinaryPrimitives.ReadUInt16BigEndian(p[(ip + 2)..]);
            bool sent = endpoints.TryGetValue(port, out var io) && io.Packets.Writer.TryWrite(new(p.ToArray(), false)); if (!sent) Interlocked.Increment(ref Drops); return sent; }
    }
    sealed class Io(Wire wire) : IEndpointPacketIo {
        public readonly Channel<EndpointPacket> Packets = Channel.CreateBounded<EndpointPacket>(512);
        public ValueTask<EndpointPacket> Receive(CancellationToken token) => Packets.Reader.ReadAsync(token);
        public bool Inject(ReadOnlySpan<byte> p) => wire.Send(p);
        public bool Reinject(EndpointPacket p) => true;
        public void Shutdown() => Packets.Writer.TryComplete();
        public void Dispose() => Shutdown();
    }
}
