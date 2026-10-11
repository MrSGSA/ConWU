using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using StreamLink.Core;

namespace StreamLink.EndpointPoc;

static class CaptureBrokerPoc
{
    public static async Task<int> Run(string binary, int rounds, string output)
    {
        if (rounds is < 1 or > 30) throw new ArgumentException("1..30 rounds");
        int checks = 0; var rows = new List<object>();
        void Check(bool value, string why) { if (!value) throw new Exception(why); checks++; }
        async Task Until(Func<bool> condition, string why, int ms = 6000) { var w = Stopwatch.StartNew(); while (!condition()) { if (w.ElapsedMilliseconds >= ms) throw new TimeoutException(why); await Task.Delay(10); } Check(true, why); }
        string root = Path.Combine(Path.GetDirectoryName(output)!, Path.GetFileNameWithoutExtension(output) + "-logs"); Directory.CreateDirectory(root);
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(10)); var token = deadline.Token;
        try {
            for (int round = 1; round <= rounds; round++) {
                await using var reflector = new Reflector(); var generation = Guid.NewGuid();
                var leases = new List<TcpEndpointLease>(); var owners = new List<TcpCaptureOwner>(); var paths = new List<NativeDatagramPath>();
                var routers = new List<MeshRouter>(); var adapters = new List<Adapter>(); var wire = new Network();
                var a = MeshIdentity.Create("https://example.com/", "", "faketcp");
                var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); var c = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));
                b.Directory = c.Directory = a.Directory; var profiles = new[] { a, b, c };
                var timer = Stopwatch.StartNew();
                try {
                    for (int i = 0; i < 3; i++) {
                        var lease = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, token); leases.Add(lease);
                        using var query = lease.AcquireAttempt(generation); await query.Observe(token);
                        owners.Add(new(lease, generation, (local, _) => wire.Open(local))); await owners[^1].Ready;
                        var adapter = new Adapter(); adapters.Add(adapter); routers.Add(new(profiles[i], adapter));
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
                            try { paths.Add(await NativeDatagramPath.Prepare(binary, root, leases[side.Local], generation, side.Context, leases[side.Remote].Local,
                                key, token, new(), captureOwner: owners[side.Local])); }
                            finally { CryptographicOperations.ZeroMemory(key); }
                        }
                    }
                    Check(paths.All(p => p.Armed && !p.Started) && wire.Count == 0, "all brokered workers armed before SYN");
                    Check(paths[0].CaptureOwnerId == paths[2].CaptureOwnerId && paths[0].AttachId != paths[2].AttachId && owners[0].Status.Sessions == 2,
                        "two workers share one capture owner and retain distinct attachment identities");
                    bool refused = false; try { using var duplicate = owners[0].Register(generation, leases[1].Local); } catch (IOException) { refused = true; }
                    Check(refused, "same wire tuple cannot acquire another independent handshake");
                    refused = false; try { using var capture = leases[0].AcquireNativeAttachment(generation); } catch (InvalidOperationException) { refused = true; }
                    Check(refused, "source lease permits only this one capture owner");
                    await Task.WhenAll(paths.Select(p => p.StartAndQualify(token)));
                    for (int peer = 1; peer <= 2; peer++) {
                        int index = (peer - 1) * 2;
                        routers[0].RegisterPath(peer + 1, paths[index], contexts[index], 1, paths[index].RemainingAttemptTime, 1);
                        routers[peer].RegisterPath(1, paths[index + 1], contexts[index + 1], 1, paths[index + 1].RemainingAttemptTime, 1);
                    }
                    await Until(() => routers.All(r => r.Status().All(p => (p.Slot == 1 || r == routers[0]) ? p.Connected : true)), "both pairs complete actual Router nomination");
                    // Only A-B/A-C have paths; B-C is deliberately not connected.
                    Check(!routers[1].Status().Single(p => p.Slot == 3).Connected && !routers[2].Status().Single(p => p.Slot == 2).Connected, "partial mesh never forwards B-C through A");
                    foreach (int peer in new[] { 1, 2 }) {
                        adapters[0].Outgoing.Add(Packet(a.LocalIp, profiles[peer].LocalIp)); adapters[peer].Outgoing.Add(Packet(profiles[peer].LocalIp, a.LocalIp));
                    }
                    await Until(() => adapters[0].Incoming.Count == 2 && adapters[1].Incoming.Count == 1 && adapters[2].Incoming.Count == 1, "shared source carries isolated authenticated full-MTU traffic for both peers");
                    foreach (var lease in leases) { using var query = lease.AcquireAttempt(generation); Check((await query.Observe(token)).Public.Equals(lease.Local), "helper queries remain usable while both raw sessions run"); }
                    foreach (int peer in new[] { 1, 2 }) {
                        var peerWire = wire.Rows.Where(p => p.Source == leases[0].Local.ToString() && p.Target == leases[peer].Local.ToString()).ToArray();
                        Check(peerWire.Any(p => p.Flags == 2), "the real native SYN uses the shared held source endpoint");
                        var http = peerWire.First(p => p.Payload == 180); var bare = peerWire.First(p => p.Payload == 48 && p.Tick >= http.Tick);
                        Check(http.Sequence == bare.Sequence, "shared capture preserves legacy overlapping HTTP/bare sequence profile");
                    }
                    await owners[0].DisposeAsync(); leases[0].Dispose();
                    Check(!owners[0].Closed.IsCompleted && !leases[0].Closed, "retiring original owner cannot close live worker references");
                    var exitClock = Stopwatch.StartNew();
                    using (var child = Process.GetProcessById(paths[0].ProcessId)) { child.Kill(); await child.WaitForExitAsync(token); }
                    await Until(() => paths[0].Failed, "exit notification invalidates path without querying the process per packet");
                    double exitDetectedMs = exitClock.Elapsed.TotalMilliseconds;
                    Check(exitDetectedMs < 250, "worker exit is detected within the 250 ms engineering target in this local case");
                    await paths[0].DisposeAsync(); await routers[1].DisposeAsync();
                    await Until(() => owners[0].Status.Sessions == 1, "one exited worker releases only its tuple");
                    Check(!paths[2].Failed && owners[0].Status.Sessions == 1 && !leases[0].Closed, "other active peer retains source capture and helper");
                    int count = adapters[2].Incoming.Count; adapters[0].Outgoing.Add(Packet(a.LocalIp, c.LocalIp));
                    await Until(() => adapters[2].Incoming.Count == count + 1, "remaining peer keeps transporting after sibling exit");
                    foreach (var router in routers) await router.DisposeAsync();
                    foreach (var owner in owners) await owner.DisposeAsync();
                    foreach (var lease in leases) lease.Dispose();
                    await Task.WhenAll(owners.Select(o => o.Closed));
                    Check(owners.All(o => o.Status is { Closed: true, Sessions: 0, Failure: "" }) && leases.All(l => l.Closed), "capture I/O joins before the final source reference is released");
                    Check(owners.All(o => o.Status.Queues is { Enqueued: > 0, Dequeued: > 0, PeakSessionDepth: > 0, PipeWrites: > 0 } q &&
                        q.Dequeued <= q.Enqueued && q.PipeWrites <= q.Dequeued), "cumulative capture/pipe diagnostics survive worker release and preserve stage counts");
                    rows.Add(new { round, elapsedMs = timer.ElapsedMilliseconds, exitDetectedMs, owners = owners.Select(o => o.Status).ToArray(), wirePackets = wire.Count });
                    Console.WriteLine($"Broker {round}/{rounds} passed");
                } finally {
                    foreach (var router in routers) await router.DisposeAsync(); foreach (var path in paths) await path.DisposeAsync();
                    foreach (var owner in owners) await owner.DisposeAsync(); foreach (var lease in leases) lease.Dispose();
                }
            }
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows,
                scope = "Three real Windows TCP helpers, actual C++ workers and authenticated named pipes, shared source demultiplexing and real MeshRouter; raw I/O simulated in memory, no WinDivert/Wintun/NAT" }, new JsonSerializerOptions { WriteIndented = true })); return 0;
        } catch (Exception ex) { await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() })); throw; }
    }
    static byte[] Packet(string from, string to) {
        byte[] p = new byte[1280]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), 1280);
        IPAddress.Parse(from).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(p, 16);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
    }
    sealed class Adapter : IPacketAdapter {
        public readonly BlockingCollection<byte[]> Outgoing = new(); public readonly ConcurrentQueue<byte[]> Incoming = new();
        public int Read(byte[] buffer) { if (!Outgoing.TryTake(out var p, 30)) return 0; p.CopyTo(buffer, 0); return p.Length; }
        public bool Write(byte[] p) { Incoming.Enqueue(p); return true; }
        public void Dispose() => Outgoing.Dispose();
    }
    sealed record Header(string Source, string Target, byte Flags, int Payload, uint Sequence, long Tick);
    sealed class Network {
        readonly ConcurrentDictionary<string, Io> endpoints = new();
        public readonly ConcurrentQueue<Header> Rows = new();
        public int Count => Rows.Count;
        public Io Open(IPEndPoint local) { var io = new Io(this); if (!endpoints.TryAdd(local.ToString(), io)) throw new IOException("duplicate capture"); return io; }
        public bool Send(ReadOnlySpan<byte> p) {
            int ip = (p[0] & 15) * 4; string source = new IPEndPoint(new IPAddress(p.Slice(12, 4)), BinaryPrimitives.ReadUInt16BigEndian(p[ip..])).ToString();
            string target = new IPEndPoint(new IPAddress(p.Slice(16, 4)), BinaryPrimitives.ReadUInt16BigEndian(p[(ip + 2)..])).ToString();
            Rows.Enqueue(new(source, target, p[ip + 13], p.Length - ip - (p[ip + 12] >> 4) * 4, BinaryPrimitives.ReadUInt32BigEndian(p[(ip + 4)..]), Environment.TickCount64));
            return endpoints.TryGetValue(target, out var io) && io.Receiving.Writer.TryWrite(new(p.ToArray(), false));
        }
    }
    sealed class Io(Network network) : IEndpointPacketIo {
        public readonly Channel<EndpointPacket> Receiving = Channel.CreateBounded<EndpointPacket>(512);
        public ValueTask<EndpointPacket> Receive(CancellationToken token) => Receiving.Reader.ReadAsync(token);
        public bool Inject(ReadOnlySpan<byte> packet) => network.Send(packet);
        public bool Reinject(EndpointPacket packet) => true;
        public void Shutdown() => Receiving.Writer.TryComplete();
        public void Dispose() => Shutdown();
    }
}
