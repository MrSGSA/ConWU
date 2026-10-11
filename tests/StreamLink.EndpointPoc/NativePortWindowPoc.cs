using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using StreamLink.Core;

namespace StreamLink.EndpointPoc;

static class NativePortWindowPoc
{
    public static async Task<int> Run(string binary, int rounds, string output, bool wide = false)
    {
        if (rounds is < 1 or > 30) throw new ArgumentException("1..30 rounds");
        int checks = 0; var rows = new List<object>();
        void Check(bool value, string why) { if (!value) throw new Exception(why); checks++; Console.WriteLine("PASS " + why); }
        string root = Path.Combine(Path.GetDirectoryName(output)!, Path.GetFileNameWithoutExtension(output) + "-logs"); Directory.CreateDirectory(root);
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(10)); var token = deadline.Token;
        async Task Until(Func<bool> predicate, string why) {
            var clock = Stopwatch.StartNew(); while (!predicate()) { if (clock.Elapsed.TotalSeconds > 7) throw new TimeoutException(why); await Task.Delay(10, token); } Check(true, why);
        }
        try {
            BudgetChecks(Check);
            for (int round = 1; round <= rounds; round++) foreach (bool clientWindow in new[] { true, false }) {
                await using var helper = new Reflector(); var generation = Guid.NewGuid(); var wire = new Wire();
                using var aSource = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), helper.Endpoint, generation, token);
                using var bSource = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), helper.Endpoint, generation, token);
                await using var aOwner = new TcpCaptureOwner(aSource, generation, (local, _) => wire.Open(local));
                await using var bOwner = new TcpCaptureOwner(bSource, generation, (local, _) => wire.Open(local));
                await Task.WhenAll(aOwner.Ready, bOwner.Ready);
                var a = MeshIdentity.Create("https://example.com", "", "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));
                b.Directory = a.Directory;
                var aIp = new Adapter(); var bIp = new Adapter(); await using var aRouter = new MeshRouter(a, aIp); await using var bRouter = new MeshRouter(b, bIp);
                var context = new TraversalAttemptContext(a.Pair.Network, a.Self.Device, aRouter.BootId, b.Self.Device, bRouter.BootId, Guid.NewGuid(),
                    Guid.NewGuid(), 1, Guid.NewGuid(), 1, TraversalProfile.FakeTcpHttpSo, true, true, Guid.NewGuid());
                var reverse = context with { LocalNodeId = context.RemoteNodeId, RemoteNodeId = context.LocalNodeId, LocalBootId = context.RemoteBootId,
                    RemoteBootId = context.LocalBootId, LocalCandidateId = context.RemoteCandidateId, RemoteCandidateId = context.LocalCandidateId, ProtocolClient = false, Nominator = false };
                var owner = clientWindow ? aOwner : bOwner; var other = clientWindow ? bOwner : aOwner;
                int width = wide ? 8 : 3;
                var candidates = Enumerable.Range(44000, 20).Where(p => p != aSource.Local.Port && p != bSource.Local.Port && p != helper.Endpoint.Port)
                    .Take(width - 1).Select(p => new IPEndPoint(IPAddress.Loopback, p)).ToList();
                candidates.Insert(width / 2, other.Lease.Local); var ports = candidates.ToArray();
                byte[] key = MeshIdentity.SharedKey(a, b.Self); int claims = 0;
                NativePortWindow? window = null; NativeDatagramPath? single = null; IMeshDatagramPath? winner = null;
                try {
                    if (round == 1) {
                        using (var occupied = owner.Register(generation, other.Lease.Local)) {
                            bool rolledBack = false;
                            try { await using var invalid = await NativePortWindow.Prepare(binary, root, owner, clientWindow ? context : reverse,
                                ports, key, () => true, token); } catch (IOException) { rolledBack = true; }
                            Check(rolledBack && owner.Status.Sessions == 1 && wire.Packets.Count == 0,
                                "mid-Prepare tuple conflict joins already prepared children without touching the original session or emitting SYN");
                        }
                        foreach (var invalid in new[] { new[] { ports[0], ports[0] }, new[] { ports[0], new IPEndPoint(IPAddress.Parse("127.0.0.2"), ports[1].Port) },
                            Enumerable.Range(43000, 9).Select(p => new IPEndPoint(IPAddress.Loopback, p)).ToArray() }) {
                            bool refused = false;
                            try { await using var rejected = await NativePortWindow.Prepare(binary, root, owner, clientWindow ? context : reverse, invalid, key, () => true, token); }
                            catch (ArgumentException) { refused = true; }
                            Check(refused && owner.Status.Sessions == 0, "duplicate ports, multiple IPs and oversized windows cannot allocate workers");
                        }
                    }
                    var preparing = Stopwatch.StartNew();
                    window = await NativePortWindow.Prepare(binary, root, owner, clientWindow ? context : reverse, ports, key,
                        () => { Interlocked.Increment(ref claims); return true; }, token);
                    long prepareMs = preparing.ElapsedMilliseconds;
                    single = await NativeDatagramPath.Prepare(binary, root, other.Lease, generation, clientWindow ? reverse : context,
                        owner.Lease.Local, key, token, captureOwner: other, countWireControl: true);
                    Check(window.Armed && single.Armed && claims == 0 && wire.Packets.Count == 0, "window prepares exact tuples without SYN or early forecast claim");
                    Check(owner.Status.Sessions == width && window.Diagnostics.Select(d => d.AttachId).Distinct().Count() == width, "one source capture holds the entire bounded window with distinct native handshakes");
                    bool collision = false; try { using var duplicate = owner.Register(generation, other.Lease.Local); } catch (IOException) { collision = true; }
                    Check(collision, "a second handshake cannot reuse a live TCP tuple");
                    var activation = window.Activate(token); var opposite = single.Activate(token);
                    await Task.WhenAll(activation, opposite); winner = await activation;
                    Check(ReferenceEquals(window.Activate(token), activation) && claims == 1, "duplicate activation reuses the task and first budgeted probe claims once");
                    Check(winner.Identity.ActualRemote.Equals(other.Lease.Local) && winner.Identity.LeaseId == owner.Lease.Id && owner.Status.Sessions == 1,
                        "matching port wins on the same source; all nonwinning native sessions exit before transfer");
                    Check(window.Diagnostics.Count(d => d.NativeExited) == width - 1, "all nonwinning native processes have confirmed exit before the winning path is exposed");
                    Check(ReferenceEquals(((ITraversalControlledPath)winner).ControlRound, window.ControlRound) && window.ControlRound.Packets <= 120,
                        "winning path inherits the one control allowance consumed by the whole window");
                    aRouter.RegisterPath(b.Self.Slot, clientWindow ? winner : single, context, 1, window.RemainingAttemptTime, 1);
                    bRouter.RegisterPath(a.Self.Slot, clientWindow ? single : winner, reverse, 1, window.RemainingAttemptTime, 1);
                    await Until(() => aRouter.Status().Single().Connected && bRouter.Status().Single().Connected, "port-window winner completes actual MeshRouter joint nomination");
                    await window.DisposeAsync(); // Attempt owner ends; Router now owns the winner.
                    aIp.Outgoing.Add(Packet(a.LocalIp, b.LocalIp)); bIp.Outgoing.Add(Packet(b.LocalIp, a.LocalIp));
                    await Until(() => aIp.Incoming.Count == 1 && bIp.Incoming.Count == 1, "full-MTU authenticated MeshLink business survives ending the window owner in both directions");
                    using var query = owner.Lease.AcquireAttempt(generation); Check((await query.Observe(token)).Public.Equals(owner.Lease.Local), "helper remains usable after losing native workers exit");
                    var transcript = wire.Packets.Where(p => p.Source == aSource.Local.ToString() && p.Target == bSource.Local.ToString()).ToArray();
                    var http = transcript.First(p => p.Payload == 180); var bare = transcript.First(p => p.Payload == 48 && p.Tick >= http.Tick);
                    Check(http.Sequence == bare.Sequence, "port selection preserves the existing overlapping HTTP/bare sequence profile");
                    rows.Add(new { round, clientWindow, tuples = width, claims, prepareMs, window.ControlRound.Packets, window.ControlRound.Bytes,
                        remainingMs = window.RemainingAttemptTime.TotalMilliseconds, actualRemote = winner.Identity.ActualRemote.ToString(), physicalNat = false });
                } finally {
                    CryptographicOperations.ZeroMemory(key);
                    await aRouter.DisposeAsync(); await bRouter.DisposeAsync();
                    if (window != null) await window.DisposeAsync(); if (winner != null) await winner.DisposeAsync(); if (single != null) await single.DisposeAsync();
                }
                Check(aOwner.Status.Sessions == 0 && bOwner.Status.Sessions == 0, "Router shutdown releases the winner and both capture session sets");
            }
            foreach (string scenario in new[] { "stale-claim", "claim-error", "cancel", "no-peer" }) {
                await using var helper = new Reflector(); var generation = Guid.NewGuid(); var wire = new Wire();
                using var lease = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), helper.Endpoint, generation, token);
                await using var owner = new TcpCaptureOwner(lease, generation, (local, _) => wire.Open(local)); await owner.Ready;
                var context = new TraversalAttemptContext("negative", "a", Guid.NewGuid(), "b", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 1, Guid.NewGuid(), 1,
                    TraversalProfile.FakeTcpHttpSo, true, true, Guid.NewGuid());
                var ports = Enumerable.Range(44000, 12).Where(p => p != lease.Local.Port && p != helper.Endpoint.Port).Take(8).Select(p => new IPEndPoint(IPAddress.Loopback, p)).ToArray();
                byte[] key = RandomNumberGenerator.GetBytes(32); int claims = 0; bool fresh = true;
                await using var window = await NativePortWindow.Prepare(binary, root, owner, context, ports, key,
                    () => { Interlocked.Increment(ref claims); if (scenario == "claim-error") throw new InvalidOperationException("injected claim failure"); return fresh; }, token);
                CryptographicOperations.ZeroMemory(key); fresh = scenario != "stale-claim";
                using var cancel = CancellationTokenSource.CreateLinkedTokenSource(token); if (scenario == "cancel") cancel.CancelAfter(150);
                var clock = Stopwatch.StartNew(); bool rejected = false;
                try { await window.Activate(cancel.Token); } catch (Exception ex) when (ex is IOException or OperationCanceledException) { rejected = true; }
                Check(rejected && owner.Status.Sessions == 0 && window.ControlRound.Packets <= 120, scenario + ": no promotion, bounded aggregate allowance and all workers joined");
                if (scenario == "stale-claim") Check(claims == 1 && wire.Packets.Count == 0 && !window.Claimed, "forecast invalidated after Prepare cannot emit even a first SYN");
                if (scenario == "stale-claim") Check(clock.ElapsedMilliseconds < 3000, "a known-invalid forecast ends immediately without spending the remaining round waiting for peers");
                if (scenario == "claim-error") Check(claims == 1 && wire.Packets.Count == 0 && clock.ElapsedMilliseconds < 3000,
                    "a failing claim callback cannot leak a SYN, restart the permit or retain native children");
                if (scenario == "cancel") Check(clock.ElapsedMilliseconds < 3000 && cancel.IsCancellationRequested, "caller cancellation releases eight prepared workers promptly");
                if (scenario == "no-peer") Check(clock.ElapsedMilliseconds is >= 7500 and < 11000 && window.RemainingAttemptTime <= TimeSpan.Zero && claims == 1,
                    "eight guesses share one eight-second deadline including native authentication");
                using var query = lease.AcquireAttempt(generation); Check((await query.Observe(token)).Public.Equals(lease.Local), "negative window leaves original helper queryable");
                rows.Add(new { scenario, elapsedMs = clock.ElapsedMilliseconds, claims, injected = wire.Packets.Count, window.ControlRound.Packets, window.ControlRound.Bytes });
            }
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows,
                scope = "real Windows exclusive TCP helpers, C++ native workers, authenticated IPC, MeshRouter and MeshLink; in-memory raw routing and IP adapters; preauthorized port arrays, no prediction model/coordinator/WinDivert/Wintun/public NAT proof" }, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        } catch (Exception ex) { await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() })); throw; }
    }
    static void BudgetChecks(Action<bool, string> check)
    {
        int claims = 0; var group = new NativeAttemptGroup(new(8, 10000, 256), () => { claims++; return true; });
        var budgets = Enumerable.Range(0, 8).Select(_ => new NativeWireBudget(group.ControlRound, group)).ToArray();
        long stamp = Stopwatch.GetTimestamp(); var first = budgets[0].Start(stamp);
        var starts = budgets.Skip(1).Select((b, i) => b.Start(stamp + i + 1)).ToArray();
        check(starts.All(s => s == first) && claims == 0, "different native workers join the original start clock without consuming the forecast");
        bool earlySelect = false; try { budgets[0].Select(); } catch (InvalidOperationException) { earlySelect = true; }
        check(earlySelect, "selecting a worker cannot bypass the first-probe forecast permission");
        for (int i = 0; i < 96; i++) if (!budgets[i % 8].Admit(NativeWireKind.Handshake, 64)) throw new Exception("shared handshake prematurely denied");
        check(budgets.All(b => !b.Admit(NativeWireKind.Handshake, 64)) && claims == 1, "all eight workers share 96 search packets and a single claimed forecast");
        for (int i = 0; i < 24; i++) if (!budgets[i % 8].Admit(NativeWireKind.Completion, 64)) throw new Exception("shared completion missing");
        check(budgets.All(b => !b.Admit(NativeWireKind.Completion, 64)) && group.ControlRound.Packets == 120, "completion does not turn each guessed tuple into another allowance");
        var expired = new NativeAttemptGroup(new(), () => throw new Exception("expired group cannot claim"));
        new NativeWireBudget(expired.ControlRound, expired).Start(stamp - Stopwatch.Frequency * 9);
        var late = new NativeWireBudget(expired.ControlRound, expired); late.Start(Stopwatch.GetTimestamp());
        check(!late.Admit(NativeWireKind.Handshake, 64) && expired.Remaining < TimeSpan.Zero, "a late worker cannot renew the shared expired deadline");
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
    sealed record Header(string Source, string Target, int Payload, uint Sequence, long Tick);
    sealed class Wire {
        readonly ConcurrentDictionary<string, Io> endpoints = new();
        public readonly ConcurrentQueue<Header> Packets = new();
        public Io Open(IPEndPoint local) { var io = new Io(this); if (!endpoints.TryAdd(local.ToString(), io)) throw new IOException("duplicate capture"); return io; }
        public bool Send(ReadOnlySpan<byte> p) {
            int ip = (p[0] & 15) * 4;
            string source = new IPEndPoint(new IPAddress(p.Slice(12, 4)), BinaryPrimitives.ReadUInt16BigEndian(p[ip..])).ToString();
            string target = new IPEndPoint(new IPAddress(p.Slice(16, 4)), BinaryPrimitives.ReadUInt16BigEndian(p[(ip + 2)..])).ToString();
            Packets.Enqueue(new(source, target, p.Length - ip - (p[ip + 12] >> 4) * 4, BinaryPrimitives.ReadUInt32BigEndian(p[(ip + 4)..]), Environment.TickCount64));
            if (endpoints.TryGetValue(target, out var io)) io.Input.Writer.TryWrite(new(p.ToArray(), false));
            return true; // a blackholed remote is not a local injection failure
        }
    }
    sealed class Io(Wire wire) : IEndpointPacketIo {
        public readonly Channel<EndpointPacket> Input = Channel.CreateBounded<EndpointPacket>(1024);
        public ValueTask<EndpointPacket> Receive(CancellationToken token) => Input.Reader.ReadAsync(token);
        public bool Inject(ReadOnlySpan<byte> p) => wire.Send(p);
        public bool Reinject(EndpointPacket p) => true;
        public void Shutdown() => Input.Writer.TryComplete();
        public void Dispose() => Shutdown();
    }
}
