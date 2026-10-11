using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

static partial class Program
{
    static async Task ManagedUdp(string output, int rounds = 30)
    {
        var rows = new List<object>();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(160));
        try {
            foreach (string environment in new[] { "real-loopback", "model-eim-apdf", "model-prflx" }) {
                for (int iteration = 1; iteration <= rounds; iteration++) {
                    var a = MeshIdentity.Create("https://example.com/", "", "udp");
                    var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
                    var leftAdapter = new RoutedAdapter(); var rightAdapter = new RoutedAdapter();
                    await using var ra = new MeshRouter(a, leftAdapter, selection: new(AllowUdpFallback: true)); await using var rb = new MeshRouter(b, rightAdapter, selection: new(AllowUdpFallback: true));
                    await using var reflector = new Reflector(IPAddress.Loopback);
                    var generationA = Guid.NewGuid(); var generationB = Guid.NewGuid(); var attempt = Guid.NewGuid();
                    ITraversalSocket left, right; IPEndPoint server;
                    if (environment == "real-loopback") {
                        left = new PressureSocket(new TraversalSocket(new(IPAddress.Loopback, 0))); right = new TraversalSocket(new(IPAddress.Loopback, 0)); server = reflector.Endpoint;
                    } else {
                        var lab = new NatLab();
                        left = lab.Add("192.0.2.1", "eim", environment == "model-prflx" ? "adf" : "apdf", 40111, maximumPayload: 1344);
                        right = lab.Add("192.0.2.2", environment == "model-prflx" ? "apdm" : "eim", "apdf", 50111, maximumPayload: 1344);
                        server = NatLab.Reflectors[0];
                    }
                    Guid socketA = left.Id, socketB = right.Id;
                    byte[] key = MeshIdentity.SharedKey(a, b.Self);
                    await using var ua = new UdpTraversal(left, generationA, attempt, 1, 2, key);
                    await using var ub = new UdpTraversal(right, generationB, attempt, 2, 1, key); CryptographicOperations.ZeroMemory(key);
                    var oa = await ua.Observe(server, deadline.Token); var ob = await ub.Observe(server, deadline.Token);
                    var clock = Stopwatch.StartNew();
                    var punch = await Task.WhenAll(ua.Punch([ob.Mapped], null, deadline.Token), ub.Punch([oa.Mapped], null, deadline.Token));
                    Check(punch.All(p => p.Success), environment + " checks and full-size MTU round trip");
                    if (environment == "model-prflx") Check(ua.Selected != null && !ua.Selected.Equals(ob.Mapped), "formal UDP path uses authenticated peer-reflexive source");
                    var context = new TraversalAttemptContext(a.Pair.Network, a.Self.Device, ra.BootId, b.Self.Device, rb.BootId, attempt,
                        Guid.NewGuid(), 1, Guid.NewGuid(), 1, TraversalProfile.UdpDirect, true, true, Guid.NewGuid());
                    var reverse = context with { LocalNodeId = context.RemoteNodeId, RemoteNodeId = context.LocalNodeId,
                        LocalBootId = context.RemoteBootId, RemoteBootId = context.LocalBootId, LocalCandidateId = context.RemoteCandidateId,
                        RemoteCandidateId = context.LocalCandidateId, ProtocolClient = false, Nominator = false };
                    var pa = ua.RetainPath(generationA, Guid.NewGuid()); var pb = ub.RetainPath(generationB, Guid.NewGuid());
                    var roundA = ((ITraversalControlledPath)pa).ControlRound;
                    if (environment == "real-loopback" && iteration == 1) ((PressureSocket)left).FailNext = true;
                    Check(roundA.Packets == punch[0].SentPackets && roundA.Bytes > 0, "path promotion retains the spent attempt budget");
                    if (iteration == 1) {
                        bool duplicate = false; try { _ = ua.RetainPath(generationA, Guid.NewGuid()); } catch (InvalidOperationException) { duplicate = true; }
                        Check(duplicate, "a second path cannot steal the winning socket's payload receiver");
                        bool receiver = false; try { await ua.ReceivePayload(deadline.Token); } catch (InvalidOperationException) { receiver = true; }
                        Check(receiver, "legacy payload receive cannot compete with the registered adapter");
                    }
                    ra.RegisterPath(2, pa, context, 1, ua.RemainingAttemptTime, 1);
                    rb.RegisterPath(1, pb, reverse, 1, ub.RemainingAttemptTime, 1);
                    await ua.DisposeAsync(); await ub.DisposeAsync();
                    Check(!ua.Closed && !ub.Closed, "ending attempt leaves active path references and the same sockets alive");
                    if (iteration == 1) {
                        var held = new List<IDisposable>();
                        try {
                            for (int i = 0; i < 6; i++) held.Add(TraversalResources.Shared.Acquire());
                            bool full = false; try { using var extra = TraversalResources.Shared.Acquire(); } catch (IOException) { full = true; }
                            Check(full, "two retained paths still occupy two of the machine's eight UDP resources");
                        } finally { foreach (var item in held) item.Dispose(); }
                    }
                    async Task Wait(Func<bool> predicate) {
                        var waiting = Stopwatch.StartNew(); while (!predicate()) { if (waiting.ElapsedMilliseconds > 5500) throw new Exception("formal UDP router path did not converge"); await Task.Delay(10, deadline.Token); }
                    }
                    await Wait(() => ra.Paths(2).Any(p => p.Active && p.Stage == NominationStage.Selected) && rb.Paths(1).Any(p => p.Active && p.Stage == NominationStage.Selected));
                    double established = clock.Elapsed.TotalMilliseconds;
                    if (environment == "real-loopback" && iteration == 1) Check(((PressureSocket)left).Failures == 1 && !pa.Failed, "transient UDP send-buffer pressure drops one control datagram without destroying the path");
                    Check(ra.Paths(2).Single().ResourceId == oa.SocketId && oa.SocketId == socketA && rb.Paths(1).Single().ResourceId == socketB,
                        "STUN through nomination uses the identical SocketResourceId");
                    Check(roundA.Packets > punch[0].SentPackets && roundA.Packets <= 120 && roundA.Bytes <= 65536, "router nomination shares original packet and byte limits");
                    leftAdapter.Outgoing.Add(InnerPacket(a.LocalIp, b.LocalIp)); rightAdapter.Outgoing.Add(InnerPacket(b.LocalIp, a.LocalIp));
                    await Wait(() => leftAdapter.Incoming.Count == 1 && rightAdapter.Incoming.Count == 1);
                    Check(leftAdapter.Incoming.Single().Length == 1280 && rightAdapter.Incoming.Single().Length == 1280,
                        "both managed Routers deliver full-size virtual IPv4 over retained UDP paths");
                    if (environment == "real-loopback" && iteration == 1) {
                        Guid nextAttempt = Guid.NewGuid(); byte[] nextKey = MeshIdentity.SharedKey(a, b.Self);
                        await using var nextA = new UdpTraversal(new TraversalSocket(new(IPAddress.Loopback, 0)), generationA, nextAttempt, 1, 2, nextKey);
                        await using var nextB = new UdpTraversal(new TraversalSocket(new(IPAddress.Loopback, 0)), generationB, nextAttempt, 2, 1, nextKey);
                        CryptographicOperations.ZeroMemory(nextKey);
                        var result = await Task.WhenAll(nextA.Punch([nextB.Local], null, deadline.Token), nextB.Punch([nextA.Local], null, deadline.Token));
                        Check(result.All(r => r.Success), "real second socket pair prepares a UDP migration candidate");
                        var nextContext = context with { AttemptId = nextAttempt, LocalCandidateId = Guid.NewGuid(), RemoteCandidateId = Guid.NewGuid(), LocalCandidateVersion = 2, RemoteCandidateVersion = 2 };
                        var nextReverse = reverse with { AttemptId = nextAttempt, LocalCandidateId = nextContext.RemoteCandidateId, RemoteCandidateId = nextContext.LocalCandidateId, LocalCandidateVersion = 2, RemoteCandidateVersion = 2 };
                        var nextPathA = nextA.RetainPath(generationA, Guid.NewGuid()); var nextPathB = nextB.RetainPath(generationB, Guid.NewGuid());
                        ra.RegisterPath(2, nextPathA, nextContext, 2, nextA.RemainingAttemptTime, 1);
                        rb.RegisterPath(1, nextPathB, nextReverse, 2, nextB.RemainingAttemptTime, 1);
                        await nextA.DisposeAsync(); await nextB.DisposeAsync();
                        await Wait(() => ra.Paths(2).Any(p => p.Active && p.ResourceId == nextA.SocketId && p.Stage == NominationStage.Selected) && rb.Paths(1).Any(p => p.Active && p.ResourceId == nextB.SocketId && p.Stage == NominationStage.Selected));
                        ra.CancelPath(2, nextPathA.Identity.PathId);
                        await Wait(() => ra.Paths(2).Any(p => p.Active && p.ResourceId == socketA) && rb.Paths(1).Any(p => p.Active && p.ResourceId == socketB));
                        await Wait(() => nextA.Closed && nextB.Closed);
                        Check(!ua.Closed && !ub.Closed && !nextPathA.TrySend(new byte[64]), "UDP rollback keeps old sockets and prevents sends from retired path references");
                        leftAdapter.Outgoing.Add(InnerPacket(a.LocalIp, b.LocalIp)); rightAdapter.Outgoing.Add(InnerPacket(b.LocalIp, a.LocalIp));
                        await Wait(() => leftAdapter.Incoming.Count == 2 && rightAdapter.Incoming.Count == 2);
                        Check(true, "real UDP payloads resume over original resources after candidate cancellation");
                    }
                    await ra.DisposeAsync(); await rb.DisposeAsync();
                    Check(ua.Closed && ub.Closed, "last path/receive references release both sockets and resource slots");
                    rows.Add(new { environment, iteration, socketA, socketB, dfRequested = left.DontFragment, payload = 1344, outerIpv4Bytes = 1372, establishedMs = established,
                        packets = roundA.Packets, bytes = roundA.Bytes });
                }
                Console.WriteLine($"PASS {environment}: {rounds}/{rounds} actual Router UDP adapter rounds");
            }
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", rounds = rows.Count, checks,
                scope = "production Router/MeshLink with retained UDP sockets and memory packet adapters; environments counted separately below",
                realLoopbackRounds = rounds, modelRounds = rounds * 2,
                wireDfCaptured = false, realNat = false, wintun = false, rows }, new JsonSerializerOptions { WriteIndented = true }));
        } catch (Exception ex) {
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", completed = rows.Count, checks, failure = ex.ToString(), rows }, new JsonSerializerOptions { WriteIndented = true })); throw;
        }
    }
    static byte[] InnerPacket(string from, string to)
    {
        byte[] bytes = new byte[1280]; bytes[0] = 0x45; bytes[8] = 64; bytes[9] = 17;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), 1280);
        IPAddress.Parse(from).GetAddressBytes().CopyTo(bytes, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(bytes, 16);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10), (ushort)~sum); return bytes;
    }
    sealed class RoutedAdapter : IPacketAdapter
    {
        public readonly BlockingCollection<byte[]> Outgoing = new(); public readonly ConcurrentQueue<byte[]> Incoming = new();
        public int Read(byte[] target) { if (!Outgoing.TryTake(out var bytes, 25)) return 0; bytes.CopyTo(target, 0); return bytes.Length; }
        public bool Write(byte[] bytes) { Incoming.Enqueue(bytes); return true; }
        public void Dispose() => Outgoing.Dispose();
    }
    sealed class PressureSocket(ITraversalSocket socket) : ITraversalSocket
    {
        public Guid Id => socket.Id;
        public IPEndPoint Local => socket.Local;
        public bool DontFragment => socket.DontFragment;
        public bool FailNext;
        public int Failures;
        public ValueTask Send(ReadOnlyMemory<byte> data, IPEndPoint peer, CancellationToken token) {
            if (FailNext) { FailNext = false; Failures++; throw new SocketException((int)SocketError.NoBufferSpaceAvailable); }
            return socket.Send(data, peer, token);
        }
        public ValueTask<TraversalDatagram> Receive(CancellationToken token) => socket.Receive(token);
        public void Dispose() => socket.Dispose();
    }
}
