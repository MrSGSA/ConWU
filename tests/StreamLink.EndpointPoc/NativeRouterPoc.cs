using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.EndpointPoc;

// Production attachment, path bridge, C++ protocol, MeshLink and Router. The
// raw carriage is test-only loopback UDP; adapters are in-memory IP endpoints.
static class NativeRouterPoc
{
    public static async Task<int> Run(string binary, string output)
    {
        int checks = 0; var rows = new List<object>();
        string logs = Path.Combine(Path.GetDirectoryName(output)!, Path.GetFileNameWithoutExtension(output) + "-logs");
        Directory.CreateDirectory(logs);
        void Check(bool value, string why) { if (!value) throw new Exception(why); checks++; }
        async Task Until(Func<bool> predicate, string why, int ms = 4000) {
            var clock = Stopwatch.StartNew(); while (!predicate()) { if (clock.ElapsedMilliseconds > ms) throw new Exception(why); await Task.Delay(10); } Check(true, why);
        }
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(180));
        try {
            for (int round = 1; round <= 30; round++) {
                await using var reflector = new Reflector(); Guid generation = Guid.NewGuid();
                using var aLease = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, deadline.Token);
                using var bLease = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, deadline.Token);
                using var aAttempt = aLease.AcquireAttempt(generation); using var bAttempt = bLease.AcquireAttempt(generation);
                var observedA = await aAttempt.Observe(deadline.Token); var observedB = await bAttempt.Observe(deadline.Token);
                var a = MeshIdentity.Create("https://example.com/", "", "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
                var aa = new Adapter(); var ab = new Adapter();
                await using var ra = new MeshRouter(a, aa); await using var rb = new MeshRouter(b, ab);
                var context = new TraversalAttemptContext(a.Pair.Network, a.Self.Device, ra.BootId, b.Self.Device, rb.BootId, Guid.NewGuid(),
                    Guid.NewGuid(), 1, Guid.NewGuid(), 1, TraversalProfile.FakeTcpHttpSo, true, true, Guid.NewGuid());
                var reverse = context with { LocalNodeId = context.RemoteNodeId, LocalBootId = context.RemoteBootId, RemoteNodeId = context.LocalNodeId,
                    RemoteBootId = context.LocalBootId, LocalCandidateId = context.RemoteCandidateId, RemoteCandidateId = context.LocalCandidateId, ProtocolClient = false, Nominator = false };
                int aWire = Port(), bWire = Port();
                byte loss = round switch { 28 => 2, 29 => 18, 30 => 16, _ => 0 };
                await using var proxy = new RawProtocolProxy(aWire, bWire, loss, round % 2 == 0);
                Dictionary<string, string> Env(int local, int remote) => new() { ["STREAMLINK_TEST_BIND"] = local.ToString(), ["STREAMLINK_TEST_PEER"] = remote.ToString() };
                byte[] aKey = MeshIdentity.SharedKey(a, b.Self), bKey = MeshIdentity.SharedKey(b, a.Self);
                await using var pa = await NativeDatagramPath.Prepare(binary, Path.Combine(logs, round.ToString()), aLease, generation, context, observedB.Public, aKey,
                    deadline.Token, new(), Env(aWire, proxy.ClientPort));
                await using var pb = await NativeDatagramPath.Prepare(binary, Path.Combine(logs, round.ToString()), bLease, generation, reverse, observedA.Public, bKey,
                    deadline.Token, new(), Env(bWire, proxy.ServerPort));
                CryptographicOperations.ZeroMemory(aKey); CryptographicOperations.ZeroMemory(bKey);
                Check(pa.Armed && pb.Armed && !pa.Started && !pb.Started && proxy.Snapshot().Length == 0, "both native captures ready before any SYN");
                bool refused = false; try { _ = pa.Identity; } catch (InvalidOperationException) { refused = true; }
                Check(refused && pa.RemainingAttemptTime == TimeSpan.Zero, "unstarted/unqualified resources cannot register as authenticated paths");
                proxy.Begin(); var clock = Stopwatch.StartNew();
                // A forged localhost source must not pin the dynamic server bridge.
                using var forged = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                var startA = pa.StartAndQualify(deadline.Token); var startB = pb.StartAndQualify(deadline.Token);
                for (int i = 0; i < 3; i++) { byte[] invalid = new byte[1344]; "SLF1"u8.CopyTo(invalid); invalid[4] = invalid[5] = 1;
                    await forged.SendAsync(invalid, pb.BridgeEndpoint, deadline.Token); await Task.Delay(20, deadline.Token); }
                await Task.WhenAll(startA, startB);
                var remaining = pa.RemainingAttemptTime; await pa.StartAndQualify(deadline.Token);
                Check(pa.RemainingAttemptTime <= remaining && pa.RemainingAttemptTime < TimeSpan.FromSeconds(8), "duplicate Start does not replenish round deadline");
                Check(pa.Identity.AttachId == pa.AttachId && pa.Identity.LeaseId == aLease.Id && pa.Identity.ActualLocal.Equals(observedA.Local), "router path refers to actual native attachment and retained source lease");
                Check(pb.Identity.Qualification == PathQualification.MtuQualified, "full 1344-byte bidirectional authenticated probe qualifies bridge");
                aAttempt.Dispose(); bAttempt.Dispose(); aLease.Dispose(); bLease.Dispose();
                Check(!aLease.Closed && !bLease.Closed && aLease.ReferenceCount == 1 && bLease.ReferenceCount == 1, "native path survives owner and attempt disposal");
                int spentA = pa.ControlRound.Packets, spentB = pb.ControlRound.Packets;
                ra.RegisterPath(2, pa, context, 1, pa.RemainingAttemptTime, 1);
                rb.RegisterPath(1, pb, reverse, 1, pb.RemainingAttemptTime, 1);
                bool Active(MeshRouter r, int slot) => r.Paths(slot).Any(p => p.Active && p.Stage == NominationStage.Selected);
                await Until(() => Active(ra, 2) && Active(rb, 1), "real native protocol and MeshRouter complete joint nomination", 7500);
                Check(clock.ElapsedMilliseconds < 8000, "outer + bridge authentication + MeshLink + nomination share one eight-second window");
                Check(pa.ControlRound.Packets > spentA && pb.ControlRound.Packets > spentB, "bridge and MeshLink nomination share the same round control budget");
                aa.Outgoing.Add(Packet(a.LocalIp, b.LocalIp)); ab.Outgoing.Add(Packet(b.LocalIp, a.LocalIp));
                await Until(() => aa.Incoming.Count == 1 && ab.Incoming.Count == 1, "1280-byte virtual IPv4 business packets cross actual C++ FakeTCP in both directions");
                var wire = proxy.Snapshot();
                Check(wire.Any(p => p.Client && p.Flags == 2) && wire.Any(p => !p.Client && p.Flags == 2), "both native roles emitted their own SYN");
                foreach (bool fromClient in new[] { false, true }) {
                    var packets = wire.Where(p => p.Client == fromClient).ToArray(); var http = packets.First(p => p.Payload == 180);
                    var bare = packets.First(p => p.Tick >= http.Tick && p.Payload == 48);
                    Check(http.Seq == bare.Seq && http.Ack == bare.Ack, "native integration retains legacy HTTP/bare overlapping sequence profile");
                }
                if (loss != 0) Check(wire.Any(p => p.Dropped), "requested handshake loss was exercised");
                long selectedMs = clock.ElapsedMilliseconds;
                if (round == 30) {
                    using var child = Process.GetProcessById(pa.ProcessId); child.Kill(); await child.WaitForExitAsync(deadline.Token);
                    await Until(() => pa.Failed && aLease.Closed, "native crash promptly invalidates path and releases final helper reference");
                    await Until(() => !ra.Paths(2).Any(p => p.Active), "router stops choosing crashed native without waiting 12-second link timeout");
                }
                await ra.DisposeAsync(); await rb.DisposeAsync();
                Check(pa.Closed && pb.Closed && aLease.Closed && bLease.Closed, "router shutdown awaits receive/native teardown and final lease release");
                Check(!Directory.GetFiles(Path.Combine(logs, round.ToString()), "*.conf").Any(), "ephemeral native key configuration is removed");
                rows.Add(new { round, selectedMs, loss, aLease = aLease.Id, bLease = bLease.Id, spentA = pa.ControlRound.Packets, spentB = pb.ControlRound.Packets, wire });
                if (round % 10 == 0) Console.WriteLine($"Native Router {round}/30 passed");
            }
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows,
                scope = "Production NativeDatagramPath/NativeAttachment + C++ SO/HTTP + MeshLink/MeshRouter; in-memory IP adapter; loopback-only raw protocol test carriage",
                nativeProtocol = true, nativeDriver = false, wintun = false, realNat = false, automatedDiscovery = false }, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"PASS {checks} checks, 30 native Router rounds. No installed service or driver changes."); return 0;
        } catch (Exception ex) { await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() })); throw; }
    }
    static int Port() { using var s = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); return ((IPEndPoint)s.Client.LocalEndPoint!).Port; }
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
}
