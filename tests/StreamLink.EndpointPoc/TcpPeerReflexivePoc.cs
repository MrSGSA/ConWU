using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using StreamLink.Core;

namespace StreamLink.EndpointPoc;

static class TcpPeerReflexivePoc
{
    public static async Task<int> Run(string binary, int rounds, string output)
    {
        if (rounds is < 1 or > 30) throw new ArgumentException("1..30 rounds");
        var rows = new List<object>(); int checks = 0;
        void Check(bool value, string why) { if (!value) throw new Exception(why); checks++; Console.WriteLine("PASS " + why); }
        string root = Path.Combine(Path.GetDirectoryName(output)!, Path.GetFileNameWithoutExtension(output) + "-logs"); Directory.CreateDirectory(root);
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(10)); var token = deadline.Token;
        try {
            for (int round = 0; round < rounds; round++) foreach (int stable in new[] { 0, 1 })
                rows.Add(await Pair(binary, root, stable, true, false, Check, token));
            rows.Add(await Pair(binary, root, 0, false, false, Check, token));
            rows.Add(await Pair(binary, root, 0, true, true, Check, token));
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rounds, rows,
                scope = "actual C++/parent raw broker, loopback TCP helper, MeshRouter/MeshLink; EIM+ADF vs APDM+APDF memory NAT and raw/IP adapters. No production capability, WinDivert, Wintun or public NAT claim" }, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        } catch (Exception ex) {
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() }, new JsonSerializerOptions { WriteIndented = true })); throw;
        }
    }
    static async Task<object> Pair(string binary, string root, int stable, bool enabled, bool wrongKey, Action<bool, string> check, CancellationToken token)
    {
        var a = MeshIdentity.Create("https://example.com/", "", "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var profiles = new[] { a, b }; var wire = new Wire(stable); var gen = Guid.NewGuid();
        await using var helper = new Reflector { MapForTest = wire.Reflect };
        var sources = new List<TcpEndpointLease>(); var owners = new List<TcpCaptureOwner>(); var paths = new List<NativeDatagramPath>();
        var adapters = new[] { new Adapter(), new Adapter() }; var routers = new List<MeshRouter>();
        var start = Stopwatch.StartNew();
        try {
            for (int i = 0; i < 2; i++) {
                var source = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), helper.Endpoint, gen, token); sources.Add(source);
                owners.Add(new(source, gen, (local, _) => wire.Open(i, local)));
                await owners[^1].Ready;
                using var query = source.AcquireAttempt(gen); check((await query.Observe(token)).Public.Equals(wire.Announced(i)), "same held helper obtains the mapping fixture's actual reflected candidate");
                routers.Add(new(profiles[i], adapters[i]));
            }
            var context = new TraversalAttemptContext(a.Pair.Network, a.Self.Device, routers[0].BootId, b.Self.Device, routers[1].BootId,
                Guid.NewGuid(), Guid.NewGuid(), 1, Guid.NewGuid(), 1, TraversalProfile.FakeTcpHttpSo, true, true, Guid.NewGuid());
            var reverse = context with { LocalNodeId = context.RemoteNodeId, LocalBootId = context.RemoteBootId, RemoteNodeId = context.LocalNodeId,
                RemoteBootId = context.LocalBootId, LocalCandidateId = context.RemoteCandidateId, RemoteCandidateId = context.LocalCandidateId, ProtocolClient = false, Nominator = false };
            var contexts = new[] { context, reverse };
            byte[] key = MeshIdentity.SharedKey(a, b.Self);
            try {
                for (int i = 0; i < 2; i++) {
                    byte[] used = (byte[])key.Clone(); if (wrongKey && i == 1) used[0] ^= 1;
                    try { paths.Add(await NativeDatagramPath.Prepare(binary, root, sources[i], gen, contexts[i],
                        wire.Announced(1 - i), used, token, new(), captureOwner: owners[i], countWireControl: true, peerReflexive: enabled && i == stable)); }
                    finally { CryptographicOperations.ZeroMemory(used); }
                }
            } finally { CryptographicOperations.ZeroMemory(key); }
            check(paths.All(p => p.Armed && !p.Started) && wire.Syns == 0, "source learning prepares ownership without emitting an early SYN");
            if (enabled) {
                bool refused = false;
                try { using var collision = owners[stable].Register(gen, new(Wire.Public[1 - stable], 35001), peerReflexive: true); } catch (IOException) { refused = true; }
                check(refused && owners[stable].Status.Sessions == 1, "one source capture cannot assign two learners to the same peer IP");
            }
            var tasks = paths.Select(p => p.StartAndQualify(token)).ToArray(); Exception? failure = null;
            try { await Task.WhenAll(tasks); } catch (Exception ex) when (!token.IsCancellationRequested) { failure = ex; }
            if (!enabled || wrongKey) {
                check(failure != null && paths.All(p => !p.Diagnostics.PayloadQualified),
                    wrongKey ? "tentative source port with the wrong context key cannot pass native payload authentication" : "identical destination-related mapping cannot qualify without source learning");
                check(routers.All(r => r.Paths(1).Length == 0 && r.Paths(2).Length == 0), "failed tentative endpoint is never registered or selected");
                return new { stable, enabled, wrongKey, qualified = false, elapsedMs = start.ElapsedMilliseconds, wire.Syns, wire.LearnedReplies };
            }
            if (failure != null) throw new IOException("source learning failed\n" + string.Join('\n', paths.Select(p => p.Diagnostics)), failure);
            check(paths[stable].Identity.ActualRemote.Equals(wire.Actual(1 - stable)) && !paths[stable].Identity.ActualRemote.Equals(wire.Announced(1 - stable)),
                "authenticated path identity reports the actually learned public source, not the STUN hint");
            check(wire.LearnedReplies > 0 && wire.Http > 0 && paths.All(p => p.WireControl is { HandshakePackets: > 0, Selected: false }),
                "actual native replies use learned tuple under the shared budget and continue the HTTP/udp2raw profile");
            foreach (var tuple in new[] { wire.Announced(1 - stable), wire.Actual(1 - stable) }) {
                bool reserved = false; try { using var other = owners[stable].Register(gen, tuple); } catch (IOException) { reserved = true; }
                check(reserved, "both announced and learned TCP tuples remain reserved until worker exit");
            }
            for (int i = 0; i < 2; i++) routers[i].RegisterPath(2 - i, paths[i], contexts[i], 1, paths[i].RemainingAttemptTime, 1);
            await Until(() => routers.All(r => r.Status().All(p => p.Connected)), token);
            check(paths.All(p => p.WireControl?.Selected == true), "both real Routers jointly nominate the authenticated learned path");
            for (int i = 0; i < 2; i++) adapters[i].Outgoing.Add(Packet(profiles[i].LocalIp, profiles[1 - i].LocalIp));
            await Until(() => adapters.All(d => d.Incoming.Count == 1), token);
            check(adapters.All(d => d.Incoming.Count == 1), "learned native paths deliver complete authenticated inner IP in both directions");
            for (int i = 0; i < 2; i++) { using var q = sources[i].AcquireAttempt(gen); check((await q.Observe(token)).Public.Equals(wire.Announced(i)), "helper query remains usable on the exact retained source while the learned path runs"); }
            return new { stable, enabled, wrongKey, qualified = true, elapsedMs = start.ElapsedMilliseconds, wire.Syns, wire.Http, wire.LearnedReplies,
                identities = paths.Select(p => new { p.Identity.LeaseId, remote = p.Identity.ActualRemote.ToString() }).ToArray() };
        } finally {
            foreach (var router in routers) await router.DisposeAsync();
            foreach (var path in paths) await path.DisposeAsync();
            foreach (var owner in owners) await owner.DisposeAsync();
            foreach (var source in sources) source.Dispose();
            check(sources.All(s => s.Closed) && owners.All(o => o.Closed.IsCompletedSuccessfully), "source learning teardown joins every capture and held endpoint after native exit");
        }
    }
    static async Task Until(Func<bool> ready, CancellationToken token)
    { var watch = Stopwatch.StartNew(); while (!ready()) { if (watch.ElapsedMilliseconds >= 3500) throw new TimeoutException("learned path nomination/business absent"); await Task.Delay(10, token); } }
    sealed class Wire(int stable)
    {
        public static readonly IPAddress[] Public = [IPAddress.Parse("192.0.2.10"), IPAddress.Parse("192.0.2.20")];
        readonly object gate = new(); readonly Io?[] nodes = new Io[2]; readonly Dictionary<string, Io> inbound = [];
        public int Syns, Http, LearnedReplies;
        public Io Open(int index, IPEndPoint local) { lock (gate) return nodes[index] = new(this, index, local); }
        public IPEndPoint Reflect(IPEndPoint local) {
            lock (gate) { var source = nodes.First(n => n?.Local.Equals(local) == true)!; var mapped = Mapping(source, "helper"); inbound[mapped.ToString()] = source; return mapped; }
        }
        public IPEndPoint Announced(int peer) => nodes[peer]!.Mappings["helper"];
        public IPEndPoint Actual(int peer) => peer == stable ? Announced(peer) : nodes[peer]!.Mappings[Announced(stable).ToString()];
        IPEndPoint Mapping(Io source, string target) {
            if (source.Mappings.TryGetValue(target, out var known)) return known;
            var mapped = new IPEndPoint(Public[source.Index], source.Index == stable ? source.Local.Port : target == "helper" ? 35000 : source.NextPort += 7);
            source.Mappings[target] = mapped; return mapped;
        }
        public bool Send(Io source, ReadOnlySpan<byte> packet) {
            lock (gate) {
                int ip = (packet[0] & 15) * 4; var target = new IPEndPoint(new IPAddress(packet.Slice(16, 4)), BinaryPrimitives.ReadUInt16BigEndian(packet[(ip + 2)..]));
                int payload = ip + (packet[ip + 12] >> 4) * 4;
                if ((packet[ip + 13] & 2) != 0) Syns++;
                if (packet[payload..].StartsWith("GET "u8) || packet[payload..].StartsWith("HTTP/"u8)) Http++;
                if (source.Index == stable && nodes[1 - stable]!.Mappings.TryGetValue(Announced(stable).ToString(), out var learned) && target.Equals(learned)) LearnedReplies++;
                source.Allowed.Add(target.ToString()); var outside = Mapping(source, target.ToString()); inbound[outside.ToString()] = source;
                if (!inbound.TryGetValue(target.ToString(), out var destination)) return true;
                // Stable EIM+ADF requires prewarming this source IP; hard-side
                // APDM+APDF accepts only the fixed stable tuple it contacted.
                if (destination.Index == stable ? !destination.Allowed.Any(a => IPEndPoint.Parse(a).Address.Equals(outside.Address))
                    : !destination.Allowed.Contains(outside.ToString()) || !destination.Mappings.TryGetValue(outside.ToString(), out var reverse) || !reverse.Equals(target)) return true;
                var frame = packet.ToArray(); Rewrite(frame, outside, destination.Local);
                destination.Input.Writer.TryWrite(new(frame, false)); return true;
            }
        }
        static void Rewrite(byte[] p, IPEndPoint source, IPEndPoint destination) {
            int ip = (p[0] & 15) * 4; source.Address.GetAddressBytes().CopyTo(p, 12); destination.Address.GetAddressBytes().CopyTo(p, 16);
            BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(ip), (ushort)source.Port); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(ip + 2), (ushort)destination.Port);
            p[10] = p[11] = p[ip + 16] = p[ip + 17] = 0;
            static ushort Sum(ReadOnlySpan<byte> b, uint sum = 0) { for (int i = 0; i < b.Length; i += 2) sum += i + 1 < b.Length ? BinaryPrimitives.ReadUInt16BigEndian(b[i..]) : (uint)b[i] << 8;
                while (sum > 65535) sum = (sum & 65535) + (sum >> 16); return (ushort)~sum; }
            BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), Sum(p.AsSpan(0, ip)));
            uint pseudo = 6 + (uint)(p.Length - ip); for (int i = 12; i < 20; i += 2) pseudo += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i));
            BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(ip + 16), Sum(p.AsSpan(ip), pseudo));
        }
        public sealed class Io(Wire owner, int index, IPEndPoint local) : IEndpointPacketIo {
            public int Index => index; public IPEndPoint Local => local; public readonly HashSet<string> Allowed = [];
            public readonly Dictionary<string, IPEndPoint> Mappings = []; public int NextPort = 40007;
            public readonly Channel<EndpointPacket> Input = Channel.CreateBounded<EndpointPacket>(1024);
            public ValueTask<EndpointPacket> Receive(CancellationToken token) => Input.Reader.ReadAsync(token);
            public bool Inject(ReadOnlySpan<byte> packet) => owner.Send(this, packet); public bool Reinject(EndpointPacket packet) => true;
            public void Shutdown() => Input.Writer.TryComplete(); public void Dispose() => Shutdown();
        }
    }
    sealed class Adapter : IPacketAdapter {
        public readonly BlockingCollection<byte[]> Outgoing = new(); public readonly ConcurrentQueue<byte[]> Incoming = new();
        public int Read(byte[] buffer) { if (!Outgoing.TryTake(out var p, 30)) return 0; p.CopyTo(buffer, 0); return p.Length; }
        public bool Write(byte[] packet) { Incoming.Enqueue(packet); return true; } public void Dispose() => Outgoing.Dispose();
    }
    static byte[] Packet(string source, string destination) {
        byte[] p = new byte[1280]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), 1280);
        IPAddress.Parse(source).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(destination).GetAddressBytes().CopyTo(p, 16);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
    }
}
