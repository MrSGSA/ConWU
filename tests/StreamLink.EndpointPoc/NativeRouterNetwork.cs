using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.EndpointPoc;

sealed record RouterNetworkConfig(Guid RunId, MeshProfile Profile, string LocalIp, string PeerIp, bool Coordinator,
    int BasePort, int PeerBasePort, int ReflectorPort, int PeerReflectorPort, int ControlPort, string Binary, string Output, int Rounds = 30,
    int LocalAnnouncementOffset=0,int PeerAnnouncementOffset=0,bool SourceLearning=false);
sealed record RouterNetworkControl(Guid RunId, int Round, string Kind, Guid Boot, Guid Attempt, Guid Candidate, Guid Nonce, string Endpoint);

static class NativeRouterNetwork
{
    public static void Prepare(string root)
    {
        Directory.CreateDirectory(root);
        var a = MeshIdentity.Create("https://example.com/", "", "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        Guid run = Guid.NewGuid();
        var local = new RouterNetworkConfig(run, a, "10.129.129.2", "10.129.129.1", true, 43300, 43400, 43291, 43292, 43290, "udp2raw-native.exe", "local-result.json");
        var remote = new RouterNetworkConfig(run, b, "10.129.129.1", "10.129.129.2", false, 43400, 43300, 43292, 43291, 43290, "udp2raw-native.exe", "remote-result.json");
        File.WriteAllText(Path.Combine(root, "local-private.json"), JsonSerializer.Serialize(local));
        File.WriteAllText(Path.Combine(root, "remote-private.json"), JsonSerializer.Serialize(remote));
        // This directory is ignored and the private node configs are removed by
        // the orchestration finally block. Never put credentials in the report.
    }
    public static async Task<int> Run(string file)
    {
        var c = JsonSerializer.Deserialize<RouterNetworkConfig>(await File.ReadAllTextAsync(file))!; c.Profile.Validate();
        if (c.Rounds is < 1 or > 30 || c.RunId == Guid.Empty) throw new ArgumentException("Invalid isolated test config");
        var localIp = IPAddress.Parse(c.LocalIp); var peerIp = IPAddress.Parse(c.PeerIp);
        if (IPAddress.IsLoopback(localIp) || IPAddress.IsLoopback(peerIp)) throw new ArgumentException("Two real Windows hosts required");
        string root = Path.GetDirectoryName(file)!, binary = Path.GetFullPath(c.Binary, root), output = Path.GetFullPath(c.Output, root);
        if(File.Exists(output))throw new IOException("Use a fresh result path; prior failure evidence is immutable");
        string logRoot=Path.Combine(root,Path.GetFileNameWithoutExtension(output)+"-logs");
        var peer = c.Profile.Directory!.Members.Single(m => m.Slot != c.Profile.Self.Slot);
        byte[] shared = MeshIdentity.SharedKey(c.Profile, peer);
        byte[] controlKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, c.RunId.ToByteArray(), "isolated-native-router-control-v1"u8.ToArray());
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(6));
        var token = deadline.Token; var rows = new List<object>(); int checks = 0;
        void Check(bool value, string why) { if (!value) throw new IOException(why); checks++; }
        async Task Until(Func<bool> predicate, string why, int ms = 8000) {
            var time = Stopwatch.StartNew(); while (!predicate()) { if (time.ElapsedMilliseconds > ms) throw new TimeoutException(why); await Task.Delay(10, token); } Check(true, why);
        }
        if(c.LocalAnnouncementOffset is<0 or>16||c.PeerAnnouncementOffset is<0 or>16 || !c.SourceLearning&&(c.LocalAnnouncementOffset!=0||c.PeerAnnouncementOffset!=0))throw new ArgumentException("Invalid predeclared per-end source-learning expectation");
        await using var reflector = new Reflector(new(localIp, c.ReflectorPort)){MapForTest=ep=>new(ep.Address,checked(ep.Port+c.PeerAnnouncementOffset))};
        TcpListener? listener = null;
        Socket? control = null;
        try {
            if (!c.Coordinator) {
                listener = new(new IPEndPoint(localIp, c.ControlPort)); listener.Start();
                while (control == null) { var candidate = await listener.AcceptSocketAsync(token); if (((IPEndPoint)candidate.RemoteEndPoint!).Address.Equals(peerIp)) control = candidate; else candidate.Dispose(); }
            } else {
                while (control == null) {
                    var candidate = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    try { candidate.Bind(new IPEndPoint(localIp, 0)); await candidate.ConnectAsync(new IPEndPoint(peerIp, c.ControlPort), token); control = candidate; }
                    catch (SocketException) { candidate.Dispose(); await Task.Delay(500, token); }
                }
            }
            using var stream = new NetworkStream(control, false);
            async Task<RouterNetworkControl> Exchange(RouterNetworkControl value)
            {
                byte[] body = JsonSerializer.SerializeToUtf8Bytes(value), length = new byte[4]; BinaryPrimitives.WriteInt32BigEndian(length, body.Length);
                await stream.WriteAsync(length, token); await stream.WriteAsync(body, token); await stream.WriteAsync(HMACSHA256.HashData(controlKey, body), token);
                await stream.ReadExactlyAsync(length, token); int size = BinaryPrimitives.ReadInt32BigEndian(length);
                if (size is < 1 or > 4096) throw new IOException("Bad test control length");
                byte[] reply = new byte[size], tag = new byte[32]; await stream.ReadExactlyAsync(reply, token); await stream.ReadExactlyAsync(tag, token);
                if (!CryptographicOperations.FixedTimeEquals(tag, HMACSHA256.HashData(controlKey, reply))) throw new IOException("Unauthenticated test control");
                var received = JsonSerializer.Deserialize<RouterNetworkControl>(reply)!;
                if (received.RunId != c.RunId || received.Round != value.Round || received.Kind != value.Kind) throw new IOException("Stale test control"); return received;
            }
            for (int round = 1; round <= c.Rounds; round++) {
                Guid generation = Guid.NewGuid(); var local = new IPEndPoint(localIp, c.BasePort + round); var remote = new IPEndPoint(peerIp, c.PeerBasePort + round);
                using var lease = await TcpEndpointLease.Open(local, new(peerIp, c.PeerReflectorPort), generation, token);
                using var attemptRef = lease.AcquireAttempt(generation); var observation = await attemptRef.Observe(token);
                var adapter = new Adapter(); await using var router = new MeshRouter(c.Profile, adapter);
                Guid attempt = Guid.NewGuid(), nonce = Guid.NewGuid(), candidateId = Guid.NewGuid();
                var offer = new RouterNetworkControl(c.RunId, round, "offer", router.BootId, attempt, candidateId, nonce, observation.Public.ToString());
                var other = await Exchange(offer);var announced=IPEndPoint.Parse(other.Endpoint);
                Check(announced.Equals(new IPEndPoint(remote.Address,remote.Port+c.PeerAnnouncementOffset)), "per-end remote announcement matches its predeclared offset");
                if (!c.Coordinator) { attempt = other.Attempt; nonce = other.Nonce; }
                var context = new TraversalAttemptContext(c.Profile.Pair.Network, c.Profile.Self.Device, router.BootId, peer.Device, other.Boot, attempt,
                    candidateId, 1, other.Candidate, 1, TraversalProfile.FakeTcpHttpSo, c.Coordinator, c.Coordinator, nonce);
                using var wire = new WireObserver(Path.Combine(root, "WinDivert.dll"), local, remote);
                await using var owner=c.SourceLearning?new TcpCaptureOwner(lease,generation,(source,helper)=>new WinDivertEndpointIo(Path.Combine(root,"WinDivert.dll"),source,helper)):null;
                if(owner!=null)await owner.Ready;
                await using var path = await NativeDatagramPath.Prepare(binary, Path.Combine(logRoot, round.ToString()), lease, generation, context, announced, shared, token,
                    captureOwner:owner,countWireControl:c.SourceLearning,peerReflexive:c.SourceLearning);
                long armed = Environment.TickCount64;
                await Exchange(offer with { Kind = "ready" });
                var watch = Stopwatch.StartNew(); await path.StartAndQualify(token);
                Check(path.Identity.ActualRemote.Equals(remote),"qualified real path freezes the actual expected peer tuple");
                if(c.SourceLearning)Check(path.Diagnostics.PeerSource is {Frozen:true} source && source.Learned==(c.PeerAnnouncementOffset!=0),"each endpoint learns only when its received remote announcement was shifted");
                // The same live helper still responds while raw I/O uses its P.
                var pulse = await attemptRef.Observe(token); Check(pulse.Public.Equals(observation.Public), "helper is not intercepted by native filter");
                attemptRef.Dispose(); lease.Dispose(); Check(!lease.Closed, "native path retains endpoint after Attempt disposal");
                router.RegisterPath(peer.Slot, path, context, 1, path.RemainingAttemptTime, 1);
                await Until(() => router.Paths(peer.Slot).Any(p => p.Active && p.Stage == NominationStage.Selected), "joint nomination on real WinDivert path");
                long selectedMs = watch.ElapsedMilliseconds; Check(selectedMs < 8000, "single eight-second round includes native, MeshLink and nomination");
                for (int packet = 0; packet < 10; packet++) { adapter.Outgoing.Add(Packet(c.Profile.LocalIp, MeshIdentity.Address(c.Profile.Pair.Network, peer.Slot))); await Task.Delay(20, token); }
                await Until(() => adapter.Incoming.Count >= 10, "ten full-MTU virtual IPv4 packets arrived through peer Windows driver");
                await Exchange(offer with { Kind = "business-complete" });
                long revoked = Environment.TickCount64; var capture = wire.Snapshot(armed, revoked);
                var parsed = JsonSerializer.SerializeToElement(capture);
                Check(parsed.GetProperty("error").GetInt32() == 0 && parsed.GetProperty("rst").GetInt32() == 0, "no unexpected RST at receiving Windows stack within effective window");
                Check(parsed.GetProperty("rows").EnumerateArray().Any(p => p.GetProperty("Flags").GetInt32() == (c.LocalAnnouncementOffset==0?2:18)),
                    c.LocalAnnouncementOffset==0?"correctly announced local endpoint receives peer's real bare SYN":"shifted local announcement instead receives peer's SYN+ACK on the authenticated learned reply path");
                var diagnostics=path.Diagnostics;
                await router.DisposeAsync();if(owner!=null)await owner.DisposeAsync();Check(path.Closed && lease.Closed, "actual child exit releases endpoint and loopback bridge");
                await Exchange(offer with { Kind = "retired" });
                rows.Add(new { round, transportOutcome="BusinessUsable",scenarioVerdict="Pass",selectedMs, received = adapter.Incoming.Count, lease = lease.Id, attach = path.AttachId, local = local.ToString(), remote = remote.ToString(),announced=announced.ToString(),expectedLearning=c.PeerAnnouncementOffset!=0,diagnostics,wire = capture });
                Console.WriteLine($"Two-Windows native Router {round}/{c.Rounds} pass: {selectedMs}ms");
            }
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows, c.RunId, c.LocalIp, c.PeerIp,
                transportOutcome="BusinessUsable",scenarioVerdict="Pass",c.SourceLearning,c.LocalAnnouncementOffset,c.PeerAnnouncementOffset,
                nativeDriver = true, twoWindows = true, realNat = false, wintun = false, automatedDiscovery = false,
                scope = "real SO/HTTP + MeshLink/Router over existing overlay interface, memory IP adapter; no claim about physical WAN NAT traversal" }, new JsonSerializerOptions { WriteIndented = true })); return 0;
        } catch (Exception ex) { await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() })); throw; }
        finally { listener?.Stop(); control?.Dispose(); CryptographicOperations.ZeroMemory(shared); CryptographicOperations.ZeroMemory(controlKey); }
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
}
