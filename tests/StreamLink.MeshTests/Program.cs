using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using StreamLink.Core;
using StreamLink.Discovery;

static partial class Program
{
    static int checks;
    static void Check(bool ok, string description) { if (!ok) throw new Exception(description); checks++; Console.WriteLine("PASS " + description); }
    static void Reject(Action action, string description) { try { action(); } catch (Exception ex) when (ex is CryptographicException or FormatException or IOException) { Check(true, description); return; } throw new Exception("Accepted: " + description); }
    static MeshProfile Guest(MeshProfile owner) => MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));
    static void Handshake(MeshLink a, MeshLink b)
    {
        for (int retry = 0; retry < 3; retry++) {
            var ack = b.Receive(a.Hello()); if (ack.Reply == null) continue;
            var confirm = a.Receive(ack.Reply); if (confirm.Reply == null) continue;
            if (b.Receive(confirm.Reply).Authenticated) return;
        }
        throw new Exception("Session handshake did not converge");
    }
    static byte[] Packet(string from, string to, int size = 52)
    {
        byte[] p = new byte[size]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)size);
        IPAddress.Parse(from).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(p, 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), 45123); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), 45124); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(24), (ushort)(size - 20));
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
    }
    static async Task Until(Func<bool> condition, string message)
    {
        using var timeout = new CancellationTokenSource(15000); while (!condition()) await Task.Delay(20, timeout.Token); Check(true, message);
    }
    public static async Task Main(string[] args)
    {
        if(args is ["--soak",var binary,var seconds,var output]) {
            await SustainedRawLoad(Path.GetFullPath(binary),int.Parse(seconds),Path.GetFullPath(output));return;
        }
        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp"); var b = Guest(owner); var c = Guest(owner);
        owner.Validate(); b.Validate(); c.Validate();
        Check(b.Self.Slot == 2 && c.Self.Slot == 3 && b.OwnerPrivate.Length == 0, "independent credentials and unique slots; administrator key never exported");
        Check(MeshIdentity.SharedKey(owner, b.Self).SequenceEqual(MeshIdentity.SharedKey(b, owner.Self)), "ECDH agrees between exactly two members");
        Check(!MeshIdentity.SharedKey(owner, b.Self).SequenceEqual(MeshIdentity.SharedKey(owner, c.Self)), "third member has a different link key");
        Reject(() => MeshIdentity.ValidateMember(owner.Pair.Network, owner.OwnerKey, b.Self with { Slot = 9 }), "forged address certificate rejected");
        Reject(() => MeshIdentity.ValidateDirectory(owner.Directory! with { Members = [owner.Self, c.Self] }, owner.Pair.Network, owner.OwnerKey), "tampered roster rejected");
        Reject(() => MeshIdentity.ValidateDirectory(owner.Directory!, owner.Pair.Network, owner.OwnerKey, owner.Directory!.Revision + 1), "roster rollback rejected");
        using var pairKey = new PairKeyExchange(); using var otherKey = new PairKeyExchange();
        string invite = MeshIdentity.Export(MeshIdentity.Issue(owner)), room = Guid.NewGuid().ToString("N"), candidate = Guid.NewGuid().ToString("N");
        var key = pairKey.Derive(otherKey.PublicKey, otherKey.Commitment, room, candidate, true);
        string cipher = PairKeyExchange.EncryptInvitation(key, invite, room, candidate);
        Check(cipher.Length <= 6000 && PairKeyExchange.DecryptInvitation(key, cipher, room, candidate) == invite, "mesh credential fits existing authenticated short-code exchange");
        MeshIdentity.Revoke(owner, 4); var next = Guest(owner); Check(next.Self.Slot == 5, "revoked slot is never recycled");
        using var aLink = new MeshLink(1, 2, MeshIdentity.SharedKey(owner, b.Self)); using var bLink = new MeshLink(2, 1, MeshIdentity.SharedKey(b, owner.Self));
        Check(!aLink.Connected && aLink.Data(new byte[20]) == null, "data cannot flow before mutual session handshake");
        Handshake(aLink, bLink); Check(aLink.Connected && bLink.Connected, "mutual authenticated datagram handshake");
        byte[] ip = Packet(owner.LocalIp, b.LocalIp), first = aLink.Data(ip)!, second = aLink.Data(ip)!;
        Check(bLink.Receive(second).Packet!.SequenceEqual(ip) && bLink.Receive(first).Packet!.SequenceEqual(ip), "reordering immediately delivers both packets without head-of-line blocking");
        Check(!bLink.Receive(first).Authenticated, "duplicate data rejected");
        byte[] lost = aLink.Data(ip)!, afterLoss = aLink.Data(ip)!; Check(bLink.Receive(afterLoss).Packet != null, "lost packet does not stall the next packet");
        var tampered = aLink.Data(ip)!; tampered[^1] ^= 1; Check(!bLink.Receive(tampered).Authenticated, "tampered authentication tag rejected");
        var concurrent=new byte[1024][];Parallel.For(0,concurrent.Length,i=>concurrent[i]=i%2==0?aLink.Data(ip)!:aLink.Ping()!);
        Check(concurrent.Select(p=>Convert.ToHexString(p.AsSpan(8,16))+"/"+Convert.ToHexString(p.AsSpan(40,8))).Distinct().Count()==concurrent.Length,"concurrent business/control under one logical sender have unique actual directional-key nonce tuples");
        foreach(var frame in concurrent)Check(bLink.Receive(frame).Authenticated,"concurrent frame authenticates within shared receiver replay state");
        Check(!bLink.Receive(concurrent[0]).Authenticated,"candidate/active duplicate of the same ciphertext is delivered at most once by the shared session");
        using var restarted = new MeshLink(2, 1, MeshIdentity.SharedKey(b, owner.Self)); Handshake(aLink, restarted);
        Check(restarted.Connected && !restarted.Receive(lost).Authenticated, "restart negotiates a fresh session and rejects old receiver epoch");
        Check(!aLink.Receive(bLink.Ping()!).Authenticated, "retired sender epoch rejected after peer restart");
        byte[] retiredPacket = restarted.Data(Packet(b.LocalIp, owner.LocalIp))!;
        for (int i = 0; i < 70; i++) {
            using var peerRestart = new MeshLink(2, 1, MeshIdentity.SharedKey(b, owner.Self));
            Handshake(aLink, peerRestart);
            if (!aLink.Connected || !peerRestart.Connected || aLink.Receive(peerRestart.Data(Packet(b.LocalIp, owner.LocalIp))!).Packet == null)
                throw new Exception("Repeated peer restart interrupted recovery");
        }
        Check(true, "seventy peer restarts rotate bounded session history and recover");
        Check(!aLink.Receive(retiredPacket).Authenticated, "old data stays rejected after session-history rotation");
        Check(MeshPackets.Accept(ip, IPAddress.Parse(b.LocalIp).GetAddressBytes(), 1), "IPv4 packet accepted for bound device identity");
        Check(!MeshPackets.Accept(Packet(c.LocalIp, b.LocalIp), IPAddress.Parse(b.LocalIp).GetAddressBytes(), 1), "member cannot spoof another member source address");
        Check(!MeshPackets.Accept(Packet(owner.LocalIp, c.LocalIp), IPAddress.Parse(b.LocalIp).GetAddressBytes(), 1), "member cannot use another node as relay");
        ip[10] ^= 1; Check(!MeshPackets.Valid(ip), "invalid IPv4 checksum rejected");
        Check(!MeshPackets.Valid(Packet(owner.LocalIp, b.LocalIp, 1281)), "MTU overflow rejected");
        var announcement = new MeshAnnouncement(1, owner.Self.Device, 1, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), "192.0.2.1:12345", "Owner");
        var envelope = MeshMetadata.Seal(owner, announcement); Check(MeshMetadata.Open(b, owner.Self, envelope) == announcement, "signed encrypted metadata round trip");
        Reject(() => MeshMetadata.Open(b, owner.Self, envelope with { Revision = 2 }), "metadata revision tampering rejected");
        string root = Path.Combine(Path.GetTempPath(), "streamlink-mesh-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try {
            var registry = new MeshRegistry(root); var context = new DefaultHttpContext(); context.Request.Headers.Authorization = "Bearer " + owner.Pair.Auth;
            int Status(IResult result) => ((IStatusCodeHttpResult)result).StatusCode ?? 200;
            Check(Status(registry.Directory(context, owner.Pair.Network, owner.Directory!)) == 204, "signed network registration accepted");
            Check(Status(registry.Publish(context, owner.Pair.Network, 1, envelope)) == 204, "member signed announcement accepted");
            Check(Status(registry.Publish(context, owner.Pair.Network, 1, envelope)) == 409, "metadata replay rejected by registry");
            var retainedTable=owner.Directory!;
            var replicaContext=new DefaultHttpContext();replicaContext.Request.Headers.Authorization="Bearer "+b.Pair.Auth;
            Check(b.OwnerPrivate.Length==0 && Status(registry.Directory(replicaContext,owner.Pair.Network,retainedTable))==204,"ordinary member can resend the unchanged issuer-signed table");
            var bEnvelope = MeshMetadata.Seal(b, announcement with { Slot = 2, Device = b.Self.Device });
            MeshIdentity.Revoke(owner, 2); Check(Status(registry.Directory(context, owner.Pair.Network, owner.Directory!)) == 204 && Status(registry.Publish(context, owner.Pair.Network, 2, bEnvelope)) == 403, "revoked member cannot publish after roster update");
            registry=new MeshRegistry(root);
            Check(Status(registry.Directory(replicaContext,owner.Pair.Network,retainedTable))==409 && Status(registry.Publish(replicaContext,owner.Pair.Network,2,bEnvelope))==403,"coordination restart retains revocation and rejects an old replica");
            var unauthorized = new DefaultHttpContext(); Check(Status(registry.Read(unauthorized, owner.Pair.Network)) == 401, "directory requires network authentication");
            long persistedRevision = owner.Directory!.Revision;
            Guest(owner);
            // Block the destination itself: atomic storage uses a fresh random
            // temporary name, so occupying the historical .tmp path is no fault.
            string stored = Path.Combine(root, "mesh-networks.json");
            File.Move(stored, stored + ".retained"); Directory.CreateDirectory(stored);
            bool writeFailed = false;
            try { registry.Directory(context, owner.Pair.Network, owner.Directory!); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { writeFailed = true; }
            finally { Directory.Delete(stored); File.Move(stored + ".retained", stored); }
            var unchanged = (MeshSnapshot)((IValueHttpResult)registry.Read(context, owner.Pair.Network)).Value!;
            Check(writeFailed && unchanged.Directory.Revision == persistedRevision, "failed directory persistence leaves live authorization unchanged");
        } finally { File.Delete(Path.Combine(root, "mesh-networks.json")); Directory.Delete(root); }
        // Three complete routing nodes over isolated loopback datagrams; no real
        // adapter, firewall, service, discovery server or production profile.
        var a = MeshIdentity.Create("", "", "faketcp",direct:true); var n2 = Guest(a); var n3 = Guest(a); n2.Directory = n3.Directory = a.Directory;
        var adapters = new[] { new MemoryAdapter(), new MemoryAdapter(), new MemoryAdapter() };
        await using (var r1 = new MeshRouter(a, adapters[0]))
        await using (var r2 = new MeshRouter(n2, adapters[1]))
        await using (var r3 = new MeshRouter(n3, adapters[2])) {
            bool raw = args.Length == 2 && args[0] == "--raw" && OperatingSystem.IsWindows();
            await using var transport = raw && OperatingSystem.IsWindows() ? new RawLoopback(args[1], a, r1.LocalEndpoint, r2.LocalEndpoint, r3.LocalEndpoint) : null;
            IPEndPoint? Via(int from, int to, MeshRouter destination) => transport != null && OperatingSystem.IsWindows() ? transport.Client(from, to) : destination.LocalEndpoint;
            r1.SetCandidate(2, Via(1, 2, r2), "B", ""); r1.SetCandidate(3, Via(1, 3, r3), "C", "");
            r2.SetCandidate(1, Via(2, 1, r1), "A", ""); r2.SetCandidate(3, Via(2, 3, r3), "C", "");
            r3.SetCandidate(1, Via(3, 1, r1), "A", ""); r3.SetCandidate(2, Via(3, 2, r2), "B", "");
            await Until(() => new[] { r1, r2, r3 }.All(r => r.Status().Count(p => p.Connected) == 2), "three nodes establish six independent directed paths");
            using(var d1=new DirectMeshDiscovery(a))using(var d2=new DirectMeshDiscovery(n2)){
                d1.Attach(r1);d2.Attach(r2);
                await d1.Publish(new(1,a.Self.Device,DateTime.UtcNow.Ticks,DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(),"203.0.113.1:44680","native direct host"),default);
                long deadline=Environment.TickCount64+15000;bool synchronized=false;
                while(Environment.TickCount64<deadline){d1.Tick(Environment.TickCount64);d2.Tick(Environment.TickCount64);if((await d2.Read(default))!.Nodes.Any(n=>n.Slot==1)){synchronized=true;break;}await Task.Delay(110);}
                Check(synchronized,raw?"serverless signed metadata crosses actual udp2raw FakeTCP HTTP protocol loops":"serverless signed metadata crosses the encrypted router path");
            }
            adapters[0].Outgoing.Add(Packet(a.LocalIp, n2.LocalIp)); adapters[0].Outgoing.Add(Packet(a.LocalIp, n3.LocalIp)); adapters[1].Outgoing.Add(Packet(n2.LocalIp, n3.LocalIp));
            await Until(() => adapters[1].Incoming.Count == 1 && adapters[2].Incoming.Count == 2, "three-node router delivers only to the addressed peer");
            adapters[0].Outgoing.Add(Packet(n2.LocalIp, n3.LocalIp)); await Task.Delay(150); Check(adapters[2].Incoming.Count == 2, "router refuses transit traffic even from local adapter");
            MeshIdentity.Revoke(a, 3); r1.ApplyDirectory(a.Directory!); r2.ApplyDirectory(a.Directory!);
            Check(r1.Status().Length == 1 && r2.Status().Length == 1, "removal closes only revoked member links");
            adapters[0].Outgoing.Add(Packet(a.LocalIp, n2.LocalIp)); await Until(() => adapters[1].Incoming.Count == 2, "remaining peers continue without adapter recreation");
            if (transport != null && OperatingSystem.IsWindows()) Check(transport.SawHttp, "real udp2raw FakeTCP + HTTP handshake carries native multi-client overlay");
        }
        Check(adapters.All(a => a.Disposed), "all routing pumps stop before adapter disposal");
        var offlineOwner = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var offlineB = Guest(offlineOwner); var offlineC = Guest(offlineOwner);
        offlineB.Directory = offlineC.Directory = offlineOwner.Directory;
        var memoryB = new MemoryAdapter(); var memoryC = new MemoryAdapter();
        await using (var routerB = new MeshRouter(offlineB, memoryB))
        await using (var routerC = new MeshRouter(offlineC, memoryC)) {
            routerB.SetCandidate(3, routerC.LocalEndpoint, "C", ""); routerC.SetCandidate(2, routerB.LocalEndpoint, "B", "");
            await Until(() => routerB.Status().Single(p => p.Slot == 3).Connected && routerC.Status().Single(p => p.Slot == 2).Connected, "two existing members reconnect while creator remains offline");
            memoryB.Outgoing.Add(Packet(offlineB.LocalIp, offlineC.LocalIp));
            await Until(() => memoryC.Incoming.Count == 1, "member data delivery does not depend on creator forwarding");
        }
        var limits = MeshIdentity.Create("https://example.com/", "", "faketcp");
        for (int i = 1; i < MeshIdentity.MaxMembers; i++) Guest(limits);
        Reject(() => Guest(limits), "network enforces the eight-member resource limit");
        if (args.Length >= 2 && args[0] == "--server") {
            string pin = args.Length > 3 && args[2] == "--pin" ? args[3] : "";
            var net = MeshIdentity.Create(args[1], pin, "faketcp"); var secondNode = Guest(net); var thirdNode = Guest(net);
            using var d1 = new MeshDiscoveryClient(net); using var d2 = new MeshDiscoveryClient(secondNode); using var d3 = new MeshDiscoveryClient(thirdNode);
            using var timeout = new CancellationTokenSource(25000);
            await d1.SaveDirectory(net.Directory!, timeout.Token);
            var configurations = new[] { net, secondNode, thirdNode }; var clients = new[] { d1, d2, d3 };
            for (int i = 0; i < 3; i++) await clients[i].Publish(new(configurations[i].Self.Slot, configurations[i].Self.Device, DateTime.UtcNow.Ticks, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), "192.0.2.1:" + (40000 + i), "Test " + i), timeout.Token);
            var read = await d2.Read(timeout.Token);
            Check(read?.Directory.Members.Length == 3 && read.Nodes.Length == 3, "HTTPS three-member roster and signed endpoint exchange");
            foreach (var e in read!.Nodes) MeshMetadata.Open(secondNode, read.Directory.Members.Single(m => m.Slot == e.Slot), e);
            Check(true, "HTTPS metadata decrypts with bound member identities");
            MeshIdentity.Revoke(net, thirdNode.Self.Slot); await d1.SaveDirectory(net.Directory!, timeout.Token);
            read = await d2.Read(timeout.Token); Check(read?.Directory.Members.Length == 2 && read.Nodes.All(n => n.Slot != 3), "HTTPS revocation removes stale endpoint announcements");
        }
        if (args.Length == 2 && args[0] == "--native") {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            await NativeRoundtrip(Path.GetFullPath(args[1]));
        }
        Console.WriteLine($"{checks} mesh checks passed");
    }
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    static async Task NativeRoundtrip(string components)
    {
        var local = MeshIdentity.Create("https://example.com/", "", "faketcp"); var peer = Guest(local); peer.Directory = local.Directory;
        string rule = "StreamLink-" + Guid.NewGuid().ToString("N");
        string recoveryRoot = Path.Combine(Path.GetTempPath(), "streamlink-native-test"); string recovery = Path.Combine(recoveryRoot, Guid.NewGuid().ToString("N")); Directory.CreateDirectory(recovery);
        Recovery.Recover(_ => { }, recoveryRoot); Recovery.Record(recovery, rule);
        Console.WriteLine("Isolated native adapter " + local.LocalIp);
        try {
            using var adapter = new NativeAdapter(components, local.Pair.Network, 1);
            PacketAdapterProviders.RequireProduction(adapter.Descriptor);
            Check(adapter.Descriptor.Abi==2&&adapter.Descriptor.CancelRead,"actual official provider declares versioned cancellable ABI");
            WindowsHost.AddFirewall(rule, local.LocalIp, peer.LocalIp);
            var memory = new MemoryAdapter();
            await using (var native = new MeshRouter(local, adapter))
            await using (var remote = new MeshRouter(peer, memory)) {
                Check(System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Any(n => n.GetIPProperties().UnicastAddresses.Any(x => x.Address.ToString() == local.LocalIp)), "signed Wintun adapter has correct isolated virtual IP");
                native.SetCandidate(2, remote.LocalEndpoint, "remote", ""); remote.SetCandidate(1, native.LocalEndpoint, "native", "");
                await Until(() => native.Status().Single().Connected && remote.Status().Single().Connected, "real Wintun node authenticates simulated remote node");
                using var udp = new UdpClient(new IPEndPoint(IPAddress.Parse(local.LocalIp), 0));
                byte[] payload = RandomNumberGenerator.GetBytes(1200);
                await udp.SendAsync(payload, new IPEndPoint(IPAddress.Parse(peer.LocalIp), 45124));
                await Until(() => memory.Incoming.Count > 0, "Windows UDP application traverses Wintun and encrypted datagram router");
                Check(adapter.Statistics.ReadPackets>0&&adapter.Statistics.ReadBytes>=1200,"actual adapter read accounting reflects IP packets");
                memory.Incoming.TryDequeue(out var packet); byte[] echo = packet!.ToArray(); int ipHeader = (echo[0] & 15) * 4;
                echo.AsSpan(12, 4).CopyTo(echo.AsSpan(16, 4)); IPAddress.Parse(peer.LocalIp).GetAddressBytes().CopyTo(echo, 12);
                (echo[ipHeader], echo[ipHeader + 2]) = (echo[ipHeader + 2], echo[ipHeader]); (echo[ipHeader + 1], echo[ipHeader + 3]) = (echo[ipHeader + 3], echo[ipHeader + 1]);
                echo[ipHeader + 6] = echo[ipHeader + 7] = echo[10] = echo[11] = 0;
                uint checksum = 0; for (int i = 0; i < ipHeader; i += 2) checksum += BinaryPrimitives.ReadUInt16BigEndian(echo.AsSpan(i)); while (checksum > 65535) checksum = (checksum & 65535) + (checksum >> 16);
                BinaryPrimitives.WriteUInt16BigEndian(echo.AsSpan(10), (ushort)~checksum); memory.Outgoing.Add(echo);
                using var timeout = new CancellationTokenSource(5000); var reply = await udp.ReceiveAsync(timeout.Token);
                Check(reply.Buffer.SequenceEqual(payload) && reply.RemoteEndPoint.Address.ToString() == peer.LocalIp, "return packet reaches the real Windows UDP socket with correct source IP");
            }
            Check(!System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Any(n => n.GetIPProperties().UnicastAddresses.Any(x => x.Address.ToString() == local.LocalIp)), "native adapter and virtual address removed after clean shutdown");
        } finally { WindowsHost.RemoveFirewall(rule); File.Delete(Path.Combine(recovery, "owner.json")); Directory.Delete(recovery); }
    }
    sealed class MemoryAdapter : IPacketAdapter
    {
        public BlockingCollection<byte[]> Outgoing = new(); public ConcurrentQueue<byte[]> Incoming = new(); public bool Disposed;
        public int Read(byte[] buffer) { if (!Outgoing.TryTake(out var packet, 50)) return 0; packet.CopyTo(buffer, 0); return packet.Length; }
        public bool Write(byte[] packet) { Incoming.Enqueue(packet); return true; }
        public void Dispose() { Disposed = true; Outgoing.Dispose(); }
    }
}
