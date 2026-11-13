using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

static class StreamFlowChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        Crypto(check); Settings(check);
        await Admission(check);
        foreach (string mode in new[] { "tcp", "https" }) {
            await Pair(mode, true, true, check);
            await Pair(mode, false, true, check);
            await Pair(mode, true, false, check);
            await Pair(mode,true,true,check,delayAux:true);
            if(mode=="https")await Pair(mode,true,true,check,badAuxCertificate:true);
            else await Pair(mode,true,true,check,blackholeAux:true);
            await Shared(mode, check);
        }
    }
    static async Task Admission(Action<bool,string> check)
    {
        var host = MeshIdentity.Create("", "", "tcp", direct: true, pairwise: true);
        var guest = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(host)));
        using var sink = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); int port = FreePort();
        await using var listener = new StreamMeshTransport(host, (IPEndPoint)sink.Client.LocalEndPoint!, true, port, flowLanes: true);
        byte[] shared = MeshIdentity.SharedKey(guest, host.Self);
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, info: Encoding.ASCII.GetBytes($"conwu-stream-flow-v1/{host.Pair.Network}/tcp/1/2"));
        CryptographicOperations.ZeroMemory(shared);
        byte[] nonce = RandomNumberGenerator.GetBytes(16), serverNonce = new byte[16]; long issued = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        byte[] Message(int kind, int lane = 0) {
            byte[] frame = new byte[100]; "CWF1"u8.CopyTo(frame); frame[4] = 1; frame[5] = (byte)kind; frame[6] = (byte)lane; frame[7] = 1;
            Convert.FromHexString(host.Pair.Network).CopyTo(frame, 8); frame[24] = 2; frame[25] = 1;
            nonce.CopyTo(frame, 28); serverNonce.CopyTo(frame, 44); BinaryPrimitives.WriteInt64BigEndian(frame.AsSpan(60), issued);
            HMACSHA256.HashData(key, frame.AsSpan(0, 68), frame.AsSpan(68)); return frame;
        }
        async Task<TcpClient> Open() { var socket = new TcpClient { NoDelay = true }; await socket.ConnectAsync(IPAddress.Loopback, port); return socket; }
        async Task Send(TcpClient socket, byte[] frame) { byte[] length = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)frame.Length); await socket.GetStream().WriteAsync(length.Concat(frame).ToArray()); }
        async Task<byte[]> Read(TcpClient socket) { using var timeout = new CancellationTokenSource(2000); byte[] length = new byte[2]; await socket.GetStream().ReadExactlyAsync(length, timeout.Token); byte[] frame = new byte[BinaryPrimitives.ReadUInt16BigEndian(length)]; await socket.GetStream().ReadExactlyAsync(frame, timeout.Token); return frame; }
        async Task<bool> Quiet(TcpClient socket) { using var timeout = new CancellationTokenSource(150); try { return await socket.GetStream().ReadAsync(new byte[1], timeout.Token) == 0; } catch (Exception ex) when (ex is IOException or OperationCanceledException) { return true; } }
        try {
            using (var bad = await Open()) { byte[] forged = Message(1); forged[^1] ^= 1; await Send(bad, forged); check(await Quiet(bad), "a forged group offer cannot release admission or establish a flow group"); }
            using (var bad = await Open()) { byte[] frame = Message(1); BinaryPrimitives.WriteInt64BigEndian(frame.AsSpan(60), long.MinValue + DateTimeOffset.UtcNow.ToUnixTimeSeconds()); await Send(bad, frame); check(await Quiet(bad) && !listener.Exited, "extreme untrusted timestamps cannot overflow or stop the stream listener"); }
            using (var bad = await Open()) { byte[] frame = Message(1); RandomNumberGenerator.Fill(frame.AsSpan(8, 16)); await Send(bad, frame); check(await Quiet(bad), "a credential cannot negotiate a different network's stream group"); }
            using var primary = await Open(); byte[] offer = Message(1); await Send(primary, offer);
            byte[] challenge = await Read(primary); serverNonce = challenge.AsSpan(44, 16).ToArray();
            await Send(primary, Message(3)); check((await Read(primary))[5] == 4, "an approved member must prove the fresh server challenge before auxiliary attachment");
            using (var replay = await Open()) { await Send(replay, offer); check(await Quiet(replay), "a replayed offer cannot replace a live primary group"); }
            using var auxiliary = await Open(); byte[] attach = Message(5, 2); await Send(auxiliary, attach);
            check((await Read(auxiliary))[5] == 6, "an authenticated auxiliary attaches to its existing primary group");
            using (var duplicate = await Open()) { await Send(duplicate, attach); check(await Quiet(duplicate), "replayed attachment cannot claim a second socket for an occupied lane"); }
            using (var wrong = await Open()) { byte[] frame = Message(5, 3); frame[44] ^= 1; HMACSHA256.HashData(key, frame.AsSpan(0, 68), frame.AsSpan(68)); await Send(wrong, frame); check(await Quiet(wrong), "even a valid member MAC cannot attach using a different group challenge"); }
            check(sink.Available == 0, "carrier authentication records never grant mesh membership or leak into business routing");
        } finally { CryptographicOperations.ZeroMemory(key); }
    }
    static void Crypto(Action<bool,string> check)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var left = new MeshLink(1, 2, key); using var right = new MeshLink(2, 1, key);
        right.Receive(left.Receive(right.Receive(left.Hello()).Reply!).Reply!);
        byte[] slow = left.StreamData([42], 2)!;
        check(!right.Receive(slow).Authenticated, "stream crypto extensions require an authenticated negotiated carrier");
        for (int i = 0; i < 6000; i++) if (!right.Receive(left.StreamData([7], 3)!, true).Authenticated) throw new Exception("bulk lane rejected");
        check(right.Receive(slow, true).Packet!.SequenceEqual(new byte[] { 42 }), "six thousand bulk packets cannot evict a delayed audio lane packet");
        check(!right.Receive(slow, true).Authenticated, "each stream lane independently rejects replay");
        byte[] first = left.StreamData([8], 1)!; first[7] = 2;
        check(!right.Receive(first, true).Authenticated, "changing a lane cannot reuse another lane's AEAD key or nonce");
        byte[] control = left.Control([9])!; control[7] = 1;
        check(!right.Receive(control, true).Authenticated, "stream lane extensions never authorize handshake or control records");
        check(right.Receive(left.Data([3])!).Authenticated, "legacy crypto and heartbeat counters remain separate from stream lanes");
        foreach (int port in new[] { 47998, 47999, 48000, 45123 }) {
            var small = Packet("10.4.5.1", "10.4.5.2", port, 52, 1);
            var large = Packet("10.4.5.1", "10.4.5.2", port, 1280, 2);
            check(StreamFlowClassifier.Lane(small) == StreamFlowClassifier.Lane(large), "fixed flow " + port + " retains its lane across mixed-size packets");
        }
        check(StreamFlowClassifier.Lane(Packet("10.4.5.1", "10.4.5.2", 47999, 52, 1)) == 1 &&
            StreamFlowClassifier.Lane(Packet("10.4.5.1", "10.4.5.2", 48000, 200, 1)) == 2 &&
            StreamFlowClassifier.Lane(Packet("10.4.5.1", "10.4.5.2", 47998, 1280, 1)) == 3, "Sunshine default input, audio and video flows use independent connections");
    }
    static void Settings(Action<bool,string> check)
    {
        var profile = new DeviceProfile { DeviceName = "unchanged", StreamFlowLanes = false };
        ConnectionSettings.Apply(profile, new(PathSelection: "https-only") { StreamFlowLanes = false });
        var original = ProfileChanges.Copy(profile);
        ConnectionSettings.Apply(profile, profile.SavedNetworkSettings! with { StreamFlowLanes = true });
        check(ProfileChanges.Impact(original, profile) == ProfileChangeImpact.RestartNetwork && profile.DeviceName == original.DeviceName,
            "changing stream lanes requests a reconnect without replacing identity or unrelated settings");
        var host = MeshIdentity.Create("", "", "https", direct: true, pairwise: true);
        var guest = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(host)));
        var approved = ApprovedNetworkSettings.Create(host, profile.SavedNetworkSettings! with { StreamFlowLanes = false });
        check(!approved.ForGuest(guest, new()).StreamFlowLanes, "approved configuration inherits the host stream-lane preference");
        var restored = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(profile))!;
        check(restored.StreamFlowLanes && restored.SavedNetworkSettings!.StreamFlowLanes, "stream-lane preferences survive profile save and reload");
    }
    static async Task Pair(string mode, bool serverEnabled, bool clientEnabled, Action<bool,string> check,bool badAuxCertificate=false,bool blackholeAux=false,bool delayAux=false)
    {
        var host = MeshIdentity.Create("", "", mode, direct: true, pairwise: true);
        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var cert = StreamCertificates.CreateServer(signing, DateTimeOffset.UtcNow.AddDays(1));
        using var otherSigning = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var otherCert = StreamCertificates.CreateServer(otherSigning, DateTimeOffset.UtcNow.AddDays(1));int certificateCalls=0;
        if (mode == "https") host.Pair = host.Pair with { TransportKeyPin = StreamMeshTransport.CertificatePin(cert) };
        var guest = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(host)));
        var hostAdapter = new MemoryAdapter(); var guestAdapter = new MemoryAdapter();
        await using var hr = new MeshRouter(host, hostAdapter); await using var gr = new MeshRouter(guest, guestAdapter);
        int port = FreePort();
        await using var listener = new StreamMeshTransport(host, hr.LocalEndpoint, true, port, () => badAuxCertificate&&Interlocked.Increment(ref certificateCalls)>1?otherCert:cert, flowLanes: serverEnabled);
        await using var proxy = new Proxy(new(IPAddress.Loopback, port),blackholeAux,delayAux);
        await using var client = new StreamMeshTransport(guest, proxy.Endpoint, false, 0, flowLanes: clientEnabled);
        gr.SetCandidate(1, client.ClientEndpoint, "host", "");
        await Until(() => hr.Status().Single().Connected && gr.Status().Single().Connected, mode + " healthy");
        bool full=serverEnabled&&clientEnabled&&!badAuxCertificate&&!blackholeAux;
        if(delayAux)await WarmBurst();
        if (full) await Until(() => hr.Status().Single().StreamFlows?.SplitActive==true && gr.Status().Single().StreamFlows?.SplitActive==true, mode + " three connections and FIFO fences");
        else if(badAuxCertificate||blackholeAux){await Until(()=>proxy.Count>=2,mode+" auxiliary attempted");if(blackholeAux)await Task.Delay(6500);else await Task.Delay(200);
            check(!client.Exited&&gr.Status().Single().StreamFlows?.Connections==1,mode+" failed auxiliary authentication or reply timeout preserves the primary");
            if(badAuxCertificate)check(client.PeerCertificatePin==host.Pair.TransportKeyPin,"an invalid auxiliary TLS certificate cannot replace the approved primary pin");}
        else check(hr.Status().Single().StreamFlows?.Negotiated != true && gr.Status().Single().StreamFlows?.Negotiated != true, mode + " single-connection compatibility when either endpoint disables lanes");
        await Burst(0);
        check(hr.Status().Single().LocalDrops!.AuthenticationRejected == 0 && gr.Status().Single().LocalDrops!.AuthenticationRejected == 0, mode + " formal router accepts independent lane keys without replay-window interference");
        if (full) {
            check(proxy.Count == 3, mode + " one pairing and one candidate open exactly three real connections");
            await CutDuringBurst();
            await Until(() => gr.Status().Single().StreamFlows?.Connections == 1 && hr.Status().Single().StreamFlows?.Connections == 1, mode + " auxiliary close");
            await Task.Delay(100);
            await Burst(1000);
            check(hr.Status().Single().Connected && gr.Status().Single().Connected && !client.Exited && !listener.Exited,
                mode + " auxiliary failures fall back to the existing primary without pairing or path replacement");
        }
        async Task Burst(int offset) {
            int beforeH = hostAdapter.Incoming.Count, beforeG = guestAdapter.Incoming.Count;
            for (int seq = 1; seq <= 60; seq++) foreach (int flow in new[] { 47999, 48000, 47998 }) {
                hostAdapter.Outgoing.Add(Packet(host.LocalIp, guest.LocalIp, flow, seq % 2 == 0 ? 1280 : 52, offset + seq));
                guestAdapter.Outgoing.Add(Packet(guest.LocalIp, host.LocalIp, flow, seq % 2 == 0 ? 52 : 1280, offset + seq));
            }
            await Until(() => hostAdapter.Incoming.Count >= beforeH + 180 && guestAdapter.Incoming.Count >= beforeG + 180, mode + " burst delivery");
            foreach (var packets in new[] { hostAdapter.Incoming.Skip(beforeH), guestAdapter.Incoming.Skip(beforeG) })
                foreach (var flow in packets.GroupBy(p => BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(20))))
                    check(flow.Select(p => BinaryPrimitives.ReadInt32BigEndian(p.AsSpan(28))).SequenceEqual(Enumerable.Range(offset + 1, 60)), mode + " mixed-size flow " + flow.Key + " preserves sequence in both directions");
        }
        async Task WarmBurst(){
            const int count=1400;
            for(int seq=1;seq<=count;seq++){
                foreach(int flow in new[]{47999,48000,47998}){
                    hostAdapter.Outgoing.Add(Packet(host.LocalIp,guest.LocalIp,flow,seq%2==0?1280:52,seq));
                    guestAdapter.Outgoing.Add(Packet(guest.LocalIp,host.LocalIp,flow,seq%2==0?52:1280,seq));
                }
                await Task.Delay(2);
            }
            await Until(()=>hostAdapter.Incoming.Count>=count*3&&guestAdapter.Incoming.Count>=count*3,mode+" continuous activation");
            foreach(var packets in new[]{hostAdapter.Incoming,guestAdapter.Incoming})foreach(var flow in packets.GroupBy(p=>BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(20))))
                check(flow.Select(p=>BinaryPrimitives.ReadInt32BigEndian(p.AsSpan(28))).SequenceEqual(Enumerable.Range(1,count)),mode+" FIFO activation fences preserve a flowing mixed-size stream "+flow.Key);
        }
        async Task CutDuringBurst(){
            int beforeH=hostAdapter.Incoming.Count,beforeG=guestAdapter.Incoming.Count;
            const int count=600;
            for(int seq=1;seq<=count;seq++){
                foreach(int flow in new[]{47999,48000,47998}){
                    hostAdapter.Outgoing.Add(Packet(host.LocalIp,guest.LocalIp,flow,seq%2==0?1280:52,seq));
                    guestAdapter.Outgoing.Add(Packet(guest.LocalIp,host.LocalIp,flow,seq%2==0?52:1280,seq));
                }
                if(seq==100)proxy.CutAuxiliaries();
                await Task.Delay(1);
            }
            bool Finished(IEnumerable<byte[]> packets)=>packets.GroupBy(p=>BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(20))).Count(g=>g.Any(p=>BinaryPrimitives.ReadInt32BigEndian(p.AsSpan(28))==count))==3;
            await Until(()=>Finished(hostAdapter.Incoming.Skip(beforeH))&&Finished(guestAdapter.Incoming.Skip(beforeG)),mode+" fallback under active traffic");
            foreach(var packets in new[]{hostAdapter.Incoming.Skip(beforeH),guestAdapter.Incoming.Skip(beforeG)})foreach(var flow in packets.GroupBy(p=>BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(20)))){
                int[] sequences=flow.Select(p=>BinaryPrimitives.ReadInt32BigEndian(p.AsSpan(28))).ToArray();
                check(sequences.Zip(sequences.Skip(1)).All(p=>p.First<p.Second),mode+" active auxiliary failure preserves delivered order for flow "+flow.Key);
            }
        }
    }
    static async Task Shared(string mode, Action<bool,string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "conwu-stream-lanes-" + Guid.NewGuid().ToString("N"));
        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var cert = StreamCertificates.CreateServer(signing, DateTimeOffset.UtcNow.AddDays(1));
        using var shared = new SharedMeshReceiver(folder);
        int port = FreePort(), listeners = 0;
        var routers = new List<MeshRouter>(); var leases = new List<IMeshTransport>(); var clients = new List<StreamMeshTransport>();
        try {
            for (int i = 0; i < 6; i++) {
                var host = MeshIdentity.Create("", "", mode, direct: true, pairwise: true);
                if (mode == "https") host.Pair = host.Pair with { TransportKeyPin = StreamMeshTransport.CertificatePin(cert) };
                var guest = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(host)));
                var ha = new MemoryAdapter(); var ga = new MemoryAdapter();
                var hr = new MeshRouter(host, ha); var gr = new MeshRouter(guest, ga); routers.Add(hr); routers.Add(gr);
                bool enabled = i != 1;
                leases.Add(shared.Acquire(new(folder, host, hr.LocalEndpoint, true, port, null, "off") { StreamFlowLanes = enabled, RetireEndpoint = hr.FailLegacyIngress },
                    r => { listeners++; return new StreamMeshTransport(r.Mesh, r.Target, true, port, () => cert, flowLanes: r.StreamFlowLanes, flowPolicy: r.StreamFlowPolicy); }, _ => false, p => PairNetworkFrame.Authenticated(host, p.Span), _ => 0));
                var client = new StreamMeshTransport(guest, new(IPAddress.Loopback, port), false, 0, flowLanes: true); clients.Add(client); gr.SetCandidate(1, client.ClientEndpoint, "host", "");
                await Until(() => hr.Status().Single().Connected && gr.Status().Single().Connected && (!enabled || hr.Status().Single().StreamFlows?.Connections == 3), mode + " shared " + i);
                ga.Outgoing.Add(Packet(guest.LocalIp, host.LocalIp, 47998, 1280, i));
                ha.Outgoing.Add(Packet(host.LocalIp, guest.LocalIp, 48000, 52, i));
                await Until(() => ha.Incoming.Count == 1 && ga.Incoming.Count == 1, mode + " shared data " + i);
                check(!enabled ? hr.Status().Single().StreamFlows?.Negotiated != true : hr.Status().Single().StreamFlows?.Connections == 3, mode + " shared listener applies network " + i + " policy and identity independently");
            }
            check(listeners == 1, mode + " more than sixteen real connections share one listener without duplicating mesh routes");
            leases[0].Dispose(); await Until(()=>clients[0].Exited, mode + " removed network closes its server-owned sessions");
            check(clients[0].Exited, mode + " removing a subscription retires its primary and auxiliaries at the server");
            await Task.Delay(100);
            check(routers.Skip(2).All(r => r.Status().Single().Connected), mode + " removing one network preserves all other active networks and lanes");
        } finally {
            foreach (var client in clients) await client.DisposeAsync(); foreach (var lease in leases) lease.Dispose(); shared.Dispose();
            foreach (var router in routers) await router.DisposeAsync();
            if (Directory.Exists(folder) && !Directory.EnumerateFileSystemEntries(folder).Any()) Directory.Delete(folder);
        }
    }
    static int FreePort() { var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port; }
    static async Task Until(Func<bool> condition, string why) { using var timeout = new CancellationTokenSource(12000); try { while (!condition()) await Task.Delay(20, timeout.Token); } catch (OperationCanceledException) { throw new IOException("Timed out: " + why); } }
    internal static byte[] Packet(string from, string to, int flow, int length, int sequence)
    {
        var packet = new byte[length]; packet[0] = 0x45; packet[8] = 64; packet[9] = 17;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)length); IPAddress.Parse(from).GetAddressBytes().CopyTo(packet, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(packet, 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), (ushort)flow); BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), 45123); BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24), (ushort)(length - 20));
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(28), sequence);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16); BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), (ushort)~sum); return packet;
    }
    sealed class Proxy : IAsyncDisposable
    {
        readonly TcpListener listener = new(IPAddress.Loopback, 0); readonly CancellationTokenSource stop = new(); readonly Task accept;
        readonly List<(TcpClient Local, TcpClient Remote)> pairs = []; readonly List<Task> tasks = [];
        public IPEndPoint Endpoint => (IPEndPoint)listener.LocalEndpoint;
        public int Count { get { lock (pairs) return pairs.Count; } }
        readonly bool blackholeAux;
        readonly bool delayAux;
        public Proxy(IPEndPoint target,bool blackholeAux=false,bool delayAux=false) { this.blackholeAux=blackholeAux;this.delayAux=delayAux;listener.Start(); accept = Accept(target); }
        async Task Accept(IPEndPoint target) {
            try { while (!stop.IsCancellationRequested) {
                var local = await listener.AcceptTcpClientAsync(stop.Token); var remote = new TcpClient();
                if(blackholeAux&&Count>=1){lock(pairs)pairs.Add((local,remote));continue;}
                await remote.ConnectAsync(target, stop.Token);
                lock (pairs) { bool auxiliary=pairs.Count>0;pairs.Add((local, remote)); tasks.Add(Forward(local, remote,auxiliary)); }
            } } catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException) { }
        }
        async Task Forward(TcpClient local, TcpClient remote,bool auxiliary) {
            try { if(delayAux&&auxiliary)await Task.Delay(3000,stop.Token);var flows = new[] { local.GetStream().CopyToAsync(remote.GetStream(), stop.Token), remote.GetStream().CopyToAsync(local.GetStream(), stop.Token) }; await await Task.WhenAny(flows); local.Dispose(); remote.Dispose(); try { await Task.WhenAll(flows); } catch (Exception) { } }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
        }
        public void CutAuxiliaries() { lock (pairs) foreach (var pair in pairs.Skip(1)) { pair.Local.Dispose(); pair.Remote.Dispose(); } }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); lock (pairs) foreach (var pair in pairs) { pair.Local.Dispose(); pair.Remote.Dispose(); } await accept; Task[] pending; lock (pairs) pending = tasks.ToArray(); await Task.WhenAll(pending); stop.Dispose(); }
    }
}
