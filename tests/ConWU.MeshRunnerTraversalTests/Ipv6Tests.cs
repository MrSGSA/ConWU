using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

static class Ipv6Tests
{
    public static Task<object> RunDiagnostics(string root,string url,string pin,Action<bool,string> check,CancellationToken token,bool interruptBusy=false)=>
        Runners(root,url,pin,"ipv6",check,token,false,false,true,true,interruptBusy);
    public static Task<object> RunQualityRetain(string root,string url,string pin,Action<bool,string> check,CancellationToken token)=>
        Runners(root,url,pin,"ipv6",check,token,false,false,true,true,false,true);
    public static Task<object> RunRelativeQuality(string root,string url,string pin,Action<bool,string> check,CancellationToken token)=>
        Runners(root,url,pin,"ipv6",check,token,false,false,true,true,false,true,true);
    public static Task<object> RunStandby(string root,string url,string pin,Action<bool,string> check,CancellationToken token) =>
        Runners(root,url,pin,"ipv6",check,token,false,false,true);
    public static async Task<object> Run(string root, string url, string pin, int rounds, Action<bool, string> check, CancellationToken token, bool paced = false, bool feedback = false)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromMinutes(4)); token = deadline.Token;
        await Encoding(check, token);
        var pmtu = await Sockets(rounds, check, token);
        var rows = new List<object>();
        foreach (string mode in new[] { "ipv6", "ipv6-unreachable", "old-peer", "old-service" }) rows.Add(await Runners(root, url, pin, mode, check, token, paced, feedback));
        return new { rounds, pmtu, runners = rows, realIPv6Sockets = true, realHttps = true, realNat = false, wintun = false, nativeFakeTcpIpv6 = false };
    }
    static async Task Encoding(Action<bool, string> check, CancellationToken token)
    {
        // Independent RFC 5769 section 2.3 vector, not produced by our reflector encoder.
        byte[] req = Convert.FromHexString("000100002112A442B7E7A701BC34D686FA87DFAE");
        byte[] response = Convert.FromHexString("010100482112A442B7E7A701BC34D686FA87DFAE8022000B7465737420766563746F7220002000140002A1470113A9FAA5D3F179BC25F4B5BED2B9D900080014A382954E4BE67BF11784C97C8292C275BFE3ED4180280004C8FB0B4C");
        check(Stun.Parse(response, req, AddressFamily.InterNetworkV6).Equals(IPEndPoint.Parse("[2001:db8:1234:5678:11:2233:4455:6677]:32853")), "RFC 5769 IPv6 XOR address vector decodes cookie plus transaction mask");
        bool v4 = false; try { Stun.Parse(response, req); } catch (IOException) { v4 = true; }
        check(v4, "legacy IPv4 STUN consumers cannot accept an IPv6 mapping");
        bool stale = false; var wrong = req.ToArray(); wrong[8] ^= 1;
        try { Stun.Parse(response, wrong, AddressFamily.InterNetworkV6); } catch (IOException) { stale = true; }
        check(stale, "IPv6 STUN rejects another transaction");
        bool shortAttribute = false; var shortened = response.ToArray(); shortened[39] = 16;
        try { Stun.Parse(shortened, req, AddressFamily.InterNetworkV6); } catch (IOException) { shortAttribute = true; }
        check(shortAttribute, "truncated IPv6 address attribute is rejected");
        check((await Stun.Resolve("[::1]:3478", AddressFamily.InterNetworkV6, token)).Equals(new IPEndPoint(IPAddress.IPv6Loopback, 3478)), "bracketed IPv6 reflector endpoint resolves without IPv4 conversion");
        bool mismatch = false; try { await Stun.Resolve("[::1]:3478", token); } catch (IOException) { mismatch = true; }
        check(mismatch, "explicit IPv4 resolution does not use an IPv6 literal");
        DeviceProfile.ValidateServers(["[::1]:3478", "localhost:3478"]);
        check(!new DeviceProfile().UdpIpv6, "IPv6 experimental path stays disabled in existing/default profiles");
        foreach (string invalid in new[] { "::", "::ffff:127.0.0.1", "::192.0.2.1", "fe80::1%12", "ff02::1", "fec0::1" })
            check(!Ipv6Direct.UnscopedUnicast(IPAddress.Parse(invalid)), "wire candidates reject scoped/mapped/non-unicast address " + invalid);
        foreach (string local in new[] { "::1", "fd00::1", "2001:db8::1", "3fff::1", "2002:c000:201::1", "2001:0:abcd::1" })
            check(!Ipv6Direct.Global(IPAddress.Parse(local)), "public native policy excludes local/documentation/transition address " + local);
        check(Ipv6Direct.Global(IPAddress.Parse("2606:4700:4700::1111")), "native global address passes address policy without implying reachability");
        var a = MeshIdentity.Create("https://localhost", "", "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var ca = new MeshTraversalCapabilities(1, 0, Guid.NewGuid(), [TraversalProfile.UdpDirect], UdpIpv6: 1);
        var cb = ca with { BootId = Guid.NewGuid() }; long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var candidate = new MeshTraversalCandidate(Guid.NewGuid(), 1, "[::1]:43000", "[::1]:3478", now, now + 120, CandidatePurpose.UdpDirect);
        long sequence = 0;
        await using var actor = MeshTraversalAttempt.Offer(a, b.Self, ca, cb, TraversalProfile.UdpDirect, candidate, 1, () => ++sequence);
        MeshTraversalAttempt.ValidateOffer(b, a.Self, cb, ca, actor.Outbound!);
        check(true, "authenticated Offer permits IPv6 only after bilateral capability agreement");
        bool old = false; try { MeshTraversalAttempt.ValidateOffer(b, a.Self, cb with { UdpIpv6 = 0 }, ca, actor.Outbound!); } catch (CryptographicException) { old = true; }
        check(old, "unnegotiated IPv6 Offer is rejected before endpoint allocation");
        bool mixed = false;
        try { await using var answer = MeshTraversalAttempt.Answer(b, a.Self, cb, ca, actor.Outbound!, candidate with { Id = Guid.NewGuid(), Endpoint = "127.0.0.1:43001", ObservationTarget = "127.0.0.1:3478" }, () => ++sequence); }
        catch (FormatException) { mixed = true; }
        check(mixed, "Ready cannot combine an IPv6 Offer and an IPv4 answer");
        var mutated = actor.Outbound! with { Candidate = candidate with { Endpoint = "[::1]:43002" } };
        bool tampered = false; try { MeshTraversal.Verify(a.Pair.Network, a.Self, b.Self, mutated); } catch (CryptographicException) { tampered = true; }
        check(tampered, "IPv6 endpoint remains inside the member signature");
    }
    static async Task<object> Sockets(int rounds, Action<bool, string> check, CancellationToken token)
    {
        await using var reflector = new Reflector(AddressFamily.InterNetworkV6);
        var budget = new TraversalResources(8);
        for (int i = 0; i < rounds; i++) {
            var attempt = Guid.NewGuid(); var generation = Guid.NewGuid(); byte[] key = RandomNumberGenerator.GetBytes(32);
            await using var a = UdpTraversal.Create(new(IPAddress.IPv6Loopback, 0), generation, attempt, 1, 2, key, budget);
            await using var b = UdpTraversal.Create(new(IPAddress.IPv6Loopback, 0), generation, attempt, 2, 1, key, budget);
            CryptographicOperations.ZeroMemory(key);
            var observation = await a.Observe(reflector.Endpoint, token); var local = a.Local;
            check(observation.SocketId == a.SocketId && observation.Mapped.Equals(local), "IPv6 reflection uses the actual retained socket, round " + (i + 1));
            var result = await Task.WhenAll(a.Punch([b.Local], new(3000), token), b.Punch([a.Local], new(3000), token));
            check(result.All(r => r.Success), "real IPv6 bilateral checks and 1344-byte qualification, round " + (i + 1));
            await using var pa = a.RetainPath(generation, Guid.NewGuid()); await using var pb = b.RetainPath(generation, Guid.NewGuid());
            await a.DisposeAsync(); await b.DisposeAsync();
            byte[] payload = RandomNumberGenerator.GetBytes(1344);
            var received = pb.Receive(token).AsTask(); check(pa.TrySend(payload) && (await received).Span.SequenceEqual(payload), "winning IPv6 socket survives Attempt disposal with full payload, round " + (i + 1));
            var reverse = pa.Receive(token).AsTask(); check(pb.TrySend(payload) && (await reverse).Span.SequenceEqual(payload), "retained IPv6 socket carries reverse payload, round " + (i + 1));
            await pa.DisposeAsync(); await pb.DisposeAsync();
            using var rebound = new TraversalSocket(local);
            check(rebound.DontFragment && a.Closed && b.Closed, "IPv6 final references release ports and enforce Winsock DONTFRAG, round " + (i + 1));
        }
        // Isolated per-socket cap, not an interface/system MTU change. The first
        // run found loopback SendTo did NOT reject the oversized datagram despite
        // this option. Preserve that observation instead of claiming a wire gate.
        using var limited = new TraversalSocket(new(IPAddress.IPv6Loopback, 0));
        var socket = (Socket)typeof(TraversalSocket).GetField("socket", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(limited)!;
        socket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)76, 1280);
        bool oversize = false; try { await limited.Send(new byte[1344], reflector.Endpoint, token); } catch (SocketException e) when (e.SocketErrorCode == SocketError.MessageSize) { oversize = true; }
        int cap = (int)socket.GetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)76)!;
        int df = (int)socket.GetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)14)!;
        check(df == 1, "IPv6 socket DONTFRAG readback is enabled; Internet non-fragmentation remains unverified");
        await limited.Send(new byte[1232], reflector.Endpoint, token);
        check(true, "same IPv6 MTU accepts 1232-byte payload plus 48-byte IPv6/UDP headers");
        var attempt2 = Guid.NewGuid(); var key2 = RandomNumberGenerator.GetBytes(32);
        await using var lowA = new UdpTraversal(new LimitedSocket(), Guid.NewGuid(), attempt2, 1, 2, key2, budget);
        await using var lowB = new UdpTraversal(new LimitedSocket(), Guid.NewGuid(), attempt2, 2, 1, key2, budget);
        var negative = await Task.WhenAll(lowA.Punch([lowB.Local], new(1000), token), lowB.Punch([lowA.Local], new(1000), token));
        check(negative.All(r => !r.Success && r.Failure == "mtu-too-small" && r.AuthenticatedPackets > 0), "controlled IPv6 socket MessageSize permits small authenticated checks but forbids path qualification");
        CryptographicOperations.ZeroMemory(key2);
        return new { requestedUserMtu = 1280, readbackUserMtu = cap, dontFragment = df, oversizeRejected = oversize, wirePmtuVerified = false, initialFailurePreserved = "m7-ipv6-udp-initial-pmtu-20261011.json" };
    }
    sealed class LimitedSocket : ITraversalSocket
    {
        readonly TraversalSocket inner = new(new(IPAddress.IPv6Loopback, 0));
        public Guid Id => inner.Id; public IPEndPoint Local => inner.Local; public bool DontFragment => inner.DontFragment;
        public ValueTask Send(ReadOnlyMemory<byte> p, IPEndPoint r, CancellationToken t) => p.Length > 1232
            ? ValueTask.FromException(new SocketException((int)SocketError.MessageSize)) : inner.Send(p, r, t);
        public ValueTask<TraversalDatagram> Receive(CancellationToken t) => inner.Receive(t);
        public void Dispose() => inner.Dispose();
    }
    static async Task<object> Runners(string root, string url, string pin, string mode, Action<bool, string> check, CancellationToken token, bool paced, bool feedback, bool standby=false,bool diagnostics=false,bool interruptBusy=false,bool autoQuality=false,bool timing=false)
    {
        await using var v4 = new Reflector(AddressFamily.InterNetwork); await using var v6 = new Reflector(AddressFamily.InterNetworkV6) { BlackholeMappings = mode == "ipv6-unreachable" };
        var a = MeshIdentity.Create(url, pin, "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var profiles = new[] { a, b }.Select((m, i) => new DeviceProfile { Mesh = m, TraversalMode = "tcp-udp", PathSelection = "prefer-faketcp", AllowUdpFallback = true, UdpIpv6 = i == 0 || mode != "old-peer", UdpStun = ["fixture.invalid:3478"], ManagedEgressMbps = paced ? 50 : 0,
            QualityFeedback = feedback && (i == 0 || mode != "old-peer"), StandbyPaths=standby }).ToArray();
        if(diagnostics)foreach(var profile in profiles){profile.PathDiagnostics=true;profile.DiagnosticMbps=1;profile.ManagedEgressMbps=10;}
        if(autoQuality)foreach(var profile in profiles)profile.PathSelection="auto-quality";
        var logs = new ConcurrentQueue<string>();
        var factories = profiles.Select(p => new Inspect(new MeshCandidateFactory(p, "unused", root, [TraversalProfile.UdpDirect], diagnostic: logs.Enqueue) {
            Ipv6AvailableForTest = () => true,
            ResolveTarget = (_, family, _) => Task.FromResult(family == AddressFamily.InterNetworkV6 ? v6.Endpoint : v4.Endpoint),
            RouteCheckForTest = (endpoint, expected, _) => {
                if (!IPAddress.IsLoopback(endpoint.Address) || expected != null && (!IPAddress.IsLoopback(expected) || expected.AddressFamily != endpoint.AddressFamily)) throw new IOException("fixture stays loopback in one address family");
            }
        },timing)).ToArray();
        var adapters = new[] { new Adapter(), new Adapter() }; var states = new SessionStatus?[2]; int legacy = 0;
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(token);
        MeshRuntimeServices Services(int i) => new(mesh => mode == "old-service" ? new OldService(new MeshDiscoveryClient(mesh)) : new MeshDiscoveryClient(mesh), _ => Task.FromResult<IPacketAdapter>(adapters[i]),
            async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new IOException(); },
            _ => { Interlocked.Increment(ref legacy); throw new IOException("fixture has no legacy entry"); },
            (_, _, ct) => Task.Delay(Timeout.Infinite, ct), (_, _, _) => { }, (_, _) => { }, Path.Combine(root, "ipv6-sessions")) {
                Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(factories[i])
            };
        var runners = profiles.Select((p, i) => new MeshRunner(p, logs.Enqueue, s => states[i] = s, _ => { }, _ => { }, Services(i))).ToArray();
        var clock = Stopwatch.StartNew(); var tasks = runners.Select(r => r.Run(stopping.Token)).ToArray(); long connected;
        try {
            while (!states.All(s => s?.Connected == true)) {
                foreach (var task in tasks) if (task.IsCompleted) await task;
                if (clock.Elapsed.TotalSeconds > 55) throw new IOException(string.Join('\n', logs));
                await Task.Delay(20, token);
            }
            connected = clock.ElapsedMilliseconds;
            var family = mode == "ipv6" ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            check(legacy == 0 && factories.All(f => f.Paths.Count == 1 && f.Paths.Single().ActualLocal.AddressFamily == family && f.Paths.Single().ActualRemote.AddressFamily == family), mode + ": production Runner chooses one shared address family without legacy or relay");
            check(states.All(s => s!.Degraded), mode + ": UDP is still reported as fallback, not verified streaming quality");
            check(mode == "ipv6-unreachable" ? factories.All(f => f.Gathers == 2) && v6.Count > 0 && v4.Count > 0 : factories.All(f => f.Gathers == 1), mode + ": address-family scheduling preserves the existing per-pair round budget");
            if (mode.StartsWith("old-")) check(v6.Count == 0, mode + ": missing capability prevents even IPv6 reflection traffic");
            adapters[0].Outgoing.Add(Packet(a.LocalIp, b.LocalIp)); adapters[1].Outgoing.Add(Packet(b.LocalIp, a.LocalIp));
            while (adapters.Any(x => x.Incoming.Count == 0)) await Task.Delay(20, token);
            check(adapters[0].Incoming.Single().SequenceEqual(Packet(b.LocalIp, a.LocalIp)) && adapters[1].Incoming.Single().SequenceEqual(Packet(a.LocalIp, b.LocalIp)), mode + ": formal MeshRunner/MeshLink delivers full 1280-byte inner IPv4 in both directions");
            using (var reporting = CancellationTokenSource.CreateLinkedTokenSource(token)) {
                reporting.CancelAfter(3000);
                while (!states.All(s => s?.Peers?.Single().Traffic?.Current is { AcceptedSendBytes: 1280, DeliveredReceiveBytes: 1280 })) await Task.Delay(10, reporting.Token);
            }
            check(states.All(s => s!.Peers!.Single().Traffic is { Qualification: "QualityUnknown", SendLossPercent: null, PeerDeliveredSendBytes: null, OneWayDelayMs: null }),
                mode + ": actual formal UDP status exposes directional application IP counters while absent remote quality evidence stays unknown");
            if (paced) check(factories.All(f => f.Egress is { SentBytes: > 0, Failure: "" } && f.Egress.Peers.Length == 1) && states.All(s => s?.Egress?.Mbps == 50), mode + ": same-socket UDP pacing reports actual outer bytes through formal Runner");
            if (paced) check(factories.All(f => f.Egress!.RateScope == "WholeDevice" &&
                f.Egress.Outlets.Any(o => o.Outlet.StartsWith("WindowsInterface:") && o.SentBytes > 0) &&
                f.Egress.Outlets.Sum(o => o.SentBytes) == f.Egress.SentBytes),
                mode + ": same retained UDP resource queues on actual Windows route outlet");
            if (paced) check(states.All(s => s!.Peers!.Where(p => p.Connected).All(p => p.SendQueue is { Owner: "SharedEgress", ByteUnit: "OuterIpBytes", Accounting.Conserved: true })) &&
                factories.All(f => f.Egress?.Accounting?.Conserved == true), mode + ": formal Runner exposes the same sole UDP egress queue and conserved local outcomes");
            if (feedback) await DeliveryRunnerChecks.Run(states, !mode.StartsWith("old-"), "UDP/" + mode, check, token);
            if(diagnostics&&interruptBusy){
                long due=clock.ElapsedMilliseconds+60000;
                while(!states.Any(s=>s?.Peers?.Single().Diagnostics is{State:"Sending"})){
                    if(clock.ElapsedMilliseconds>due)throw new TimeoutException("busy case diagnostic did not start");await Task.Delay(20,token);
                }
                adapters[0].Outgoing.Add(Packet(a.LocalIp,b.LocalIp));due=clock.ElapsedMilliseconds+12000;
                while(!states.All(s=>s?.Peers?.Single().Diagnostics is{State:"Cancelled"})){
                    if(clock.ElapsedMilliseconds>due)throw new TimeoutException("busy diagnostic did not cancel: "+string.Join('\n',states.Select(s=>System.Text.Json.JsonSerializer.Serialize(s?.Peers?.Single().Diagnostics))));await Task.Delay(20,token);
                }
                check(states.All(s=>s!.Peers!.Single().Diagnostics!.Cost.Active==false),"actual business arrival cancels both negotiated diagnostics and revokes their machine permits");
                check(adapters[1].Incoming.Count==2&&states.All(s=>s?.Connected==true),"busy abort preserves real application delivery on original Active instead of replacing it");
                check(factories.All(f=>f.Paths.Count==2),"busy diagnostic abort neither recreates socket resources nor starts a new candidate");
            }
            else if(diagnostics){
                long due=clock.ElapsedMilliseconds+145000;
                while(!states.All(s=>s?.Peers?.Single().Diagnostics is{State:"Done"})){
                    foreach(var task in tasks)if(task.IsCompleted)await task;
                    if(states.Any(s=>s?.Peers?.Single().Diagnostics is{State:"Cancelled"}failed))throw new IOException("formal diagnostic cancelled: "+string.Join('\n',states.Select(s=>System.Text.Json.JsonSerializer.Serialize(s?.Peers?.Single().Diagnostics))));
                    if(clock.ElapsedMilliseconds>due)throw new TimeoutException("formal diagnostic exchange: "+string.Join('\n',logs));await Task.Delay(50,token);
                }
                check(states.All(s=>s!.Peers!.Single().Diagnostics!.Windows.Length==12),"formal Router exchanges all twelve active/standby directional windows and both peers agree on completion");
                check(states.All(s=>s!.Peers!.Single().Diagnostics!.Windows.All(w=>w.TargetMbps==1&&w.Receipt.Result=="ReportedAtCutoff"&&w.Source.Accepted>0)),
                    "real same-socket production diagnostic reports match the configured low-impact test target without fabricated no-data capacity");
                if(autoQuality){
                    while(!states.All(s=>s?.Peers?.Single().Quality!=null))await Task.Delay(20,token);
                    if(!states.All(s=>s!.Peers!.Single().Quality is{CandidateQualified:true,StableBenefit:false}))
                        throw new IOException("UDP quality evidence: "+System.Text.Json.JsonSerializer.Serialize(states.Select(s=>s?.Peers?.Single())));
                    check(true,"formal UDP quality evaluates complete real windows and retains equally qualified actual socket paths");
                    check(states.Select(s=>s!.Peers!.Single().Quality!.EvidenceDigest).Distinct().Count()==1,
                        "formal separate UDP peers produce identical canonical comparison digests from real exchanged reports");
                }
                check(adapters.All(x=>x.Incoming.Count==1)&&states.All(s=>s?.Connected==true),"formal diagnostics never write synthetic payloads to the virtual IP adapter and preserve Active");
                adapters[0].Outgoing.Add(Packet(a.LocalIp,b.LocalIp));while(adapters[1].Incoming.Count<2)await Task.Delay(10,token);
                check(states.All(s=>s?.Connected==true),"ordinary business continues after negotiated diagnostic completion");
            }
            else if(standby){
                long due=clock.ElapsedMilliseconds+45000;
                while(!states.All(s=>s?.Peers?.Single().Standby is{Ready:true,BidirectionalFresh:true})){
                    foreach(var task in tasks)if(task.IsCompleted)await task;
                    if(clock.ElapsedMilliseconds>due)throw new TimeoutException("formal UDP standby: "+string.Join('\n',logs));await Task.Delay(20,token);
                }
                check(factories.All(f=>f.Paths.Count==2&&f.Paths.Select(p=>p.LeaseId).Distinct().Count()==2&&f.Paths.Select(p=>p.ActualLocal.ToString()).Distinct().Count()==2),
                    "formal UDP standby keeps two distinct winning socket resources and actual endpoints");
                await Task.Delay(8500,token);
                adapters[0].Outgoing.Add(Packet(a.LocalIp,b.LocalIp));adapters[1].Outgoing.Add(Packet(b.LocalIp,a.LocalIp));
                due=clock.ElapsedMilliseconds+4000;
                while(adapters.Any(x=>x.Incoming.Count<2)){if(clock.ElapsedMilliseconds>due)throw new TimeoutException("UDP Active interrupted");await Task.Delay(10,token);}
                check(states.All(s=>s?.Connected==true&&s.Peers?.Single().Standby is{Ready:true,BidirectionalFresh:true,Qualification:"QualityUnknown"}),
                    "after its original checking deadline formal UDP standby retains the exact socket and original Active delivers full packets");
                await factories[0].Transports.Last().DisposeAsync();
                due=clock.ElapsedMilliseconds+12000;
                while(!logs.Any(l=>l.Contains("备用已结束"))){if(clock.ElapsedMilliseconds>due)throw new TimeoutException("UDP standby did not cancel");await Task.Delay(20,token);}
                adapters[0].Outgoing.Add(Packet(a.LocalIp,b.LocalIp));adapters[1].Outgoing.Add(Packet(b.LocalIp,a.LocalIp));
                due=clock.ElapsedMilliseconds+4000;
                while(adapters.Any(x=>x.Incoming.Count<3)){if(clock.ElapsedMilliseconds>due)throw new TimeoutException("UDP Active lost after standby cleanup");await Task.Delay(10,token);}
                check(states.All(s=>s?.Connected==true)&&factories.All(f=>!f.Transports.First().Failed),"formal UDP standby cancellation leaves the original same-socket Active references intact");
            }
        } finally {
            stopping.Cancel(); foreach (var task in tasks) try { await task.WaitAsync(TimeSpan.FromSeconds(10)); } catch (OperationCanceledException) { }
        }
        check(adapters.All(x => x.Disposed), mode + ": Runner stops and joins its adapters and candidate paths");
        if (paced) check(factories.All(f => f.Egress?.QueuedBytes == 0), mode + ": UDP pacing drains cancelled resources at shutdown");
        if (paced) check(factories.All(f => f.Egress?.Accounting is { Conserved: true, Queued.Packets: 0, InFlight.Packets: 0 }), mode + ": final formal UDP egress ledger has no unclassified accepted datagrams");
        return new { mode, connectedMs = connected, elapsedMs = clock.ElapsedMilliseconds, paths = factories.Select(f => f.Paths.Select(p => new { p.LeaseId, local = p.ActualLocal.ToString(), remote = p.ActualRemote.ToString() })).ToArray(), egress = factories.Select(f => f.Egress).ToArray(),diagnostics=states.Select(s=>s?.Peers?.Single().Diagnostics).ToArray(),quality=states.Select(s=>s?.Peers?.Single().Quality).ToArray(),scope="formal production UDP Runner, real HTTPS and same Windows IPv6 loopback sockets; memory IP adapter, no physical WAN, Wintun or streaming deadline" };
    }
    sealed class Inspect(MeshCandidateFactory inner,bool timing=false) : IMeshCandidateFactory, IAsyncDisposable
    {
        public readonly ConcurrentQueue<ValidatedPathIdentity> Paths = []; public int Gathers;
        public readonly ConcurrentQueue<IMeshDatagramPath> Transports=[];
        public TraversalProfile[] Profiles => inner.Profiles; public bool SupportsUdpIpv6 => inner.SupportsUdpIpv6;
        public EgressStats? Egress => inner.Egress;
        public bool SupportsQualityFeedback => inner.SupportsQualityFeedback;
        public bool SupportsStandbyPaths => inner.SupportsStandbyPaths;
        public bool SupportsPathDiagnostics=>inner.SupportsPathDiagnostics;
        public bool SupportsAutoQuality=>inner.SupportsAutoQuality;
        public bool SupportsDiagnosticTiming=>timing&&inner.SupportsDiagnosticTiming;
        public int DiagnosticMbps=>inner.DiagnosticMbps;
        public bool SupportsStandbyProfile(TraversalProfile p)=>inner.SupportsStandbyProfile(p);
        public async Task<IMeshCandidateResource> GatherStandby(MeshMember p,TraversalProfile k,Guid a,bool allow,MeshTraversalCandidate? remote,CancellationToken t)
        {Interlocked.Increment(ref Gathers);return new Resource(await inner.GatherStandby(p,k,a,allow,remote,t),this);}
        public Task<IMeshCandidateResource> Gather(MeshMember p, TraversalProfile k, Guid a, CancellationToken t) => GatherForPeer(p, k, a, false, null, 1, t);
        public async Task<IMeshCandidateResource> GatherForPeer(MeshMember p, TraversalProfile k, Guid a, bool allow, IPEndPoint? remote, int round, CancellationToken t)
        { Interlocked.Increment(ref Gathers); return new Resource(await inner.GatherForPeer(p, k, a, allow, remote, round, t), this); }
        sealed class Resource(IMeshCandidateResource inner, Inspect owner) : IMeshCandidateResource
        {
            public MeshTraversalCandidate Candidate => inner.Candidate;
            public async Task<IPreparedMeshPath> Prepare(TraversalAttemptContext c, IPEndPoint r, CancellationToken t) => new Prepared(await inner.Prepare(c, r, t), owner);
            public ValueTask DisposeAsync() => inner.DisposeAsync();
        }
        sealed class Prepared(IPreparedMeshPath inner, Inspect owner) : IPreparedMeshPath
        {
            public TraversalAttemptContext Context => inner.Context; public bool Armed => inner.Armed; public TimeSpan RemainingAttemptTime => inner.RemainingAttemptTime;
            public async Task<IMeshDatagramPath> Activate(CancellationToken t) { var path = await inner.Activate(t); owner.Paths.Enqueue(path.Identity);owner.Transports.Enqueue(path); return path; }
            public ValueTask DisposeAsync() => inner.DisposeAsync();
        }
        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }
    // Simulates the absence of the new coordinator field, using actual HTTPS
    // for the unchanged control API. This is not an old binary compatibility run.
    sealed class OldService(MeshDiscoveryClient inner) : IMeshDiscovery, IMeshChangeDiscovery, IMeshTraversalDiscovery
    {
        public Guid BootId => inner.BootId; public bool SupportsTraversal => inner.SupportsTraversal; public bool SupportsUdpIpv6 => false;
        public bool SupportsLongPolling => inner.SupportsLongPolling;
        public Task SaveDirectory(MeshDirectory d, CancellationToken t) => inner.SaveDirectory(d, t);
        public Task Publish(MeshAnnouncement a, CancellationToken t) => inner.Publish(a, t);
        public Task<MeshSnapshot?> Read(CancellationToken t) => inner.Read(t);
        public Task<MeshSnapshot?> WaitForChanges(CancellationToken t) => inner.WaitForChanges(t);
        public Task PublishTraversal(MeshTraversalMessage[] m, CancellationToken t) => inner.PublishTraversal(m, t);
        public void Dispose() => inner.Dispose();
    }
    static byte[] Packet(string from, string to)
    {
        byte[] p = new byte[1280]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), 1280);
        IPAddress.Parse(from).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(p, 16);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
    }
    sealed class Adapter : IPacketAdapter
    {
        public readonly BlockingCollection<byte[]> Outgoing = new(); public readonly ConcurrentQueue<byte[]> Incoming = new(); public bool Disposed;
        public int Read(byte[] p) { if (!Outgoing.TryTake(out var b, 25)) return 0; b.CopyTo(p, 0); return b.Length; }
        public bool Write(byte[] p) { Incoming.Enqueue(p); return true; }
        public void Dispose() { Disposed = true; Outgoing.Dispose(); }
    }
    internal sealed class Reflector : IAsyncDisposable
    {
        readonly UdpClient udp, blackhole; readonly CancellationTokenSource stop = new(); readonly Task run;
        public bool BlackholeMappings; public int Count;
        public IPEndPoint Endpoint => (IPEndPoint)udp.Client.LocalEndPoint!;
        public Reflector(AddressFamily family)
        {
            var ip = family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
            udp = new(new IPEndPoint(ip, 0)); blackhole = new(new IPEndPoint(ip, 0)); run = Run();
        }
        async Task Run() { try { while (true) {
            var p = await udp.ReceiveAsync(stop.Token); if (p.Buffer.Length != 20) continue; Interlocked.Increment(ref Count);
            var mapped = BlackholeMappings ? (IPEndPoint)blackhole.Client.LocalEndPoint! : p.RemoteEndPoint;
            var bytes = mapped.Address.GetAddressBytes(); byte[] reply = new byte[28 + bytes.Length]; p.Buffer.CopyTo(reply, 0); reply[0] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(2), (ushort)(reply.Length - 20)); reply[21] = 0x20; reply[23] = (byte)(4 + bytes.Length); reply[25] = bytes.Length == 16 ? (byte)2 : (byte)1;
            BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(26), (ushort)(mapped.Port ^ 0x2112));
            for (int i = 0; i < bytes.Length; i++) reply[28 + i] = (byte)(bytes[i] ^ p.Buffer[4 + i]);
            // Wrong transaction from the right source must not complete Observe.
            var wrong = reply.ToArray(); wrong[8] ^= 1; await udp.SendAsync(wrong, p.RemoteEndPoint, stop.Token);
            await udp.SendAsync(reply, p.RemoteEndPoint, stop.Token);
        } } catch (OperationCanceledException) when (stop.IsCancellationRequested) { } }
        public async ValueTask DisposeAsync() { stop.Cancel(); await run; udp.Dispose(); blackhole.Dispose(); stop.Dispose(); }
    }
}
