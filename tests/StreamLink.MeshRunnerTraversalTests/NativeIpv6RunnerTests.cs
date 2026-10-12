using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

static class NativeIpv6RunnerTests
{
    public static Task<object> RunDiagnostics(string binary,string root,string url,string pin,Action<bool,string> check,CancellationToken token)=>
        Pair(binary,root,url,pin,"ipv6",check,token,false,false,true,true);
    public static Task<object> RunQuality(string binary,string root,string url,string pin,string qualityMode,Action<bool,string> check,CancellationToken token)=>
        Pair(binary,root,url,pin,"ipv6",check,token,false,false,true,true,qualityMode);
    public static Task<object> RunRelativeQuality(string binary,string root,string url,string pin,Action<bool,string> check,CancellationToken token)=>
        Pair(binary,root,url,pin,"ipv6",check,token,false,false,true,true,"benefit",timing:true);
    public static async Task<object> Run(string binary, string root, string url, string pin, Action<bool, string> check, CancellationToken token, bool paced = false, bool feedback = false)
    {
        CaptureFilterTests.Run(Path.Combine(Path.GetDirectoryName(binary)!, "..", "downloads", "WinDivert-2.2.2-A", "x64", "WinDivert.dll"), check);
        await Contract(check);
        var rows = new List<object>();
        foreach (string mode in new[] { "ipv6", "ipv6-unreachable", "old-native-abi", "old-service" }) rows.Add(await Pair(binary, root, url, pin, mode, check, token, paced, feedback));
        return new { rows, actualNative = true, realTcpHelpers = true, realHttps = true, rawCaptureSimulated = true, realWinDivertIo = false, realNat = false, wintun = false };
    }
    public static async Task<object> RunStandby(string binary,string root,string url,string pin,Action<bool,string> check,CancellationToken token)
    {
        var rows=new List<object>();
        foreach(string mode in new[]{"ipv6","standby-old-peer","standby-old-service"})rows.Add(await Pair(binary,root,url,pin,mode,check,token,false,false,true));
        return new{rows,actualNative=true,realTcpHelpers=true,realHttps=true,rawCaptureSimulated=true,realWinDivertIo=false,realNat=false,wintun=false};
    }
    static async Task Contract(Action<bool, string> check)
    {
        var a = MeshIdentity.Create("https://localhost", "", "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var ca = new MeshTraversalCapabilities(1, 1, Guid.NewGuid(), [TraversalProfile.FakeTcpHttpSo, TraversalProfile.UdpDirect], UdpIpv6: 1, FakeTcpIpv6: 1);
        var cb = ca with { BootId = Guid.NewGuid() }; long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), seq = 0;
        var c = new MeshTraversalCandidate(Guid.NewGuid(), 1, "[::1]:40001", "[::1]:3478", now, now + 120, CandidatePurpose.SimultaneousOpen);
        await using var offer = MeshTraversalAttempt.Offer(a, b.Self, ca, cb, TraversalProfile.FakeTcpHttpSo, c, 1, () => ++seq);
        MeshTraversalAttempt.ValidateOffer(b, a.Self, cb, ca, offer.Outbound!);
        check(true, "FakeTCP IPv6 candidate is covered by authenticated bilateral capability negotiation");
        bool rejected = false; try { MeshTraversalAttempt.ValidateOffer(b, a.Self, cb with { FakeTcpIpv6 = 0 }, ca, offer.Outbound!); } catch (CryptographicException) { rejected = true; }
        check(rejected, "UDP IPv6 capability cannot authorize a FakeTCP IPv6 Offer");
        check(!new DeviceProfile().FakeTcpIpv6, "FakeTCP IPv6 remains disabled in default/existing device profiles");
    }
    static async Task<object> Pair(string binary, string root, string url, string pin, string mode, Action<bool, string> check, CancellationToken token, bool paced, bool feedback, bool standby=false,bool diagnostics=false,string qualityMode="",bool timing=false)
    {
        await using var v4 = new Reflector(); await using var v6 = new Reflector(new(IPAddress.IPv6Loopback, 0));
        var a = MeshIdentity.Create(url, pin, "faketcp"); var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var profiles = new[] { a, b }.Select(m => new DeviceProfile { Mesh = m, TraversalMode = "tcp", PathSelection = "faketcp-only", FakeTcpIpv6 = true, TcpStun = ["fixture.invalid:3478"], ManagedEgressMbps = paced ? 50 : 0, QualityFeedback = feedback }).ToArray();
        for(int i=0;i<profiles.Length;i++)profiles[i].StandbyPaths=standby&&(i==0||mode!="standby-old-peer");
        if(diagnostics)foreach(var profile in profiles){profile.PathDiagnostics=true;profile.DiagnosticMbps=1;profile.ManagedEgressMbps=10;}
        if(qualityMode.Length>0)foreach(var profile in profiles)profile.PathSelection="auto-quality";
        var wire = new Wire(mode == "ipv6-unreachable"); var logs = new ConcurrentQueue<string>();
        var factories = profiles.Select((p, i) => new Inspect(new MeshCandidateFactory(p, binary, root, [TraversalProfile.FakeTcpHttpSo], captureBroker: true,
            diagnostic: logs.Enqueue, ipv6Native: mode != "old-native-abi" || i == 0, wireControl: true,diagnosticNative:diagnostics) {
            Ipv6AvailableForTest = () => true,
            ResolveTarget = (_, family, _) => Task.FromResult(family == AddressFamily.InterNetworkV6 ? v6.Endpoint : v4.Endpoint),
            OpenCaptureForTest = (local, _) => wire.Open(local),
            RouteCheckForTest = (remote, expected, _) => {
                if (!IPAddress.IsLoopback(remote.Address) || expected != null && (!IPAddress.IsLoopback(expected) || expected.AddressFamily != remote.AddressFamily)) throw new IOException("fixture remains family-matched loopback");
            }
        },timing)).ToArray();
        var adapters = new[] { new Adapter(), new Adapter() }; var states = new SessionStatus?[2];
        using var running = CancellationTokenSource.CreateLinkedTokenSource(token); int legacy = 0;
        MeshRuntimeServices Services(int i) => new(m => mode == "old-service" || mode=="standby-old-service" ? new OldService(new MeshDiscoveryClient(m),mode=="standby-old-service") : new MeshDiscoveryClient(m),
            _ => Task.FromResult<IPacketAdapter>(adapters[i]), async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new IOException(); },
            _ => { Interlocked.Increment(ref legacy); throw new IOException("no legacy entry"); }, (_, _, ct) => Task.Delay(Timeout.Infinite, ct), (_, _, _) => { }, (_, _) => { }, Path.Combine(root, "native-ipv6")) {
                Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(factories[i])
            };
        var clock = Stopwatch.StartNew(); long connected;
        object? recovery=null;int controlledDrops=0;
        var tasks = profiles.Select((p, i) => new MeshRunner(p, logs.Enqueue, s => states[i] = s, _ => { }, _ => { }, Services(i)).Run(running.Token)).ToArray();
        try {
            while (!states.All(s => s?.Connected == true)) {
                foreach (var task in tasks) if (task.IsCompleted) await task;
                if (clock.Elapsed.TotalSeconds > 55) throw new TimeoutException(string.Join('\n', logs));
                await Task.Delay(20, token);
            }
            connected = clock.ElapsedMilliseconds;
            var family = mode == "ipv6" || mode.StartsWith("standby-") ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            check(legacy == 0 && factories.All(f => f.Paths.Count == 1 && f.Paths.Single().ActualLocal.AddressFamily == family && f.Paths.Single().ActualRemote.AddressFamily == family), mode + ": actual production candidate factory and Runner agree on the FakeTCP address family");
            check(states.All(s => s!.Degraded == false) && factories.All(f => f.Paths.Single().Profile == TraversalProfile.FakeTcpHttpSo), mode + ": only FakeTCP policy never substitutes UDP or relay");
            check(mode == "ipv6-unreachable" ? factories.All(f => f.Gathers == 2) && v6.Accepted == 2 && v4.Accepted == 2 : factories.All(f => f.Gathers == 1), mode + ": automatic fallback uses the second existing TCP round");
            if (mode.StartsWith("old-")) check(v6.Accepted == 0, mode + ": missing ABI/server capability prevents IPv6 helper allocation");
            adapters[0].Outgoing.Add(Packet(a.LocalIp, b.LocalIp)); adapters[1].Outgoing.Add(Packet(b.LocalIp, a.LocalIp));
            while (adapters.Any(x => x.Incoming.Count == 0)) await Task.Delay(20, token);
            check(adapters[0].Incoming.Single().SequenceEqual(Packet(b.LocalIp, a.LocalIp)) && adapters[1].Incoming.Single().SequenceEqual(Packet(a.LocalIp, b.LocalIp)), mode + ": authenticated MeshLink transports full inner IPv4 through actual native workers in both directions");
            using (var reporting = CancellationTokenSource.CreateLinkedTokenSource(token)) {
                reporting.CancelAfter(3000);
                while (!states.All(s => s?.Peers?.Single().Traffic?.Current is { AcceptedSendBytes: 1280, DeliveredReceiveBytes: 1280 })) await Task.Delay(10, reporting.Token);
            }
            check(states.All(s => s!.Peers!.Single().Traffic is { Qualification: "QualityUnknown", SendLossPercent: null, PeerDeliveredSendBytes: null, OneWayDelayMs: null }),
                mode + ": formal native Runner exposes actual directional IP observations without inventing peer receipt or loss");
            check(wire.Packets > 0 && wire.MaximumBytes >= 1392, mode + ": native serialized packet length is measured separately from UDP framing");
            check(factories.All(f => f.Transports.Single().WireControl is { Selected: true, HandshakePackets: > 0, BusinessPackets: > 0 }), mode + ": formal factory enables native wire accounting and only selected business bypasses control limits");
            if (paced) check(factories.All(f => f.Egress is { SentBytes: > 0, Failure: "" } && f.Egress.Peers.Length == 1) && states.All(s => s?.Egress?.Mbps == 50), mode + ": formal native broker uses shared per-member pacing and reports it through Runner status");
            if (feedback) await DeliveryRunnerChecks.Run(states, mode != "old-service", "native/" + mode, check, token);
            if(qualityMode=="benefit"){
                var original=factories[0].Paths.First().ActualLocal;
                wire.DropFrame=(source,bytes)=>source.Equals(original)&&bytes>=1300&&Interlocked.Increment(ref controlledDrops)%4==0;
            }
            if(diagnostics){
                long due=clock.ElapsedMilliseconds+145000;
                while(!states.All(s=>s?.Peers?.Single().Diagnostics is{State:"Done"})){
                    foreach(var task in tasks)if(task.IsCompleted)await task;
                    if(states.Any(s=>s?.Peers?.Single().Diagnostics is{State:"Cancelled"}))throw new IOException("native formal diagnostic cancelled: "+string.Join('\n',states.Select(s=>System.Text.Json.JsonSerializer.Serialize(s?.Peers?.Single().Diagnostics))));
                    if(clock.ElapsedMilliseconds>due)throw new TimeoutException("native formal diagnostic exchange: "+string.Join('\n',logs));await Task.Delay(50,token);
                }
                check(states.All(s=>s!.Peers!.Single().Diagnostics!.Windows.Length==12),"formal native Router completes twelve authenticated directional active/standby windows");
                if(qualityMode.Length>0){
                    while(!states.All(s=>s?.Peers?.Single().Quality!=null))await Task.Delay(20,token);
                    if(!states.All(s=>s!.Peers!.Single().Quality!.CandidateQualified))
                        throw new IOException("native quality evidence: "+System.Text.Json.JsonSerializer.Serialize(states.Select(s=>s?.Peers?.Single())));
                    check(true,"formal native comparison qualifies candidate from actual final injection, receiver cutoff and loaded RTT evidence");
                    check(states.Select(s=>s!.Peers!.Single().Quality!.EvidenceDigest).Distinct().Count()==1,"both native peers agree on exact comparison digest despite local resource and clock differences");
                    long failureAt=clock.ElapsedMilliseconds;
                    if(qualityMode=="hard-failure"){
                        check(states.All(s=>s!.Peers!.Single().Quality!.StableBenefit==false),"equally good native paths do not switch before a hard worker fault");
                        long expires=states.Max(s=>s!.Peers!.Single().Diagnostics!.Windows.Where(w=>w.Leg%6<3).Min(w=>w.ObservedMs))+90000+750;
                        int wait=(int)Math.Max(0,expires-Environment.TickCount64);
                        if(wait>30000)throw new IOException("unexpected diagnostic timing; cannot borrow extra standby lifetime");
                        await Task.Delay(wait,token);
                        using(var reporting=CancellationTokenSource.CreateLinkedTokenSource(token)){
                            reporting.CancelAfter(2000);
                            while(!states.All(s=>s!.Peers!.Single().Quality!.Reason.StartsWith("ActiveEvidenceUnavailable:ExpiredObservation",StringComparison.Ordinal)))
                                await Task.Delay(20,reporting.Token);
                        }
                        check(states.All(s=>s!.Peers!.Single().Quality is{CandidateQualified:true,StableBenefit:false}&&s.Peers!.Single().Quality!.Reason.StartsWith("ActiveEvidenceUnavailable:ExpiredObservation",StringComparison.Ordinal)),
                            "older Active windows expire without discarding the still-fresh retained candidate or authorizing a healthy-path switch");
                        failureAt=clock.ElapsedMilliseconds;
                        using var worker=Process.GetProcessById(factories[0].Transports.First().ProcessId);worker.Kill();
                    }
                    long switchDeadline=clock.ElapsedMilliseconds+8000;
                    while(!factories.All(f=>f.Transports.Last().WireControl is{Selected:true})){
                        foreach(var task in tasks)if(task.IsCompleted)await task;
                        if(clock.ElapsedMilliseconds>switchDeadline)throw new TimeoutException("native quality selection did not converge: "+string.Join('\n',logs)+System.Text.Json.JsonSerializer.Serialize(states));
                        await Task.Delay(20,token);
                    }
                    check(factories.All(f=>f.Transports.Count==2),"formal quality selection reuses the already-qualified native tuple without a new capture/helper or ISS");
                    if(qualityMode=="benefit")check(controlledDrops>0,"selection responds to measured controlled old-path ingress loss, not idle RTT or manual policy approval");
                    var observed=new List<long>();
                    for(int probe=0;probe<11;probe++){
                        int expected=adapters[1].Incoming.Count+1;adapters[0].Outgoing.Add(Packet(a.LocalIp,b.LocalIp));
                        using var delivery=CancellationTokenSource.CreateLinkedTokenSource(token);delivery.CancelAfter(1500);
                        while(adapters[1].Incoming.Count<expected)await Task.Delay(10,delivery.Token);
                        observed.Add(clock.ElapsedMilliseconds);await Task.Delay(300,token);
                    }
                    recovery=new{trigger=qualityMode=="hard-failure"?"NativeWorkerKilled":"DiagnosticComparisonCompleted",triggerAtMs=failureAt,firstBusinessMs=observed[0],stableBusinessStartMs=observed[0],stableBusinessConfirmedMs=observed.Last(),continuousProbeCount=observed.Count,
                        elapsedToStableStartMs=observed[0]-failureAt,scope="measured delivery of full IP packets on memory adapter after actual native common nomination; no physical WAN or application playback"};
                    check(factories[0].Transports.Last().WireControl is{Selected:true,BusinessPackets:>=11},"complete business IP uses the newly selected retained C++ transport");
                }else{
                check(factories.All(f=>f.Transports.Count==2&&f.Transports.Last().WireControl is{Standby:true,Selected:false,BusinessPackets:0,DiagnosticPackets:>0}),
                    "formal native standby sends diagnostic labels under exact resource grant without gaining ordinary business permission");
                check(adapters.All(x=>x.Incoming.Count==1)&&states.All(s=>s?.Connected==true),"native formal measurement leaves original virtual IP path active and never writes synthetic samples to adapter");
                adapters[0].Outgoing.Add(Packet(a.LocalIp,b.LocalIp));while(adapters[1].Incoming.Count<2)await Task.Delay(10,token);
                check(factories[0].Transports.First().WireControl is{BusinessPackets:>0,Selected:true},"native original Active resumes ordinary business after the comparison transaction");
                }
            }
            else if (standby) {
                if (mode=="ipv6") {
                    long due=clock.ElapsedMilliseconds+45000;
                    while(!factories.All(f=>f.Transports.Count==2&&f.Transports.Last().WireControl is{Standby:true,Selected:false})){
                        foreach(var task in tasks)if(task.IsCompleted)await task;
                        if(clock.ElapsedMilliseconds>due)throw new TimeoutException("standby preparation failed: "+string.Join('\n',logs));
                        await Task.Delay(20,token);
                    }
                    check(factories.All(f=>f.Paths.Select(p=>p.ActualLocal.ToString()).Distinct().Count()==2&&f.Paths.Select(p=>p.LeaseId).Distinct().Count()==2),
                        "formal native standby uses a different retained source and TCP tuple, never a second SEQ state on Active");
                    await Task.Delay(8500,token);
                    adapters[0].Outgoing.Add(Packet(a.LocalIp,b.LocalIp));adapters[1].Outgoing.Add(Packet(b.LocalIp,a.LocalIp));
                    due=clock.ElapsedMilliseconds+4000;
                    while(adapters.Any(x=>x.Incoming.Count<2)){if(clock.ElapsedMilliseconds>due)throw new TimeoutException("Active interrupted by retained standby");await Task.Delay(10,token);}
                    check(factories.All(f=>f.Transports.Last().WireControl is{Standby:true,Selected:false,BusinessPackets:0,MaintenancePackets:>0})&&states.All(s=>s?.Connected==true),
                        "past the original native eight-second deadline only old Active carries full business; standby remains maintenance-only");
                    await factories[0].Transports.Last().DisposeAsync();
                    due=clock.ElapsedMilliseconds+12000;
                    while(!logs.Any(l=>l.Contains("备用已结束"))){if(clock.ElapsedMilliseconds>due)throw new TimeoutException("failed standby was not cancelled");await Task.Delay(20,token);}
                    adapters[0].Outgoing.Add(Packet(a.LocalIp,b.LocalIp));adapters[1].Outgoing.Add(Packet(b.LocalIp,a.LocalIp));
                    due=clock.ElapsedMilliseconds+4000;
                    while(adapters.Any(x=>x.Incoming.Count<3)){if(clock.ElapsedMilliseconds>due)throw new TimeoutException("Active lost after standby failure");await Task.Delay(10,token);}
                    check(factories.All(f=>f.Transports.First().WireControl is{Selected:true,BusinessPackets:>0})&&states.All(s=>s?.Connected==true),
                        "native standby process/path failure cancels only that candidate and retains both original authenticated Active owners");
                }else{
                    await Task.Delay(TraversalLimits.UpgradeResidenceMs+1500,token);
                    check(factories.All(f=>f.Gathers==1&&f.Paths.Count==1),mode+": missing peer/server standby permission prevents a second actual helper/capture allocation");
                }
            }
        } finally {
            running.Cancel(); foreach (var task in tasks) try { await task.WaitAsync(TimeSpan.FromSeconds(10)); } catch (OperationCanceledException) { }
        }
        check(wire.Endpoints.Values.All(io => io.Closed) && adapters.All(ad => ad.Disposed), mode + ": shutdown joins actual capture/worker owners before resource release");
        if (paced) check(factories.All(f => f.Egress?.QueuedBytes == 0), mode + ": pacing closes without retaining a worker or queued packet");
        if (paced) check(factories.All(f => f.Egress?.Accounting is { Conserved: true, Queued.Packets: 0, InFlight.Packets: 0 }), mode + ": final native broker egress accounts for every local raw submission");
        return new { mode, connectedMs = connected, elapsedMs = clock.ElapsedMilliseconds, wire.Packets, wire.MaximumBytes,
            paths = factories.Select(f => f.Paths.Select(p => new { p.LeaseId, p.AttachId, local = p.ActualLocal.ToString(), remote = p.ActualRemote.ToString() })).ToArray(),
            wireControl = factories.Select(f => f.Transports.Select(p => p.WireControl)).ToArray(), egress = factories.Select(f => f.Egress).ToArray(),diagnostics=states.Select(s=>s?.Peers?.Single().Diagnostics).ToArray(),
            quality=states.Select(s=>s?.Peers?.Single().Quality).ToArray(),qualityMode,controlledDrops,recovery,
            scope="formal Runner/Factory/Actor/native C++, real HTTPS and Windows TCP helpers/pipes; raw IP and virtual IP memory fixtures, no physical NAT/WinDivert/Wintun or WAN guarantee" };
    }
    internal sealed class Inspect(MeshCandidateFactory inner,bool timing=false) : IMeshCandidateFactory, IAsyncDisposable
    {
        public bool PollNetworkChange() => inner.PollNetworkChange();
        public int Gathers; public readonly ConcurrentQueue<ValidatedPathIdentity> Paths = [];
        public readonly ConcurrentQueue<NativeDatagramPath> Transports = [];
        public TraversalProfile[] Profiles => inner.Profiles; public bool SupportsFakeTcpIpv6 => inner.SupportsFakeTcpIpv6;
        public bool SupportsTcpPeerReflexive => inner.SupportsTcpPeerReflexive;
        public bool SupportsUdpExploration => inner.SupportsUdpExploration;
        public bool SupportsQualityFeedback => inner.SupportsQualityFeedback;
        public bool SupportsStandbyPaths => inner.SupportsStandbyPaths;
        public bool SupportsPathDiagnostics=>inner.SupportsPathDiagnostics;
        public bool SupportsAutoQuality=>inner.SupportsAutoQuality;
        public bool SupportsDiagnosticTiming=>timing&&inner.SupportsDiagnosticTiming;
        public int DiagnosticMbps=>inner.DiagnosticMbps;
        public bool SupportsStandbyProfile(TraversalProfile p) => inner.SupportsStandbyProfile(p);
        public async Task<IMeshCandidateResource> GatherStandby(MeshMember peer,TraversalProfile p,Guid attempt,bool v6,MeshTraversalCandidate? remote,CancellationToken t)
        {Interlocked.Increment(ref Gathers);var gathered=await inner.GatherStandby(peer,p,attempt,v6,remote,t);Candidates.Enqueue(gathered.Candidate);return new Resource(gathered,this);}
        public readonly ConcurrentQueue<MeshTraversalCandidate> Candidates = [];
        public EgressStats? Egress => inner.Egress;
        public Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile p, Guid a, CancellationToken t) => GatherForPeer(peer, p, a, false, null, 1, t);
        public async Task<IMeshCandidateResource> GatherForPeer(MeshMember peer, TraversalProfile p, Guid a, bool v6, IPEndPoint? r, int round, CancellationToken t)
        { Interlocked.Increment(ref Gathers); return new Resource(await inner.GatherForPeer(peer, p, a, v6, r, round, t), this); }
        public async Task<IMeshCandidateResource> GatherSourceAware(MeshMember peer, TraversalProfile p, Guid attempt, bool v6, MeshTraversalCandidate? remote,
            int round, bool prediction, bool source, CancellationToken t)
        { Interlocked.Increment(ref Gathers); var gathered = await inner.GatherSourceAware(peer, p, attempt, v6, remote, round, prediction, source, t); Candidates.Enqueue(gathered.Candidate); return new Resource(gathered, this); }
        public async Task<IMeshCandidateResource> GatherEnhanced(MeshMember peer, TraversalProfile p, Guid attempt, bool v6, MeshTraversalCandidate? remote,
            int round, bool prediction, bool source, bool exploration, Func<bool> eligible, CancellationToken t)
        { Interlocked.Increment(ref Gathers); var gathered = await inner.GatherEnhanced(peer, p, attempt, v6, remote, round, prediction, source, exploration, eligible, t); Candidates.Enqueue(gathered.Candidate); return new Resource(gathered, this); }
        sealed class Resource(IMeshCandidateResource inner, Inspect owner) : IMeshCandidateResource {
            public MeshTraversalCandidate Candidate => inner.Candidate;
            public TimeSpan ExplorationRemaining => inner.ExplorationRemaining;
            public object? ExplorationStats => inner.ExplorationStats;
            public async Task<IPreparedMeshPath> PrepareCandidate(TraversalAttemptContext c, MeshTraversalCandidate r, CancellationToken t) => new Prepared(await inner.PrepareCandidate(c, r, t), owner);
            public async Task<IPreparedMeshPath> Prepare(TraversalAttemptContext c, IPEndPoint r, CancellationToken t) => new Prepared(await inner.Prepare(c, r, t), owner);
            public ValueTask DisposeAsync() => inner.DisposeAsync();
        }
        sealed class Prepared(IPreparedMeshPath inner, Inspect owner) : IPreparedMeshPath {
            public TraversalAttemptContext Context => inner.Context; public bool Armed => inner.Armed; public TimeSpan RemainingAttemptTime => inner.RemainingAttemptTime;
            public async Task<IMeshDatagramPath> Activate(CancellationToken t) { var p = await inner.Activate(t); owner.Paths.Enqueue(p.Identity); if (p is NativeDatagramPath native) owner.Transports.Enqueue(native); return p; }
            public ValueTask DisposeAsync() => inner.DisposeAsync();
        }
        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }
    internal sealed class Wire(bool dropIpv6)
    {
        public readonly ConcurrentDictionary<string, Io> Endpoints = []; public int Packets, MaximumBytes;
        public Func<IPEndPoint,int,bool>? DropFrame;
        public Io Open(IPEndPoint endpoint) { var io = new Io(this); if (!Endpoints.TryAdd(endpoint.ToString(), io)) throw new IOException("duplicate capture"); return io; }
        public bool Send(ReadOnlySpan<byte> p) {
            if (!TcpCaptureOwner.Tuple(p, out var source, out var target, true)) throw new IOException("malformed native output");
            Interlocked.Increment(ref Packets); MaximumBytes = Math.Max(MaximumBytes, p.Length);
            if (dropIpv6 && target.AddressFamily == AddressFamily.InterNetworkV6) return true;
            if(DropFrame?.Invoke(source,p.Length)==true)return true;
            return Endpoints.TryGetValue(target.ToString(), out var io) && io.Packets.Writer.TryWrite(new(p.ToArray(), false));
        }
    }
    internal sealed class Io(Wire wire) : IEndpointPacketIo {
        public readonly Channel<EndpointPacket> Packets = Channel.CreateBounded<EndpointPacket>(512); public bool Closed;
        public ValueTask<EndpointPacket> Receive(CancellationToken t) => Packets.Reader.ReadAsync(t);
        public bool Inject(ReadOnlySpan<byte> p) => wire.Send(p);
        public bool Reinject(EndpointPacket p) => true;
        public void Shutdown() => Packets.Writer.TryComplete();
        public void Dispose() { Closed = true; Shutdown(); }
    }
    sealed class OldService(MeshDiscoveryClient inner,bool preserveIpv6=false) : IMeshDiscovery, IMeshChangeDiscovery, IMeshTraversalDiscovery {
        public Guid BootId => inner.BootId; public bool SupportsTraversal => inner.SupportsTraversal; public bool SupportsFakeTcpIpv6 => preserveIpv6&&inner.SupportsFakeTcpIpv6;
        public bool SupportsLongPolling => inner.SupportsLongPolling;
        public Task SaveDirectory(MeshDirectory d, CancellationToken t) => inner.SaveDirectory(d, t);
        public Task Publish(MeshAnnouncement a, CancellationToken t) => inner.Publish(a, t);
        public Task<MeshSnapshot?> Read(CancellationToken t) => inner.Read(t);
        public Task<MeshSnapshot?> WaitForChanges(CancellationToken t) => inner.WaitForChanges(t);
        public Task PublishTraversal(MeshTraversalMessage[] m, CancellationToken t) => inner.PublishTraversal(m, t);
        public void Dispose() => inner.Dispose();
    }
    internal static byte[] Packet(string from, string to) {
        byte[] p = new byte[1280]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), 1280);
        IPAddress.Parse(from).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(p, 16);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
    }
    internal sealed class Adapter : IPacketAdapter {
        public readonly BlockingCollection<byte[]> Outgoing = new(); public readonly ConcurrentQueue<byte[]> Incoming = new(); public bool Disposed;
        public int Read(byte[] p) { if (!Outgoing.TryTake(out var b, 25)) return 0; b.CopyTo(p, 0); return b.Length; }
        public bool Write(byte[] p) { Incoming.Enqueue(p); return true; }
        public void Dispose() { Disposed = true; Outgoing.Dispose(); }
    }
}
