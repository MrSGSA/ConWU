using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

sealed record TraversalNode(DeviceProfile Profile, string Local, string Peer, string Kind, string Route, int SourcePort,
    int ReflectorPort, int PeerReflectorPort, int MeasureDelay, int LifetimeSeconds = 100, bool CaptureBroker = false,
    bool MeasureLoad = true, int ReflectedPortOffset = 0, int PeerSourcePort = 0, bool RequireLearnedSource = false, bool LocalHelper = false,
    int PeerAnnouncedPortOffset = 0, bool ExpectedNoDirectPath = false);

static class TraversalNetwork
{
    const int EchoPort = 47683;
    public static async Task Run(string[] args)
    {
        if (args[0] == "traversal-prepare") {
            if (args.Length != 7) throw new ArgumentException("traversal-prepare folder coordination.json local-ip peer-ip legacy|tcp|udp host|public");
            string root = Path.GetFullPath(args[1]); Directory.CreateDirectory(root);
            using var coordination = JsonDocument.Parse(File.ReadAllText(args[2]));
            var a = MeshIdentity.Create(coordination.RootElement.GetProperty("url").GetString()!, coordination.RootElement.GetProperty("pin").GetString()!, "faketcp");
            var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
            var local = new TraversalNode(new() { Mesh = a, DeviceName = "Isolated-A", TraversalMode = args[5]=="legacy"?"legacy":"tcp-udp", AllowUdpFallback = args[5] == "udp", Enabled = true }, args[3], args[4], args[5], args[6], 44411, 44401, 44402, 2);
            var remote = new TraversalNode(new() { Mesh = b, DeviceName = "Isolated-B", TraversalMode = args[5]=="legacy"?"legacy":"tcp-udp", AllowUdpFallback = args[5] == "udp", Enabled = true }, args[4], args[3], args[5], args[6], 44412, 44402, 44401, 28);
            if(args[5]=="legacy"){local.Profile.ManualEndpoint=args[3]+":44411";local.Profile.ListenPort=44411;remote.Profile.ManualEndpoint=args[4]+":44412";remote.Profile.ListenPort=44412;}
            File.WriteAllText(Path.Combine(root, "local.private.json"), JsonSerializer.Serialize(local));
            File.WriteAllText(Path.Combine(root, "remote.private.json"), JsonSerializer.Serialize(remote));
            Console.WriteLine(JsonSerializer.Serialize(new { localVirtualIp = a.LocalIp, peerVirtualIp = b.LocalIp, localPort = local.SourcePort, peerPort = remote.SourcePort })); return;
        }
        if (args[0] != "traversal-run" || args.Length != 3) throw new ArgumentException("traversal-run node.private.json result.json");
        string file = Path.GetFullPath(args[1]), output = Path.GetFullPath(args[2]), folder = Path.GetDirectoryName(file)!;
        var c = JsonSerializer.Deserialize<TraversalNode>(File.ReadAllText(file))!; c.Profile.Validate();
        if (c.Kind is not ("tcp" or "udp" or "legacy") || c.Route is not ("host" or "public") || c.LifetimeSeconds is < 30 or > 600) throw new ArgumentException("Invalid isolated test scope");
        if (c.ReflectedPortOffset is < 0 or > 16 || c.ReflectedPortOffset != 0 && (c.Kind != "tcp" || c.Route != "host") ||
            c.PeerSourcePort is < 0 or > 65535 || c.PeerAnnouncedPortOffset is<0 or>16 || c.LocalHelper && (c.Kind != "tcp" || c.Route != "host") ||
            c.RequireLearnedSource && (!c.Profile.TcpPeerReflexive || c.Kind != "tcp" || c.Route != "host" || !c.CaptureBroker))
            throw new ArgumentException("Invalid source-learning fixture scope");
        string components = Path.Combine(AppContext.BaseDirectory, "components");
        var mesh = c.Profile.Mesh!; var peer = mesh.Directory!.Members.Single(m => m.Slot != mesh.Self.Slot);
        var kind = c.Kind == "tcp" ? TraversalProfile.FakeTcpHttpSo : TraversalProfile.UdpDirect;
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(c.LifetimeSeconds)); var token = stop.Token;
        await using var reflector = c.Route == "host" && c.Kind == "tcp" ? new Reflector(new(IPAddress.Parse(c.Local), c.ReflectorPort)) {
            Silent = false,
            MapForTest = ep => c.ReflectedPortOffset == 0 ? ep : new(ep.Address, checked(ep.Port + c.ReflectedPortOffset))
        } : null;
        await using var udpReflector = c.Route == "host" && c.Kind == "udp" ? new UdpReflector(new(IPAddress.Parse(c.Local), c.ReflectorPort)) : null;
        var factory = c.Route == "host" && c.Kind!="legacy" ? new HostFactory(c, components, folder) : null;
        SingleProfile? selectedFactory=null;
        SessionStatus? latest = null; var timeline = new List<object>(); QualityResult? quality = null; int echoes = 0;
        long connected = 0; string failure = "", cleanupFailure=""; Exception? originalRunFailure=null; bool adapterCreated = false, controlReady=false, deadlineReached=false; var timer = Stopwatch.StartNew();
        var services = MeshRuntimeServices.Default with {
            SessionRoot = Path.Combine(folder, "sessions"),
            Adapter = async p => { var adapter = await MeshRuntimeServices.Default.Adapter(p); adapterCreated = true; return adapter; },
            Probe = async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new InvalidOperationException(); }, // no UPnP/router changes in this independent test
            Record = (_, _) => { },
            Candidates = async (profile, sessions, log, ct) => c.Kind=="legacy"?null:selectedFactory=new SingleProfile((IMeshCandidateFactory?)factory ??
                await MeshCandidateFactory.Create(profile, Path.Combine(components, "udp2raw-native.exe"), sessions, log, ct) ?? throw new IOException("Capability unavailable"), kind),
            QualityServer = (ip, authorize, ct) => Task.WhenAll(Quality.Serve(ip, authorize, ct), EchoServer(ip, MeshIdentity.Address(mesh.Pair.Network, peer.Slot), ct)),
            QualityWithPolicy = (profile, ip, authorize, ct) => Task.WhenAll(
                Quality.Serve(ip, authorize, ct, new(()=>profile.AllowManualQualityRequests)),
                EchoServer(ip, MeshIdentity.Address(mesh.Pair.Network, peer.Slot), ct))
        };
        var runner = new MeshRunner(c.Profile, s => { Console.WriteLine(s); lock (timeline) timeline.Add(new { elapsedMs = timer.ElapsedMilliseconds, message = s }); }, s => {
            latest = s; if (s.Connected && connected == 0) { connected = timer.ElapsedMilliseconds; Console.WriteLine("Independent Wintun connected at " + connected + " ms"); }
        }, _ => { }, _ => { }, services);
        Task running = Task.CompletedTask;
        try {
            await MeshCoordinatorPreflight.Check(mesh.Pair,token);controlReady=true;
            if(!File.Exists(Path.Combine(components,"udp2raw-native.exe")))throw new IOException("Native component missing");
            running=runner.Run(token);
            while (latest?.Connected != true) { if (running.IsCompleted) await running; await Task.Delay(100, token); }
            using (var socket = new UdpClient(new IPEndPoint(IPAddress.Parse(mesh.LocalIp), 0))) {
                socket.Client.DontFragment = true; socket.Connect(IPAddress.Parse(MeshIdentity.Address(mesh.Pair.Network, peer.Slot)), EchoPort);
                for (int i = 0; i < 10; i++) {
                    byte[] data = RandomNumberGenerator.GetBytes(1252); // 1280-byte inner IPv4, not just the small STUN probe
                    await socket.SendAsync(data, token); using var wait = CancellationTokenSource.CreateLinkedTokenSource(token); wait.CancelAfter(2500);
                    var echo = await socket.ReceiveAsync(wait.Token); if (!echo.Buffer.SequenceEqual(data)) throw new IOException("Full-MTU echo mismatch"); echoes++;
                }
            }
            factory?.FinishWireCapture(); // keep handshake/MTU headers; do not retain a 50 Mbps capture in memory
            if (c.MeasureLoad) {
                await Task.Delay(TimeSpan.FromSeconds(c.MeasureDelay), token);
                byte[] key = MeshIdentity.SharedKey(mesh, peer);
                try { quality = await Quality.Measure(MeshIdentity.Address(mesh.Pair.Network, peer.Slot), Convert.ToHexString(key), 50, token, 20, mesh.LocalIp); }
                finally { CryptographicOperations.ZeroMemory(key); }
                Console.WriteLine(JsonSerializer.Serialize(quality));
            }
            await running;
        } catch (OperationCanceledException) when (token.IsCancellationRequested) { deadlineReached=true; }
        catch (Exception ex) { originalRunFailure=ex;failure = ex.ToString(); Console.Error.WriteLine(failure); }
        finally {
            stop.Cancel(); try { await running; } catch (OperationCanceledException) { } catch (Exception ex) { if(!ReferenceEquals(ex,originalRunFailure))cleanupFailure = ex.ToString(); }
            var evidence = factory?.Evidence();
            string sourceExpectation = c.Kind=="udp" ? "NotApplicable" : factory!=null ? factory.SourceExpectationPass()?"Pass":"Fail" :
                !c.RequireLearnedSource ? "NotApplicable" : "Fail";
            // A completed test is not a quality pass. Keep the configured load
            // and measured result separate, especially when nested over an old tunnel.
            bool loadPass = quality is { LossPercent: 0, ReceivedMbps: >= 49 };
            bool checkExecuted=selectedFactory?.NativePaths.Any(p=>p.Started)==true || connected>0;
            bool infrastructureReady=controlReady&&adapterCreated&&(selectedFactory?.PreparedCount>0||c.Kind=="legacy"&&connected>0);
            string transportOutcome=echoes==10?"BusinessUsable":deadlineReached&&connected==0&&checkExecuted?"NoDirectPathWithinBudget":connected>0?"IncompleteBusiness":"NotEstablished";
            // No-path cases have no selected-source assertion to evaluate.
            if(c.ExpectedNoDirectPath&&connected==0)sourceExpectation="NotApplicable";
            var verdict=TraversalVerdict.Evaluate(new(c.ExpectedNoDirectPath,infrastructureReady,checkExecuted,transportOutcome,sourceExpectation,
                echoes==10&&(!c.MeasureLoad||quality!=null),c.MeasureLoad,loadPass,cleanupFailure.Length==0,failure));
            Environment.ExitCode=verdict.ExitCode;
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { schemaVersion=4,fixtureVersion="PF2-01-v1",status = verdict.ScenarioVerdict,exitCode=verdict.ExitCode, c.Kind, c.Route,
                functionalStatus = verdict.FunctionalStatus, loadStatus = quality == null ? "NotTested" : loadPass ? "Pass" : "Fail",
                learningStatus = sourceExpectation, c.ReflectedPortOffset, c.PeerAnnouncedPortOffset,c.LocalHelper,
                transportOutcome,scenarioVerdict=verdict.ScenarioVerdict,failureCategory=verdict.FailureCategory,infrastructureReady,checkExecuted,controlReady,
                cleanupOutcome=cleanupFailure.Length==0?"Complete":"Fail",cleanupFailure,coordinatorUri=new Uri(mesh.Pair.Service).GetLeftPart(UriPartial.Authority),runnerExit=runner.ExitDiagnostics,
                loadCriterion = "50 Mbps requested for 20 seconds; at least 49 Mbps received and zero reported loss; not a latency or long-duration gate",
                scope = c.Route == "host" ? IPAddress.IsLoopback(IPAddress.Parse(c.Local))?"Single Windows host, isolated real Wintun/WinDivert runners over loopback. No two-device or physical NAT claim.":"Two real Windows Wintun/WinDivert endpoints over an existing overlay; no new public NAT reachability claim" : "Production physical-egress collector and Wintun; no relay claim depends on actual route evidence",
                actualWintun = adapterCreated, actualWinDivert = c.Kind != "udp" && connected > 0, oldOverlayUnderlay = c.Route == "host"&&!IPAddress.IsLoopback(IPAddress.Parse(c.Local)), connectedMs = connected, fullMtuEchoes = echoes,
                quality, session = latest, evidence,selectedPathDiagnostics=selectedFactory?.NativePaths.Select(p=>p.Diagnostics).ToArray(), failure, timeline }, new JsonSerializerOptions { WriteIndented = true }));
            factory?.Dispose();
        }
    }
    static async Task EchoServer(string local, string peer, CancellationToken token)
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Parse(local), EchoPort)); var allowed = IPAddress.Parse(peer);
        while (!token.IsCancellationRequested) { var data = await udp.ReceiveAsync(token); if (data.RemoteEndPoint.Address.Equals(allowed) && data.Buffer.Length == 1252) await udp.SendAsync(data.Buffer, data.RemoteEndPoint, token); }
    }
    sealed class SingleProfile(IMeshCandidateFactory inner, TraversalProfile profile) : IMeshCandidateFactory, IAsyncDisposable {
        public readonly System.Collections.Concurrent.ConcurrentQueue<NativeDatagramPath> NativePaths=[];
        public int PreparedCount;
        public TraversalProfile[] Profiles => inner.Profiles.Contains(profile) ? [profile] : throw new IOException("Requested profile unavailable");
        public bool SupportsUdpIpv6 => inner.SupportsUdpIpv6;
        public bool SupportsFakeTcpIpv6 => inner.SupportsFakeTcpIpv6;
        public bool SupportsTcpPrediction => inner.SupportsTcpPrediction;
        public bool SupportsTcpPeerReflexive => inner.SupportsTcpPeerReflexive;
        public async Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile kind, Guid attempt, CancellationToken token) => new Observed(await inner.Gather(peer, kind, attempt, token),this);
        public async Task<IMeshCandidateResource> GatherSourceAware(MeshMember peer, TraversalProfile kind, Guid attempt, bool allowIpv6,
            MeshTraversalCandidate? remote, int round, bool predictionAllowed, bool peerSourceAllowed, CancellationToken token) =>
            new Observed(await inner.GatherSourceAware(peer, kind, attempt, allowIpv6, remote, round, predictionAllowed, peerSourceAllowed, token),this);
        sealed class Observed(IMeshCandidateResource inner,SingleProfile owner):IMeshCandidateResource {
            public MeshTraversalCandidate Candidate=>inner.Candidate;
            public void AuthorizeUdpWitness(MeshTraversalCandidate remote)=>inner.AuthorizeUdpWitness(remote);
            IPreparedMeshPath Track(IPreparedMeshPath p){if(p.Armed)Interlocked.Increment(ref owner.PreparedCount);if(p is NativeDatagramPath n)owner.NativePaths.Enqueue(n);return p;}
            public async Task<IPreparedMeshPath> Prepare(TraversalAttemptContext c,IPEndPoint r,CancellationToken t)=>Track(await inner.Prepare(c,r,t));
            public async Task<IPreparedMeshPath> PrepareCandidate(TraversalAttemptContext c,MeshTraversalCandidate r,CancellationToken t)=>Track(await inner.PrepareCandidate(c,r,t));
            public ValueTask DisposeAsync()=>inner.DisposeAsync();
        }
        public async ValueTask DisposeAsync() { if (inner is IAsyncDisposable owner) await owner.DisposeAsync(); }
    }
    sealed class HostFactory(TraversalNode config, string components, string folder) : IMeshCandidateFactory, IDisposable, IAsyncDisposable
    {
        readonly Guid generation = Guid.NewGuid(); readonly List<object> observations = [];
        readonly TraversalNode node = config; readonly string root = folder, binary = Path.Combine(components, "udp2raw-native.exe"), divert = Path.Combine(components, "WinDivert.dll");
        TcpEndpointLease? tcp; UdpTraversal? udp; WireObserver? wire; long armed, ended;
        TcpCaptureOwner? capture;
        readonly List<NativeDatagramPath> paths = [];
        readonly List<IPEndPoint> announcedSources=[];
        NativePathDiagnostics[] diagnostics = [];
        public bool LearnedSource => diagnostics.Any(d => d.PayloadQualified && d.PeerSource is { Learned: true, Frozen: true });
        public bool SourceExpectationPass() {
            bool expectedLearning=node.PeerAnnouncedPortOffset!=0;
            return paths.Count>0 && paths.Zip(announcedSources).Where(p=>p.First.Diagnostics.PayloadQualified).Any(p=>{
                var source=p.First.Diagnostics.PeerSource;
                var expected=new IPEndPoint(p.Second.Address,p.Second.Port-node.PeerAnnouncedPortOffset);
                return p.First.Identity.ActualRemote.Equals(expected) && (source?.Enabled==true?source.Frozen&&source.Learned==expectedLearning:!expectedLearning);
            });
        }
        public bool SupportsTcpPeerReflexive => node.Kind == "tcp" && node.CaptureBroker && node.Profile.TcpPeerReflexive;
        public TraversalProfile[] Profiles => [node.Kind == "tcp" ? TraversalProfile.FakeTcpHttpSo : TraversalProfile.UdpDirect];
        public Task<IMeshCandidateResource> GatherSourceAware(MeshMember peer, TraversalProfile kind, Guid attempt, bool allowIpv6,
            MeshTraversalCandidate? remote, int round, bool predictionAllowed, bool peerSourceAllowed, CancellationToken token) {
            bool source = SupportsTcpPeerReflexive && peerSourceAllowed;
            if (remote?.PeerReflexive == true && !source) throw new IOException("Fixture source learning was not jointly authorized");
            return GatherCore(peer, kind, attempt, source, token);
        }
        public async Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile kind, Guid attempt, CancellationToken token)
            => await GatherCore(peer, kind, attempt, false, token);
        async Task<IMeshCandidateResource> GatherCore(MeshMember peer, TraversalProfile kind, Guid attempt, bool source, CancellationToken token)
        {
            try {
            var local = new IPEndPoint(IPAddress.Parse(node.Local), node.SourcePort);
            var remote = node.LocalHelper ? new(local.Address, node.ReflectorPort) : new IPEndPoint(IPAddress.Parse(node.Peer), node.PeerReflectorPort);
            IPEndPoint observed;
            if (kind == TraversalProfile.FakeTcpHttpSo) {
                tcp = await TcpEndpointLease.Open(local, remote, generation, token); using var reference = tcp.AcquireAttempt(generation);
                observed = (await reference.Observe(token)).Public;
                if (node.CaptureBroker) { capture = new(tcp, generation, (source, helper) => new WinDivertEndpointIo(divert, source, helper)); await capture.Ready; }
                observations.Add(new { resource = tcp.Id, protocol = "tcp", local = tcp.Local.ToString(), target = remote.ToString(), mapped = observed.ToString() });
            } else {
                byte[] key = MeshIdentity.SharedKey(node.Profile.Mesh!, peer);
                try { udp = UdpTraversal.Create(local, generation, attempt, node.Profile.Mesh!.Self.Slot, peer.Slot, key); }
                finally { CryptographicOperations.ZeroMemory(key); }
                var observation = await udp.Observe(remote, token); observed = observation.Mapped;
                observations.Add(new { resource = observation.SocketId, protocol = "udp", local = observation.Local.ToString(), target = remote.ToString(), mapped = observed.ToString() });
            }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return new Resource(this, peer, new(Guid.NewGuid(), 1, observed.ToString(), remote.ToString(), now, now + 120, CandidatePurpose.Host, PeerReflexive: source));
            } catch { if (capture != null) await capture.DisposeAsync(); tcp?.Dispose(); if (udp != null) await udp.DisposeAsync(); throw; }
        }
        public void FinishWireCapture() { diagnostics = paths.Select(p => p.Diagnostics).ToArray(); ended = Environment.TickCount64; wire?.Dispose(); }
        public object Evidence() => new { observations, diagnostics = diagnostics.Length == 0 ? paths.Select(p => p.Diagnostics).ToArray() : diagnostics, captureBroker = node.CaptureBroker, capture = capture?.Status,
            resourceClosed = (tcp?.Closed ?? true) && (udp?.Closed ?? true), wire = wire?.Snapshot(armed, ended == 0 ? Environment.TickCount64 : ended,
                diagnostics.LastOrDefault(d => d.PayloadQualified) is {} path ? IPEndPoint.Parse(path.Peer).Port : null) };
        public void Dispose() { wire?.Dispose(); }
        public async ValueTask DisposeAsync() { if (capture != null) { await capture.DisposeAsync(); await capture.Closed; } tcp?.Dispose(); }
        sealed class Resource(HostFactory owner, MeshMember peer, MeshTraversalCandidate candidate) : IMeshCandidateResource {
            bool transferred;
            public MeshTraversalCandidate Candidate => candidate;
            public async Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context, IPEndPoint remote, CancellationToken token) {
                if (owner.udp != null) { var result = owner.udp.PreparePath(context, owner.generation, remote); transferred = true; return result; }
                owner.wire = new WireObserver(owner.divert, owner.tcp!.Local, remote, owner.node.PeerSourcePort);
                byte[] key = MeshIdentity.SharedKey(owner.node.Profile.Mesh!, peer);
                try { var result = await NativeDatagramPath.Prepare(owner.binary, owner.root, owner.tcp, owner.generation, context, remote, key, token,
                    captureOwner: owner.capture, countWireControl: candidate.PeerReflexive, peerReflexive: candidate.PeerReflexive);
                    owner.paths.Add(result);owner.announcedSources.Add(remote); owner.armed = Environment.TickCount64; return result; }
                finally { CryptographicOperations.ZeroMemory(key); }
            }
            public async ValueTask DisposeAsync() { if (owner.ended == 0) owner.ended = Environment.TickCount64; owner.tcp?.Dispose(); if (!transferred && owner.udp != null) await owner.udp.DisposeAsync(); }
        }
    }
    sealed class UdpReflector : IAsyncDisposable {
        readonly UdpClient socket; readonly CancellationTokenSource stop = new(); readonly Task receiving;
        public UdpReflector(IPEndPoint local) { socket = new(local); receiving = Receive(); }
        async Task Receive() {
            while (!stop.IsCancellationRequested) {
                var packet = await socket.ReceiveAsync(stop.Token); if (packet.Buffer.Length != 20) continue;
                byte[] response = new byte[32]; packet.Buffer.CopyTo(response, 0); response[0] = 1; response[1] = 1; response[3] = 12; response[21] = 0x20; response[23] = 8; response[25] = 1;
                BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(26), (ushort)(packet.RemoteEndPoint.Port ^ 0x2112));
                BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(28), BinaryPrimitives.ReadUInt32BigEndian(packet.RemoteEndPoint.Address.GetAddressBytes()) ^ 0x2112a442);
                await socket.SendAsync(response, packet.RemoteEndPoint, stop.Token);
            }
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); try { await receiving; } catch (OperationCanceledException) { } socket.Dispose(); stop.Dispose(); }
    }
}
