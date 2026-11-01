using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    static int checks;
    public static void Check(bool ok, string message) { if (!ok) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
    public static async Task Until(Func<bool> condition, string message, int timeout = 6000)
    {
        var clock = Stopwatch.StartNew(); while (!condition()) { if (clock.ElapsedMilliseconds >= timeout) throw new Exception("Timed out: " + message); await Task.Delay(20); }
        Check(true, message);
    }
    static MeshProfile Guest(MeshProfile owner) => MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));
    static async Task Stop(Task task, CancellationTokenSource cancellation)
    { cancellation.Cancel(); try { await task.WaitAsync(TimeSpan.FromSeconds(3)); } catch (OperationCanceledException) { } }
    public static async Task Main(string[] args)
    {
        if (args is ["--existing-entries-only"]) { await ExistingEntries(); return; }
        if (args is ["--probe-cancel-only"]) { await MappingProbeCancellation(); return; }
        if (args is ["--connection-feedback-only"]) { ConnectionFeedback(); return; }
        if (args is ["--tcp-selection-only"]) { await TcpTests.SelectionOwnership(); return; }
        if (args is ["--entry-probe-only"]) { await EntryProbeReuse(); return; }
        if (args is ["--scheduler-only"]) { await Scheduler(); return; }
        if(args is ["--half-open-only",var halfOpenReport]){
            await HalfOpenRecovery(Path.GetFullPath(halfOpenReport));return;
        }
        if(args is ["--pump-fault-only",var pumpReport]){
            await PumpFaultRecovery(Path.GetFullPath(pumpReport));return;
        }
        if(args is ["--service-retry-only",var serviceReport]){
            await ServiceFaultRetry(Path.GetFullPath(serviceReport));return;
        }
        if(args is ["--quality-isolation-only",var qualityReport]){
            await QualityIsolation(Path.GetFullPath(qualityReport));Console.WriteLine($"PASS {checks} optional quality isolation checks");return;
        }
        if (args is ["--startup-only", var startupReport]) {
            await Startup(Path.GetFullPath(startupReport));
            Console.WriteLine($"PASS {checks} async startup/cancel checks"); return;
        }
        if (args is ["--network-wake-only", var wakeReport]) {
            await NetworkWake(Path.GetFullPath(wakeReport));
            Console.WriteLine($"PASS {checks} compatibility network wake checks"); return;
        }
        if(args is ["--alive-recovery-only",var recoveryReport]){
            await AliveProcessRecovery(Path.GetFullPath(recoveryReport));
            Console.WriteLine($"PASS {checks} unchanged-endpoint compatibility recovery checks");return;
        }
        if (args is ["--contend", var contenderPort]) {
            using var rival = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = false };
            rival.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            try { rival.Bind(new IPEndPoint(IPAddress.Loopback, int.Parse(contenderPort))); Environment.ExitCode = 2; }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AccessDenied or SocketError.AddressAlreadyInUse) { Console.WriteLine(ex.SocketErrorCode); }
            return;
        }
        ConnectionFeedback();
        await TcpTests.Run();
        await ExistingEntries();
        await EntryProbeReuse();
        await Migration();
        await ListenerFailure();
        await AliveProcessRecovery();
        await HalfOpenRecovery();
        await PumpFaultRecovery();
        await ServiceFaultRetry();
        await Scheduler();
        await QualityIsolation();
        await Startup();
        Console.WriteLine($"{checks} TCP / mesh connection checks passed; loopback only, no installed service or network configuration changes.");
    }
    static byte[] Packet(string from, string to)
    {
        byte[] packet = new byte[1280]; packet[0] = 0x45; packet[8] = 64; packet[9] = 17;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 1280);
        IPAddress.Parse(from).GetAddressBytes().CopyTo(packet, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(packet, 16);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(i)); while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), (ushort)~sum); return packet;
    }
    static async Task Migration()
    {
        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp"); var guest = Guest(owner); guest.Directory = owner.Directory;
        byte[] key = MeshIdentity.SharedKey(guest, owner.Self); using var peer = new MeshLink(2, 1, key); CryptographicOperations.ZeroMemory(key);
        await using var oldPath = new PeerEndpoint(peer); await using var newPath = new PeerEndpoint(peer) { SuppressPong = true };
        var adapter = new MemoryAdapter(); await using var router = new MeshRouter(owner, adapter);
        var oldTransport = new StubTransport(oldPath.Endpoint); var newTransport = new StubTransport(newPath.Endpoint);
        using var paths = new MeshPeerTransports(router, endpoint => endpoint == oldPath.Endpoint.ToString() ? oldTransport : newTransport, Console.WriteLine);
        paths.Update(2, oldPath.Endpoint.ToString(), "peer", "");
        await Until(() => router.UsesPath(2, oldPath.Endpoint), "first path proves an authenticated round trip");
        paths.Update(2, oldPath.Endpoint.ToString(), "peer", "");
        paths.Update(2, newPath.Endpoint.ToString(), "peer", "");
        await Task.Delay(1900);
        Check(newPath.Received > 0 && router.UsesPath(2, oldPath.Endpoint) && !oldTransport.Disposed, "authenticated new endpoint without a returned challenge cannot replace the healthy path");
        adapter.Outgoing.Add(Packet(owner.LocalIp, guest.LocalIp));
        await Until(() => oldPath.DataPackets == 1, "full-MTU business packet still uses the old path during validation");
        using (var spoof = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0))) {
            await spoof.SendAsync(RandomNumberGenerator.GetBytes(100), router.LocalEndpoint); await Task.Delay(100);
            Check(router.UsesPath(2, oldPath.Endpoint), "unauthenticated local datagram cannot change the active path");
        }
        newPath.SuppressPong = false;
        newPath.RedirectPong = oldPath.Send;
        await Task.Delay(1700);
        Check(router.UsesPath(2, oldPath.Endpoint), "correct challenge returned through a different endpoint does not validate the candidate");
        newPath.RedirectPong = null;
        await Until(() => router.UsesPath(2, newPath.Endpoint), "replacement selected only after its exact challenge returns");
        await oldPath.Send(peer.Ping()!, router.LocalEndpoint); await Task.Delay(150);
        Check(router.UsesPath(2, newPath.Endpoint), "late authenticated traffic from the old path cannot switch routing back");
        paths.Update(2, newPath.Endpoint.ToString(), "peer", "");
        Check(oldTransport.Disposed && !newTransport.Disposed && !adapter.Disposed, "only the retired transport closes; the TUN and new path remain");
        adapter.Outgoing.Add(Packet(owner.LocalIp, guest.LocalIp));
        await Until(() => newPath.DataPackets == 1, "business packet uses the validated replacement");
        paths.Update(2, "", "peer", "expired announcement");
        Check(!newTransport.Disposed, "expired discovery metadata does not tear down a proven path");
        router.FailLegacyListener();
        Check(router.UsesPath(2,newPath.Endpoint),"listener failure preserves a path owned by an independent client");
        router.FailLegacyTransport(2,oldPath.Endpoint);
        Check(router.UsesPath(2,newPath.Endpoint),"failure of a retired owner cannot revoke the replacement's fresh proof");
        newTransport.Exited=true;
        paths.Update(2,newPath.Endpoint.ToString(),"peer","fixture native exit",()=>false);
        Check(!router.HasHealthyPath(2)&&router.Status().Single().Liveness?.Reason=="TransportExited"&&newTransport.Disposed&&!adapter.Disposed,
            "confirmed active transport exit revokes health immediately without waiting twelve seconds or recreating the adapter");
        await newPath.Send(peer.Ping()!,router.LocalEndpoint);await Task.Delay(150);
        Check(!router.HasHealthyPath(2),"late authenticated traffic from the failed owner's endpoint cannot restore health");
    }
    static async Task ListenerFailure()
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        byte[] key=MeshIdentity.SharedKey(guest,owner.Self);using var peer=new MeshLink(2,1,key);CryptographicOperations.ZeroMemory(key);
        await using var inbound=new PeerEndpoint(peer);var adapter=new MemoryAdapter();await using var router=new MeshRouter(owner,adapter);
        router.SetLegacyListenerControl(true);
        await inbound.Send(peer.Hello(),router.LocalEndpoint);
        await Until(()=>router.UsesPath(2,inbound.Endpoint),"unsolicited authenticated listener traffic proves its own return path");
        router.FailLegacyListener();
        Check(!router.HasHealthyPath(2)&&router.Status().Single().Liveness?.Reason=="TransportExited"&&!adapter.Disposed,
            "shared listener exit revokes its incoming paths without closing the adapter");
        await inbound.Send(peer.Ping()!,router.LocalEndpoint);await Task.Delay(150);
        Check(!router.HasHealthyPath(2),"late listener datagrams cannot resurrect a confirmed failed owner");
    }
    static async Task AliveProcessRecovery(string? output=null)
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        byte[] key=MeshIdentity.SharedKey(guest,owner.Self);using var peer=new MeshLink(2,1,key);CryptographicOperations.ZeroMemory(key);
        await using var endpoint=new PeerEndpoint(peer);var adapter=new MemoryAdapter();await using var router=new MeshRouter(owner,adapter);
        var transports=new List<ForwardingTransport>();bool admit=true;int admissions=0;
        using var paths=new MeshPeerTransports(router,_=>{var t=new ForwardingTransport(endpoint.Endpoint);transports.Add(t);return t;},Console.WriteLine);
        bool Begin(){admissions++;return admit;}
        void Tick()=>paths.Update(2,endpoint.Endpoint.ToString(),"same peer","",Begin);
        Tick();await Until(()=>router.UsesPath(2,transports[0].ClientEndpoint),"initial compatibility client proves its retained path");Tick();
        int healthyAdmissions=admissions;
        for(int i=0;i<10;i++){Tick();await Task.Delay(50);}
        Check(transports.Count==1&&admissions==healthyAdmissions,"healthy unchanged peer does not allocate a replacement or consume attempt admission");
        var recoveryClock=Stopwatch.StartNew();transports[0].Muted=true;admit=false;
        await Until(()=>!router.HasHealthyPath(2),"actual unresponsive path expires the unchanged twelve-second health window",15000);
        long lostAt=recoveryClock.ElapsedMilliseconds;
        Tick();Check(transports.Count==1&&!transports[0].Disposed&&!transports[0].Exited,"deferred recovery keeps live old ownership while respecting shared attempt admission");
        admit=true;endpoint.SuppressPong=true;Tick();
        long replacementAt=recoveryClock.ElapsedMilliseconds;
        Check(transports.Count==2&&paths.HasPending&&transports[0].ClientEndpoint.Port!=transports[1].ClientEndpoint.Port,
            "unchanged public endpoint receives an independently bound replacement despite its old live process");
        await Task.Delay(1300);Tick();
        Check(!transports[0].Disposed&&!adapter.Disposed&&!router.UsesPath(2,transports[1].ClientEndpoint),
            "new authenticated traffic without a returned path challenge cannot retire old ownership");
        endpoint.SuppressPong=false;
        await Until(()=>router.UsesPath(2,transports[1].ClientEndpoint),"same-public-endpoint replacement must return its own authenticated challenge");Tick();
        long selectedAt=recoveryClock.ElapsedMilliseconds;
        Check(transports[0].Disposed&&!transports[1].Disposed&&!paths.HasPending&&!adapter.Disposed,
            "only after validation does recovery retire the old transport and preserve the adapter");
        adapter.Outgoing.Add(Packet(owner.LocalIp,guest.LocalIp));
        await Until(()=>endpoint.DataPackets==1,"full-MTU application data traverses the recovered compatibility path");
        long businessAt=recoveryClock.ElapsedMilliseconds;
        for(int i=0;i<10;i++){Tick();await Task.Delay(50);}
        Check(transports.Count==2,"successful recovery does not repeatedly allocate new clients for the same endpoint");
        if(output!=null){Directory.CreateDirectory(Path.GetDirectoryName(output)!);await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{
            status="Pass",checks,healthTimeoutMs=12000,detectedMs=lostAt,replacementPreparedMs=replacementAt,
            candidateSelectedMs=selectedAt,firstCompleteIpAtPeerMs=businessAt,fromPreparationToFirstCompleteIpMs=businessAt-replacementAt,
            nativeProcessExitTriggered=false,publicEndpointChanged=false,adapterRecreated=false,
            scope="production Router and compatibility path manager over real loopback UDP forwarding and memory IP adapter; live transport flag, not an actual native process or Windows suspend/WAN",
            stableBusiness="NotMeasured",relay=false},new JsonSerializerOptions{WriteIndented=true}));}
    }
    static async Task Scheduler()
    {
        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp"); var guest = Guest(owner); guest.Directory = owner.Directory;
        byte[] key = MeshIdentity.SharedKey(guest, owner.Self); using var peer = new MeshLink(2, 1, key); CryptographicOperations.ZeroMemory(key);
        await using var endpoint = new PeerEndpoint(peer);
        var directoryOwner = JsonSerializer.Deserialize<MeshProfile>(JsonSerializer.Serialize(owner))!;
        var discovery = new Discovery(owner, guest, endpoint.Endpoint.ToString());
        var adapter = new MemoryAdapter();
        var opening = new TaskCompletionSource<IPacketAdapter>(TaskCreationOptions.RunContinuationsAsynchronously);
        var mapped = new TaskCompletionSource<IMapping>(TaskCreationOptions.RunContinuationsAsynchronously);
        var mapping = new Mapping(); var transports = new ConcurrentBag<IMeshTransport>(); int adapterCount = 0, cleanups = 0, probes = 0;
        string folder = Path.Combine(Path.GetTempPath(), "streamlink-mesh-scheduling-" + Guid.NewGuid().ToString("N"));
        var services = new MeshRuntimeServices(_ => discovery,
            _ => { Interlocked.Increment(ref adapterCount); return opening.Task; },
            async (_, _, token) => { if (Interlocked.Increment(ref probes) > 1) await Task.Delay(Timeout.Infinite, token); return await mapped.Task.WaitAsync(token); },
            request => {
                IMeshTransport transport = request.Server ? new StubTransport(null) : new ForwardingTransport(request.Target);
                transports.Add(transport); return transport;
            },
            (_, _, token) => Task.Delay(Timeout.Infinite, token), (_, _, remote) => { if (remote.Length == 0) cleanups++; }, (_, _) => { }, folder);
        var profile = new DeviceProfile { Mesh = owner };
        SessionStatus? status = null;
        var logs = new ConcurrentQueue<string>();
        var runner = new MeshRunner(profile, line => { logs.Enqueue(line); Console.WriteLine(line); }, s => status = s, _ => { }, _ => { }, services);
        using var stop = new CancellationTokenSource(); Task running = runner.Run(stop.Token);
        try {
            await Until(() => discovery.Reads > 0 && discovery.Published.Count > 0, "coordination starts while adapter and local TCP mapping are still pending");
            Check(discovery.Watches > 0, "production MeshRunner selects the change-feed interface when supported");
            Check(!opening.Task.IsCompleted && !mapped.Task.IsCompleted, "slow adapter and mapping were not implicitly awaited");
            opening.SetResult(adapter);
            await Until(() => status?.Connected == true, "peer entry connects while the local mapping probe remains blocked");
            Check(!mapped.Task.IsCompleted, "strict local NAT does not block using another member's entry");
            Check(status?.ControlAdmission is { SearchAdmitted: > 0, AdmittedBytes: > 0 },
                "formal Runner status exposes cumulative control admission separately from wire traffic");
            Check(status?.EnhancementAdmission is { Active: 0, Waiting: 0, Granted: 0 },
                "default legacy Runner reports idle cross-protocol admission without enabling enhancement probes");
            mapped.SetResult(mapping);
            await Until(() => transports.OfType<StubTransport>().Any(), "local entry starts when mapping completes");
            await Until(() => discovery.Published.Any(p => p.Endpoint == mapping.PublicEndpoint.ToString()), "new TCP entry is published promptly");
            discovery.BlockReads = new(TaskCreationOptions.RunContinuationsAsynchronously);
            await Until(() => discovery.WaitingReads > 0, "test holds the coordination GET open");
            var firstServer = transports.OfType<StubTransport>().First(); firstServer.Exited = true;
            var clock = Stopwatch.StartNew();
            await Until(() => transports.OfType<StubTransport>().Count() == 2, "exited local transport restarts without waiting for HTTP", 1500);
            Console.WriteLine($"Local child restart while GET blocked: {clock.ElapsedMilliseconds} ms");
            mapping.Change(new(IPAddress.Loopback, 43002));
            await Until(() => discovery.Published.Any(p => p.Endpoint == mapping.PublicEndpoint.ToString()), "changed mapping is published while the independent GET remains blocked", 4000);
            Check(discovery.WaitingReads > 0 && status?.Connected == true && !adapter.Disposed, "HTTP stall preserves the working encrypted peer path");
            await Until(() => status?.Peers?.Single().Recovery?.StablePathConfirmedMs != null,
                "formal idle Runner reports ordinary same-path keepalive confirmation", 20000);
            await Until(() => logs.Any(l => l.StartsWith("StablePath ")), "formal Runner emits idle path evidence", 1500);
            Check(status!.Peers!.Single().Recovery!.FirstBusinessMs == null && logs.Count(l => l.StartsWith("StablePath ")) == 1 &&
                !logs.Any(l => l.StartsWith("FirstBusiness ") || l.StartsWith("StableBusiness ")),
                "idle service logs path reachability once without claiming business recovery");
            int data = endpoint.DataPackets; adapter.Outgoing.Add(Packet(owner.LocalIp, guest.LocalIp));
            await Until(() => endpoint.DataPackets > data, "real encrypted datagram delivery continues through a coordination stall");
            endpoint.ReplyPacket = Packet(guest.LocalIp, owner.LocalIp);
            using (var sampling = new CancellationTokenSource()) {
                var feeding = Task.Run(async () => { try { while (true) { adapter.Outgoing.Add(Packet(owner.LocalIp, guest.LocalIp)); await Task.Delay(100, sampling.Token); } } catch (OperationCanceledException) when (sampling.IsCancellationRequested) { } });
                try {
                    await Until(() => status?.Peers?.Single().Recovery?.StableBusinessConfirmedMs != null,
                        "formal Runner status carries actual legacy business recovery evidence while coordination is blocked", 10000);
                    await Until(() => logs.Any(l => l.StartsWith("StableBusiness ")), "formal Runner emits stable confirmation event", 1500);
                    Check(logs.Count(l => l.StartsWith("FirstBusiness ")) == 1 && logs.Count(l => l.StartsWith("StableBusiness ")) == 1,
                        "first and stable business are logged once per episode, without every-frame logging");
                } finally { sampling.Cancel(); await feeding; endpoint.ReplyPacket = null; }
            }
            var previous = transports.OfType<ForwardingTransport>().Single(); previous.Exited = true;
            await Until(() => transports.OfType<ForwardingTransport>().Count() == 2, "outbound transport also restarts while HTTP is blocked", 1500);
            await Until(() => transports.OfType<ForwardingTransport>().LastOrDefault(t => !t.Exited)?.Packets > 0 && status?.Connected == true, "restarted transport is authenticated without recreating the adapter");
            Check(adapterCount == 1 && !adapter.Disposed, "mapping and per-peer recovery retain one adapter");
            mapping.ReleaseGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
            var retainedServer = transports.OfType<StubTransport>().Single(t => !t.Disposed);
            long beforeWithdrawal = discovery.Published.Last().Revision;
            mapping.Failed.SetException(new IOException("simulated mapping failure"));
            await Until(() => mapping.Removing, "failed TCP mapping starts asynchronous lease cleanup");
            Check(!retainedServer.Disposed, "candidate lease failure preserves the listening FakeTCP process and its accepted sessions");
            await Until(() => discovery.Published.Any(p => p.Revision > beforeWithdrawal && p.Endpoint.Length == 0),
                "expired mapping is withdrawn even while the listening process remains", 4000);
            var latest = transports.OfType<ForwardingTransport>().Single(t => !t.Disposed); latest.Exited = true;
            await Until(() => transports.OfType<ForwardingTransport>().Count() == 3, "slow lease deletion does not block another outbound recovery", 1500);
            Check(probes == 1, "replacement mapping waits for old owned lease cleanup to avoid deleting the new lease");
            mapping.ReleaseGate.SetResult();
            await Until(() => probes == 2, "mapping retry resumes after safe lease cleanup");
            MeshIdentity.Revoke(directoryOwner, 2); runner.UpdateDirectory(directoryOwner.Directory!);
            await Until(() => transports.OfType<ForwardingTransport>().All(t => t.Disposed), "local member revocation closes its paths even while HTTP is blocked", 1500);
        } finally {
            if (!opening.Task.IsCompleted) opening.TrySetResult(adapter);
            mapping.ReleaseGate?.TrySetResult();
            await Stop(running, stop);
            foreach (var d in Directory.EnumerateDirectories(folder)) Directory.Delete(d); Directory.Delete(folder);
        }
        Check(adapter.Disposed && mapping.Disposed && transports.All(t => t is StubTransport s ? s.Disposed : ((ForwardingTransport)t).Disposed), "cancellation closes adapter, mapping and every transport");
        Check(discovery.Disposed && discovery.WaitingReads == 0 && cleanups == 2, "in-flight HTTP and owned session cleanup finish on shutdown (revocation plus exit)");
    }
    sealed class MemoryAdapter : IPacketAdapter
    {
        public readonly BlockingCollection<byte[]> Outgoing = new(); public bool Disposed; public volatile bool ReadFault;
        public int Read(byte[] buffer) { if(ReadFault)throw new IOException("injected adapter read fault");if (!Outgoing.TryTake(out var packet, 50)) return 0; packet.CopyTo(buffer, 0); return packet.Length; }
        public bool Write(byte[] packet) => true;
        public void Dispose() { Disposed = true; Outgoing.Dispose(); }
    }
    sealed class StubTransport(IPEndPoint? endpoint) : IMeshTransport
    {
        public IPEndPoint? ClientEndpoint => endpoint; public bool Exited { get; set; } public bool Disposed;
        public void Dispose() { Disposed = true; Exited = true; }
    }
    sealed class Mapping : IMapping, IMappingRefresh
    {
        public IPAddress LocalAddress => IPAddress.Loopback;
        public bool IsValid => !Disposed && !Failed.Task.IsCompleted;
        public IPEndPoint PublicEndpoint { get; private set; } = new(IPAddress.Loopback, 43001);
        public event Action<IPEndPoint>? Changed; public bool Disposed;
        public readonly TaskCompletionSource Failed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource? ReleaseGate; public bool Removing;
        int refreshes;
        public int Refreshes => Volatile.Read(ref refreshes);
        public void RequestRefresh() => Interlocked.Increment(ref refreshes);
        public void Change(IPEndPoint endpoint) { PublicEndpoint = endpoint; Changed?.Invoke(endpoint); }
        public Task Maintain(CancellationToken token) => Failed.Task.WaitAsync(token);
        public async ValueTask DisposeAsync() { Removing = true; if (ReleaseGate != null) await ReleaseGate.Task; Disposed = true; }
    }
    sealed class Discovery(MeshProfile owner, MeshProfile guest, string endpoint) : IMeshDiscovery, IMeshChangeDiscovery
    {
        public int Reads, WaitingReads, Watches; public bool Disposed;
        public bool SupportsLongPolling => true;
        public Task<MeshSnapshot?> WaitForChanges(CancellationToken token) { Interlocked.Increment(ref Watches); return Read(token); }
        public TaskCompletionSource? BlockReads;
        public readonly ConcurrentQueue<MeshAnnouncement> Published = [];
        public Task SaveDirectory(MeshDirectory directory, CancellationToken token) => Task.CompletedTask;
        public Task Publish(MeshAnnouncement announcement, CancellationToken token) { Published.Enqueue(announcement); return Task.CompletedTask; }
        public async Task<MeshSnapshot?> Read(CancellationToken token)
        {
            Interlocked.Increment(ref Reads);
            if (BlockReads is {} wait) {
                Interlocked.Increment(ref WaitingReads); try { await wait.Task.WaitAsync(token); } finally { Interlocked.Decrement(ref WaitingReads); }
            }
            return new(owner.Directory!, [MeshMetadata.Seal(guest, new(2, guest.Self.Device, DateTime.UtcNow.Ticks, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), endpoint, "test peer"))]);
        }
        public void Dispose() => Disposed = true;
    }
    sealed class ForwardingTransport : IMeshTransport
    {
        readonly UdpClient socket = new(new IPEndPoint(IPAddress.Loopback, 0));
        readonly CancellationTokenSource stop = new(); readonly Task pump; readonly IPEndPoint remote; IPEndPoint? local;
        public IPEndPoint ClientEndpoint { get; }
        public bool Exited { get; set; } public bool Disposed; public int Packets; public volatile bool Muted, MuteUplink;
        public ForwardingTransport(IPEndPoint remote) { this.remote = remote; ClientEndpoint = (IPEndPoint)socket.Client.LocalEndPoint!; pump = Pump(); }
        async Task Pump()
        {
            while (!stop.IsCancellationRequested) {
                var packet = await socket.ReceiveAsync(stop.Token); Interlocked.Increment(ref Packets);
                if(Muted)continue;
                if (packet.RemoteEndPoint.Equals(remote)) { if (local != null) await socket.SendAsync(packet.Buffer, local, stop.Token); }
                else { local = packet.RemoteEndPoint; if(!MuteUplink)await socket.SendAsync(packet.Buffer, remote, stop.Token); }
            }
        }
        public void Dispose()
        {
            if (Disposed) return; Disposed = true; Exited = true; stop.Cancel();
            try { pump.GetAwaiter().GetResult(); } catch (OperationCanceledException) { }
            socket.Dispose(); stop.Dispose();
        }
    }
    sealed class PeerEndpoint : IAsyncDisposable
    {
        readonly UdpClient socket = new(new IPEndPoint(IPAddress.Loopback, 0));
        readonly CancellationTokenSource stop = new(); readonly Task pump; readonly MeshLink link;
        public IPEndPoint Endpoint { get; }
        public bool SuppressPong; public int Received, DataPackets;
        public byte[]? ReplyPacket;
        public byte[]? LastSuppressedPong;
        public Func<byte[], IPEndPoint, Task>? RedirectPong;
        public PeerEndpoint(MeshLink link) { this.link = link; Endpoint = (IPEndPoint)socket.Client.LocalEndPoint!; pump = Pump(); }
        public Task Send(byte[] bytes, IPEndPoint to) => socket.SendAsync(bytes, to, stop.Token).AsTask();
        async Task Pump()
        {
            while (!stop.IsCancellationRequested) {
                UdpReceiveResult packet;
                try { packet = await socket.ReceiveAsync(stop.Token); }
                catch(SocketException ex) when(ex.SocketErrorCode==SocketError.ConnectionReset) { continue; }
                var message = link.Receive(packet.Buffer); Interlocked.Increment(ref Received);
                if (message.Packet != null) {
                    Interlocked.Increment(ref DataPackets);
                    if (ReplyPacket is {} reply && link.Data(reply) is {} encoded) await socket.SendAsync(encoded, packet.RemoteEndPoint, stop.Token);
                }
                if (message.Reply is {} held && SuppressPong && held[4] == 6) LastSuppressedPong = held;
                if (message.Reply != null && !(SuppressPong && message.Reply[4] == 6)) {
                    if (message.Reply[4] == 6 && RedirectPong is {} redirect) await redirect(message.Reply, packet.RemoteEndPoint);
                    else await socket.SendAsync(message.Reply, packet.RemoteEndPoint, stop.Token);
                }
            }
        }
        public async ValueTask DisposeAsync()
        {
            stop.Cancel(); try { await pump; } catch (OperationCanceledException) { } socket.Dispose(); stop.Dispose();
        }
    }
}
