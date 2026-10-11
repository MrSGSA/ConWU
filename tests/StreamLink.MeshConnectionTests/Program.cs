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

static class Program
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
    public static async Task Main()
    {
        await TcpTests.Run();
        await Migration();
        await Scheduler();
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
        var runner = new MeshRunner(profile, Console.WriteLine, s => status = s, _ => { }, _ => { }, services);
        using var stop = new CancellationTokenSource(); Task running = runner.Run(stop.Token);
        try {
            await Until(() => discovery.Reads > 0 && discovery.Published.Count > 0, "coordination starts while adapter and local TCP mapping are still pending");
            Check(discovery.Watches > 0, "production MeshRunner selects the change-feed interface when supported");
            Check(!opening.Task.IsCompleted && !mapped.Task.IsCompleted, "slow adapter and mapping were not implicitly awaited");
            opening.SetResult(adapter);
            await Until(() => status?.Connected == true, "peer entry connects while the local mapping probe remains blocked");
            Check(!mapped.Task.IsCompleted, "strict local NAT does not block using another member's entry");
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
            int data = endpoint.DataPackets; adapter.Outgoing.Add(Packet(owner.LocalIp, guest.LocalIp));
            await Until(() => endpoint.DataPackets > data, "real encrypted datagram delivery continues through a coordination stall");
            var previous = transports.OfType<ForwardingTransport>().Single(); previous.Exited = true;
            await Until(() => transports.OfType<ForwardingTransport>().Count() == 2, "outbound transport also restarts while HTTP is blocked", 1500);
            await Until(() => transports.OfType<ForwardingTransport>().LastOrDefault(t => !t.Exited)?.Packets > 0 && status?.Connected == true, "restarted transport is authenticated without recreating the adapter");
            Check(adapterCount == 1 && !adapter.Disposed, "mapping and per-peer recovery retain one adapter");
            mapping.ReleaseGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
            mapping.Failed.SetException(new IOException("simulated mapping failure"));
            await Until(() => mapping.Removing, "failed TCP mapping starts asynchronous lease cleanup");
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
        public readonly BlockingCollection<byte[]> Outgoing = new(); public bool Disposed;
        public int Read(byte[] buffer) { if (!Outgoing.TryTake(out var packet, 50)) return 0; packet.CopyTo(buffer, 0); return packet.Length; }
        public bool Write(byte[] packet) => true;
        public void Dispose() { Disposed = true; Outgoing.Dispose(); }
    }
    sealed class StubTransport(IPEndPoint? endpoint) : IMeshTransport
    {
        public IPEndPoint? ClientEndpoint => endpoint; public bool Exited { get; set; } public bool Disposed;
        public void Dispose() { Disposed = true; Exited = true; }
    }
    sealed class Mapping : IMapping
    {
        public IPAddress LocalAddress => IPAddress.Loopback;
        public IPEndPoint PublicEndpoint { get; private set; } = new(IPAddress.Loopback, 43001);
        public event Action<IPEndPoint>? Changed; public bool Disposed;
        public readonly TaskCompletionSource Failed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource? ReleaseGate; public bool Removing;
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
        public bool Exited { get; set; } public bool Disposed; public int Packets;
        public ForwardingTransport(IPEndPoint remote) { this.remote = remote; ClientEndpoint = (IPEndPoint)socket.Client.LocalEndPoint!; pump = Pump(); }
        async Task Pump()
        {
            while (!stop.IsCancellationRequested) {
                var packet = await socket.ReceiveAsync(stop.Token); Interlocked.Increment(ref Packets);
                if (packet.RemoteEndPoint.Equals(remote)) { if (local != null) await socket.SendAsync(packet.Buffer, local, stop.Token); }
                else { local = packet.RemoteEndPoint; await socket.SendAsync(packet.Buffer, remote, stop.Token); }
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
        public Func<byte[], IPEndPoint, Task>? RedirectPong;
        public PeerEndpoint(MeshLink link) { this.link = link; Endpoint = (IPEndPoint)socket.Client.LocalEndPoint!; pump = Pump(); }
        public Task Send(byte[] bytes, IPEndPoint to) => socket.SendAsync(bytes, to, stop.Token).AsTask();
        async Task Pump()
        {
            while (!stop.IsCancellationRequested) {
                var packet = await socket.ReceiveAsync(stop.Token); var message = link.Receive(packet.Buffer); Interlocked.Increment(ref Received);
                if (message.Packet != null) Interlocked.Increment(ref DataPackets);
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
