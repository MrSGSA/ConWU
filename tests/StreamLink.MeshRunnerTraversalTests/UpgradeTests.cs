using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

static class UpgradeTests
{
    public static async Task<object> Run(string binary, string root, string url, string pin, Action<bool, string> check, CancellationToken token)
    {
        var a = MeshIdentity.Create(url, pin, "faketcp");
        var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
        var meshes = new[] { a, b }; var adapters = new[] { new Adapter(), new Adapter() };
        var states = new SessionStatus?[2]; var logs = new ConcurrentQueue<string>();
        await using var reflector = new Reflector(); await using var wires = new Wires();
        var factories = meshes.Select(m => new MixedFactory(m, binary, root, reflector, wires)).ToArray();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        var tasks = Enumerable.Range(0, 2).Select(i => {
            var services = new MeshRuntimeServices(m => new CompatibleDiscovery(m, wires), _ => Task.FromResult<IPacketAdapter>(adapters[i]),
                async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new InvalidOperationException(); },
                _ => throw new IOException("no legacy entry in upgrade fixture"), (_, _, ct) => Task.Delay(Timeout.Infinite, ct),
                (_, _, _) => { }, (_, _) => { }, Path.Combine(root, "upgrade")) {
                    Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(factories[i])
                };
            return new MeshRunner(new() { Mesh = meshes[i], TraversalMode = "tcp-udp", PathSelection = "prefer-faketcp", AllowUdpFallback = true },
                s => logs.Enqueue(i + " " + s), s => states[i] = s, _ => { }, _ => { }, services).Run(stop.Token);
        }).ToArray();
        var watch = Stopwatch.StartNew(); long udpAt = 0, failedAt = 0, upgradedAt = 0;
        int sent = 0; bool carry = false, sawDisconnected = false; long nextData = 0;
        async Task Until(Func<bool> condition, string why, int ms) {
            long began = watch.ElapsedMilliseconds;
            while (!condition()) {
                foreach (var task in tasks) if (task.IsCompleted) await task;
                if (watch.ElapsedMilliseconds - began > ms) throw new TimeoutException(why + "\n" + string.Join('\n', logs));
                if (carry && watch.ElapsedMilliseconds >= nextData) {
                    nextData = watch.ElapsedMilliseconds + 100;
                    sawDisconnected |= states.Any(s => s?.Connected != true);
                    for (int i = 0; i < 2; i++) adapters[i].Outgoing.Add(Packet(meshes[i].LocalIp, meshes[1 - i].LocalIp, sent));
                    sent++;
                }
                await Task.Delay(20, token);
            }
            check(true, why);
        }
        object result;
        try {
            await Until(() => states.All(s => s?.Connected == true && s.Degraded), "Runner falls back to authenticated UDP after the initial native gathering failure", 60000);
            udpAt = watch.ElapsedMilliseconds; carry = true;
            check(udpAt < 15000, "initial method failure advances to UDP within the same foreground window without a 30-second sleep");
            var udp = factories.Select(f => f.All.Single(x => x.Udp != null).Udp!).ToArray();
            var ids = udp.Select(u => u.SocketId).ToArray();
            check(udp.All(u => !u.Closed), "UDP winning sockets remain owned before background upgrade");
            long oldCapabilityUntil = watch.ElapsedMilliseconds + TraversalLimits.UpgradeResidenceMs + 5000;
            await Until(() => watch.ElapsedMilliseconds >= oldCapabilityUntil, "legacy capability advertisement stays in use beyond the residence window", 38000);
            check(wires.Visits.Count == 1 && udp.All(u => !u.Closed), "SO support without the upgrade capability cannot trigger background endpoint allocation");
            wires.AdvertiseUpgrade = true;
            await Until(() => logs.Count(s => s.Contains("FakeTCP 升级未完成")) >= 2 && factories.All(f => f.All.Where(x => x.Tcp != null).All(x => x.Closed)),
                "both native prepared workers fail activation and are reclaimed without cancelling UDP", 50000);
            failedAt = watch.ElapsedMilliseconds;
            check(states.All(s => s?.Connected == true && s.Degraded) && udp.Select(u => u.SocketId).SequenceEqual(ids) && udp.All(u => !u.Closed),
                "failed upgrade restores selected UDP actors with the same live socket resources");
            check(wires.Visits.Where(v => v.Mode == 2).All(v => v.Tick - wires.FirstUdpTick >= TraversalLimits.UpgradeResidenceMs),
                "background attempts respect the real 30-second residence before preparation");
            await Until(() => states.All(s => s?.Connected == true && !s.Degraded), "native FakeTCP returns and both Runners jointly upgrade their live UDP paths", 95000);
            upgradedAt = watch.ElapsedMilliseconds;
            check(wires.Visits.Where(v => v.Mode == 3).All(v => v.Tick - wires.Visits.First(x => x.Mode == 2 && x.Slot == v.Slot).Tick >= TraversalLimits.UpgradeCooldownMs),
                "failed background attempts respect the real 60-second cooldown rather than busy-looping");
            await Until(() => udp.All(u => u.Closed), "UDP preparation and retired path references converge after successful nomination", 14000);
            // An expired old Offer/Cancel cannot resurrect the retired actor;
            // keep healthy FakeTCP beyond another residence window.
            int gathers = wires.Visits.Count;
            long steadyUntil = watch.ElapsedMilliseconds + TraversalLimits.UpgradeResidenceMs + 1000;
            await Until(() => watch.ElapsedMilliseconds >= steadyUntil, "healthy upgraded FakeTCP stays selected while business continues", 35000);
            check(wires.Visits.Count == gathers, "a healthy FakeTCP path does not trigger another background candidate");
            carry = false;
            await Until(() => adapters.All(d => d.Incoming.Count == sent), "all full-MTU datagrams arrive once in each direction across failed and successful upgrades", 2500);
            check(!sawDisconnected && adapters.All(d => d.Incoming.Select(p => BinaryPrimitives.ReadInt32BigEndian(p.AsSpan(20))).Distinct().Count() == sent),
                "no reported connectivity gap or duplicate application delivery during this controlled transition");
            result = new { scenario = "UDP-to-FakeTCP-product-upgrade", udpAtMs = udpAt, failedUpgradeAtMs = failedAt, upgradedAtMs = upgradedAt,
                fullMtuPacketsEachDirection = sent, residenceMs = TraversalLimits.UpgradeResidenceMs, cooldownMs = TraversalLimits.UpgradeCooldownMs,
                attempts = wires.Visits.ToArray(), realHttps = true, realUdpSockets = true, nativeTestBackend = true, realNat = false, wintun = false };
        } finally {
            stop.Cancel(); foreach (var task in tasks) try { await task.WaitAsync(TimeSpan.FromSeconds(10)); } catch (OperationCanceledException) { }
        }
        check(factories.All(f => f.All.All(x => x.Closed)) && adapters.All(d => d.Disposed), "Runner shutdown releases upgraded native resources and IP adapters");
        return result;
    }
    internal static byte[] Packet(string from, string to, int sequence) {
        byte[] p = new byte[1280]; p[0] = 0x45; p[8] = 64; p[9] = 17; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), 1280);
        IPAddress.Parse(from).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(to).GetAddressBytes().CopyTo(p, 16);
        BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(20), sequence);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i));
        while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), (ushort)~sum); return p;
    }
    sealed record Visit(int Slot, int Mode, long Tick, Guid Attempt);
    sealed class Wires : IAsyncDisposable {
        readonly object gate = new(); readonly Dictionary<Guid, (int Mode, RawProtocolProxy Proxy)> routes = [];
        readonly RawProtocolProxy udpPlaceholder = new(0, 0);
        public RawProtocolProxy GetUdpPlaceholder() => udpPlaceholder;
        public readonly ConcurrentQueue<Visit> Visits = new(); public long FirstUdpTick;
        public volatile bool AdvertiseUpgrade;
        public (int Mode, RawProtocolProxy Proxy) Get(int slot, Guid attempt) {
            lock (gate) {
                if (!routes.TryGetValue(attempt, out var route)) {
                    var proxy = new RawProtocolProxy(0, 0); proxy.Begin(); route = (routes.Count + 1, proxy); routes.Add(attempt, route);
                }
                Visits.Enqueue(new(slot, route.Mode, Environment.TickCount64, attempt)); return route;
            }
        }
        public async ValueTask DisposeAsync() { foreach (var route in routes.Values) await route.Proxy.DisposeAsync(); await udpPlaceholder.DisposeAsync(); }
    }
    sealed class CompatibleDiscovery(MeshProfile mesh, Wires wires) : IMeshDiscovery, IMeshTraversalDiscovery, IMeshChangeDiscovery {
        readonly MeshDiscoveryClient inner = new(mesh);
        public Guid BootId => inner.BootId;
        public bool SupportsTraversal => inner.SupportsTraversal;
        public bool SupportsLongPolling => inner.SupportsLongPolling;
        public Task SaveDirectory(MeshDirectory directory, CancellationToken token) => inner.SaveDirectory(directory, token);
        public Task Publish(MeshAnnouncement announcement, CancellationToken token) => inner.Publish(announcement with {
            Traversal = announcement.Traversal is {} c ? c with { BackgroundUpgrade = wires.AdvertiseUpgrade ? 1 : 0 } : null
        }, token);
        public Task<MeshSnapshot?> Read(CancellationToken token) => inner.Read(token);
        public Task<MeshSnapshot?> WaitForChanges(CancellationToken token) => inner.WaitForChanges(token);
        public Task PublishTraversal(MeshTraversalMessage[] messages, CancellationToken token) => inner.PublishTraversal(messages, token);
        public void Dispose() => inner.Dispose();
    }
    sealed class MixedFactory(MeshProfile mesh, string binary, string root, Reflector reflector, Wires wires) : IMeshCandidateFactory {
        public readonly ConcurrentQueue<Factory> All = new();
        public TraversalProfile[] Profiles => [TraversalProfile.FakeTcpHttpSo, TraversalProfile.UdpDirect];
        public async Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile profile, Guid attempt, CancellationToken token) {
            int mode = 0; RawProtocolProxy proxy;
            if (profile == TraversalProfile.FakeTcpHttpSo) {
                (mode, proxy) = wires.Get(mesh.Self.Slot, attempt);
                if (mode == 1) throw new IOException("injected initial native gathering failure");
            } else {
                Interlocked.CompareExchange(ref wires.FirstUdpTick, Environment.TickCount64, 0);
                // UDP doesn't use the raw-frame fixture, so reuse any placeholder.
                proxy = wires.GetUdpPlaceholder();
            }
            var factory = new Factory(mesh, profile, binary, root, reflector, proxy); All.Enqueue(factory);
            var resource = await factory.Gather(peer, profile, attempt, token);
            return mode == 2 ? new FailActivation(resource) : resource;
        }
    }
    sealed class FailActivation(IMeshCandidateResource resource) : IMeshCandidateResource {
        public MeshTraversalCandidate Candidate => resource.Candidate;
        public async Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context, IPEndPoint remote, CancellationToken token) => new FailedPrepared(await resource.Prepare(context, remote, token));
        public ValueTask DisposeAsync() => resource.DisposeAsync();
    }
    sealed class FailedPrepared(IPreparedMeshPath inner) : IPreparedMeshPath {
        public TraversalAttemptContext Context => inner.Context;
        public bool Armed => inner.Armed;
        public TimeSpan RemainingAttemptTime => inner.RemainingAttemptTime;
        public Task<IMeshDatagramPath> Activate(CancellationToken token) => Task.FromException<IMeshDatagramPath>(new IOException("injected native activation failure"));
        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }
}
