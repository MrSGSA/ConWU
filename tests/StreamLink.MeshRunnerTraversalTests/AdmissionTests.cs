using System.Net;
using StreamLink.Core;
using StreamLink.Service;

static class AdmissionTests
{
    public static async Task Run(string executable, string root, Action<bool, string> check, CancellationToken token)
    {
        var budget = new MeshRequestBudget();
        for (int i = 0; i < 4; i++) check(budget.Take(), "ordinary discovery uses its shared request allowance");
        check(!budget.Take() && budget.Take(true) && budget.Take(true) && !budget.Take(true), "ordinary HTTP preserves two completion tokens and cannot bypass the common burst");
        var mesh = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var peers = new List<MeshProfile>(); for (int i = 0; i < 7; i++) peers.Add(MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(mesh))));
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        var discovery = new Discovery(); var factory = new PendingFactory();
        await using var router = new MeshRouter(mesh, new EmptyAdapter(), discovery.BootId, new(AllowUdpFallback: true));
        await using var manager = new MeshTraversalManager(mesh, router, discovery, factory, new(), _ => { }, stop.Token);
        var announcements = peers.ToDictionary(p => p.Self.Slot, p => new MeshAnnouncement(p.Self.Slot, p.Self.Device, 1,
            DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), "", "test", new(1, 0, Guid.NewGuid(), [TraversalProfile.UdpDirect])));
        manager.Tick(announcements, ""); manager.Tick(announcements, "");
        check(factory.Visited.SequenceEqual(new[] { 2, 3 }), "seven waiting peers admit exactly two concurrent light endpoint preparations");
        MeshIdentity.Revoke(mesh, 2); router.ApplyDirectory(mesh.Directory!);
        for (int i = 0; i < 15 && factory.Visited.Count < 3; i++) { manager.Tick(announcements, ""); await Task.Delay(10, token); }
        check(factory.Cancelled >= 1 && factory.Visited.SequenceEqual(new[] { 2, 3, 4 }), "revocation cancels in-flight gathering and fairly admits the next peer without exceeding two slots");
        stop.Cancel(); await manager.DisposeAsync();
        check(factory.Cancelled == 3 && factory.Live == 0, "scheduler shutdown joins every admitted endpoint preparation");

        // A signed peer request cannot re-enable a locally forbidden protocol.
        foreach (var selection in new[] { new PathSelection(), new PathSelection(PathPolicy.FakeTcpOnly, true) }) {
            var owner = MeshIdentity.Create("https://example.com/", "", "faketcp");
            var guest = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner))); guest.Directory = owner.Directory;
            var control = new Discovery(); var mixed = new PendingFactory(TraversalProfile.FakeTcpHttpSo, TraversalProfile.UdpDirect);
            await using var limitedRouter = new MeshRouter(guest, new EmptyAdapter(), control.BootId, selection);
            await using var limited = new MeshTraversalManager(guest, limitedRouter, control, mixed, new(), _ => { }, token);
            check(limited.Capabilities.Profiles.SequenceEqual(new[] { TraversalProfile.FakeTcpHttpSo }), "advertisement filters UDP before endpoint preparation under " + selection.Policy);
            var remoteCaps = new MeshTraversalCapabilities(1, 1, Guid.NewGuid(), mixed.Profiles);
            var claimed = limited.Capabilities with { Profiles = mixed.Profiles };
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), sequence = 0;
            await using var offer = MeshTraversalAttempt.Offer(owner, guest.Self, remoteCaps, claimed, TraversalProfile.UdpDirect,
                new(Guid.NewGuid(), 1, "192.0.2.1:40001", null, now, now + 120, CandidatePurpose.UdpDirect), 1, () => ++sequence);
            limited.Receive([offer.Outbound!]); limited.Tick(new Dictionary<int, MeshAnnouncement> {
                [1] = new(1, owner.Self.Device, 1, now + 120, "", "owner", remoteCaps)
            }, "");
            check(mixed.Visited.Count == 0 && !limited.Owns(1), "authenticated unsupported UDP Offer cannot gather or reserve a path under " + selection.Policy);
        }

        using (var heavyStop = CancellationTokenSource.CreateLinkedTokenSource(token)) {
            var heavyDiscovery = new Discovery(); var heavyFactory = new PendingFactory(TraversalProfile.FakeTcpHttpSo);
            await using var heavyRouter = new MeshRouter(mesh, new EmptyAdapter(), heavyDiscovery.BootId);
            await using var heavy = new MeshTraversalManager(mesh, heavyRouter, heavyDiscovery, heavyFactory, new(), _ => { }, heavyStop.Token);
            var nativeAnnouncements = announcements.ToDictionary(p => p.Key, p => p.Value with {
                Endpoint = "192.0.2.100:41080", Traversal = p.Value.Traversal! with { NativeAbi = 1, Profiles = [TraversalProfile.FakeTcpHttpSo] }
            });
            heavy.Tick(nativeAnnouncements, "");
            check(heavyFactory.Visited.Count == 0, "explicit entry gets the initial fast-path window before new endpoint preparation");
            await Task.Delay(15100, token); heavy.Tick(nativeAnnouncements, ""); heavy.Tick(nativeAnnouncements, "");
            check(heavyFactory.Visited.Count == 1, "unverified explicit entry cannot block traversal indefinitely; only one native attempt is admitted");
            heavyStop.Cancel(); await heavy.DisposeAsync();
            check(heavyFactory.Live == 0 && heavyFactory.Cancelled == 1, "native admission slot is released only after its pending operation ends");
        }

        string native = Path.Combine(Path.GetDirectoryName(executable)!, "udp2raw-native.exe");
        var config = new DeviceProfile { Mesh = mesh, TraversalMode = "tcp" };
        var production = await MeshCandidateFactory.Create(config, native, root, _ => { }, token);
        check(production?.Profiles.SequenceEqual(new[] { TraversalProfile.FakeTcpHttpSo }) == true, "production capability preflight requires explicit prepared/SO flags on the WinDivert build without loading a driver");
        var wrongBackend = await MeshCandidateFactory.Create(config, executable, root, _ => { }, token);
        check(wrongBackend == null, "test backend cannot be advertised as production WinDivert capability");
        config.TraversalMode = "tcp-udp";
        check(await MeshCandidateFactory.Create(config, executable, root, _ => { }, token) == null, "production collector does not enable UDP solely because traversal mode includes UDP");
        config.AllowUdpFallback = true;
        check((await MeshCandidateFactory.Create(config, executable, root, _ => { }, token))?.Profiles.SequenceEqual(new[] { TraversalProfile.UdpDirect }) == true,
            "explicit fallback permission enables the production UDP collector even when native preflight is unavailable");
        config.PathSelection = "faketcp-only";
        check(await MeshCandidateFactory.Create(config, executable, root, _ => { }, token) == null, "FakeTcpOnly also filters production collection with fallback permission retained");
        config.TraversalMode = "legacy";
        check(await MeshCandidateFactory.Create(config, "nonexistent.exe", root, _ => { }, token) == null, "legacy configuration starts no new native process or candidate collection");
    }
    sealed class PendingFactory(params TraversalProfile[] kinds) : IMeshCandidateFactory
    {
        public readonly List<int> Visited = []; public int Live, Cancelled;
        public TraversalProfile[] Profiles => kinds.Length == 0 ? [TraversalProfile.UdpDirect] : kinds;
        public async Task<IMeshCandidateResource> Gather(MeshMember peer, TraversalProfile profile, Guid attempt, CancellationToken token)
        {
            Visited.Add(peer.Slot); Interlocked.Increment(ref Live);
            try { await Task.Delay(Timeout.Infinite, token); throw new InvalidOperationException(); }
            finally { Interlocked.Increment(ref Cancelled); Interlocked.Decrement(ref Live); }
        }
    }
    sealed class Discovery : IMeshTraversalDiscovery {
        public Guid BootId { get; } = Guid.NewGuid(); public bool SupportsTraversal => true;
        public Task PublishTraversal(MeshTraversalMessage[] messages, CancellationToken token) => Task.CompletedTask;
    }
    sealed class EmptyAdapter : IPacketAdapter {
        public int Read(byte[] buffer) { Thread.Sleep(10); return 0; }
        public bool Write(byte[] packet) => true;
        public void Dispose() { }
    }
}
