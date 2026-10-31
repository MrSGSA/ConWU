using System.Collections.Concurrent;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    static async Task EntryProbeReuse()
    {
        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var guest = Guest(owner); var offline = Guest(owner); guest.Directory = owner.Directory;
        var peers = new[] { guest.Self, offline.Self };
        var nodes = new Dictionary<int, MeshAnnouncement>();
        bool Healthy(int slot) => slot == guest.Self.Slot;
        Check(!MeshRunner.NeedsEntryProbe(peers, nodes, Healthy, 100), "offline members do not restart optional entry discovery beside a healthy path");
        nodes[offline.Self.Slot] = new(offline.Self.Slot, offline.Self.Device, 1, 99, "", "offline");
        Check(!MeshRunner.NeedsEntryProbe(peers, nodes, Healthy, 100), "expired announcements cannot keep optional probes running");
        nodes[offline.Self.Slot] = nodes[offline.Self.Slot] with { Expires = 200 };
        Check(MeshRunner.NeedsEntryProbe(peers, nodes, Healthy, 100), "new online unconnected member can resume local entry discovery");
        Check(MeshRunner.NeedsEntryProbe(peers, nodes, _ => false, 100), "loss of the last healthy path resumes discovery without weakening health proof");
        byte[] key = MeshIdentity.SharedKey(guest, owner.Self);
        using var peer = new MeshLink(guest.Self.Slot, owner.Self.Slot, key); System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
        await using var endpoint = new PeerEndpoint(peer);
        var discovery = new Discovery(owner, guest, endpoint.Endpoint.ToString()); var adapter = new MemoryAdapter();
        var transports = new ConcurrentBag<ForwardingTransport>(); var logs = new ConcurrentQueue<string>();
        int probes = 0; SessionStatus? status = null;
        string folder = Path.Combine(Path.GetTempPath(), "streamlink-entry-probe-" + Guid.NewGuid().ToString("N"));
        var services = new MeshRuntimeServices(_ => discovery, _ => Task.FromResult<IPacketAdapter>(adapter),
            (_, _, _) => { Interlocked.Increment(ref probes); return Task.FromException<IMapping>(new IOException("fixture has no gateway")); },
            request => { var t = new ForwardingTransport(request.Target); transports.Add(t); return t; },
            (_, _, ct) => Task.Delay(Timeout.Infinite, ct), (_, _, _) => { }, (_, _) => { }, folder) {
                NetworkWake = () => new MeshNetworkWake(false), Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(null)
            };
        var runner = new MeshRunner(new DeviceProfile { Mesh = owner }, logs.Enqueue, s => status = s, _ => { }, _ => { }, services);
        using var stop = new CancellationTokenSource(); var running = runner.Run(stop.Token);
        try {
            await Until(() => status?.Connected == true, "real Runner authenticates the peer while its own optional mapping fails");
            await Until(() => logs.Any(l => l.StartsWith("现有在线成员已直连")), "normal probe retry is deferred after a healthy direct path", 6500);
            Check(probes == 1 && transports.Count == 1 && !transports.Single().Disposed && !adapter.Disposed,
                "automatic retry deadline does not re-probe, replace transport or close the adapter");
            runner.RequestRetry();
            await Until(() => probes == 2, "explicit retry still requests an entry probe beside the retained path");
            Check(transports.Count == 1 && !transports.Single().Disposed, "explicit entry retry also preserves the healthy business transport");
        } finally {
            await Stop(running, stop);
            foreach (var d in Directory.EnumerateDirectories(folder)) Directory.Delete(d); Directory.Delete(folder);
        }
    }
}
