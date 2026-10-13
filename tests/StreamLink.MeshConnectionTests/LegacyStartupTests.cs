using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    static async Task Startup(string? output = null)
    {
        var rows = new List<object>();
        var queue = new LegacyStartupQueue();
        using (var release = new ManualResetEventSlim())
        using (var entered = new ManualResetEventSlim())
        using (var stop = new CancellationTokenSource()) {
            var native = new StubTransport(null); int others = 0;
            var blocked = queue.Start(() => { entered.Set(); release.Wait(); return native; }, stop.Token);
            Check(entered.Wait(2000), "actual background constructor holds the one startup slot");
            using var queuedStop = new CancellationTokenSource();
            var cancelled = queue.Start(() => { Interlocked.Increment(ref others); return new StubTransport(null); }, queuedStop.Token);
            var remaining = Enumerable.Range(0, 6).Select(_ => queue.Start(() => { Interlocked.Increment(ref others); return new StubTransport(null); }, CancellationToken.None)).ToArray();
            try {
                await Task.Delay(80);
                Check(others == 0 && !blocked.IsCompleted, "seven waiters cannot run parallel native constructors");
                queuedStop.Cancel(); bool rejected = false; try { await cancelled; } catch (OperationCanceledException) { rejected = true; }
                Check(rejected && others == 0, "cancelled queued startup never enters its constructor");
                stop.Cancel(); release.Set(); rejected = false; try { await blocked; } catch (OperationCanceledException) { rejected = true; }
                Check(rejected && native.Disposed, "in-flight constructor is joined and its cancelled result retired");
                foreach (var result in await Task.WhenAll(remaining)) result.Dispose();
                Check(others == 6, "startup slot returns to the remaining fair queue after cancellation");
            } finally { release.Set(); try { (await blocked).Dispose(); } catch (OperationCanceledException) { } foreach (var task in remaining) (await task).Dispose(); }
        }
        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp"); var guest = Guest(owner); guest.Directory = owner.Directory;
        byte[] key = MeshIdentity.SharedKey(guest, owner.Self);
        using var peer = new MeshLink(2, 1, key); CryptographicOperations.ZeroMemory(key);
        await using var first = new PeerEndpoint(peer);
        await using var stale = new PeerEndpoint(peer) { SuppressPong = true };
        var adapter = new MemoryAdapter(); await using var router = new MeshRouter(owner, adapter);
        router.SetCandidate(2, first.Endpoint, "peer", "");
        await Until(() => router.UsesPath(2, first.Endpoint), "existing path authenticates before startup/cancel checks");
        using (var release = new ManualResetEventSlim())
        using (var entered = new ManualResetEventSlim()) {
            var pending = new StubTransport(stale.Endpoint);
            await using var paths = new MeshPeerTransports(router, (_, token) => queue.Start(() => { entered.Set(); release.Wait(); return pending; }, token), _ => { });
            var watch = Stopwatch.StartNew(); paths.Update(2, stale.Endpoint.ToString(), "peer", "");
            Check(watch.ElapsedMilliseconds < 200 && paths.HasPending, "production path tick returns while a constructor is synchronously blocked");
            Check(entered.Wait(2000), "pending constructor really entered before cancellation");
            paths.InvalidatePreparation(2);
            var closing = paths.DisposeAsync().AsTask();
            Check(!closing.IsCompleted && router.UsesPath(2, first.Endpoint), "shutdown waits for the owned constructor while the unrelated active path stays usable");
            release.Set(); await closing.WaitAsync(TimeSpan.FromSeconds(3));
            Check(pending.Disposed && router.UsesPath(2, first.Endpoint), "late cancelled constructor result cannot register or replace Active");
        }
        router.SetCandidate(2, stale.Endpoint, "peer", "checking");
        await Until(() => stale.LastSuppressedPong != null, "test holds an actual authenticated candidate challenge reply");
        byte[] oldPong = stale.LastSuppressedPong!;
        router.CancelLegacyCandidate(2, stale.Endpoint);
        router.SetCandidate(2, first.Endpoint, "peer", "active retained");
        await stale.Send(oldPong, router.LocalEndpoint); await stale.Send(peer.Hello(), router.LocalEndpoint);
        await Task.Delay(300);
        Check(router.UsesPath(2, first.Endpoint), "cancelled candidate cannot return a late challenge or trigger a fresh probe through unsolicited Hello");
        router.SetCandidate(2, stale.Endpoint, "peer", "fresh explicit registration"); stale.SuppressPong = false;
        await Until(() => router.UsesPath(2, stale.Endpoint), "explicit new registration of that endpoint still requires and completes a fresh challenge");
        rows.Add(new { cancelledConstructors = true, latePongRejected = true, oldPathRetained = true, fullProductionRunner = false,
            scope = "production startup queue/path manager/Router, real UDP encrypted frames, memory IP adapter and blocked constructor fixture; no native process, driver, installed service or WAN" });
        rows.Add(await StartupRunner());
        if (output != null) { Directory.CreateDirectory(Path.GetDirectoryName(output)!); await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows }, new JsonSerializerOptions { WriteIndented = true })); }
    }
    static async Task<object> StartupRunner()
    {
        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp"); var guest = Guest(owner); guest.Directory = owner.Directory;
        byte[] key = MeshIdentity.SharedKey(guest, owner.Self); using var peer = new MeshLink(2, 1, key); CryptographicOperations.ZeroMemory(key);
        await using var remote = new PeerEndpoint(peer);
        var adapter = new MemoryAdapter(); var discovery = new Discovery(owner, guest, remote.Endpoint.ToString());
        using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        ForwardingTransport? transport = null; SessionStatus? status = null; int creations = 0;
        string root = Path.Combine(Path.GetTempPath(), "streamlink-startup-runner-" + Guid.NewGuid().ToString("N"));
        var services = new MeshRuntimeServices(_ => discovery, _ => Task.FromResult<IPacketAdapter>(adapter),
            async (_, _, token) => { await Task.Delay(Timeout.Infinite, token); throw new IOException(); },
            request => {
                Interlocked.Increment(ref creations); transport = new(remote.Endpoint); request.ReserveEndpoint?.Invoke(transport.ClientEndpoint);
                entered.Set(); release.Wait(); return transport;
            }, (_, _, token) => Task.Delay(Timeout.Infinite, token), (_, _, _) => { }, (_, _) => { }, root) {
                Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(null)
            };
        var runner = new MeshRunner(new DeviceProfile { Mesh = owner }, _ => { }, s => status = s, _ => { }, _ => { }, services);
        using var stop = new CancellationTokenSource(); Task running = runner.Run(stop.Token);
        try {
            await Until(() => entered.IsSet, "formal Runner starts its real blocked constructor in the background");
            int reads = discovery.Reads; long revision = discovery.Published.Last().Revision;
            await Until(() => discovery.Reads > reads, "formal Runner keeps discovery alive while native preparation is blocked", 4000);
            Check(creations == 1 && status?.Connected != true, "formal Runner neither duplicates startup nor announces usable business before preparation");
            release.Set();
            await Until(() => status?.Connected == true, "formal Runner publishes completed preparation and authenticates its own path");
            adapter.Outgoing.Add(Packet(owner.LocalIp, guest.LocalIp));
            await Until(() => remote.DataPackets == 1, "full-MTU encrypted IP traverses the async prepared production path");
        } finally { release.Set(); await Stop(running, stop); }
        Check(adapter.Disposed && transport?.Disposed == true && discovery.Disposed && creations == 1,
            "formal Runner stop joins startup and closes its original adapter/transport/discovery");
        return new { fullProductionRunner = true, creations, reads = discovery.Reads, driver = false,
            scope = "production MeshRunner including pre-launch endpoint reservation, real UDP encrypted path; blocked constructor and IP adapter are fixtures" };
    }
}
