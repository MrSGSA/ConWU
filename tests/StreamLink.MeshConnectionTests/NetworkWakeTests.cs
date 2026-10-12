using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.ServiceProcess;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    static async Task NetworkWake(string output)
    {
        var rows = new List<object>();
        try {
            long now = 0;
            using (var wake = new MeshNetworkWake(false, () => now)) {
                wake.Signal(false); now = 249; Check(!wake.Take(now), "network hints wait for the quiet debounce window");
                now = 250; Check(wake.Take(now) && !wake.Take(now), "network hint is delivered once after 250ms");
                for (int i = 0; i < 100; i++) { now++; wake.Signal(false); }
                now = 2249; Check(!wake.Take(now), "address storms cannot bypass the shared two-second wake interval");
                now = 2250; Check(wake.Take(now) && !wake.Take(now), "coalesced address storm eventually produces one wake");
                wake.Dispose(); now += 5000; wake.Signal(true); MeshNetworkWake.ResumeAll();
                Check(!wake.Take(now), "disposed runner cannot be revived by a late network or resume event");
            }
            using (var wake = new MeshNetworkWake(false, () => now)) {
                for (int i = 0; i < 11; i++) { wake.Signal(false); now += 100; }
                Check(wake.Take(now), "continuous notifications have a bounded one-second debounce instead of indefinite starvation");
            }
            using (var host = Host.CreateApplicationBuilder().Build())
            using (var service = new StreamLinkServiceLifetime(host.Services.GetRequiredService<IHostEnvironment>(),
                host.Services.GetRequiredService<IHostApplicationLifetime>(), host.Services.GetRequiredService<ILoggerFactory>(),
                Options.Create(new HostOptions()), Options.Create(new WindowsServiceLifetimeOptions { ServiceName = "StreamLink" })))
            using (var wake = new MeshNetworkWake(false, () => now)) {
                Check(service.CanHandlePowerEvent && service.ServiceName == "StreamLink", "service lifetime enables SCM power commands while retaining the service identity");
                var callback = typeof(StreamLinkServiceLifetime).GetMethod("OnPowerEvent", BindingFlags.NonPublic | BindingFlags.Instance)!;
                callback.Invoke(service, [PowerBroadcastStatus.Suspend]); Check(!wake.Take(now), "suspend callback does not close or restart business resources");
                foreach (var reason in new[] { PowerBroadcastStatus.ResumeAutomatic, PowerBroadcastStatus.ResumeSuspend, PowerBroadcastStatus.ResumeCritical }) {
                    now += 2500; callback.Invoke(service, [reason]);
                    Check(wake.Take(now) && !wake.Take(now), reason + ": actual service callback coalesces a runner wake without requiring a desktop");
                }
                rows.Add(new { powerCallback = "Pass", realScmDispatch = false, realSuspend = false });
            }
            rows.Add(await ProbeWake());
            Directory.CreateDirectory(Path.GetDirectoryName(output)!);
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows,
                scope = "production legacy MeshRunner, real Windows UDP forwarded encrypted path; mapping/adapter/OS signals are fixtures; actual SCM callback method invoked without installing or starting a service" }, new JsonSerializerOptions { WriteIndented = true }));
        } catch (Exception ex) {
            Directory.CreateDirectory(Path.GetDirectoryName(output)!);
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, error = ex.ToString() }, new JsonSerializerOptions { WriteIndented = true })); throw;
        }
    }
    static async Task<object> ProbeWake()
    {
        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp"); var guest = Guest(owner); guest.Directory = owner.Directory;
        byte[] key = MeshIdentity.SharedKey(guest, owner.Self);
        using var peer = new MeshLink(2, 1, key); System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
        await using var endpoint = new PeerEndpoint(peer);
        var discovery = new Discovery(owner, guest, endpoint.Endpoint.ToString());
        var adapter = new MemoryAdapter(); var mapping = new Mapping(); using var wake = new MeshNetworkWake(false);
        var transports = new ConcurrentBag<IMeshTransport>(); var logs = new ConcurrentQueue<string>(); int probes = 0, adapters = 0;
        SessionStatus? status = null;
        string folder = Path.Combine(Path.GetTempPath(), "streamlink-network-wake-" + Guid.NewGuid().ToString("N"));
        var services = new MeshRuntimeServices(_ => discovery, _ => { Interlocked.Increment(ref adapters); return Task.FromResult<IPacketAdapter>(adapter); },
            (_, _, _) => Interlocked.Increment(ref probes) == 1 ? Task.FromException<IMapping>(new IOException("initial interface not ready")) : Task.FromResult<IMapping>(mapping),
            request => { IMeshTransport transport = request.Server ? new StubTransport(null) : new ForwardingTransport(request.Target); transports.Add(transport); return transport; },
            (_, _, token) => Task.Delay(Timeout.Infinite, token), (_, _, _) => { }, (_, _) => { }, folder) {
                NetworkWake = () => wake, Candidates = (_, _, _, _) => Task.FromResult<IMeshCandidateFactory?>(null)
            };
        var runner = new MeshRunner(new DeviceProfile { Mesh = owner }, logs.Enqueue, s => status = s, _ => { }, _ => { }, services);
        using var stop = new CancellationTokenSource(); Task running = runner.Run(stop.Token); double retryMs = 0, refreshMs = 0;
        try {
            await Until(() => logs.Any(l => l.StartsWith("入口暂不可用")), "first entry probe fails with the normal five-second backoff", 1500);
            Check(probes == 1, "failed entry is not retried continuously before a network hint");
            var clock = Stopwatch.StartNew(); wake.Signal(true);
            await Until(() => probes == 2 && transports.OfType<StubTransport>().Any(), "resume wakes the failed entry probe without waiting five seconds", 1500); retryMs = clock.Elapsed.TotalMilliseconds;
            await Until(() => status?.Connected == true, "same production Runner authenticates its independent direct peer path");
            int count = transports.Count; var server = transports.OfType<StubTransport>().Single(); var client = transports.OfType<ForwardingTransport>().Single();
            clock.Restart(); wake.Signal(true);
            await Until(() => mapping.Refreshes == 1, "network wake requests refresh from the held mapping instead of rebinding its port", 3500); refreshMs = clock.Elapsed.TotalMilliseconds;
            Check(!server.Disposed && !client.Disposed && transports.Count == count && probes == 2 && adapters == 1 && status?.Connected == true,
                "healthy native listener, active peer transport and virtual adapter survive the wake unchanged");
            int refreshBefore = mapping.Refreshes; for (int i = 0; i < 1000; i++) wake.Signal(false);
            await Task.Delay(400);
            Check(mapping.Refreshes == refreshBefore && transports.Count == count && probes == 2,
                "notification storm cannot create helper pulses, workers, sockets or mapping retries for every event");
        } finally {
            await Stop(running, stop);
            foreach (var d in Directory.EnumerateDirectories(folder)) Directory.Delete(d); Directory.Delete(folder);
        }
        Check(adapter.Disposed && mapping.Disposed && transports.All(t => t is StubTransport s ? s.Disposed : ((ForwardingTransport)t).Disposed),
            "wake-aware runner joins and retires its original resources on explicit stop");
        return new { retryMs, refreshMs, probes, adapters, helperRefreshHints = mapping.Refreshes, physicalInterfaceChange = false,
            scope = "actual encrypted UDP forwarded path and default legacy Runner; entry helper and notification source are controlled fixtures" };
    }
}
