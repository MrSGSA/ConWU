using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    // Real encrypted loopback traffic, with only the old client's uplink cut.
    // Inbound authenticated probes continue. They must not count as proof that
    // our outbound traffic can reach this peer through the same path.
    static async Task HalfOpenRecovery(string? output = null)
    {
        var owner = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var guest = Guest(owner); guest.Directory = owner.Directory;
        byte[] key = MeshIdentity.SharedKey(guest, owner.Self);
        using var peer = new MeshLink(2, 1, key); CryptographicOperations.ZeroMemory(key);
        await using var endpoint = new PeerEndpoint(peer);
        var adapter = new MemoryAdapter(); await using var router = new MeshRouter(owner, adapter);
        var transports = new List<ForwardingTransport>();
        using var paths = new MeshPeerTransports(router, ep => {
            var transport = new ForwardingTransport(System.Net.IPEndPoint.Parse(ep));
            transports.Add(transport); return transport;
        }, Console.WriteLine);
        string remote = endpoint.Endpoint.ToString();
        paths.Update(2, remote, "peer", "验证中");
        await Until(() => router.HasHealthyPath(2), "half-open fixture begins with an authenticated round trip");
        paths.Update(2, remote, "peer", "验证中");
        var original = transports.Single(); original.MuteUplink = true;
        var clock = Stopwatch.StartNew(); int inbound = 0; bool detected = false;
        using var stop = new CancellationTokenSource();
        Task probes = Task.Run(async () => {
            while(!stop.IsCancellationRequested) {
                await endpoint.Send(peer.ProbePath(Random.Shared.NextInt64())!, original.ClientEndpoint);
                Interlocked.Increment(ref inbound); await Task.Delay(60, stop.Token);
            }
        });
        try {
            while(clock.ElapsedMilliseconds < 19000 && transports.Count == 1) {
                if(!router.HasHealthyPath(2))detected = true;
                paths.Update(2, remote, "peer", "恢复中");
                await Task.Delay(50);
            }
            Check(detected && transports.Count == 2 && inbound > 100,
                "one-way authenticated traffic cannot keep a dead uplink healthy; same endpoint gets a new client");
            Check(!original.Disposed && !adapter.Disposed,
                "recovery retains the old transport and virtual adapter while replacement is unproven");
            await Until(() => router.UsesPath(2, transports[1].ClientEndpoint),
                "independently bound replacement proves its own round trip");
            paths.Update(2, remote, "peer", "恢复中");
            Check(original.Disposed && !transports[1].Disposed && !adapter.Disposed,
                "only the proven replacement retires the old client");
            adapter.Outgoing.Add(Packet(owner.LocalIp, guest.LocalIp));
            await Until(() => endpoint.DataPackets > 0, "full MTU business resumes after one-way failure");
            if(output != null) {
                Directory.CreateDirectory(Path.GetDirectoryName(output)!);
                await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new {
                    status="Pass", elapsedMs=clock.ElapsedMilliseconds, inboundAuthenticatedProbes=inbound,
                    transports=transports.Count, adapterRecreated=false,
                    scope="production MeshRouter + compatibility manager, real encrypted UDP loopback; one old-client direction blackholed; physical WAN and native capture not covered"
                }, new JsonSerializerOptions { WriteIndented=true }));
            }
        } finally {
            stop.Cancel();try { await probes; } catch(OperationCanceledException) { }
        }
    }
}
