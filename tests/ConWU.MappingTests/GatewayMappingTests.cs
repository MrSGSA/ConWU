using System.Net;
using System.Net.Sockets;
using StreamLink.Core;

static partial class PortControlTests
{
    static async Task IndependentTcp(Action<bool, string> check, List<object> rows, CancellationToken token)
    {
        await using (var server = new Server { Lifetime = 180 }) {
            var logs = new List<string>(); int calls = 0;
            var free = new TcpListener(IPAddress.Loopback, 0); free.Start(); int source = ((IPEndPoint)free.LocalEndpoint).Port; free.Stop();
            var mapping = await GatewayMapping.SelectTcp(ct => TcpMapping.Create(source, 41301, _ => { }, ct, []),
                () => [IPAddress.Loopback], (ip, ct) => { calls++; return PortControlLease.Open(server.Route, 41301, 0, PortMappingProtocol.Tcp, () => true, ct); }, true, logs.Add, token);
            await using (mapping) {
                var lease = (GatewayMapping)mapping;
                check(calls == 1 && mapping.IsValid && lease.Snapshot.Protocol == PortMappingProtocol.Tcp && mapping.PublicEndpoint.Port == 45000 &&
                    lease.Snapshot.Local == "127.0.0.1:41301", "real TCP provider failure with no STUN servers falls back to an independent explicit Q mapping");
                using var stillFree = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
                stillFree.Bind(new IPEndPoint(IPAddress.Loopback, source)); stillFree.Listen();
                check(stillFree.IsBound, "independent explicit TCP entry retains no fake STUN binding on helper port P");
                int changed = 0; mapping.Changed += _ => changed++;
                var maintaining = mapping.Maintain(token); var key = ((byte)6, (ushort)41301); server.AssignedPorts[key] = 46301;
                await server.Notify(PcpReply(server.LastMaps[key], server.Epoch, 180, 46301, server.ExternalAddress), server.Clients[key]);
                await Wait(() => mapping.IsValid && mapping.PublicEndpoint.Port == 46301, token);
                check(changed == 1 && !maintaining.IsCompleted, "helper-free TCP entry retains renewal/notification handling and reports endpoint changes");
            }
            check(server.Deletes == 1 && server.Requests.All(p => p[0] == 2), "independent TCP shutdown deletes only its actual PCP grant and sends no STUN traffic");
            check(!mapping.IsValid, "retired independent mapping can no longer advertise an entry");
            rows.Add(new { mapping = "tcp-independent-gateway", helperUsed = false, nativeUsed = false, actualGateway = false, actualPcpDatagrams = true });
        }
        await using (var server = new Server { Lifetime = 180 }) {
            int opens = 0;
            await using var mapping = await GatewayMapping.Create(() => [IPAddress.Parse("127.0.0.2"), IPAddress.Loopback],
                (_, ct) => ++opens == 1 ? throw new IOException("unavailable first exit") : PortControlLease.Open(server.Route, 41302, 0, PortMappingProtocol.Tcp, () => true, ct), _ => { }, token);
            check(opens == 2 && mapping.IsValid && server.Deletes == 0, "failure on one physical exit does not dispose the successful next gateway resource");
        }
        await using (var server = new Server { Lifetime = 180, ExternalAddress = IPAddress.Parse("100.64.0.2") }) {
            bool rejected = false;
            try { await using var mapping = await GatewayMapping.Create(() => [IPAddress.Loopback],
                (_, ct) => PortControlLease.Open(server.Route, 41303, 0, PortMappingProtocol.Tcp, () => true, ct), _ => { }, token); }
            catch (IOException) { rejected = true; }
            check(rejected && server.Deletes == 1, "independent entry rejects inner-CGN address without borrowing a STUN address and cleans the failed grant");
        }
        await using (var server = new Server { Lifetime = 180 }) {
            await using var mapping = await GatewayMapping.SelectTcp(_ => Task.FromException<TcpMapping>(new TimeoutException("legacy observation timeout")), () => [IPAddress.Loopback],
                (_, ct) => PortControlLease.Open(server.Route, 41304, 0, PortMappingProtocol.Tcp, () => true, ct), true, _ => { }, token);
            check(mapping.IsValid, "internal legacy observation timeout does not cancel a separately viable explicit gateway entry");
        }
        foreach (bool canceled in new[] { false, true }) {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(token); if (canceled) stop.Cancel(); int selected = 0;
            bool failed = false;
            try {
                await using var mapping = await GatewayMapping.SelectTcp(_ => canceled ? Task.FromCanceled<TcpMapping>(stop.Token) : Task.FromException<TcpMapping>(new IOException("legacy failed")),
                    () => { selected++; return []; }, (_, _) => throw new Exception("must not open"), canceled, _ => { }, stop.Token);
            } catch (Exception ex) when (ex is OperationCanceledException or IOException) { failed = true; }
            check(failed && selected == 0, "independent TCP gateway fallback respects " + (canceled ? "caller cancellation" : "disabled experimental option"));
        }
    }
}
