using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.EndpointPoc;

static partial class PortControlTests
{
    public static async Task TcpMappingWake(string output, Action<bool, string> check)
    {
        int passed = 0; var rows = new List<object>();
        void Check(bool ok, string why) { check(ok, why); passed++; Console.WriteLine("PASS " + why); }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20)); var token = timeout.Token;
        try {
            await using var gateway = new Server { Lifetime = 180 };
            await using var reflector = new Reflector();
            using var free = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            free.Bind(new IPEndPoint(IPAddress.Loopback, 0)); int port = ((IPEndPoint)free.LocalEndPoint!).Port; free.Dispose();
            var lease = await PortControlLease.Open(gateway.Route, 41308, 0, PortMappingProtocol.Tcp, () => true, token);
            TcpBinding? binding = null; TcpMapping? mapping = null;
            try {
                (binding, var observed) = await TcpBinding.Connect(port, IPAddress.Loopback, _ => { }, token, [reflector.Endpoint.ToString()]);
                mapping = new TcpMapping(lease, binding, observed, _ => { });
                var before = mapping.HelperResource; int gatewayCreates = gateway.Creates;
                for (int i = 0; i < 1000; i++) mapping.RequestRefresh();
                var clock = Stopwatch.StartNew(); var maintaining = mapping.Maintain(token);
                await Wait(() => reflector.Requests == 2 && mapping.HelperResource.QueryUsable, token);
                double refreshedMs = clock.Elapsed.TotalMilliseconds;
                Check(refreshedMs < 1500 && reflector.Accepted == 1 && mapping.HelperResource.LeaseId == before.LeaseId &&
                    mapping.HelperResource.Local == before.Local && !maintaining.IsCompleted,
                    "coalesced wake pulses the same held TCP helper/resource/source endpoint before the ten-second timer");
                await Task.Delay(400, token);
                Check(reflector.Requests == 2 && reflector.Accepted == 1 && gateway.Creates == gatewayCreates,
                    "one thousand queued refresh hints cause one helper query and no premature gateway renewal");
                Check(mapping.PublicEndpoint.Equals(TcpMapping.GatewayCandidate(lease)) && mapping.PublicEndpoint.Port != port && mapping.IsValid,
                    "helper refresh never overwrites the explicit Q public entry with helper P observation");
                rows.Add(new { refreshedMs, acceptedConnections = reflector.Accepted, helperRequests = reflector.Requests,
                    sameLease = before.LeaseId == mapping.HelperResource.LeaseId, sameLocalEndpoint = before.Local == mapping.HelperResource.Local,
                    extraGatewayCreates = gateway.Creates - gatewayCreates });
                await mapping.DisposeAsync(); mapping.RequestRefresh();
                await Wait(() => reflector.Active == 0, token);
                Check(mapping.HelperResource.Closed && gateway.Deletes == 1 && !mapping.IsValid,
                    "mapping stop closes its held helper and exact gateway grant; late wake is harmless");
            } finally {
                if (mapping != null) await mapping.DisposeAsync();
                else { binding?.Dispose(); await lease.DisposeAsync(); }
            }
            Directory.CreateDirectory(Path.GetDirectoryName(output)!);
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks = passed, rows,
                scope = "real Windows TCP/STUN and loopback PCP gateway datagrams; gateway behavior is a fixture, no physical NAT/router/service mutation" }, new JsonSerializerOptions { WriteIndented = true }));
        } catch (Exception ex) {
            Directory.CreateDirectory(Path.GetDirectoryName(output)!);
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks = passed, rows, error = ex.ToString() }, new JsonSerializerOptions { WriteIndented = true })); throw;
        }
    }
}
