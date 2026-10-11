using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.EndpointPoc;

static class PortControlTests
{
    public static async Task Run(Action<bool, string> check)
    {
        var rows = new List<object>(); var clock = Stopwatch.StartNew(); int passed = 0;
        void Check(bool ok, string why) { check(ok, why); passed++; Console.WriteLine("PASS " + why); }
        using var overall = new CancellationTokenSource(TimeSpan.FromSeconds(90)); var ct = overall.Token;
        for (int round = 0; round < 30; round++) {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            foreach (var protocol in new[] { PortMappingProtocol.Tcp, PortMappingProtocol.Udp }) {
                var request = PortControlProtocol.Pcp(IPAddress.Parse("192.168.1.2"), 41080, protocol, nonce, 180, new(IPAddress.Any, 40002));
                Check(request.Length == 60 && request[36] == (byte)protocol && new IPAddress(request.AsSpan(8, 16)).IsIPv4MappedToIPv6 &&
                    BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(42)) == 40002, "PCP request encodes exact protocol/local IPv4/ports without wildcard");
                var response = PcpReply(request, 7, 90, 45000, IPAddress.Parse("1.1.1.1"));
                Check(PortControlProtocol.ParsePcp(response, request) is { Lifetime: 90, Epoch: 7, External.Port: 45000 }, "parser honors assigned port and lifetime rather than requested values");
                response[24] ^= 1; Check(PortControlProtocol.ParsePcp(response, request) == null, "foreign nonce cannot establish PCP ownership");
                response[24] ^= 1; response[36] = (byte)(protocol == PortMappingProtocol.Tcp ? PortMappingProtocol.Udp : PortMappingProtocol.Tcp);
                Check(PortControlProtocol.ParsePcp(response, request) == null, "TCP and UDP mapping replies cannot be confused");
            }
        }
        Check(Math.Abs(PortControlTiming.InitialRetry(PortControlKind.Pcp, 0) - 2.7) < 1e-10 && Math.Abs(PortControlTiming.InitialRetry(PortControlKind.Pcp, 1) - 3.3) < 1e-10 &&
            PortControlTiming.NextRetry(PortControlKind.NatPmp, .25, 0) == .5 && PortControlTiming.NextRetry(PortControlKind.NatPmp, 64, 0) == 64, "protocol retransmission intervals retain PCP jitter and NAT-PMP exponential schedule");
        Check(PortControlTiming.PcpRenewFraction(1, 0) == .5 && PortControlTiming.PcpRenewFraction(1, 1) == .625 &&
            PortControlTiming.PcpRenewFraction(2, 0) == .75 && PortControlTiming.PcpRenewFraction(3, 0) == .875, "PCP renewal fractions use granted expiry, independently of UPnP timing");
        Check(!PortControlTiming.EpochChanged(PortControlKind.Pcp, 100, 101, 1) && PortControlTiming.EpochChanged(PortControlKind.Pcp, 100, 0, 1) &&
            PortControlTiming.EpochChanged(PortControlKind.Pcp, 100, 140, 2) && PortControlTiming.EpochChanged(PortControlKind.NatPmp, 100, 100, 10), "protocol-specific epoch drift and reboot detection");
        Check(!PortControlRoute.GlobalV4(IPAddress.Parse("100.64.0.1")) && !PortControlRoute.GlobalV4(IPAddress.Parse("192.168.1.1")) &&
            !PortControlRoute.GlobalV4(IPAddress.Parse("203.0.113.1")) && PortControlRoute.GlobalV4(IPAddress.Parse("1.1.1.1")), "private/CGN/documentation addresses are not published as global gateway candidates");
        rows.Add(new { scope = "deterministic packet codec", rounds = 30, tcp = true, udp = true, nat = false });
        {
            var request = PortControlProtocol.Pcp(IPAddress.Loopback, 41080, PortMappingProtocol.Tcp, RandomNumberGenerator.GetBytes(12), 180, new(IPAddress.Any, 40002));
            var response = PcpReply(request, 100, 8, 45000, IPAddress.Parse("1.1.1.1"));
            byte[] withOption = [.. response, 1, 0, 0, 0];
            Check(PortControlProtocol.ParsePcp(withOption, request) != null, "client ignores unknown response options including mandatory-range codes per RFC 6887");
            withOption[^1] = 8;
            Check(PortControlProtocol.ParsePcp(withOption, request) == null && PortControlProtocol.ParsePcp(response[..24], request) == null,
                "truncated MAP and structurally invalid options cannot establish ownership");
            var defaults = JsonSerializer.Deserialize<DeviceProfile>("{}")!;
            var oldService = JsonSerializer.Deserialize<ControlReply>("{\"Ok\":true}")!;
            Check(!defaults.PortControlMapping && oldService.PortControlVersion == 0, "old profiles and old services leave new mapping capability disabled");
        }

        await using (var server = new Server { PoisonFirst = true }) {
            var resources = new TraversalResources(1); var route = server.Route;
            await using var lease = await PortControlLease.Open(route, 41080, 40002, PortMappingProtocol.Tcp, () => true, ct, resources);
            Check(lease.Valid && lease.External.Port == 45000 && lease.Snapshot.Ownership == "PcpNonce" && lease.Snapshot.Lifetime == 8, "real loopback PCP ignores wrong-source/nonce/op packets, then accepts exact grant");
            bool busy = false; try { await using var duplicate = await PortControlLease.Open(route, 41080, 40002, PortMappingProtocol.Tcp, () => true, ct); } catch (IOException) { busy = true; }
            Check(busy && server.Creates == 1, "second local owner cannot acquire the same internal tuple");
            await lease.DisposeAsync();
            Check(server.Deletes == 1 && lease.Snapshot.Cleanup == "DeleteConfirmed" && server.Requests.Where(p => p.Length == 60).All(p => p.AsSpan(24, 12).SequenceEqual(server.FirstNonce)), "PCP cleanup is exact nonce/protocol/internal port, with no wildcard deletion");
            using var released = resources.Acquire(); Check(lease.Snapshot.State == "Closed", "cleanup releases control socket quota and ownership");
        }
        await using (var server = new Server { Pmp = true }) {
            bool routeValid = true;
            await using var lease = await PortControlLease.Open(server.Route, 41081, 40003, PortMappingProtocol.Udp, () => routeValid, ct);
            Check(lease.Snapshot.Provider == PortControlKind.NatPmp && server.Requests.Take(3).Select(p => p[0] + "/" + p[1]).SequenceEqual(new[] { "2/1", "0/0", "0/1" }), "explicit unsupported-version response causes serial address-then-UDP-map NAT-PMP fallback");
            var running = lease.Maintain(ct); await Wait(() => server.Creates >= 2, ct);
            Check(server.Requests.Where(p => p.Length == 12).Last()[6..8].SequenceEqual(new byte[] { 0xaf, 0xc8 }), "NAT-PMP renewal suggests the actual assigned external port");
            routeValid = false; try { await running; } catch (OperationCanceledException) { }
            Check(!lease.Valid && lease.Snapshot.State == "RouteChanged", "route change invalidates candidate without waiting for lease expiry");
            await lease.DisposeAsync(); Check(server.Deletes == 0, "NAT-PMP never deletes a lease without nonce ownership");
        }
        await using (var server = new Server { Error = 2 }) {
            bool refused = false;
            try { await using var lease = await PortControlLease.Open(server.Route, 41082, 40004, PortMappingProtocol.Tcp, () => true, ct); }
            catch (PortControlException) { refused = true; }
            Check(refused && server.Requests.All(p => p[0] == 2) && server.Deletes == 0, "authorization error neither downgrades nor deletes another owner's mapping");
            int sent = server.Requests.Count;
            try { await using var lease = await PortControlLease.Open(server.Route, 41082, 40004, PortMappingProtocol.Tcp, () => true, ct); } catch (IOException) { }
            Check(server.Requests.Count == sent, "server error lifetime suppresses immediate gateway retry");
        }
        await using (var server = new Server { DropCreates = true }) {
            using var cancel = new CancellationTokenSource(200);
            try { await using var lease = await PortControlLease.Open(server.Route, 41083, 40005, PortMappingProtocol.Tcp, () => true, cancel.Token); } catch (OperationCanceledException) { }
            Check(server.Creates == 1 && server.Deletes == 1 && server.Requests.All(p => p[0] == 2), "canceled/ambiguous PCP create cleans up only its nonce and does not assume NAT-PMP support");
        }
        await using (var server = new Server()) {
            await using var lease = await PortControlLease.Open(server.Route, 41084, 40006, PortMappingProtocol.Tcp, () => true, ct);
            var running = lease.Maintain(ct); server.Reboot = true;
            try { await running; Check(false, "reboot expected"); } catch (IOException) { }
            Check(!lease.Valid && lease.Snapshot.State == "GatewayEpochChanged", "gateway reboot invalidates the old candidate even if external tuple is unchanged");
        }
        await using (var server = new Server { ExternalAddress = IPAddress.Parse("100.64.0.2") }) {
            await using var lease = await PortControlLease.Open(server.Route, 41085, 40007, PortMappingProtocol.Tcp, () => true, ct);
            bool rejected = false; try { TcpMapping.GatewayCandidate(lease); } catch (IOException) { rejected = true; }
            Check(rejected, "inner CGN mapping is not spliced onto an unrelated STUN public port");
        }
        await using (var server = new Server()) {
            await using var lease = await PortControlLease.Open(server.Route, 41087, 40009, PortMappingProtocol.Tcp, () => true, ct);
            server.DropCreates = true;
            try { await lease.Maintain(ct); Check(false, "expiry expected"); } catch (IOException) { }
            Check(!lease.Valid && lease.Snapshot.RemainingSeconds == 0 && lease.Snapshot.State == "ExpiredOrRenewalFailed",
                "unanswered renewal expires at granted lifetime without downgrade or stale candidate advertisement");
            Check(server.Requests.All(p => p[0] == 2), "PCP renewal loss does not switch protocol");
        }
        await using (var server = new Server()) {
            await using var active = await PortControlLease.Open(server.Route, 41088, 40010, PortMappingProtocol.Tcp, () => true, ct);
            server.DropCreates = true;
            using var waiting = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var queued = PortControlLease.Open(server.Route, 41089, 40011, PortMappingProtocol.Udp, () => true, waiting.Token);
            try {
                await Wait(() => server.Creates >= 2, ct);
                var elapsed = Stopwatch.StartNew();
                try { await active.Maintain(ct); Check(false, "queued expiry expected"); } catch (IOException) { }
                Check(!active.Valid && !queued.IsCompleted && elapsed.Elapsed.TotalSeconds < 10,
                    "gateway serialization cannot extend an active lease past its granted expiry while another request retries");
            } finally { waiting.Cancel(); try { await using var unexpected = await queued; } catch (OperationCanceledException) { } }
        }
        // Formal TcpMapping object, real TCP helper, real UDP gateway protocol,
        // without router/firewall/native mutations or an Internet destination.
        await using (var server = new Server { ChangePortOnRenew = true })
        await using (var helper = new Reflector { Silent = false }) {
            var temporary = new TcpListener(IPAddress.Loopback, 0); temporary.Start(); int source = ((IPEndPoint)temporary.LocalEndpoint).Port; temporary.Stop();
            var (binding, observed) = await TcpBinding.Connect(source, IPAddress.Loopback, _ => { }, ct, [helper.Endpoint.ToString()]);
            var lease = await PortControlLease.Open(server.Route, 41086, 40008, PortMappingProtocol.Tcp, () => true, ct);
            await using var mapping = new TcpMapping(lease, binding, observed, _ => { });
            var updates = new ConcurrentQueue<IPEndPoint>(); mapping.Changed += updates.Enqueue;
            var maintaining = mapping.Maintain(ct); await Wait(() => updates.Count > 0, ct);
            Check(mapping.PublicEndpoint.Port == 45001 && mapping.HelperObservation!.Public.Port == source && mapping.IsValid,
                "production TCP candidate tracks the gateway's actual reassigned port, independently of its helper observation");
            helper.Silent = true; await Wait(() => mapping.HelperObservation == null, ct);
            Check(mapping.IsValid && !maintaining.IsCompleted && mapping.PublicEndpoint.Port == 45001,
                "loss of a STUN helper observation does not withdraw a valid independent gateway mapping");
            await mapping.DisposeAsync(); try { await maintaining; } catch (OperationCanceledException) { }
            await Wait(() => helper.Active == 0, ct);
            Check(server.Deletes == 1 && helper.Active == 0, "product disposal joins renewal/keepalive before releasing the helper and exact PCP lease");
            rows.Add(new { scope = "production TcpMapping + real loopback helper and gateway datagrams", hasNative = false, hasRealNat = false, actualPort = mapping.PublicEndpoint.Port, cleanup = true });
        }
        Directory.CreateDirectory("artifacts");
        await File.WriteAllTextAsync("artifacts/m7-port-control-20261011.json", JsonSerializer.Serialize(new { status = "Pass", checks = passed, elapsedMs = clock.Elapsed.TotalMilliseconds, rows }, new JsonSerializerOptions { WriteIndented = true }));
    }
    static async Task Wait(Func<bool> condition, CancellationToken token) { while (!condition()) await Task.Delay(20, token); }
    static byte[] PcpReply(byte[] request, uint epoch, uint lifetime, ushort port, IPAddress address, byte error = 0)
    {
        byte[] b = request.ToArray(); b[1] = 0x81; b[3] = error;
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), lifetime); BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(8), epoch); b.AsSpan(12, 12).Clear();
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(42), port); address.MapToIPv6().GetAddressBytes().CopyTo(b, 44); return b;
    }
    sealed class Server : IAsyncDisposable
    {
        readonly UdpClient socket = new(new IPEndPoint(IPAddress.Loopback, 0));
        readonly CancellationTokenSource stop = new();
        readonly Stopwatch clock = Stopwatch.StartNew();
        readonly Task run;
        public readonly ConcurrentQueue<byte[]> Requests = [];
        public bool Pmp, PoisonFirst, Reboot, DropCreates, ChangePortOnRenew;
        public byte Error;
        public IPAddress ExternalAddress = IPAddress.Parse("1.1.1.1");
        public byte[] FirstNonce = [];
        public int Creates, Deletes;
        public PortControlRoute Route { get; }
        public Server() { Route = new("loopback-fixture", IPAddress.Loopback, (IPEndPoint)socket.Client.LocalEndPoint!, Guid.NewGuid().ToString()); run = Run(); }
        async Task Run()
        {
            try {
                while (true) {
                    var packet = await socket.ReceiveAsync(stop.Token); byte[] p = packet.Buffer; Requests.Enqueue(p);
                    uint epoch = Reboot ? 0 : (uint)(100 + clock.Elapsed.TotalSeconds); byte[] response;
                    if (p[0] == 2 && Pmp) { response = new byte[8]; response[3] = 1; BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(4), epoch); }
                    else if (p[0] == 2) {
                        if (FirstNonce.Length == 0) FirstNonce = p.AsSpan(24, 12).ToArray();
                        bool deleting = BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(4)) == 0;
                        if (deleting) Deletes++; else Creates++;
                        if (DropCreates && !deleting) continue;
                        response = PcpReply(p, epoch, deleting ? 0u : 8u, (ushort)(ChangePortOnRenew && Creates > 1 ? 45001 : 45000), ExternalAddress, Error);
                        if (PoisonFirst && Creates == 1 && !deleting) {
                            using var foreign = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); await foreign.SendAsync(response, packet.RemoteEndPoint, stop.Token);
                            await socket.SendAsync(new byte[1200], packet.RemoteEndPoint, stop.Token);
                            var bad = response.ToArray(); bad[24] ^= 1; await socket.SendAsync(bad, packet.RemoteEndPoint, stop.Token);
                            bad = response.ToArray(); bad[1] = 0x82; await socket.SendAsync(bad, packet.RemoteEndPoint, stop.Token);
                        }
                    } else if (p[1] == 0) {
                        response = new byte[12]; response[1] = 128; BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(4), epoch); ExternalAddress.GetAddressBytes().CopyTo(response, 8);
                    } else {
                        Creates++; response = new byte[16]; response[1] = (byte)(p[1] | 128);
                        BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(4), epoch); p.AsSpan(4, 2).CopyTo(response.AsSpan(8));
                        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10), 45000); BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(12), 8);
                        if (BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(8)) == 0) Deletes++;
                    }
                    await socket.SendAsync(response, packet.RemoteEndPoint, stop.Token);
                }
            } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); await run; socket.Dispose(); stop.Dispose(); }
    }
}
