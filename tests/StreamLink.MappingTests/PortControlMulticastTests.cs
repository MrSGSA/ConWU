using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using StreamLink.Core;

static partial class PortControlTests
{
    static int NoticePort()
    {
        using var free = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        free.Bind(new IPEndPoint(IPAddress.Loopback, 0)); return ((IPEndPoint)free.LocalEndPoint!).Port;
    }
    static PortControlRoute NoticeRoute(Server server, int port)
    {
        var nic = NetworkInterface.GetAllNetworkInterfaces().Single(n => n.NetworkInterfaceType == NetworkInterfaceType.Loopback);
        return server.Route with { InterfaceId = nic.Id, NotificationPort = port };
    }
    static Socket OtherMulticastClient(int port, int index)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
            socket.Bind(new IPEndPoint(OperatingSystem.IsWindows() ? IPAddress.Any : PortControlMulticast.Group, port));
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(PortControlMulticast.Group, index));
            return socket;
        } catch { socket.Dispose(); throw; }
    }
    static async Task<SocketReceiveMessageFromResult> Notice(Socket socket, CancellationToken token)
    {
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(token); wait.CancelAfter(2000);
        return await socket.ReceiveMessageFromAsync(new byte[1200], SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), wait.Token);
    }
    static async Task MulticastNotifications(Action<bool, string> check, List<object> rows, CancellationToken token)
    {
        // Actual Windows loopback multicast I/O, without sending to a real LAN.
        await using (var server = new Server { Lifetime = 180 }) {
            int port = NoticePort(); var route = NoticeRoute(server, port); var resources = new TraversalResources(2);
            using var before = OtherMulticastClient(port, route.NotificationInterface());
            await using var a = await PortControlLease.Open(route, 41200, 0, PortMappingProtocol.Tcp, () => true, token, resources);
            await using var b = await PortControlLease.Open(route, 41201, 0, PortMappingProtocol.Udp, () => true, token, resources);
            using var after = OtherMulticastClient(port, route.NotificationInterface());
            check(a.Snapshot.NotificationMode == "UnicastAndMulticast" && b.Snapshot.NotificationMode == "UnicastAndMulticast", "two leases share one optional multicast quota alongside the one control socket");
            var ma = a.Maintain(token); var mb = b.Maintain(token);
            var first = Notice(before, token); var last = Notice(after, token);
            await server.Multicast(Announce(server.Epoch), port);
            var observed = await first; var later = await last;
            check(observed.RemoteEndPoint.Equals(route.Gateway) && observed.PacketInformation.Interface == route.NotificationInterface() &&
                observed.PacketInformation.Address.Equals(PortControlMulticast.Group) && later.RemoteEndPoint.Equals(route.Gateway),
                "clients opened before and after StreamLink both receive multicast with real destination/interface/source metadata");
            check(!PortControlMulticast.Matches(route, route.NotificationInterface(), route.Gateway, PortControlMulticast.Group, route.NotificationInterface() + 1) &&
                !PortControlMulticast.Matches(route, route.NotificationInterface(), new(IPAddress.Parse("127.0.0.2"), route.Gateway.Port), PortControlMulticast.Group, route.NotificationInterface()),
                "arrival metadata policy also rejects a mismatched interface index or source IP (metadata negative cases, not a second real interface)");
            await using var foreign = new Server { Lifetime = 180 };
            await foreign.Multicast(Announce(0), port);
            await server.Notify(Announce(0), new(IPAddress.Loopback, port)); // unicast to shared port
            await server.Multicast(Announce(0)[..23], port);
            await server.Multicast(new byte[1200], port);
            var key = ((byte)6, (ushort)41200);
            await server.Multicast(PcpReply(server.LastMaps[key], 0, 180, 46000, IPAddress.Parse("1.1.1.1")), port);
            await Task.Delay(150, token);
            check(a.Valid && b.Valid && a.Snapshot.Notifications == 0 && b.Snapshot.Notifications == 0,
                "multicast rejects another source port, unicast destination, malformed/oversized notices and MAP replies");
            server.Reboot = true; var clock = Stopwatch.StartNew();
            for (int i = 0; i < 4; i++) await server.Multicast(Announce(0), port);
            await Wait(() => a.Snapshot.Notifications == 1 && b.Snapshot.Notifications == 1, token);
            await Wait(() => a.Valid && b.Valid, token);
            check(server.Creates == 4 && a.Snapshot.Revalidations == 1 && b.Snapshot.Revalidations == 1 && clock.Elapsed.TotalSeconds < 7,
                "real multicast reboot coalesces and renews TCP/UDP mappings on their existing control resource");
            double recoveryMs = clock.Elapsed.TotalMilliseconds;
            using (var required = resources.Acquire()) {
                check(a.Snapshot.NotificationMode == "UnicastOnly" && a.Snapshot.NotificationReason == "ResourcePreempted" && a.Valid && b.Valid,
                    "required socket synchronously closes optional receiver before taking quota without withdrawing mappings");
                bool full = false; try { using var extra = resources.Acquire(); } catch (IOException) { full = true; }
                check(full, "preemption counts control plus required socket within the original two-slot maximum");
                server.AssignedPorts[key] = 46200;
                await server.Notify(PcpReply(server.LastMaps[key], 0, 180, 46200, IPAddress.Parse("1.1.1.1")), server.Clients[key]);
                await Wait(() => a.Valid && a.External.Port == 46200, token);
                check(a.Snapshot.Notifications == 2 && !ma.IsCompleted && !mb.IsCompleted, "unicast recovery remains usable after multicast quota is preempted");
            }
            await a.DisposeAsync(); await b.DisposeAsync();
            using var q1 = resources.Acquire(); using var q2 = resources.Acquire();
            check(server.Deletes == 2, "all shared notification and control quotas return after exact PCP cleanup");
            rows.Add(new { notification = "windows-loopback-multicast", recoveryMs, interfaceIndex = observed.PacketInformation.Interface,
                receiverPort = port, ttl = 0, concurrentOtherReceivers = 2, preemption = true, actualGateway = false });
        }
        await using (var a = new Server { Lifetime = 180 })
        await using (var b = new Server { Lifetime = 180, Pmp = true }) {
            int port = NoticePort(); var resources = new TraversalResources(3);
            var ra = NoticeRoute(a, port); var rb = NoticeRoute(b, port);
            await using var first = await PortControlLease.Open(ra, 41202, 0, PortMappingProtocol.Tcp, () => true, token, resources);
            using (var otherLedger = PortControlMulticast.Subscribe(ra, new TraversalResources(), _ => throw new Exception("must not dispatch")))
                check(otherLedger.Mode == "UnicastOnly" && otherLedger.Reason == "LedgerMismatch", "a shared multicast receiver cannot bypass the device ledger through a second budget");
            bool current = true;
            await using var second = await PortControlLease.Open(rb, 41203, 0, PortMappingProtocol.Udp, () => current, token, resources);
            _ = first.Maintain(token); _ = second.Maintain(token);
            check(first.Snapshot.NotificationMode == "UnicastAndMulticast" && second.Snapshot.NotificationMode == "UnicastAndMulticast", "distinct gateways on one ledger share the multicast socket and join each interface once");
            b.Reboot = true; b.ExternalAddress = IPAddress.Parse("1.0.0.1"); byte[] address = new byte[12]; address[1] = 128; b.ExternalAddress.GetAddressBytes().CopyTo(address, 8);
            await b.Multicast(address, port); await Wait(() => second.Snapshot.Revalidations == 1 && second.Valid, token);
            check(first.Snapshot.Notifications == 0 && first.Valid && second.External.Address.Equals(b.ExternalAddress), "NAT-PMP multicast updates only its exact gateway's lease, without touching the PCP subscriber");
            await first.DisposeAsync();
            check(second.Snapshot.NotificationMode == "UnicastAndMulticast", "removing one gateway keeps another gateway's membership and receiver alive");
            current = false; b.ExternalAddress = IPAddress.Parse("8.8.8.8"); b.ExternalAddress.GetAddressBytes().CopyTo(address, 8);
            await b.Multicast(address, port); await Task.Delay(100, token);
            check(second.Snapshot.Notifications == 1 && second.External.Address.Equals(IPAddress.Parse("1.0.0.1")), "old route generation cannot consume a multicast hint even before the route watchdog wakes");
            await second.DisposeAsync();
            using var q1 = resources.Acquire(); using var q2 = resources.Acquire(); using var q3 = resources.Acquire();
            check(b.Deletes == 0, "NAT-PMP multicast support retains natural-expiry-only ownership and releases every quota");
        }
        foreach (bool occupied in new[] { false, true }) {
            await using var server = new Server { Lifetime = 180 }; int port = NoticePort();
            using var exclusive = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            if (occupied) { exclusive.ExclusiveAddressUse = true; exclusive.Bind(new IPEndPoint(IPAddress.Any, port)); }
            var resources = new TraversalResources(occupied ? 2 : 1);
            await using var lease = await PortControlLease.Open(NoticeRoute(server, port), occupied ? 41204 : 41205, 0, PortMappingProtocol.Tcp, () => true, token, resources);
            check(lease.Valid && lease.Snapshot.NotificationMode == "UnicastOnly" && (occupied ? lease.Snapshot.NotificationReason.StartsWith("SocketUnavailable:") : lease.Snapshot.NotificationReason == "SocketBudgetUnavailable"),
                "optional receiver degrades with precise reason on " + (occupied ? "exclusive bind conflict" : "full socket budget"));
            await lease.DisposeAsync(); using var q1 = resources.Acquire();
            if (occupied) { using var q2 = resources.Acquire(); check(exclusive.IsBound, "failed shared bind returns its quota and never alters the exclusive external socket"); }
        }
        await OptionalSocketRaces(check, token);
    }
    static async Task OptionalSocketRaces(Action<bool, string> check, CancellationToken token)
    {
        for (int round = 0; round < 30; round++) {
            var resources = new TraversalResources(1); int opened = 0, closed = 0;
            var optional = resources.TryOpenOptional(() => { Interlocked.Increment(ref opened); return new OnClose(() => Interlocked.Increment(ref closed)); });
            await Task.WhenAll(Task.Run(() => optional!.Dispose(), token), Task.Run(() => { using var required = resources.Acquire(); }, token));
            using var quota = resources.Acquire();
            check(opened == 1 && closed == 1 && !optional!.IsActive, "concurrent explicit close/preemption returns one optional quota exactly once");
        }
        var ledger = new TraversalResources(1);
        bool threw = false; try { ledger.TryOpenOptional(() => throw new SocketException((int)SocketError.AddressAlreadyInUse)); } catch (SocketException) { threw = true; }
        using var recovered = ledger.Acquire(); check(threw, "optional resource constructor failure returns its reservation");
        var concurrent = new TraversalResources(1); int closes = 0;
        using var started = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        var opening = Task.Run(() => concurrent.TryOpenOptional(() => {
            started.Set(); release.Wait(token); return new OnClose(() => Interlocked.Increment(ref closes));
        }), token);
        started.Wait(token);
        var taking = Task.Run(() => concurrent.Acquire(), token);
        await Task.Delay(30, token);
        check(!taking.IsCompleted, "required acquisition cannot overbook an optional socket still being initialized");
        release.Set(); using var optionalOpening = await opening; using var taken = await taking;
        check(closes == 1 && !optionalOpening!.IsActive, "preemption racing initialization closes the actual resource before handing its slot to required I/O");
    }
    sealed class OnClose(Action close) : IDisposable { public void Dispose() => close(); }
}
