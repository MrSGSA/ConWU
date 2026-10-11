using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using StreamLink.EndpointPoc;
using StreamLink.Core;

static partial class PortControlTests
{
    static byte[] Announce(uint epoch)
    {
        byte[] packet = new byte[24]; packet[0] = 2; packet[1] = 0x80;
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8), epoch); return packet;
    }
    static async Task Notifications(Action<bool, string> check, List<object> rows, CancellationToken token)
    {
        await using (var server = new Server { Lifetime = 180 }) {
            var resources = new TraversalResources(1);
            await using var a = await PortControlLease.Open(server.Route, 41120, 40020, PortMappingProtocol.Tcp, () => true, token, resources);
            await using var b = await PortControlLease.Open(server.Route, 41121, 40021, PortMappingProtocol.Udp, () => true, token, resources);
            var ma = a.Maintain(token); var mb = b.Maintain(token);
            var ka = ((byte)6, (ushort)41120); var kb = ((byte)17, (ushort)41121);
            var client = server.Clients[ka];
            check(client.Equals(server.Clients[kb]), "TCP/UDP mapping notifications share the original one-quota control socket");
            var update = PcpReply(server.LastMaps[ka], server.Epoch, 180, 46111, IPAddress.Parse("1.1.1.1"));
            await server.Notify(update, client, foreign: true);
            var bad = update.ToArray(); bad[24] ^= 1; await server.Notify(bad, client);
            bad = update.ToArray(); bad[36] = 17; await server.Notify(bad, client);
            bad = Announce(0); bad[3] = 2; await server.Notify(bad, client);
            await server.Notify(Announce(0)[..23], client); await server.Notify([.. Announce(0), 1, 0, 0, 8], client);
            await server.Notify(Announce(server.Epoch), client);
            await Task.Delay(150, token);
            check(a.Valid && b.Valid && a.Snapshot.Notifications == 0 && b.Snapshot.Notifications == 0 && server.Creates == 2,
                "idle receive rejects foreign source/nonce/protocol and malformed ANNOUNCE; current epoch does not recreate mappings");

            server.AssignedPorts[ka] = 46000; server.DropCreates = true;
            update = PcpReply(server.LastMaps[ka], server.Epoch, 180, 46000, IPAddress.Parse("1.1.1.1"));
            var clock = Stopwatch.StartNew(); await server.Notify(update, client);
            await Wait(() => server.Creates == 3, token);
            check(!a.Valid && a.Snapshot.State == "GatewayRevalidating" && a.External.Port == 45000 && b.Valid && b.External.Port == 45000,
                "unsolicited MAP withdraws only its candidate; an unconfirmed hint cannot publish its port or grant lifetime");
            for (int i = 0; i < 50; i++) await server.Notify(update, client);
            server.DropCreates = false; await Wait(() => a.Valid, token);
            check(a.External.Port == 46000 && a.Snapshot.Notifications == 1 && a.Snapshot.Revalidations == 1 && a.Snapshot.Id != b.Snapshot.Id,
                "bounded duplicate hints coalesce; an exact-resource MAP response publishes the gateway's assigned port");
            check(server.LastMaps[ka].AsSpan(24, 12).SequenceEqual(update.AsSpan(24, 12)) && server.Clients[ka].Equals(client),
                "revalidation retains PCP nonce and real control source endpoint");
            double recoveryMs = clock.Elapsed.TotalMilliseconds;
            await a.DisposeAsync(); try { await ma; } catch (OperationCanceledException) { }
            await server.Notify(update, client); await Task.Delay(60, token);
            check(a.Snapshot.State == "Closed" && b.Valid && b.Snapshot.Notifications == 0, "late retired-lease MAP cannot reactivate it or mutate another subscriber");
            server.AssignedPorts[kb] = 46002;
            await server.Notify(PcpReply(server.LastMaps[kb], server.Epoch, 180, 46002, IPAddress.Parse("1.1.1.1")), client);
            await Wait(() => b.Valid && b.External.Port == 46002, token);
            check(!mb.IsCompleted && b.Snapshot.Revalidations == 1 && b.Snapshot.NotificationMode == "UnicastOnly", "closing one lease preserves the other lease's idle receiver and notification processing");
            await b.DisposeAsync(); try { await mb; } catch (OperationCanceledException) { }
            using var quota = resources.Acquire();
            check(server.Deletes == 2 && a.Snapshot.State == "Closed" && b.Snapshot.State == "Closed", "last subscriber joins the unique receiver, releases quota and deletes only its exact PCP mappings");
            rows.Add(new { notification = "pcp-map-update", recoveryMs, sharedControlSource = client.ToString(), multicast = false, actualGateway = false });
        }
        await using (var server = new Server { Lifetime = 180 }) {
            var resources = new TraversalResources(1);
            await using var a = await PortControlLease.Open(server.Route, 41122, 40022, PortMappingProtocol.Tcp, () => true, token, resources);
            await using var b = await PortControlLease.Open(server.Route, 41123, 40023, PortMappingProtocol.Udp, () => true, token, resources);
            var ma = a.Maintain(token); var mb = b.Maintain(token); var ids = new[] { a.Snapshot.Id, b.Snapshot.Id };
            server.Reboot = true; var clock = Stopwatch.StartNew();
            await server.Notify(Announce(0), server.Clients[((byte)6, (ushort)41122)]);
            await Wait(() => a.Snapshot.Notifications == 1 && b.Snapshot.Notifications == 1, token);
            await Wait(() => a.Valid && b.Valid, token);
            check(a.Snapshot.Epoch == 0 && b.Snapshot.Epoch == 0 && a.Snapshot.Id == ids[0] && b.Snapshot.Id == ids[1] && server.Creates == 4 && !ma.IsCompleted && !mb.IsCompleted,
                "ANNOUNCE reboot revalidates both protocol leases with retained ownership after bounded jitter");
            check(clock.Elapsed.TotalSeconds < 7, "idle reboot recovery occurs before the 90-second ordinary renewal in this loopback case");
            rows.Add(new { notification = "pcp-announce", recoveryMs = clock.Elapsed.TotalMilliseconds, actualGateway = false });
        }
        await using (var server = new Server { Lifetime = 180, Pmp = true }) {
            await using var lease = await PortControlLease.Open(server.Route, 41124, 40024, PortMappingProtocol.Udp, () => true, token);
            var maintaining = lease.Maintain(token); var client = server.Clients[((byte)17, (ushort)41124)];
            byte[] changed = new byte[12]; changed[1] = 128; server.Reboot = true; server.ExternalAddress = IPAddress.Parse("1.0.0.1");
            server.ExternalAddress.GetAddressBytes().CopyTo(changed, 8);
            await server.Notify(changed, client, foreign: true); await Task.Delay(100, token);
            check(lease.Valid && lease.Snapshot.Notifications == 0, "NAT-PMP address hint still rejects a different UDP source port");
            await server.Notify(changed, client); await Wait(() => lease.Snapshot.Revalidations == 1 && lease.Valid, token);
            check(lease.External.Address.Equals(server.ExternalAddress) && lease.Snapshot.Provider == PortControlKind.NatPmp && lease.Snapshot.Ownership == "LocalGrantNoDelete",
                "NAT-PMP rechecks address then mapping on the same control socket; it acquires no PCP nonce deletion capability");
            await lease.DisposeAsync(); try { await maintaining; } catch (OperationCanceledException) { }
            check(server.Deletes == 0, "notification recovery never introduces NAT-PMP deletion");
        }
        await using (var server = new Server { Lifetime = 180 }) {
            bool current = true; var resources = new TraversalResources(1);
            await using var lease = await PortControlLease.Open(server.Route, 41125, 40025, PortMappingProtocol.Tcp, () => current, token, resources);
            var maintaining = lease.Maintain(token); var key = ((byte)6, (ushort)41125);
            current = false; await server.Notify(Announce(0), server.Clients[key]);
            try { await maintaining.WaitAsync(TimeSpan.FromSeconds(7), token); } catch (OperationCanceledException) { } catch (IOException) { }
            check(!lease.Valid && lease.Snapshot.State == "RouteChanged" && server.Creates == 1, "changed route forbids revalidation sends and ignores the old gateway's restart hint");
            await lease.DisposeAsync(); using var quota = resources.Acquire();
            check(server.Deletes == 0, "route loss does not delete a mapping through an unrelated new gateway");
        }
        await using (var server = new Server { Lifetime = 180 }) {
            await using var lease = await PortControlLease.Open(server.Route, 41126, 40026, PortMappingProtocol.Tcp, () => true, token);
            var maintaining = lease.Maintain(token); var key = ((byte)6, (ushort)41126); server.DropCreates = true;
            await server.Notify(PcpReply(server.LastMaps[key], server.Epoch, 180, 46006, IPAddress.Parse("1.1.1.1")), server.Clients[key]);
            await Wait(() => server.Creates == 2, token); var clock = Stopwatch.StartNew();
            await lease.DisposeAsync(); try { await maintaining; } catch (OperationCanceledException) { }
            check(clock.Elapsed.TotalSeconds < 2 && lease.Snapshot.State == "Closed" && server.Deletes == 1,
                "canceling an outstanding notification exchange joins receiver work and exact cleanup without waiting for retry expiry");
        }
        await using (var server = new Server { Lifetime = 180 })
        await using (var helper = new Reflector()) {
            var temporary = new TcpListener(IPAddress.Loopback, 0); temporary.Start(); int source = ((IPEndPoint)temporary.LocalEndpoint).Port; temporary.Stop();
            var (binding, observed) = await TcpBinding.Connect(source, IPAddress.Loopback, _ => { }, token, [helper.Endpoint.ToString()]);
            var lease = await PortControlLease.Open(server.Route, 41127, 40027, PortMappingProtocol.Tcp, () => true, token);
            await using var mapping = new TcpMapping(lease, binding, observed, _ => { });
            var maintaining = mapping.Maintain(token); var key = ((byte)6, (ushort)41127); var identity = lease.Snapshot.Id; int changes = 0;
            mapping.Changed += _ => Interlocked.Increment(ref changes);
            server.AssignedPorts[key] = 46007;
            await server.Notify(PcpReply(server.LastMaps[key], server.Epoch, 180, 46007, IPAddress.Parse("1.1.1.1")), server.Clients[key]);
            await Wait(() => mapping.IsValid && mapping.PublicEndpoint.Port == 46007, token);
            check(changes == 1 && lease.Snapshot.Id == identity && mapping.HelperObservation!.Local.Port == source && helper.Active == 1 && !maintaining.IsCompleted,
                "production TcpMapping publishes a notification-driven port update while retaining the real TCP helper and lease");
            server.ExternalAddress = IPAddress.Parse("100.64.0.9");
            await server.Notify(PcpReply(server.LastMaps[key], server.Epoch, 180, 46007, server.ExternalAddress), server.Clients[key]);
            try { await maintaining.WaitAsync(TimeSpan.FromSeconds(10), token); } catch (IOException) { }
            check(!mapping.IsValid && mapping.PublicEndpoint.Address.Equals(IPAddress.Parse("1.1.1.1")),
                "an unsolicited inner-CGN address is never published as a reachable public TCP candidate");
            await mapping.DisposeAsync(); await Wait(() => helper.Active == 0, token);
            rows.Add(new { notification = "production-tcp-mapping", helperClosed = true, changes, hasNative = false, actualGateway = false });
        }
        await using (var server = new Server { Lifetime = 180 }) {
            await using var lease = await PortControlLease.Open(server.Route, 41128, 40028, PortMappingProtocol.Udp, () => true, token);
            var maintaining = lease.Maintain(token); var key = ((byte)17, (ushort)41128); server.DropCreates = true;
            var clock = Stopwatch.StartNew();
            await server.Notify(PcpReply(server.LastMaps[key], server.Epoch, 180, 46008, IPAddress.Parse("1.1.1.1")), server.Clients[key]);
            bool timedOut = false;
            try { await maintaining.WaitAsync(TimeSpan.FromSeconds(11), token); } catch (IOException) { timedOut = true; }
            check(timedOut && !lease.Valid && lease.Snapshot.State == "GatewayRevalidationFailed" && clock.Elapsed.TotalSeconds is >= 7.5 and < 10.5 && server.Creates <= 4,
                "unanswered notification revalidation exits within its eight-second budget without republishing the old grant or downgrading protocol");
            rows.Add(new { notification = "revalidation-timeout", elapsedMs = clock.Elapsed.TotalMilliseconds, requests = server.Creates, actualGateway = false });
        }
    }
}
