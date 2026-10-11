using System.Net;
using System.Buffers.Binary;
using System.Security.Cryptography;
using StreamLink.Core;

static class UdpModel
{
    public static async Task Run(Action<bool, string> check, List<object> rows)
    {
        using var deadline = new CancellationTokenSource(30000); var token = deadline.Token;
        var scope = new PortPredictionScope(Guid.NewGuid(), "controlled-nat-fixture", "10.200.0.2", TraversalProfile.UdpDirect);
        var windows = new List<PortAllocationWindow>(); var machine = new TraversalResources(); var lab = new NatLab();
        PortAllocationSample Sample(NatObservation o) => new(o.SocketId, Guid.NewGuid(), o.Local.ToString(), o.Target.ToString(), o.Mapped.ToString(), o.ObservedAt, true, PortAllocationEvidence.UdpStunObserved, ProbeStartedAt: o.ProbeStartedAt);
        for (int i = 0; i < 20; i++) {
            var source = lab.Add("192.0.2.2", "apdm", "apdf", 40000 + i * 100, localPort: 45000 + i);
            await using var traversal = new UdpTraversal(source, scope.NetworkGeneration, Guid.NewGuid(), 2, 1, RandomNumberGenerator.GetBytes(32), machine);
            var before = await traversal.Observe(NatLab.Reflectors[0], token);
            await Task.Delay(2, token);
            int background = 0;
            if (i % 3 == 0) { await traversal.Observe(NatLab.Reflectors[2], token); background = 1; }
            var after = await traversal.Observe(NatLab.Reflectors[1], token);
            if (source.Bindings.Count != 2 + background) throw new Exception("calibration mapping inventory mismatch");
            windows.Add(new(Guid.NewGuid(), scope, Sample(before), Sample(after), background));
            await Task.Delay(2, token);
        }
        var model = NatPortPrediction.Fit(windows, out var report);
        check(model != null && report.Model == "fixed-step" && report.MaximumPorts == 2 && report.ValidationHits == 10,
            "twenty real UdpTraversal STUN observation windows train and hold out a two-port model against counted APDM mappings");
        rows.Add(report);
        foreach (bool predictive in new[] { false, true }) {
            var network = new NatLab(); var a = network.Add("192.0.2.1", "eim", "apdf", 50000, maximumPayload: 1344);
            var b = network.Add("192.0.2.2", "apdm", "apdf", 46000, maximumPayload: 1344, localPort: predictive ? 46002 : 46001);
            byte[] key = RandomNumberGenerator.GetBytes(32); Guid attempt = Guid.NewGuid();
            await using var left = new UdpTraversal(a, Guid.NewGuid(), attempt, 1, 2, key, new());
            await using var right = new UdpTraversal(b, scope.NetworkGeneration, attempt, 2, 1, key, new());
            var reflectedA = await left.Observe(NatLab.Reflectors[0], token); var reflectedB = await right.Observe(NatLab.Reflectors[0], token);
            IPEndPoint[] candidates = [reflectedB.Mapped]; PortForecast? forecast = null;
            if (predictive) {
                if (!model!.TryForecast(scope, Sample(reflectedB), () => !b.Disposed, true, out forecast, out string reason) || !model.TryClaim(forecast!.Id)) throw new Exception("forecast not admitted: " + reason);
                candidates = forecast.Ports.Select(p => new IPEndPoint(IPAddress.Parse(forecast.Address), p)).ToArray();
            }
            var results = await Task.WhenAll(left.Punch(candidates, new(DurationMs: 1500), token), right.Punch([reflectedA.Mapped], new(DurationMs: 1500), token));
            check(results.All(r => r.Success == predictive), predictive
                ? "bounded prediction succeeds with EIM/APDF versus sequential APDM/APDF using the same winning sockets"
                : "the same strict-filtering topology fails ordinary reflected-port checks before prediction");
            if (predictive) {
                using var sender = new MeshLink(1, 2, key); using var receiver = new MeshLink(2, 1, key);
                await left.SendPayload(sender.Hello(), token);
                var ack = receiver.Receive((await right.ReceivePayload(token)).Data);
                await right.SendPayload(ack.Reply!, token);
                var confirm = sender.Receive((await left.ReceivePayload(token)).Data);
                await left.SendPayload(confirm.Reply!, token); receiver.Receive((await right.ReceivePayload(token)).Data);
                byte[] ip = Packet(false);
                await left.SendPayload(sender.Data(ip)!, token);
                check(receiver.Receive((await right.ReceivePayload(token)).Data).Packet!.SequenceEqual(ip), "predicted retained UDP path delivers authenticated full-MTU MeshLink payload A to B");
                byte[] reverseIp = Packet(true); await right.SendPayload(receiver.Data(reverseIp)!, token);
                check(sender.Receive((await left.ReceivePayload(token)).Data).Packet!.SequenceEqual(reverseIp), "predicted retained UDP path delivers authenticated full-MTU MeshLink payload B to A");
                model!.Finish(forecast!.Id, PredictionOutcome.PathAuthenticated);
            }
            rows.Add(new { predictive, results, candidates = candidates.Select(p => p.ToString()), actualMappingsA = a.Bindings.Count,
                actualMappingsB = b.Bindings.Count, controlPackets = network.Wire.Count(p => p.Packet.AsSpan().StartsWith("SLP2"u8)),
                socketA = a.Id, socketB = b.Id, actualUdpSockets = false, rawNetwork = "NAT model", realUdpTraversal = true, meshRunner = false });
        }
    }
    static byte[] Packet(bool reverse)
    {
        byte[] packet = new byte[1280]; RandomNumberGenerator.Fill(packet.AsSpan(28));
        packet[0] = 0x45; packet[8] = 64; packet[9] = 17;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 1280);
        IPAddress.Parse(reverse ? "10.130.130.2" : "10.130.130.1").GetAddressBytes().CopyTo(packet, 12);
        IPAddress.Parse(reverse ? "10.130.130.1" : "10.130.130.2").GetAddressBytes().CopyTo(packet, 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), 41000); BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), 41001);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24), 1260);
        uint sum = 0; for (int i = 0; i < 20; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(i));
        while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), (ushort)~sum); return packet;
    }
}
