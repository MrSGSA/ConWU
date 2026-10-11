using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;

namespace StreamLink.Core;

public static class TcpShapeProbe
{
    // One sequence per resource per factory lifetime. Never binds P, opens a
    // second capture handle, hands the helper to native, or mutates peer state.
    public static async Task<TcpShapeObservation[]> Run(TcpCaptureOwner owner, ITcpObservationControl control,
        Func<bool> takeRequest, Action<IPEndPoint> checkRoute, CancellationToken token, TraversalResources? resources = null)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(token); limit.CancelAfter(20000);
        token = limit.Token;
        using var held = owner.Lease.AcquireAttempt(owner.Lease.NetworkGeneration);
        async Task<TcpObserverReply> Request(string op, Guid ticket, TcpProbeSpec[]? probes = null)
        {
            while (!takeRequest()) await Task.Delay(100, token);
            return await control.TcpObservation(op, ticket, probes, token);
        }
        var catalog = await Request("catalog", Guid.Empty);
        if (catalog.Version != 1 || catalog.Epoch == Guid.Empty || catalog.Points is null) throw new IOException("观察服务能力无效");
        TcpObserverProtocol.ValidatePoints(catalog.Points);
        var points = catalog.Points.Where(p => !TcpObserverProtocol.Endpoint(p.Endpoint).Equals(owner.Lease.Reflector)).ToArray();
        foreach (var point in points) checkRoute(TcpObserverProtocol.Endpoint(point.Endpoint));
        if (points.Length == 0) throw new IOException("观察点与 helper 四元组冲突");
        var output = new List<TcpShapeObservation>();
        // Reserve one extra tuple at a time (seven peers + one diagnostic), with
        // no independent SEQ state ever sharing an Active/Candidate tuple.
        // One ticket, at most four destinations; read only after its capture
        // window ends so a late conflicting source cannot escape ambiguity checks.
        var group = points;
        var specs = group.Select(p => new TcpProbeSpec(Guid.NewGuid(), p.Id,
            System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(RandomNumberGenerator.GetBytes(4)))).ToArray();
        // Register first; any busy tuple aborts this diagnostic, leaving
        // its current owner untouched. It never delays product Gather.
        Guid ticket = Guid.NewGuid(); var opened = await Request("register", ticket, specs);
        Validate(opened, ticket, catalog.Epoch, specs, group);
        long began = Stopwatch.GetTimestamp();
        for (int i = 0; i < group.Length; i++) {
            token.ThrowIfCancellationRequested();
            using var session = owner.Register(owner.Lease.NetworkGeneration, TcpObserverProtocol.Endpoint(group[i].Endpoint));
            await session.CaptureReady; session.Start();
            byte[] packet = TcpShapeSyn.Create(owner.Lease.Local, session.Peer, specs[i].Iss, unchecked((uint)Environment.TickCount64));
            for (int retry = 0; retry < 3; retry++) {
                if (Stopwatch.GetElapsedTime(began).TotalSeconds >= 3 || DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() >= opened.Expires) break;
                while (!(resources ?? TraversalResources.Shared).TrySend(packet.Length, maintenance: true)) await Task.Delay(25, token);
                if (Stopwatch.GetElapsedTime(began).TotalSeconds >= 3 || DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() >= opened.Expires) break;
                if (!session.Send(packet)) throw new IOException("观察原生端点已退出");
                await Task.Delay(150, token);
            }
            // No ReceiveFrom competitor: broker is the sole receiver;
            // bounded per-session queue is discarded on release.
        }
        var remaining = TimeSpan.FromSeconds(TcpObserverProtocol.WindowSeconds) - Stopwatch.GetElapsedTime(began);
        if (remaining > TimeSpan.Zero) await Task.Delay(remaining + TimeSpan.FromMilliseconds(100), token);
        var result = await Request("read", ticket);
        Validate(result, ticket, catalog.Epoch, specs, group);
        foreach (var e in result.Evidence) output.Add(new(owner.Lease.Id, owner.Lease.NetworkGeneration,
            owner.Lease.Local.ToString(), owner.Lease.Reflector.ToString(), e.ProbeId, e.Target, e.Source,
            e.ObservedAt, (e.ObservedAt ?? result.Expires) + 60000, e.State,
            CaptureOwnerId: owner.OwnerId,
            InterfaceId: System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => n.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(owner.Lease.Local.Address)))?.Id ?? "Unknown",
            ProbeWindowEndsAt: result.Expires));
        return output.ToArray();
    }
    static void Validate(TcpObserverReply r, Guid ticket, Guid epoch, TcpProbeSpec[] specs, TcpObserverPoint[] points)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (r.Version != 1 || r.Epoch != epoch || r.TicketId != ticket || r.Expires > now + 10000 || r.Expires < now - 60000 ||
            r.Evidence == null || r.Evidence.Length != specs.Length || r.Evidence.Any(e => e == null) || r.Evidence.Select(e => e.ProbeId).Distinct().Count() != specs.Length ||
            r.Evidence.Any(e => !specs.Any(s => s.ProbeId == e.ProbeId && s.ObserverId == e.ObserverId) ||
                !points.Any(p => p.Id == e.ObserverId && p.Endpoint == e.Target) || e.TcpHandshakeVerified != "NotTested" ||
                e.LegacyPayloadVerified != "NotTested" || e.State is not ("Pending" or "NotObserved" or "SynObserved" or "Ambiguous") ||
                e.Source != null && (!IPEndPoint.TryParse(e.Source, out var ep) || ep.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || ep.Port == 0) ||
                (e.State == "SynObserved") != (e.Source != null) || e.Source != null && e.ObservedAt == null ||
                e.ObservedAt > now + 5000 || e.ObservedAt > r.Expires || e.ObservedAt < r.Expires - 8000))
            throw new IOException("TCP 观察回复与登记目标或证据级别不符");
    }
}
