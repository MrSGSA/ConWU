using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;

namespace StreamLink.Core;

public static class TcpShapeProbe
{
    // One sequence per resource per factory lifetime. Never binds P, opens a
    // second capture handle, hands the helper to native, or mutates peer state.
    public static Task<TcpShapeObservation[]> Run(TcpCaptureOwner owner, ITcpObservationControl control,
        Func<bool> takeRequest, Action<IPEndPoint> checkRoute, CancellationToken token, TraversalResources? resources = null) =>
        RunCore(owner, control, takeRequest, checkRoute, token, resources, freshDestinations: 0);

    // Uses a new dedicated owner per window. Quiet and interference windows
    // measure the SAME first/last destinations; only the middle probe differs.
    public static Task<TcpShapeObservation[]> RunCalibration(TcpCaptureOwner owner, ITcpObservationControl control,
        Func<bool> takeRequest, Action<IPEndPoint> checkRoute, bool interference, CancellationToken token, TraversalResources? resources = null, Action? registrationConfirmed = null) =>
        RunCore(owner, control, takeRequest, checkRoute, token, resources, 0, interference, registrationConfirmed);

    // Explicit, capability-gated observation primitive for a future calibrated
    // strategy. Caller retains the lease after return; this does not publish a
    // candidate, certify mapping stability or authorize another TCP tuple.
    public static Task<TcpShapeObservation[]> RunFresh(TcpCaptureOwner owner, ITcpObservationControl control,
        Func<bool> takeRequest, Action<IPEndPoint> checkRoute, CancellationToken token, TraversalResources? resources = null, int destinations = 1, TcpObserverReply? preparedCatalog = null, TraversalControlRound? controlRound = null)
    {
        if (destinations is < 1 or > 2) throw new ArgumentOutOfRangeException(nameof(destinations));
        if (controlRound != null && !ReferenceEquals(controlRound.Machine, resources ?? TraversalResources.Shared)) throw new ArgumentException("Probe round belongs to another machine budget");
        return RunCore(owner, control, takeRequest, checkRoute, token, resources, destinations, preparedCatalog: preparedCatalog, controlRound: controlRound);
    }
    internal static Task<TcpShapeObservation[]> RunFreshWithInterfaceLookup(TcpCaptureOwner owner, ITcpObservationControl control,
        Func<bool> takeRequest, CancellationToken token, TraversalResources resources, Func<IPAddress, string> lookup) =>
        RunCore(owner, control, takeRequest, _ => { }, token, resources, 2, interfaceLookup: lookup);
    static string SourceInterface(IPAddress source) => System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
        .FirstOrDefault(n => n.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(source)))?.Id ?? "Unknown";
    static async Task<TcpShapeObservation[]> RunCore(TcpCaptureOwner owner, ITcpObservationControl control,
        Func<bool> takeRequest, Action<IPEndPoint> checkRoute, CancellationToken token, TraversalResources? resources, int freshDestinations, bool? calibration = null, Action? registrationConfirmed = null, TcpObserverReply? preparedCatalog = null, TraversalControlRound? controlRound = null, Func<IPAddress, string>? interfaceLookup = null)
    {
        bool fresh = freshDestinations != 0;
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(token); limit.CancelAfter(20000);
        token = limit.Token;
        using var held = owner.Lease.AcquireAttempt(owner.Lease.NetworkGeneration);
        async Task<TcpObserverReply> Request(string op, Guid ticket, TcpProbeSpec[]? probes = null)
        {
            while (!takeRequest()) await Task.Delay(100, token);
            return await control.TcpObservation(op, ticket, probes, token);
        }
        var catalog = preparedCatalog ?? await Request("catalog", Guid.Empty);
        if (catalog.Version != 1 || catalog.Epoch == Guid.Empty || catalog.Points is null) throw new IOException("观察服务能力无效");
        if (fresh && catalog.FreshWindowMs != TcpObserverProtocol.FreshWindowMs) throw new IOException("观察服务不支持短窗口；不能使用旧观察代替新鲜端点");
        TcpObserverProtocol.ValidatePoints(catalog.Points);
        var points = catalog.Points.Where(p => !TcpObserverProtocol.Endpoint(p.Endpoint).Equals(owner.Lease.Reflector)).ToArray();
        if (calibration != null) {
            if (points.Length < 3) throw new IOException("校准需要至少三个独立观察目标，含背景探测目标");
            points = calibration.Value ? [points[0], points[1], points[2]] : [points[0], points[2]];
        }
        if (fresh) points = points.Take(freshDestinations).ToArray();
        // Resolve invariant source metadata once, BEFORE the short registration
        // and first SYN. Windows interface enumeration may block on virtual
        // adapters; it cannot be allowed to age already-validated observations
        // or be repeated for every evidence item after the freshness check.
        string interfaceId = (interfaceLookup ?? SourceInterface)(owner.Lease.Local.Address);
        token.ThrowIfCancellationRequested();
        foreach (var point in points) checkRoute(TcpObserverProtocol.Endpoint(point.Endpoint));
        if (points.Length == 0) throw new IOException("观察点与 helper 四元组冲突");
        var output = new List<TcpShapeObservation>();
        var probeStarted = new Dictionary<Guid, long>();
        // Reserve one extra tuple at a time (seven peers + one diagnostic), with
        // no independent SEQ state ever sharing an Active/Candidate tuple.
        // One ticket, at most four (fresh: two) destinations; read only after its capture
        // window ends so a late conflicting source cannot escape ambiguity checks.
        var group = points;
        var specs = group.Select(p => new TcpProbeSpec(Guid.NewGuid(), p.Id,
            System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(RandomNumberGenerator.GetBytes(4)))).ToArray();
        // Register first; any busy tuple aborts this diagnostic, leaving
        // its current owner untouched. It never delays product Gather.
        Guid ticket = Guid.NewGuid(); long registering = Stopwatch.GetTimestamp();
        var opened = await Request(fresh ? "register-fresh" : "register", ticket, specs);
        int windowMs = fresh ? TcpObserverProtocol.FreshWindowMs : TcpObserverProtocol.WindowSeconds * 1000;
        Validate(opened, ticket, catalog.Epoch, specs, group, windowMs);
        registrationConfirmed?.Invoke(); // local receipt is later than server ticket creation
        // Counting request-budget queuing conservatively can only reject a
        // marginal window. Server UTC never extends local send/freshness limits.
        if (fresh && Stopwatch.GetElapsedTime(registering).TotalMilliseconds >= windowMs) throw new IOException("短窗口登记已过期");
        if (fresh) limit.CancelAfter(TraversalLimits.PredictionAgeMs);
        long began = Stopwatch.GetTimestamp();
        for (int i = 0; i < group.Length; i++) {
            token.ThrowIfCancellationRequested();
            using var session = owner.Register(owner.Lease.NetworkGeneration, TcpObserverProtocol.Endpoint(group[i].Endpoint));
            await session.CaptureReady; session.Start();
            byte[] packet = TcpShapeSyn.Create(owner.Lease.Local, session.Peer, specs[i].Iss, unchecked((uint)Environment.TickCount64));
            for (int retry = 0; retry < (fresh ? 2 : 3); retry++) {
                bool CanSend() => fresh ? Stopwatch.GetElapsedTime(registering).TotalMilliseconds < windowMs :
                    Stopwatch.GetElapsedTime(began).TotalSeconds < 3 && DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() < opened.Expires;
                if (!CanSend()) break;
                while (!(controlRound?.TrySend(packet.Length, completion: false) ?? (resources ?? TraversalResources.Shared).TrySend(packet.Length, maintenance: true))) await Task.Delay(25, token);
                if (!CanSend()) break;
                probeStarted.TryAdd(specs[i].ProbeId, Stopwatch.GetTimestamp());
                if (!session.Send(packet)) throw new IOException("观察原生端点已退出");
                await Task.Delay(fresh ? 75 : 150, token);
            }
            // No ReceiveFrom competitor: broker is the sole receiver;
            // bounded per-session queue is discarded on release.
        }
        var remaining = TimeSpan.FromMilliseconds(windowMs) - Stopwatch.GetElapsedTime(began);
        if (remaining > TimeSpan.Zero) await Task.Delay(remaining + TimeSpan.FromMilliseconds(100), token);
        var result = await Request("read", ticket);
        Validate(result, ticket, catalog.Epoch, specs, group, windowMs);
        if (fresh && (!result.Final || probeStarted.Count != specs.Length ||
            probeStarted.Values.Any(t => Stopwatch.GetElapsedTime(t).TotalMilliseconds >= TraversalLimits.PredictionAgeMs)))
            throw new IOException("短窗口未完成或本机观察已过期");
        foreach (var e in result.Evidence) output.Add(new(owner.Lease.Id, owner.Lease.NetworkGeneration,
            owner.Lease.Local.ToString(), owner.Lease.Reflector.ToString(), e.ProbeId, e.Target, e.Source,
            e.ObservedAt, (e.ObservedAt ?? result.Expires) + 60000, e.State,
            CaptureOwnerId: owner.OwnerId,
            InterfaceId: interfaceId,
            ProbeWindowEndsAt: result.Expires, LocalProbeStartedAt: probeStarted.GetValueOrDefault(e.ProbeId)));
        if (fresh && probeStarted.Values.Any(t => Stopwatch.GetElapsedTime(t).TotalMilliseconds >= TraversalLimits.PredictionAgeMs))
            throw new IOException("完成观察封装时本机证据已过期");
        return output.ToArray();
    }
    static void Validate(TcpObserverReply r, Guid ticket, Guid epoch, TcpProbeSpec[] specs, TcpObserverPoint[] points, int windowMs)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (r.Version != 1 || r.Epoch != epoch || r.TicketId != ticket || r.CaptureWindowMs != windowMs || r.Expires > now + 10000 || r.Expires < now - 60000 ||
            r.Evidence == null || r.Evidence.Length != specs.Length || r.Evidence.Any(e => e == null) || r.Evidence.Select(e => e.ProbeId).Distinct().Count() != specs.Length ||
            r.Evidence.Any(e => !specs.Any(s => s.ProbeId == e.ProbeId && s.ObserverId == e.ObserverId) ||
                !points.Any(p => p.Id == e.ObserverId && p.Endpoint == e.Target) || e.TcpHandshakeVerified != "NotTested" ||
                e.LegacyPayloadVerified != "NotTested" || e.State is not ("Pending" or "NotObserved" or "SynObserved" or "Ambiguous") ||
                e.Source != null && (!IPEndPoint.TryParse(e.Source, out var ep) || ep.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || ep.Port == 0) ||
                (e.State == "SynObserved") != (e.Source != null) || e.Source != null && e.ObservedAt == null ||
                e.ObservedAt > now + 5000 || e.ObservedAt > r.Expires || e.ObservedAt < r.Expires - windowMs))
            throw new IOException("TCP 观察回复与登记目标或证据级别不符");
    }
}
