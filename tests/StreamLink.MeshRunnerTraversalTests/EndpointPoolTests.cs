using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Threading.Channels;
using StreamLink.Core;
using StreamLink.EndpointPoc;
using StreamLink.Service;

static class EndpointPoolTests
{
    public static async Task Run(Action<bool, string> check, CancellationToken token)
    {
        await using var reflector = new Reflector(); var generation = Guid.NewGuid();
        var opened = new List<Io>(); var clock = new Clock();
        await using var pool = new MeshTcpEndpointPool(generation, (_, _) => { var io = new Io(); opened.Add(io); return io; }, new(), time: clock);
        var uses = await Task.WhenAll(Enumerable.Range(0, 7).Select(_ => pool.Acquire(IPAddress.Loopback, reflector.Endpoint, token)));
        var lease = uses[0].Lease; var owner = uses[0].Owner; var io = opened.Single();
        check(uses.All(u => ReferenceEquals(u.Lease, lease) && ReferenceEquals(u.Owner, owner) && u.Observed.Equals(lease.Local)) && reflector.Accepted == 1,
            "production pool: concurrent candidates retain one actual source/helper and capture owner");
        check(reflector.Requests == 1 && uses.All(u => u.ObservedAt == uses[0].ObservedAt),
            "seven concurrent candidates coalesce into one real STUN transaction without refreshing observation time");
        await pool.PruneUnused(token);
        check(!lease.Closed && reflector.Accepted == 1, "quota reclamation cannot evict borrowed candidate sources");
        clock.Advance(1999);
        using (var cached = await pool.Acquire(IPAddress.Loopback, reflector.Endpoint, token)) {
            var altered = cached.Observed; altered.Port = 1;
            check(reflector.Requests == 1 && cached.ObservedAt == uses[0].ObservedAt && cached.Observed.Port == lease.Local.Port,
                "recent result keeps real timestamp and cannot be mutated by another borrower");
        }
        clock.Advance(1);
        using (var fresh = await pool.Acquire(IPAddress.Loopback, reflector.Endpoint, token))
            check(reflector.Requests == 2 && fresh.Lease.Id == lease.Id && fresh.ObservedAt > uses[0].ObservedAt,
                "at two-second boundary the exact held source is reobserved, never rebound");
        using var a = owner.Register(generation, new(IPAddress.Loopback, 43001));
        using var b = owner.Register(generation, new(IPAddress.Loopback, 43002));
        bool refused = false; try { using var stale = owner.Register(Guid.NewGuid(), new(IPAddress.Loopback, 43003)); } catch (IOException) { refused = true; }
        check(refused, "capture rejects stale generation");
        byte[] packet = Packet(lease.Local, a.Peer);
        check(!a.Send(packet) && io.Sent == 0, "capture refuses raw sends before Start");
        a.Start(); b.Start();
        refused = false; try { a.Send(Packet(lease.Local, b.Peer)); } catch (IOException) { refused = true; }
        check(refused && io.Sent == 0, "worker cannot inject another peer tuple");
        refused = false; try { a.Send(Packet(new(IPAddress.Loopback, 43004), a.Peer)); } catch (IOException) { refused = true; }
        check(refused, "worker cannot spoof a different local source");
        await io.Packets.Writer.WriteAsync(new(Packet(reflector.Endpoint, lease.Local), false), token);
        await io.Packets.Writer.WriteAsync(new(Packet(lease.Local, reflector.Endpoint), true), token);
        await io.Packets.Writer.WriteAsync(new(Packet(lease.Local, a.Peer), true), token);
        await io.Packets.Writer.WriteAsync(new(Packet(a.Peer, lease.Local), false), token);
        await io.Packets.Writer.WriteAsync(new(Packet(b.Peer, lease.Local), false), token);
        check((await a.Receive(token)).AsSpan().SequenceEqual(Packet(a.Peer, lease.Local)) &&
            (await b.Receive(token)).AsSpan().SequenceEqual(Packet(b.Peer, lease.Local)), "one receiver demultiplexes exact authorized source tuples");
        check(owner.Status is { KernelSuppressed: 1, HelperReinjected: 2 } && io.Returned == 2, "helper exception is bidirectional and kernel peer response is suppressed");
        a.Revoke();
        refused = false; try { using var duplicate = owner.Register(generation, a.Peer); } catch (IOException) { refused = true; }
        check(refused && !a.Send(packet), "revocation stops injection but reserves tuple until child exit");
        refused = false; try { a.Start(); } catch (IOException) { refused = true; }
        check(refused, "late Start cannot revive a revoked worker");
        foreach (var use in uses) use.Dispose();
        await pool.PruneUnused(token);
        check(!lease.Closed && b.Send(Packet(lease.Local, b.Peer)), "ending all candidate references preserves native worker and source");
        // A genuine failed helper transaction must retire query capability, not
        // kill the still-working authorized raw path.
        clock.Advance(2000); reflector.Silent = true;
        bool timedOut = false;
        using (var shortWait = CancellationTokenSource.CreateLinkedTokenSource(token)) {
            int beforeQuery = Volatile.Read(ref reflector.Requests);
            var partial = pool.Acquire(IPAddress.Loopback, reflector.Endpoint, shortWait.Token);
            await Wait(() => Volatile.Read(ref reflector.Requests) > beforeQuery, token);
            check(reflector.Requests == beforeQuery + 1, "failed-helper negative case reaches the real reflection stream before cancellation");
            shortWait.Cancel();
            try { using var failed = await partial; }
            catch (OperationCanceledException) { timedOut = true; }
        }
        reflector.Silent = false;
        check(timedOut && !lease.QueryUsable && !lease.Closed && b.Send(Packet(lease.Local, b.Peer)), "ambiguous helper query cannot tear down established peer capture");
        using var replacement = await pool.Acquire(IPAddress.Loopback, reflector.Endpoint, token);
        check(replacement.Lease.Id != lease.Id && replacement.Lease.Local.Port != lease.Local.Port && opened.Count == 2 && !lease.Closed,
            "replacement observation uses a distinct held endpoint while retired source remains in use");
        a.Dispose(); b.Dispose(); await owner.Closed.WaitAsync(token);
        check(lease.Closed && io.Closed, "final worker release joins capture and then closes retired helper");
        opened.Last().Shutdown(); await Wait(() => replacement.Owner.Failed, token);
        using var renewed = await pool.Acquire(IPAddress.Loopback, reflector.Endpoint, token);
        check(renewed.Lease.Id != replacement.Lease.Id && !renewed.Owner.Failed,
            "failed capture invalidates even a recent cached observation and requires another owned source");
        renewed.Dispose();
        replacement.Dispose();
        await pool.PruneUnused(token);
        check(renewed.Lease.Closed && opened.All(i => i.Closed),
            "unused source reclamation joins capture and releases the final real helper after every borrower ends");
        using var reopened = await pool.Acquire(IPAddress.Loopback, reflector.Endpoint, token);
        check(reopened.Lease.Id != renewed.Lease.Id && !reopened.Lease.Closed && !reopened.Owner.Failed,
            "reacquiring a reclaimed slot creates a new owned resource instead of reviving its retired generation");
        reopened.Dispose(); await pool.DisposeAsync();
        check(replacement.Lease.Closed && opened.All(i => i.Closed), "pool shutdown closes all final owned endpoints");
        await Isolation(check, token);
        await Shutdown(check, token);
        await Factory(check, token);
        await ReflectorChurn(check,token);
    }
    static async Task ReflectorChurn(Action<bool,string> check,CancellationToken token){
        var reflectors=new List<Reflector>();var captures=new List<Io>();
        await using var pool=new MeshTcpEndpointPool(Guid.NewGuid(),(_,_)=>{var io=new Io();captures.Add(io);return io;},new());
        try{
            for(int i=0;i<=TraversalLimits.TcpResources;i++)reflectors.Add(new Reflector());
            using var held=await pool.Acquire(IPAddress.Loopback,reflectors[0].Endpoint,token);
            var idle=new List<TcpEndpointLease>();
            for(int i=1;i<TraversalLimits.TcpResources;i++){using var use=await pool.Acquire(IPAddress.Loopback,reflectors[i].Endpoint,token);idle.Add(use.Lease);}
            using var next=await pool.Acquire(IPAddress.Loopback,reflectors[^1].Endpoint,token);
            check(!held.Lease.Closed&&held.Lease.QueryUsable&&!next.Lease.Closed,"ordinary SO pool frees idle reflector slots without evicting a borrowed source");
            check(idle.All(l=>l.Closed)&&captures.Take(TraversalLimits.TcpResources).Skip(1).All(c=>c.Closed),"reflector replacement joins and releases every evicted helper/capture owner");
        }finally{await pool.DisposeAsync();foreach(var r in reflectors)await r.DisposeAsync();}
    }
    static async Task Factory(Action<bool, string> check, CancellationToken token)
    {
        await using var reflector = new Reflector(); var clock = new Clock();
        var mesh = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var peers = Enumerable.Range(0, 7).Select(_ => MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(mesh))).Self).ToArray();
        var captures = new System.Collections.Concurrent.ConcurrentBag<Io>();
        var profile = new DeviceProfile { Mesh = mesh, TraversalMode = "tcp", TcpStun = ["fixture.invalid:3478"], StandbyPaths=true };
        await using var factory = new MeshCandidateFactory(profile, "unused", "unused", [TraversalProfile.FakeTcpHttpSo], captureBroker: true,wireControl:true) {
            ResolveTarget = (_, _, _) => Task.FromResult(reflector.Endpoint), RouteCheckForTest = (_, _, _) => { }, EndpointTimeForTest = clock,
            OpenCaptureForTest = (_, _) => { var capture = new Io(); captures.Add(capture); return capture; }
        };
        var resources = await Task.WhenAll(peers.Select(p => factory.Gather(p, TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), token)));
        try {
            var first = resources[0].Candidate;
            check(reflector.Accepted == 1 && reflector.Requests == 1 && captures.Count == 1 &&
                resources.Select(r => r.Candidate.Id).Distinct().Count() == 7 && resources.All(r => r.Candidate.Endpoint == first.Endpoint),
                "formal seven-peer candidate factory uses independent candidate IDs with one held source and one STUN observation");
            clock.Advance(1500);
            await using var cached = await factory.Gather(peers[0], TraversalProfile.FakeTcpHttpSo, Guid.NewGuid(), token);
            check(reflector.Requests == 1 && cached.Candidate.ObservedAt == first.ObservedAt && cached.Candidate.Expires == first.Expires,
                "formal candidate publication preserves original observation and expiry across a cached borrow");
            await using var standby=await factory.GatherStandby(peers[0],TraversalProfile.FakeTcpHttpSo,Guid.NewGuid(),false,null,token);
            check(standby.Candidate.Standby&&standby.Candidate.Endpoint!=first.Endpoint&&reflector.Accepted==2&&captures.Count==2,
                "formal standby source is isolated from the seven-peer shared source without granting another handshake on its tuple");
            await using var coalesced=await factory.GatherStandby(peers[0],TraversalProfile.FakeTcpHttpSo,Guid.NewGuid(),false,null,token);
            check(coalesced.Candidate.Endpoint==standby.Candidate.Endpoint&&coalesced.Candidate.Id!=standby.Candidate.Id&&reflector.Accepted==2,
                "same authenticated peer standby partition coalesces observations instead of manufacturing a source per AttemptId");
        } finally { foreach (var resource in resources) await resource.DisposeAsync(); }
        await factory.DisposeAsync();
        check(captures.All(c => c.Closed), "formal factory closes its shared owner after all peer candidates release");
    }
    static async Task Isolation(Action<bool, string> check, CancellationToken token)
    {
        await using var blocked = new Reflector { Silent = true };
        await using var healthy = new Reflector();
        var captures = new System.Collections.Concurrent.ConcurrentBag<Io>();
        await using var pool = new MeshTcpEndpointPool(Guid.NewGuid(), (_, _) => { var io = new Io(); captures.Add(io); return io; }, new());
        using var held = CancellationTokenSource.CreateLinkedTokenSource(token);
        var pending = pool.Acquire(IPAddress.Loopback, blocked.Endpoint, held.Token);
        await Wait(() => blocked.Requests == 1, token);
        using (var waiting = CancellationTokenSource.CreateLinkedTokenSource(token)) {
            var cancelled = pool.Acquire(IPAddress.Loopback, blocked.Endpoint, waiting.Token);
            waiting.Cancel(); bool removed = false;
            try { using var ignored = await cancelled; } catch (OperationCanceledException) { removed = true; }
            check(removed && blocked.Requests == 1 && !pending.IsCompleted,
                "cancelling a queued same-source candidate neither queries nor cancels its active borrower");
        }
        var elapsed = Stopwatch.StartNew();
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(token); limit.CancelAfter(1000);
        using var other = await pool.Acquire(IPAddress.Loopback, healthy.Endpoint, limit.Token);
        check(!pending.IsCompleted && healthy.Requests == 1 && elapsed.ElapsedMilliseconds < 1000,
            "another source completes real helper query while the first STUN flow is still unanswered");
        held.Cancel(); bool firstCancelled = false;
        try { using var ignored = await pending; } catch (OperationCanceledException) { firstCancelled = true; }
        check(firstCancelled && other.Lease.QueryUsable && !other.Owner.Failed,
            "in-flight query cancellation is isolated to that source, preserving unrelated capture");
        other.Dispose(); await pool.DisposeAsync();
        check(captures.All(c => c.Closed) && other.Lease.Closed, "independent source operations all join during shutdown");
    }
    static async Task Shutdown(Action<bool, string> check, CancellationToken token)
    {
        await using var reflector = new Reflector { Silent = true };
        var captures = new System.Collections.Concurrent.ConcurrentBag<Io>();
        var pool = new MeshTcpEndpointPool(Guid.NewGuid(), (_, _) => { var io = new Io(); captures.Add(io); return io; }, new());
        var requests = Enumerable.Range(0, 7).Select(_ => pool.Acquire(IPAddress.Loopback, reflector.Endpoint, token)).ToArray();
        await Wait(() => reflector.Requests == 1, token);
        await Task.WhenAll(pool.DisposeAsync().AsTask(), pool.DisposeAsync().AsTask()).WaitAsync(TimeSpan.FromSeconds(3), token);
        int cancelled = 0;
        foreach (var pending in requests) try { using var unexpected = await pending; } catch (OperationCanceledException) { cancelled++; }
        check(cancelled == 7 && captures.All(c => c.Closed), "shutdown cancels in-flight and six queued borrowers without orphan capture or duplicate disposal");
        bool rejected = false; try { using var unexpected = await pool.Acquire(IPAddress.Loopback, reflector.Endpoint, token); } catch (ObjectDisposedException) { rejected = true; }
        check(rejected, "disposed source pool rejects later acquisition");
    }
    static async Task Wait(Func<bool> ready, CancellationToken token)
    {
        var clock = Stopwatch.StartNew();
        while (!ready()) { if (clock.ElapsedMilliseconds >= 2000) throw new TimeoutException("Helper query never arrived"); await Task.Delay(5, token); }
    }
    sealed class Clock : TimeProvider
    {
        long tick;
        readonly DateTimeOffset origin = DateTimeOffset.UtcNow;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Interlocked.Read(ref tick);
        public override DateTimeOffset GetUtcNow() => origin.AddMilliseconds(GetTimestamp());
        public void Advance(int ms) => Interlocked.Add(ref tick, ms);
    }
    static byte[] Packet(IPEndPoint from, IPEndPoint to)
    {
        byte[] p = new byte[40]; p[0] = 0x45; p[3] = 40; p[9] = 6; p[32] = 0x50; p[33] = 0x10;
        from.Address.GetAddressBytes().CopyTo(p, 12); to.Address.GetAddressBytes().CopyTo(p, 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), (ushort)from.Port); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), (ushort)to.Port); return p;
    }
    sealed class Io : IEndpointPacketIo
    {
        public readonly Channel<EndpointPacket> Packets = Channel.CreateUnbounded<EndpointPacket>();
        public int Sent, Returned; public bool Closed;
        public ValueTask<EndpointPacket> Receive(CancellationToken token) => Packets.Reader.ReadAsync(token);
        public bool Inject(ReadOnlySpan<byte> p) { Sent++; return true; }
        public bool Reinject(EndpointPacket packet) { Returned++; return true; }
        public void Shutdown() => Packets.Writer.TryComplete();
        public void Dispose() { Closed = true; Shutdown(); }
    }
}
