using System.Buffers.Binary;
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
        var opened = new List<Io>();
        await using var pool = new MeshTcpEndpointPool(generation, (_, _) => { var io = new Io(); opened.Add(io); return io; }, new());
        var uses = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => pool.Acquire(IPAddress.Loopback, reflector.Endpoint, token)));
        var lease = uses[0].Lease; var owner = uses[0].Owner; var io = opened.Single();
        check(uses.All(u => ReferenceEquals(u.Lease, lease) && ReferenceEquals(u.Owner, owner) && u.Observed.Equals(lease.Local)) && reflector.Accepted == 1,
            "production pool: concurrent candidates retain one actual source/helper and capture owner");
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
        check(!lease.Closed && b.Send(Packet(lease.Local, b.Peer)), "ending all candidate references preserves native worker and source");
        // A genuine failed helper transaction must retire query capability, not
        // kill the still-working authorized raw path.
        reflector.Silent = true;
        bool timedOut = false;
        using (var shortWait = CancellationTokenSource.CreateLinkedTokenSource(token)) {
            shortWait.CancelAfter(180);
            try { using var failed = await pool.Acquire(IPAddress.Loopback, reflector.Endpoint, shortWait.Token); }
            catch (OperationCanceledException) { timedOut = true; }
        }
        reflector.Silent = false;
        check(timedOut && !lease.QueryUsable && !lease.Closed && b.Send(Packet(lease.Local, b.Peer)), "ambiguous helper query cannot tear down established peer capture");
        using var replacement = await pool.Acquire(IPAddress.Loopback, reflector.Endpoint, token);
        check(replacement.Lease.Id != lease.Id && replacement.Lease.Local.Port != lease.Local.Port && opened.Count == 2 && !lease.Closed,
            "replacement observation uses a distinct held endpoint while retired source remains in use");
        a.Dispose(); b.Dispose(); await owner.Closed.WaitAsync(token);
        check(lease.Closed && io.Closed, "final worker release joins capture and then closes retired helper");
        replacement.Dispose(); await pool.DisposeAsync();
        check(replacement.Lease.Closed && opened.All(i => i.Closed), "pool shutdown closes all final owned endpoints");
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
