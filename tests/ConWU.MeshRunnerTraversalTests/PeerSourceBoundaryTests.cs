using System.Buffers.Binary;
using System.Net;
using System.Threading.Channels;
using StreamLink.Core;
using StreamLink.EndpointPoc;

static class PeerSourceBoundaryTests
{
    public static async Task Run(Action<bool, string> check, CancellationToken token)
    {
        await using var helper = new Reflector(); var generation = Guid.NewGuid();
        using var lease = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), helper.Endpoint, generation, token);
        var io = new Io(); await using var owner = new TcpCaptureOwner(lease, generation, (_, _) => io); await owner.Ready;
        var announced = new IPEndPoint(IPAddress.Loopback, 44001);
        using var session = owner.Register(generation, announced, peerReflexive: true);
        bool rejected = false; try { session.Start(); } catch (IOException) { rejected = true; }
        check(rejected && io.Sent == 0, "source learner cannot Start without wire accounting");
        var round = new TraversalControlRound(new()); var budget = new NativeWireBudget(round); session.ConfigureWireBudget(budget); budget.Start(System.Diagnostics.Stopwatch.GetTimestamp()); session.Start();
        uint iss = uint.MaxValue;
        check(session.Send(Frame(lease.Local, announced, 2, iss, 0)), "learner emits its original SYN and records the wrapping ISS");
        var first = new IPEndPoint(IPAddress.Loopback, 44002);
        byte[][] invalid = [Frame(new(IPAddress.Parse("127.0.0.2"), 44002), lease.Local, 2, 101, 0),
            Frame(first, lease.Local, 18, 101, 1), Frame(first, lease.Local, 4, 101, 0),
            Frame(first, lease.Local, 16, 101, 0), Frame(first, lease.Local, 18, 101, 0, 1),
            Frame(lease.Local, lease.Local, 2, 101, 0)];
        foreach (var packet in invalid) await io.Input.Writer.WriteAsync(new(packet, false), token);
        var valid = Frame(first, lease.Local, 18, uint.MaxValue, 0); await io.Input.Writer.WriteAsync(new(valid, false), token);
        check((await session.Receive(token)).AsSpan().SequenceEqual(valid) && session.PeerSource.Hypotheses == 1,
            "wrong IP, wrong ACK, RST, pure ACK, payload SYN and self tuple do not enter the source set; valid zero-wrapped ACK does");
        for (int i = 1; i < 4; i++) { var next = Frame(new(IPAddress.Loopback, 44002 + i), lease.Local, 2, (uint)(200 + i), 0); await io.Input.Writer.WriteAsync(new(next, false), token); await session.Receive(token); }
        await io.Input.Writer.WriteAsync(new(Frame(new(IPAddress.Loopback, 44006), lease.Local, 2, 999, 0), false), token);
        using (var wait = CancellationTokenSource.CreateLinkedTokenSource(token)) {
            wait.CancelAfter(120); bool bounded = false; try { await session.Receive(wait.Token); } catch (OperationCanceledException) { bounded = true; }
            check(bounded && session.PeerSource.Hypotheses == 4, "a fifth source hypothesis is ignored without a fifth reservation");
        }
        rejected = false; try { session.Send(Frame(lease.Local, first, 18, iss, 0), (NativeWireKind)99); } catch (IOException) { rejected = true; }
        check(rejected && !session.PeerLearned && owner.Status.WireTuples == 1, "invalid wire category cannot mutate the learned tuple");
        rejected = false; try { session.Send(Frame(lease.Local, first, 16, 0, 1)); } catch (IOException) { rejected = true; }
        check(rejected && !session.PeerLearned, "incorrect source confirmation cannot claim another TCP tuple");
        check(session.Send(Frame(lease.Local, first, 16, 0, 0)) && session.Peer.Equals(first) && owner.Status is { Sessions: 1, WireTuples: 2 },
            "matching wrapped ACK claims one actual source while retaining the announced tuple on the same session");
        session.FreezePeer();
        rejected = false; try { session.Send(Frame(lease.Local, new(IPAddress.Loopback, 44003), 18, iss, 202)); } catch (IOException) { rejected = true; }
        check(rejected && session.PeerSource.Frozen && session.Peer.Equals(first), "frozen source cannot be changed by a second previously observed endpoint");
        foreach (var tuple in new[] { announced, first }) {
            rejected = false; try { using var other = owner.Register(generation, tuple); } catch (IOException) { rejected = true; }
            check(rejected, "no independent handshake may claim a live source alias");
        }
        session.Dispose(); check(owner.Status is { Sessions: 0, WireTuples: 0 }, "confirmed worker exit releases every alias and source hypothesis");
    }
    static byte[] Frame(IPEndPoint source, IPEndPoint target, byte flags, uint seq, uint ack, int payload = 0)
    {
        byte[] p = new byte[40 + payload]; p[0] = 0x45; p[9] = 6; p[32] = 0x50; p[33] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length); source.Address.GetAddressBytes().CopyTo(p, 12); target.Address.GetAddressBytes().CopyTo(p, 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), (ushort)source.Port); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), (ushort)target.Port);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(24), seq); BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(28), ack); return p;
    }
    sealed class Io : IEndpointPacketIo {
        public readonly Channel<EndpointPacket> Input = Channel.CreateUnbounded<EndpointPacket>(); public int Sent;
        public ValueTask<EndpointPacket> Receive(CancellationToken token) => Input.Reader.ReadAsync(token);
        public bool Inject(ReadOnlySpan<byte> p) { Sent++; return true; } public bool Reinject(EndpointPacket p) => true;
        public void Shutdown() => Input.Writer.TryComplete(); public void Dispose() => Shutdown();
    }
}
