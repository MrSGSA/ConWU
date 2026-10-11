using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Threading.Channels;
using StreamLink.Core;
using StreamLink.EndpointPoc;

static class WireBudgetTests
{
    public static async Task<object> Run(Action<bool, string> check, CancellationToken token)
    {
        check(NativeRawChannel.DecodeHeader(1392, false) == (1392, NativeWireKind.Handshake), "legacy raw pipe frame remains canonical without metadata capability");
        foreach (var invalid in new[] { (Word: 65536u + 80u, Enabled: false), (Word: 4u * 65536 + 80, Enabled: true), (Word: 0xffff0050u, Enabled: true), (Word: 39u, Enabled: true) }) {
            bool rejected = false; try { NativeRawChannel.DecodeHeader(invalid.Word, invalid.Enabled); } catch (IOException) { rejected = true; }
            check(rejected, "raw pipe rejects unknown/unnegotiated category or undersized frame before allocation: " + invalid.Word);
        }
        var round = new TraversalControlRound(new TraversalResources(8, 10000, 256));
        var budget = new NativeWireBudget(round);
        check(!budget.Admit(NativeWireKind.Handshake, 64) && round.Packets == 0, "no native packet is admitted before Start");
        long started = Stopwatch.GetTimestamp(); budget.Start(started); budget.Start(started);
        bool restart = false; try { budget.Start(started + 1); } catch (InvalidOperationException) { restart = true; }
        check(restart, "duplicate Start cannot reset the native eight-second deadline");
        for (int i = 0; i < 96; i++) if (!budget.Admit(NativeWireKind.Business, 64)) throw new Exception("unexpected round exhaustion");
        check(!budget.Admit(NativeWireKind.Business, 64) && round.Packets == 96, "unselected Business labels still consume the same round, preserving completion reserve");
        for (int i = 0; i < 24; i++) if (!budget.Admit(NativeWireKind.Completion, 64)) throw new Exception("completion reserve missing");
        check(round.Packets == 120 && round.Bytes == 7680 && !budget.Admit(NativeWireKind.Completion, 64), "actual native IP packet bytes share one 120-packet round across categories");
        budget.Select();
        check(budget.Admit(NativeWireKind.Business, 1392) && round.Packets == 120 && budget.Snapshot().BusinessBytes == 1392,
            "authenticated selected business no longer consumes control tokens or renews the round");
        check(budget.Admit(NativeWireKind.Maintenance, 64) && budget.Snapshot().MaintenancePackets == 1, "selected heartbeats use machine maintenance tokens after round exhaustion");
        var expired = new NativeWireBudget(new(new())); expired.Start(Stopwatch.GetTimestamp() - 9 * Stopwatch.Frequency);
        check(!expired.Admit(NativeWireKind.Completion, 64) && !expired.Admit(NativeWireKind.Business, 64), "late completion and unselected business cannot revive an expired native round");
        var byteRound = new TraversalControlRound(new TraversalResources(8, 10000, 256)); var byteBudget = new NativeWireBudget(byteRound); byteBudget.Start(Stopwatch.GetTimestamp());
        for (int i = 0; i < 4; i++) if (!byteBudget.Admit(NativeWireKind.Handshake, 16384)) throw new Exception("byte allowance missing");
        check(byteRound.Bytes == 65536 && !byteBudget.Admit(NativeWireKind.Completion, 40), "whole outer IP bytes, rather than only MeshLink payload, enforce the round byte ceiling");
        var predictionMachine = new TraversalResources(8, 10000, 256);
        var predictionRound = new TraversalControlRound(predictionMachine);
        predictionRound.TrySend(60, false); predictionRound.TrySend(60, false);
        long measuredAt = Stopwatch.GetTimestamp() - Stopwatch.Frequency;
        var predictionGroup = new NativeAttemptGroup(predictionMachine, () => true, measuredAt, predictionRound);
        var predictionWire = new NativeWireBudget(predictionRound, predictionGroup); predictionWire.Start(Stopwatch.GetTimestamp());
        check(predictionWire.Admit(NativeWireKind.Handshake, 60) && predictionRound.Packets == 3 && predictionRound.Bytes == 180 && predictionGroup.Remaining.TotalSeconds < 7,
            "fresh observations and native SYN share the already-started deadline and same actual round allowance");
        bool foreign = false; try { _ = new NativeAttemptGroup(new(), () => true, controlRound: predictionRound); } catch (ArgumentException) { foreign = true; }
        check(foreign, "a prediction round cannot be reassigned to a separate machine budget");

        await using var reflector = new Reflector();
        Guid generation = Guid.NewGuid();
        using var lease = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, token);
        var io = new RecordingIo(); await using var owner = new TcpCaptureOwner(lease, generation, (_, _) => io);
        await owner.Ready.WaitAsync(token);
        var machine = new TraversalResources();
        var sessions = new List<TcpCaptureOwner.Session>(); var budgets = new List<NativeWireBudget>();
        var frames = new List<byte[]>();
        try {
            for (int i = 0; i < 7; i++) {
                var peer = new IPEndPoint(IPAddress.Parse("192.0.2." + (i + 1)), 42000 + i);
                var session = owner.Register(generation, peer); sessions.Add(session);
                var accounting = new NativeWireBudget(new(machine)); budgets.Add(accounting); session.ConfigureWireBudget(accounting);
                accounting.Start(Stopwatch.GetTimestamp()); session.Start();
                if (i == 6) accounting.Select();
                frames.Add(Packet(lease.Local, peer, 64));
            }
            long begin = Stopwatch.GetTimestamp(); int turn = 0;
            while (Stopwatch.GetElapsedTime(begin).TotalSeconds < 3) {
                for (int j = 0; j < 7; j++) { int i = (turn + j) % 7; sessions[i].Send(frames[i], i == 6 ? NativeWireKind.Maintenance : NativeWireKind.Handshake); }
                turn++; await Task.Delay(1, token);
            }
            double elapsed = Stopwatch.GetElapsedTime(begin).TotalSeconds;
            var all = budgets.Select(b => b.Snapshot()).ToArray(); var sends = io.Sends.ToArray();
            long search = all.Sum(b => b.HandshakePackets), maintenance = all.Sum(b => b.MaintenancePackets);
            check(sends.Length == search + maintenance && owner.Status.Injected == sends.Length && all.All(b => b.Denied > 0),
                "seven concurrent sessions are charged at the actual capture injection boundary, including denied attempts");
            check(sends.Length <= 8 + 60 * elapsed && search <= 8 + 48 * elapsed && maintenance <= 8 + 24 * elapsed && maintenance > 0,
                "shared native search and maintenance obey the global 60pps/burst8 and 48/24pps sublimits");
            bool invalid = false;
            try { sessions[6].Send(Packet(lease.Local, sessions[6].Peer, 40), NativeWireKind.Business); } catch (IOException) { invalid = true; }
            check(invalid, "header-only TCP control cannot masquerade as business metadata");
            int before = io.Sends.Count; sessions[0].Revoke();
            check(!sessions[0].Send(frames[0]) && io.Sends.Count == before, "Revoked session never injects or consumes another frame");
            return new { elapsed, search, maintenance, injected = sends.Length, budgets = all, finalInjectionTest = true,
                realTcpHelper = true, rawIo = "memory", independentPhysicalWindows = false };
        } finally { foreach (var session in sessions) session.Dispose(); }
    }
    static byte[] Packet(IPEndPoint from, IPEndPoint to, int size)
    {
        byte[] p = new byte[size]; p[0] = 0x45; p[9] = 6; p[32] = 0x50; p[33] = 0x10;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)size);
        from.Address.GetAddressBytes().CopyTo(p, 12); to.Address.GetAddressBytes().CopyTo(p, 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), (ushort)from.Port); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), (ushort)to.Port);
        return p;
    }
    sealed class RecordingIo : IEndpointPacketIo
    {
        readonly Channel<EndpointPacket> inbound = Channel.CreateUnbounded<EndpointPacket>();
        public readonly ConcurrentQueue<long> Sends = [];
        public ValueTask<EndpointPacket> Receive(CancellationToken t) => inbound.Reader.ReadAsync(t);
        public bool Inject(ReadOnlySpan<byte> p) { Sends.Enqueue(Stopwatch.GetTimestamp()); return true; }
        public bool Reinject(EndpointPacket p) => true;
        public void Shutdown() => inbound.Writer.TryComplete();
        public void Dispose() => Shutdown();
    }
}
