using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Threading.Channels;

namespace StreamLink.Core;

public sealed record EndpointPacket(byte[] Bytes, bool Outbound, byte[]? PlatformAddress = null);
public interface IEndpointPacketIo : IDisposable
{
    ValueTask<EndpointPacket> Receive(CancellationToken token);
    bool Inject(ReadOnlySpan<byte> packet);
    bool Reinject(EndpointPacket packet);
    void Shutdown();
}

public sealed record CaptureOwnerStatus(Guid OwnerId, Guid LeaseId, bool Retiring, bool Closed, int Sessions,
    long Received, long Injected, long KernelSuppressed, long HelperReinjected, long QueueDrops, string Failure)
{
    public CaptureQueueDiagnostics Queues { get; init; } = new(0, 0, 0, 0, 0, 0, 0, 0);
    public int WireTuples { get; init; }
}
public sealed record TcpPeerSourceStats(bool Enabled, string Announced, string Actual, int Hypotheses, bool Learned, bool Frozen);
public sealed record CaptureQueueDiagnostics(long Enqueued, long Dequeued, int PeakSessionDepth,
    double MaximumQueueMs, long QueuedOver20Ms, long PipeWrites, double MaximumPipeWriteMs, long PipeWritesOver16Ms);

// Exactly one capture handle owns this exclusive source endpoint. Workers own
// independent session references, never a second handle/bind on the same P.
// The caller retains the lease's original owner reference; this class retains
// the unique NativeReference until capture I/O and every worker have stopped.
public sealed class TcpCaptureOwner : IAsyncDisposable
{
    readonly object gate = new();
    readonly TcpEndpointLease.NativeReference reference;
    readonly IEndpointPacketIo io;
    readonly EgressPacer? pacer;
    readonly EgressRouteCache routes = new();
    readonly Dictionary<IPEndPoint, Session> sessions = [];
    readonly CancellationTokenSource stop = new();
    readonly Task receiver;
    readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly TaskCompletionSource closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    bool retiring, closing;
    string failure = "";
    long received, injected, suppressed, helperReinjected, queueDrops;
    long enqueued, dequeued, queueTicks, queuedOver20, pipeWrites, pipeTicks, pipeOver16;
    int peakDepth;
    public TcpEndpointLease Lease { get; }
    public Guid OwnerId => reference.AttachId;
    public Task Ready => ready.Task;
    public Task Closed => closed.Task;
    public bool Failed { get { lock (gate) return failure.Length != 0 || closing; } }
    public CaptureOwnerStatus Status { get { lock (gate) return new(OwnerId, Lease.Id, retiring, closed.Task.IsCompletedSuccessfully, sessions.Values.Distinct().Count(), received, injected, suppressed, helperReinjected, queueDrops, failure) {
        WireTuples = sessions.Count,
        Queues = new(enqueued, dequeued, peakDepth, queueTicks * 1000d / Stopwatch.Frequency, queuedOver20,
            pipeWrites, pipeTicks * 1000d / Stopwatch.Frequency, pipeOver16)
    }; } }

    public TcpCaptureOwner(TcpEndpointLease lease, Guid generation, Func<IPEndPoint, IPEndPoint, IEndpointPacketIo> open, EgressPacer? pacer = null)
    {
        this.pacer = pacer;
        reference = lease.AcquireNativeAttachment(generation); Lease = lease;
        try { io = open(lease.Local, lease.Reflector); receiver = Task.Factory.StartNew(Receive, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default).Unwrap(); }
        catch { reference.Dispose(); throw; }
    }
    public Session Register(Guid generation, IPEndPoint peer, string? fairnessKey = null, bool peerReflexive = false)
    {
        lock (gate) {
            if (retiring || closing || failure.Length != 0 || generation != Lease.NetworkGeneration ||
                peer.AddressFamily != Lease.Local.AddressFamily || peer.Port == 0 ||
                peer.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !Ipv6Direct.UnscopedUnicast(peer.Address) ||
                peer.Equals(Lease.Local) || peer.Equals(Lease.Reflector) || sessions.Values.Distinct().Count() >= 8 ||
                peerReflexive && (peer.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                    sessions.Values.Any(s => s.peerReflexive && s.announced.Address.Equals(peer.Address))))
                throw new IOException("Capture owner unavailable or unauthorized tuple");
            if (sessions.ContainsKey(peer)) throw new IOException("The TCP wire tuple already has a live or retiring session");
            var session = new Session(this, new(IPAddress.Parse(peer.Address.ToString()), peer.Port), fairnessKey, peerReflexive); sessions.Add(session.Peer, session); return session;
        }
    }
    // Unfragmented IPv4/TCP or fixed-header IPv6/TCP. Extension/fragment/jumbo
    // packets are deliberately rejected, never parsed at an assumed TCP offset.
    // A capture tuple is an authorization boundary, never a member identity proof.
    internal static bool Tuple(ReadOnlySpan<byte> p, out IPEndPoint source, out IPEndPoint target, bool exactLength = false)
    {
        source = target = null!;
        if (p.Length < 40 || p.Length > 65535) return false;
        if (p[0] >> 4 == 6) {
            int size = 40 + BinaryPrimitives.ReadUInt16BigEndian(p[4..]);
            if (p.Length < 60 || p[6] != 6 || size < 60 || size > p.Length || exactLength && size != p.Length ||
                (p[52] >> 4) < 5 || 40 + (p[52] >> 4) * 4 > size) return false;
            source = new(new IPAddress(p.Slice(8, 16)), BinaryPrimitives.ReadUInt16BigEndian(p[40..]));
            target = new(new IPAddress(p.Slice(24, 16)), BinaryPrimitives.ReadUInt16BigEndian(p[42..]));
            return source.Port != 0 && target.Port != 0 && Ipv6Direct.UnscopedUnicast(source.Address) && Ipv6Direct.UnscopedUnicast(target.Address);
        }
        if (p[0] >> 4 != 4 || p[9] != 6 || (p[6] & 0x3f) != 0 || p[7] != 0) return false;
        int ip = (p[0] & 15) * 4, declared = BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
        if (ip < 20 || p.Length < ip + 20 || declared < ip + 20 || declared > p.Length || exactLength && declared != p.Length) return false;
        int tcp = (p[ip + 12] >> 4) * 4;
        if (tcp < 20 || ip + tcp > declared) return false;
        source = new(new IPAddress(p.Slice(12, 4)), BinaryPrimitives.ReadUInt16BigEndian(p[ip..]));
        target = new(new IPAddress(p.Slice(16, 4)), BinaryPrimitives.ReadUInt16BigEndian(p[(ip + 2)..]));
        return source.Port != 0 && target.Port != 0;
    }
    async Task Receive()
    {
        ready.TrySetResult();
        try {
            while (!stop.IsCancellationRequested) {
                var packet = await io.Receive(stop.Token);
                if (!Tuple(packet.Bytes, out var source, out var target)) continue;
                lock (gate) {
                    if (closing) break;
                    received++;
                    var local = packet.Outbound ? source : target; var remote = packet.Outbound ? target : source;
                    // The production filter excludes helper in both directions.
                    // Defensive reinjection preserves a helper if an adapter errs.
                    if (!local.Equals(Lease.Local) || remote.Equals(Lease.Reflector)) {
                        if (!io.Reinject(packet)) throw new IOException("Cannot return excluded packet to kernel");
                        if (remote.Equals(Lease.Reflector)) helperReinjected++;
                        continue;
                    }
                    if (packet.Outbound) { suppressed++; continue; }
                    sessions.TryGetValue(remote, out var session);
                    session ??= sessions.Values.Distinct().FirstOrDefault(s => s.ObserveSource(remote, packet.Bytes));
                    if (session != null && session.started && !session.retired && !session.revoked) {
                        if (!session.incoming.Writer.TryWrite(new(packet.Bytes, Stopwatch.GetTimestamp()))) queueDrops++;
                        else { enqueued++; session.depth++; peakDepth = Math.Max(peakDepth, session.depth); }
                    }
                }
            }
        } catch (Exception ex) when (stop.IsCancellationRequested && ex is OperationCanceledException or ObjectDisposedException or IOException or ChannelClosedException) { }
        catch (Exception ex) {
            lock (gate) { failure = ex.GetType().Name; foreach (var session in sessions.Values) session.incoming.Writer.TryComplete(ex); }
            ready.TrySetException(ex);
        }
    }
    void Release(Session session)
    {
        lock (gate) {
            if (!session.retired) {
                session.retired = true; session.started = false; session.incoming.Writer.TryComplete();
                foreach (var key in sessions.Where(pair => ReferenceEquals(pair.Value, session)).Select(pair => pair.Key).ToArray()) sessions.Remove(key);
            }
            if (retiring && sessions.Count == 0 && !closing) { closing = true; _ = Close(); }
        }
    }
    async Task Close()
    {
        try {
            stop.Cancel();
            // Even a failed shutdown must not skip joining the actual receiver.
            try { io.Shutdown(); } catch (Exception ex) { lock (gate) failure = "shutdown-" + ex.GetType().Name; }
            await receiver; io.Dispose();
            reference.Dispose(); stop.Dispose(); closed.TrySetResult();
        } catch (Exception ex) {
            lock (gate) failure = "close-" + ex.GetType().Name;
            // If capture closure cannot be proved, retain source ownership.
            closed.TrySetException(ex);
        }
    }
    public ValueTask DisposeAsync()
    {
        lock (gate) {
            retiring = true; // existing session references retain capture
            if (sessions.Count != 0) return ValueTask.CompletedTask;
            if (!closing) { closing = true; _ = Close(); }
            return new(closed.Task);
        }
    }
    public sealed class Session : IDisposable
    {
        readonly TcpCaptureOwner owner;
        internal readonly record struct QueuedPacket(byte[] Bytes, long EnqueuedAt);
        internal readonly Channel<QueuedPacket> incoming = Channel.CreateBounded<QueuedPacket>(new BoundedChannelOptions(64) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = true });
        internal int depth;
        internal bool started, retired, revoked;
        IPEndPoint peer;
        internal readonly IPEndPoint announced;
        internal readonly bool peerReflexive;
        readonly Dictionary<IPEndPoint, uint> sourceSyns = [];
        int hypotheses;
        uint? ownIss;
        long startedAt;
        bool frozen;
        readonly EgressPacer.Flow? outbound;
        internal Session(TcpCaptureOwner owner, IPEndPoint peer, string? fairnessKey, bool peerReflexive)
        { this.owner = owner; this.peer = peer; announced = peer; this.peerReflexive = peerReflexive;
          outbound = owner.pacer?.RegisterRouted(fairnessKey ?? peer.ToString(), _ => owner.routes.Get(Lease.Local.Address, Volatile.Read(ref this.peer).Address),
              (packet, kind) => SendNow(packet.Span, (NativeWireKind)(kind ?? NativeWireKind.Handshake))); }
        NativeWireBudget? wireBudget;
        internal void ConfigureWireBudget(NativeWireBudget budget)
        {
            lock (owner.gate) { if (started || wireBudget != null) throw new InvalidOperationException("Wire budget must be attached once before Start"); wireBudget = budget; }
        }
        public Guid AttachId { get; } = Guid.NewGuid();
        public Guid CaptureOwnerId => owner.OwnerId;
        public TcpEndpointLease Lease => owner.Lease;
        public IPEndPoint Peer { get { var value = Volatile.Read(ref peer); return new(IPAddress.Parse(value.Address.ToString()), value.Port); } }
        public bool PeerLearned => !Peer.Equals(announced);
        public TcpPeerSourceStats PeerSource { get { lock (owner.gate) return new(peerReflexive, announced.ToString(), peer.ToString(), hypotheses, PeerLearned, frozen); } }
        public void FreezePeer() { lock (owner.gate) frozen = true; }
        public bool Failed { get { lock (owner.gate) return retired || revoked || owner.failure.Length != 0 || owner.closing; } }
        public Task CaptureReady => owner.Ready;
        public void Start() { lock (owner.gate) { if (Failed) throw new IOException("Capture session unavailable"); if (peerReflexive && wireBudget == null) throw new IOException("Source learning requires wire accounting"); if (startedAt == 0) startedAt = Stopwatch.GetTimestamp(); started = true; } }
        public void Revoke() { lock (owner.gate) { started = false; revoked = true; } }
        public bool Send(ReadOnlySpan<byte> packet, NativeWireKind kind = NativeWireKind.Handshake)
        {
            if (!Tuple(packet, out var source, out var target, exactLength: true) || !source.Equals(Lease.Local))
                throw new IOException("Worker attempted an unauthorized raw tuple");
            if (!Enum.IsDefined(kind) || wireBudget == null && kind != NativeWireKind.Handshake) throw new IOException("Unauthorized wire metadata");
            int ip = (packet[0] >> 4) == 6 ? 40 : (packet[0] & 15) * 4;
            int tcp = (packet[ip + 12] >> 4) * 4;
            if (kind is NativeWireKind.Business or NativeWireKind.Diagnostic && (packet.Length <= ip + tcp || (packet[ip + 13] & 7) != 0))
                throw new IOException("TCP shape control cannot use the business budget");
            lock (owner.gate) {
                if (!started || Failed) return false;
                if (!target.Equals(peer) && !ClaimSource(target, packet)) throw new IOException("Worker attempted an unobserved or conflicting peer tuple");
            }
            if (outbound == null) return SendNow(packet, kind);
            // Only actual small TCP shape controls get priority. Encrypted
            // udp2raw payloads cannot be classified by guessed application data.
            bool control = packet.Length <= 256 && (packet.Length == ip + tcp || (packet[ip + 13] & 7) != 0);
            return kind==NativeWireKind.Diagnostic&&wireBudget is{}budget
                ?outbound.TrySendWhenReady(packet,packet.Length,kind,budget.DiagnosticDelay)
                :outbound.TrySend(packet, packet.Length, context: kind, priority: control);
        }
        bool SendNow(ReadOnlySpan<byte> packet, NativeWireKind kind)
        {
            lock (owner.gate) {
                if (!started || Failed) return false;
                if (!Tuple(packet, out _, out var target, exactLength: true) || !target.Equals(peer)) return false;
                if (wireBudget != null && !wireBudget.Admit(kind, packet.Length)) return false;
                if (peerReflexive && SynHeader(packet, out byte flags, out uint seq, out _, out _) && flags == 2)
                    ownIss ??= seq;
                try { bool sent = owner.io.Inject(packet); if (sent) owner.injected++; return sent; }
                catch (Exception ex) { owner.failure = "inject-" + ex.GetType().Name; throw; }
            }
        }
        bool Learning => peerReflexive && !frozen && started && !retired && !revoked && !PeerLearned && ownIss != null &&
            startedAt != 0 && Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds < TraversalLimits.SoRoundMs;
        // Only initial, empty TCP shape SYNs from the declared peer IP may enter
        // the bounded hypothesis set. They are not authenticated path evidence.
        internal bool ObserveSource(IPEndPoint source, ReadOnlySpan<byte> packet)
        {
            if (!Learning || !source.Address.Equals(announced.Address) || source.Equals(Lease.Reflector) || source.Equals(Lease.Local) ||
                !SynHeader(packet, out byte flags, out uint seq, out uint ack, out _) || flags is not (2 or 18) ||
                flags == 18 && ack != unchecked(ownIss!.Value + 1)) return false;
            if (sourceSyns.TryGetValue(source, out uint previous)) return previous == seq;
            if (sourceSyns.Count >= TraversalLimits.TcpSourceHypotheses) return false;
            sourceSyns.Add(new(source.Address, source.Port), seq); hypotheses++; return true;
        }
        bool ClaimSource(IPEndPoint target, ReadOnlySpan<byte> packet)
        {
            if (!Learning || !sourceSyns.TryGetValue(target, out uint remoteIss) || owner.sessions.ContainsKey(target) ||
                !SynHeader(packet, out byte flags, out uint seq, out uint ack, out _) || ack != unchecked(remoteIss + 1) ||
                !(flags == 18 && seq == ownIss || flags == 16 && seq == unchecked(ownIss!.Value + 1))) return false;
            // Keep the announced tuple reserved until confirmed worker exit.
            // The changed tuple shares the same ISS/state, never a second SYN.
            owner.sessions.Add(new(target.Address, target.Port), this);
            Volatile.Write(ref peer, new(target.Address, target.Port)); sourceSyns.Clear(); return true;
        }
        static bool SynHeader(ReadOnlySpan<byte> p, out byte flags, out uint seq, out uint ack, out int ip)
        {
            flags = 0; seq = ack = 0; ip = (p[0] >> 4) == 6 ? 40 : (p[0] & 15) * 4;
            int tcp = (p[ip + 12] >> 4) * 4;
            if (p.Length != ip + tcp) return false;
            flags = p[ip + 13]; seq = BinaryPrimitives.ReadUInt32BigEndian(p[(ip + 4)..]); ack = BinaryPrimitives.ReadUInt32BigEndian(p[(ip + 8)..]); return true;
        }
        public async ValueTask<byte[]> Receive(CancellationToken token)
        {
            var packet = await incoming.Reader.ReadAsync(token);
            long ticks = Stopwatch.GetTimestamp() - packet.EnqueuedAt;
            lock (owner.gate) {
                depth--; owner.dequeued++; owner.queueTicks = Math.Max(owner.queueTicks, ticks);
                if (ticks * 1000d / Stopwatch.Frequency > 20) owner.queuedOver20++;
            }
            return packet.Bytes;
        }
        internal void RecordPipeWrite(long started)
        {
            long ticks = Stopwatch.GetTimestamp() - started;
            lock (owner.gate) {
                owner.pipeWrites++; owner.pipeTicks = Math.Max(owner.pipeTicks, ticks);
                if (ticks * 1000d / Stopwatch.Frequency > 16) owner.pipeOver16++;
            }
        }
        // The caller must confirm its native worker exited before releasing this
        // tuple; Revoke alone must not allow a second independent ISS/state.
        public void Dispose() { outbound?.Dispose(); owner.Release(this); }
    }
}
