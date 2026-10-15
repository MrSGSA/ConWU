using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;

namespace StreamLink.Core;

public sealed record TraversalDatagram(byte[] Data, IPEndPoint Source);
public interface ITraversalSocket : IDisposable
{
    Guid Id { get; }
    IPEndPoint Local { get; }
    bool DontFragment => false;
    ValueTask Send(ReadOnlyMemory<byte> packet, IPEndPoint remote, CancellationToken token);
    ValueTask<TraversalDatagram> Receive(CancellationToken token);
}

// Exclusive, unconnected socket: STUN, checks and application datagrams retain
// one binding. Never share a Windows UDP port using SO_REUSEADDR.
public sealed class TraversalSocket : ITraversalSocket
{
    readonly Socket socket;
    public Guid Id { get; } = Guid.NewGuid();
    public IPEndPoint Local => (IPEndPoint)socket.LocalEndPoint!;
    public bool DontFragment { get; }
    public TraversalSocket(IPEndPoint local)
    {
        socket = new(local.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try {
            socket.ExclusiveAddressUse = true;
            if (local.AddressFamily == AddressFamily.InterNetworkV6) {
                socket.DualMode = false;
                // Winsock IPV6_DONTFRAG = 14. Socket.DontFragment addresses IPv4.
                // Do not silently qualify a fragmented path on other platforms.
                if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("原生 IPv6 PMTU 当前仅验证 Windows");
                socket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)14, 1);
                DontFragment = (int)socket.GetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)14)! != 0;
            } else { socket.DontFragment = true; DontFragment = socket.DontFragment; }
            socket.Bind(local); socket.ReceiveBufferSize = 1 << 20;
        }
        catch { socket.Dispose(); throw; }
    }
    public async ValueTask Send(ReadOnlyMemory<byte> packet, IPEndPoint remote, CancellationToken token)
        => _ = await socket.SendToAsync(packet, SocketFlags.None, remote, token);
    public async ValueTask<TraversalDatagram> Receive(CancellationToken token)
    {
        byte[] buffer = new byte[4096];
        var result = await socket.ReceiveFromAsync(buffer, SocketFlags.None,
            new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0), token);
        return new(buffer[..result.ReceivedBytes], (IPEndPoint)result.RemoteEndPoint);
    }
    public void Dispose() => socket.Dispose();
}

// One shared limiter for all attempts on a machine, not one budget per peer.
// Data packets do not use this limiter; this bounds control probes only.
public sealed record TraversalResourceUsage(int OpenUdpResources, int PeakUdpResources, long SearchAdmitted,
    long MaintenanceAdmitted, long SearchDeferred, long MaintenanceDeferred, long AdmittedBytes);

public sealed class TraversalResources(int maximumSockets = 8, int packetsPerSecond = 60, int burst = 8)
{
    public static TraversalResources Shared { get; } = new();
    public TraversalEnhancementScheduler Enhancements { get; } = new();
    readonly object gate = new();
    double tokens = burst;
    double byteTokens = TraversalLimits.ControlBytesPerSecond, searchTokens = burst, maintenanceTokens = burst;
    long tick = Stopwatch.GetTimestamp();
    int sockets, peakSockets;
    bool exploring;
    long searchAdmitted, maintenanceAdmitted, searchDeferred, maintenanceDeferred, admittedBytes;
    readonly (long Bin, int Count)[] recentControls = new (long, int)[10];
    public int RecentControlAdmissions {
        get { lock (gate) {
            long now = (long)(Stopwatch.GetElapsedTime(0, Stopwatch.GetTimestamp()).TotalMilliseconds / 100);
            return recentControls.Where(b => b.Bin <= now && now - b.Bin < 10).Sum(b => b.Count);
        } }
    }
    readonly HashSet<OptionalSocket> optionalSockets = [];
    public IDisposable Acquire()
    {
        while (true) {
            OptionalSocket victim;
            lock (gate) {
                if (sockets < (exploring ? TraversalLimits.ExperimentalResources : maximumSockets)) { sockets++; peakSockets = Math.Max(peakSockets, sockets); return new Lease(this); }
                victim = optionalSockets.FirstOrDefault() ?? throw new IOException("打洞资源已满，请等待其他尝试结束");
                optionalSockets.Remove(victim);
            }
            // Join the optional receiver and close its socket BEFORE returning
            // the quota. Never invoke resource teardown while holding gate.
            victim.Dispose();
        }
    }
    internal OptionalSocket? TryOpenOptional(Func<IDisposable> open)
    {
        OptionalSocket result;
        lock (gate) {
            if (sockets >= maximumSockets) return null; // optional listeners never consume exploration slots
            sockets++; peakSockets = Math.Max(peakSockets, sockets); result = new(this); optionalSockets.Add(result);
        }
        try { result.Open(open); return result; }
        catch { result.Dispose(); throw; }
    }
    // Only for auxiliary receive resources; open/Dispose must not acquire more
    // resources from this ledger. Required Active/Candidate sockets can revoke
    // it, whereas optional resources cannot evict each other.
    internal sealed class OptionalSocket(TraversalResources owner) : IDisposable
    {
        readonly object sync = new();
        IDisposable? resource;
        bool disposed;
        int active;
        public bool IsActive => Volatile.Read(ref active) != 0;
        internal void Open(Func<IDisposable> open)
        {
            lock (sync) { if (disposed) return; resource = open(); Volatile.Write(ref active, 1); }
        }
        public void Dispose()
        {
            lock (sync) {
                if (disposed) return; disposed = true; Volatile.Write(ref active, 0);
                try { resource?.Dispose(); }
                finally { resource = null; lock (owner.gate) { owner.optionalSockets.Remove(this); owner.sockets--; } }
            }
        }
    }
    public bool TrySend(int bytes = 128, bool maintenance = false) => TrySendCore(bytes, maintenance, false);
    internal bool TryControlSend(int bytes, bool completion) => TrySendCore(bytes, false, completion);
    bool TrySendCore(int bytes, bool maintenance, bool completion)
    {
        if (bytes is < 1 or > TraversalLimits.ControlBytesPerSecond) return false;
        lock (gate) {
            long now = Stopwatch.GetTimestamp(); double seconds = Stopwatch.GetElapsedTime(tick, now).TotalSeconds; tick = now;
            tokens = Math.Min(burst, tokens + seconds * packetsPerSecond);
            searchTokens = Math.Min(burst, searchTokens + seconds * Math.Min(48, packetsPerSecond));
            maintenanceTokens = Math.Min(burst, maintenanceTokens + seconds * Math.Min(TraversalLimits.MaintenancePps, packetsPerSecond));
            byteTokens = Math.Min(TraversalLimits.ControlBytesPerSecond, byteTokens + seconds * TraversalLimits.ControlBytesPerSecond);
            if (tokens < 1 || byteTokens < bytes || maintenance && maintenanceTokens < 1 || !maintenance && !completion && searchTokens < 1) {
                if (maintenance) maintenanceDeferred++; else searchDeferred++;
                return false;
            }
            tokens--; byteTokens -= bytes;
            if (maintenance) { maintenanceTokens--; maintenanceAdmitted++; }
            else { if (!completion) searchTokens--; searchAdmitted++; }
            admittedBytes += bytes;
            long bin = (long)(Stopwatch.GetElapsedTime(0, now).TotalMilliseconds / 100);
            int index = (int)(bin % recentControls.Length);
            var prior = recentControls[index]; recentControls[index] = (bin, prior.Bin == bin ? prior.Count + 1 : 1);
            return true;
        }
    }
    // Admission counts, not packets observed on the wire: an authorized sender
    // can still fail or be canceled. Kernel helper/native legacy overhead and
    // sockets not acquired through this ledger are deliberately not implied.
    public TraversalResourceUsage Usage()
    {
        lock (gate) return new(sockets, peakSockets, searchAdmitted, maintenanceAdmitted,
            searchDeferred, maintenanceDeferred, admittedBytes);
    }
    // Explicit experimental ownership, on this same ledger. Releasing the
    // expansion never closes an Active resource; it prevents further growth
    // above the normal limit until outstanding references return their quota.
    internal IDisposable BeginUdpExploration()
    {
        lock (gate) {
            if (exploring || maximumSockets > TraversalLimits.ExperimentalResources) throw new IOException("UDP 高成本探索资源已被占用");
            exploring = true; return new ExplorationLease(this);
        }
    }
    sealed class ExplorationLease(TraversalResources owner) : IDisposable
    {
        int disposed;
        public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) == 0) lock (owner.gate) owner.exploring = false; }
    }
    sealed class Lease(TraversalResources owner) : IDisposable
    {
        int disposed;
        public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) == 0) lock (owner.gate) owner.sockets--; }
    }
}

public sealed record PunchBudget(int DurationMs = 6000, int MaximumPackets = 120, int MaximumCandidates = 8);
public sealed record PunchResult(bool Success, string Endpoint, string Failure, int SentPackets, int AuthenticatedPackets, int LearnedCandidates, double ElapsedMs);

// Experimental connectivity foundation, NOT ICE and NOT the udp2raw data plane.
// Credentials/attempt ID must arrive via an authenticated control channel. A
// caller must encrypt/authenticate application payloads (e.g. with MeshLink).
// The same socket and receive pump remain alive after candidate verification.
public sealed partial class UdpTraversal : IAsyncDisposable
{
    const int CheckSize = 96, ProbeSize = TraversalLimits.UdpRequiredPayload, MacSize = 32;
    sealed class Candidate(IPEndPoint endpoint, bool learned) { public IPEndPoint Endpoint = endpoint; public byte[] Nonce = RandomNumberGenerator.GetBytes(16); public Guid PeerSource; public bool Learned = learned, Triggered, Checked; }
    sealed record Pending(IPEndPoint Target, byte[] Request, TaskCompletionSource<IPEndPoint> Reply);
    readonly ITraversalSocket socket;
    readonly TraversalResources resources;
    readonly IDisposable lease;
    readonly Guid generation;
    byte localSlot, remoteSlot;
    readonly byte[] attempt, key;
    readonly object gate = new();
    readonly Dictionary<string, Candidate> candidates = [];
    readonly ConcurrentDictionary<string, Pending> queries = new();
    readonly Channel<TraversalDatagram> payloads = Channel.CreateBounded<TraversalDatagram>(new BoundedChannelOptions(128) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true, SingleWriter = true });
    readonly CancellationTokenSource stop = new();
    readonly Task receiving;
    readonly SemaphoreSlim observing = new(1, 1);
    PunchBudget budget = new();
    TraversalControlRound round;
    IPEndPoint? selected;
    long started;
    int sent, authenticated, learned, begun, disposed;
    string failure = "";
    UdpProbeGroup? group;
    readonly Guid probeSource = Guid.NewGuid(); // per-resource wire token, never the local SocketResourceId
    public Guid SocketId => socket.Id;
    public IPEndPoint Local => socket.Local;
    internal bool ReceiveReady => !Closed && !receiving.IsCompleted;
    public IPEndPoint? Selected { get { lock (gate) return group == null || group.IsWinner(probeSource) ? selected : null; } }

    public UdpTraversal(ITraversalSocket socket, Guid networkGeneration, Guid attemptId, int localSlot, int remoteSlot, byte[] sharedKey, TraversalResources? resources = null)
        : this(socket, networkGeneration, attemptId, localSlot, remoteSlot, sharedKey, resources ?? TraversalResources.Shared, null) { }
    // Production callers obtain quota BEFORE binding the actual candidate
    // socket. The public injected-socket constructor remains for owned adapters.
    public static UdpTraversal Create(IPEndPoint local, Guid networkGeneration, Guid attemptId, int localSlot, int remoteSlot, byte[] sharedKey, TraversalResources? resources = null, EgressPacer? pacer = null, string? fairnessKey = null)
    {
        var machine = resources ?? TraversalResources.Shared; var quota = machine.Acquire();
        ITraversalSocket? socket = null;
        try { socket = new TraversalSocket(local); if (pacer != null) socket = new PacedTraversalSocket(socket, pacer, fairnessKey ?? remoteSlot.ToString()); return new(socket, networkGeneration, attemptId, localSlot, remoteSlot, sharedKey, machine, quota); }
        catch { socket?.Dispose(); quota.Dispose(); throw; }
    }
    internal static UdpTraversal CreateUsing(Func<ITraversalSocket> open, Guid networkGeneration, Guid attemptId,
        int localSlot, int remoteSlot, byte[] sharedKey, TraversalResources machine)
    {
        var quota = machine.Acquire(); ITraversalSocket? socket = null;
        try { socket = open(); return new(socket, networkGeneration, attemptId, localSlot, remoteSlot, sharedKey, machine, quota); }
        catch { socket?.Dispose(); quota.Dispose(); throw; }
    }
    UdpTraversal(ITraversalSocket socket, Guid networkGeneration, Guid attemptId, int localSlot, int remoteSlot, byte[] sharedKey, TraversalResources resources, IDisposable? quota)
    {
        try {
        if (networkGeneration == Guid.Empty || attemptId == Guid.Empty || sharedKey.Length != 32 || localSlot is < 1 or > 254 || remoteSlot is < 1 or > 254 || localSlot == remoteSlot)
            throw new ArgumentException("打洞会话身份无效");
        this.resources = resources; lease = quota ?? this.resources.Acquire();
        this.socket = socket; generation = networkGeneration; attempt = attemptId.ToByteArray(); this.localSlot = (byte)localSlot; this.remoteSlot = (byte)remoteSlot;
        key = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedKey, 32, attempt, "streamlink-udp-check-v2"u8.ToArray());
        round = new(this.resources);
        receiving = Receive();
        } catch { socket.Dispose(); lease?.Dispose(); throw; }
    }
    bool ValidEndpoint(IPEndPoint ep)
    {
        if (ep.AddressFamily != Local.AddressFamily || ep.Port is < 1 or > 65535) return false;
        if (ep.AddressFamily == AddressFamily.InterNetworkV6) return Ipv6Direct.UnscopedUnicast(ep.Address);
        byte first = ep.Address.GetAddressBytes()[0]; return first is > 0 and < 224 && !ep.Address.Equals(IPAddress.Broadcast);
    }
    public async Task<NatObservation> Observe(IPEndPoint server, CancellationToken token)
    {
        AcquireOperation();
        try { return await ObserveCore(server, token); }
        finally { await ReleaseReference(); }
    }
    async Task<NatObservation> ObserveCore(IPEndPoint server, CancellationToken token)
    {
        if (!ValidEndpoint(server)) throw new ArgumentException("反射服务器地址无效");
        await observing.WaitAsync(token);
        try {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            byte[] request = Stun.Request(); string id = Convert.ToHexString(request.AsSpan(8, 12));
            var completion = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
            TimeSpan? remaining = group?.Remaining ?? explorationSeed?.Remaining;
            if (remaining <= TimeSpan.Zero) throw new IOException("UDP 探索共同期限已结束");
            deadline.CancelAfter(remaining == null ? TimeSpan.FromMilliseconds(3500) : TimeSpan.FromMilliseconds(Math.Clamp(remaining.Value.TotalMilliseconds, 0, 3500)));
            queries[id] = new(server, request, completion);
            long probeStarted = Stopwatch.GetTimestamp(); // conservative age, includes any send admission/queue delay
            try {
                for (;;) {
                    deadline.Token.ThrowIfCancellationRequested();
                    if (group != null ? group.Round.TrySend(request.Length, false) : explorationSeed != null ? explorationSeed.SendAdmission(request.Length) : resources.TrySend(request.Length))
                        await socket.Send(request, server, deadline.Token);
                    var finished = await Task.WhenAny(completion.Task, Task.Delay(700, deadline.Token));
                    deadline.Token.ThrowIfCancellationRequested();
                    if (finished == completion.Task) return new(socket.Id, generation, "udp", Local, server, await completion.Task, DateTimeOffset.UtcNow, probeStarted);
                }
            } finally { queries.TryRemove(id, out _); }
        } finally { observing.Release(); }
    }
    bool InWindow() => started != 0 && Stopwatch.GetElapsedTime(started).TotalMilliseconds < budget.DurationMs;
    Candidate? Add(IPEndPoint endpoint, bool learnedFromPeer)
    {
        if (!ValidEndpoint(endpoint)) return null;
        string id = endpoint.ToString();
        if (candidates.TryGetValue(id, out var existing)) return existing;
        if (candidates.Count >= budget.MaximumCandidates) {
            var replace = candidates.FirstOrDefault(p => learnedFromPeer && !p.Value.Learned && !p.Value.Endpoint.Equals(selected));
            if (replace.Value == null) return null;
            candidates.Remove(replace.Key);
        }
        var candidate = new Candidate(endpoint, learnedFromPeer); candidates.Add(id, candidate); if (learnedFromPeer) learned++; return candidate;
    }
    byte[] Encode(byte kind, byte[] nonce)
    {
        int size = kind >= 3 ? ProbeSize : CheckSize;
        byte[] packet = RandomNumberGenerator.GetBytes(size); "SLP2"u8.CopyTo(packet);
        packet[4] = kind; packet[5] = localSlot; packet[6] = remoteSlot; packet[7] = 0;
        attempt.CopyTo(packet, 8); nonce.CopyTo(packet, 24);
        if (group != null) { "SLG3"u8.CopyTo(packet); packet[7] = group.Stable ? (byte)1 : (byte)2; probeSource.TryWriteBytes(packet.AsSpan(40, 16)); }
        HMACSHA256.HashData(key, packet.AsSpan(0, size - MacSize), packet.AsSpan(size - MacSize)); return packet;
    }
    bool ValidProbe(byte[] packet) => packet.Length is CheckSize or ProbeSize &&
        (group == null ? packet.AsSpan(0, 4).SequenceEqual("SLP2"u8) && packet[4] is >= 1 and <= 4 && packet[7] == 0 :
            packet.AsSpan(0, 4).SequenceEqual("SLG3"u8) && packet[4] is >= 1 and <= 6 && packet[7] == (group.Stable ? 2 : 1) && new Guid(packet.AsSpan(40, 16)) != Guid.Empty) &&
        packet.Length == (packet[4] >= 3 ? ProbeSize : CheckSize) &&
        packet[5] == remoteSlot && packet[6] == localSlot && packet.AsSpan(8, 16).SequenceEqual(attempt) &&
        CryptographicOperations.FixedTimeEquals(packet.AsSpan(packet.Length - MacSize), HMACSHA256.HashData(key, packet.AsSpan(0, packet.Length - MacSize)));
    async Task Check(byte kind, byte[] nonce, IPEndPoint remote)
    {
        lock (gate) {
            if (!InWindow() || group != null && !group.Allows(remote) || !round.TrySend(kind >= 3 ? ProbeSize : CheckSize, kind >= 3)) return;
            sent++;
            group?.Admitted(kind, remote);
        }
        try { await socket.Send(Encode(kind, nonce), remote, stop.Token);Interlocked.Increment(ref completedCheckSends);group?.Sent(probeSource); }
        catch (SocketException ex) { lock (gate) failure = ex.SocketErrorCode == SocketError.MessageSize && kind >= 3 ? "mtu-too-small" : "send-" + ex.SocketErrorCode; }
    }
    async Task Receive()
    {
        try {
            while (!stop.IsCancellationRequested) {
                TraversalDatagram message;
                try { message = await socket.Receive(stop.Token); }
                catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize) { continue; }
                byte[] packet = message.Data;
                if(packet.AsSpan().StartsWith("SLW4"u8)){
                    try{await ReceiveWitness(message);}catch(SocketException){}continue;
                }
                if (packet.Length >= 20 && packet.AsSpan(4, 4).SequenceEqual(new byte[] { 0x21, 0x12, 0xa4, 0x42 }) &&
                    queries.TryGetValue(Convert.ToHexString(packet.AsSpan(8, 12)), out var pending)) {
                    if (message.Source.Equals(pending.Target)) { try {
                        var mapped = Stun.Parse(packet, pending.Request, Local.AddressFamily);
                        if (ValidEndpoint(mapped)) pending.Reply.TrySetResult(mapped);
                    } catch (IOException) { } }
                    continue;
                }
                if (packet.Length >= 4 && (packet.AsSpan(0, 4).SequenceEqual("SLP2"u8) || packet.AsSpan(0, 4).SequenceEqual("SLG3"u8))) {
                    Candidate? candidate; bool trigger = false;
                    bool selectionReply = false;
                    lock (gate) {
                        if (!InWindow() || !ValidProbe(packet) || group != null && !group.Allows(message.Source)) continue;
                        authenticated++;
                        Guid sender = group == null ? Guid.Empty : new Guid(packet.AsSpan(40, 16));
                        if (packet[4] is 5 or 6) {
                            if (group == null || !message.Source.Equals(selected) || new Guid(packet.AsSpan(24, 16)) != probeSource ||
                                !candidates.TryGetValue(message.Source.ToString(), out candidate) || candidate.PeerSource != sender ||
                                packet[4] != (group.Stable ? 6 : 5) || !group.Commit(probeSource)) continue;
                            selectionReply = packet[4] == 5;
                        } else if (packet[4] is 2 or 4) {
                            candidates.TryGetValue(message.Source.ToString(), out candidate);
                            bool blind = packet[4] == 2 && group?.BlindResponse(message.Source, packet.AsSpan(24, 16)) == true;
                            if (blind) candidate ??= Add(message.Source, true);
                            if (candidate != null && (candidate.PeerSource == Guid.Empty || candidate.PeerSource == sender) &&
                                (blind || packet.AsSpan(24, 16).SequenceEqual(candidate.Nonce))) {
                                candidate.PeerSource = sender;
                                if (packet[4] == 2) candidate.Checked = true;
                                else if (candidate.Checked) selected ??= message.Source;
                            }
                            continue;
                        } else {
                            candidate = Add(message.Source, true);
                            if (candidate != null && candidate.PeerSource != Guid.Empty && candidate.PeerSource != sender) continue;
                            if (candidate != null) candidate.PeerSource = sender;
                            if (candidate != null && !candidate.Triggered) { candidate.Triggered = true; trigger = true; }
                        }
                    }
                    if (packet[4] is 5 or 6) { if (selectionReply) await Check(6, packet.AsSpan(40, 16).ToArray(), message.Source); continue; }
                    if (candidate != null) {
                        await Check(packet[4] == 3 ? (byte)4 : (byte)2, packet.AsSpan(24, 16).ToArray(), message.Source);
                        if (trigger) await Check(1, candidate.Nonce, candidate.Endpoint);
                    }
                    continue;
                }
                lock (gate) if (selected != null && (group == null || group.IsWinner(probeSource)) && message.Source.Equals(selected) && packet.Length <= ProbeSize) payloads.Writer.TryWrite(message);
            }
        } catch (Exception ex) when (stop.IsCancellationRequested && ex is OperationCanceledException or ObjectDisposedException or SocketException) { }
        catch (Exception ex) {
            lock (gate) failure = "receive-" + ex.GetType().Name;
            foreach (var query in queries.Values) query.Reply.TrySetException(ex);
            foreach (var query in witnesses.Values) query.Completion.TrySetException(ex);
        } finally { payloads.Writer.TryComplete(); }
    }
    public async Task<PunchResult> Punch(IEnumerable<IPEndPoint> endpoints, PunchBudget? limits, CancellationToken token)
    {
        AcquireOperation();
        try { return await PunchCore(endpoints, limits, token); }
        finally { await ReleaseReference(); }
    }
    async Task<PunchResult> PunchCore(IEnumerable<IPEndPoint> endpoints, PunchBudget? limits, CancellationToken token)
    {
        var input = endpoints.ToArray(); var settings = limits ?? new();
        if (group == null && (settings.DurationMs is < 100 or > 10000 || settings.MaximumPackets is < 2 or > 256) ||
            group != null && (settings.DurationMs != UdpProbeGroup.DurationMs || settings.MaximumPackets != UdpProbeGroup.PacketLimit) ||
            settings.MaximumCandidates is < 1 or > 8 || input.Length > settings.MaximumCandidates || input.Any(ep => !ValidEndpoint(ep) || group != null && !group.Allows(ep))) throw new ArgumentException("打洞预算或候选无效");
        if (Interlocked.Exchange(ref begun, 1) != 0) throw new InvalidOperationException("每轮打洞需要新的会话，不能重用过期凭据");
        lock (gate) { budget = settings; round = group?.Round ?? (witnessStarted == 0 ? new(resources, settings.MaximumPackets) : round); started = group?.Started ?? Stopwatch.GetTimestamp(); foreach (var endpoint in input) Add(endpoint, false); }
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
        bool success = false;
        long nextSelection = 0;
        try { while (true) {
            token.ThrowIfCancellationRequested(); stop.Token.ThrowIfCancellationRequested();
            Candidate[] pending;
            lock (gate) {
                if (selected != null && (group == null || group.IsWinner(probeSource)) || group?.Lost(probeSource) == true || group?.Exhausted == true || !InWindow() || receiving.IsCompleted) { success = selected != null && (group == null || group.IsWinner(probeSource)); return new(success, success ? selected!.ToString() : "", success ? "" : failure.Length > 0 ? failure : group?.Lost(probeSource) == true ? "group-not-selected" : group?.Exhausted == true ? "probe-budget-exhausted" : candidates.Values.Any(c => c.Checked) ? "mtu-unverified" : round.Packets >= budget.MaximumPackets ? "probe-budget-exhausted" : "no-verified-path", sent, authenticated, learned, Stopwatch.GetElapsedTime(started).TotalMilliseconds); }
                pending = candidates.Values.ToArray();
            }
            if (group == null || group.Drive(probeSource)) {
                IPEndPoint? proposed; lock (gate) proposed = selected;
                if (group != null && proposed != null) {
                    if (group.Stable && Environment.TickCount64 >= nextSelection) {
                        nextSelection = Environment.TickCount64 + 200;
                        var chosen = pending.Single(c => c.Endpoint.Equals(proposed)); await Check(5, chosen.PeerSource.ToByteArray(), proposed);
                    }
                } else {
                    foreach (var candidate in pending) await Check(candidate.Checked ? (byte)3 : (byte)1, candidate.Nonce, candidate.Endpoint);
                    if (group?.Stable == true && group.NextGuess() is {} guess) await Check(1, group.Nonce(guess), guess);
                }
            }
            await Task.Delay(group == null ? 200 : 25, cancellation.Token);
        } } finally { group?.Retire(probeSource); if (!success) lock (gate) started = 0; }
    }
    // These methods retain the verified socket. They provide transport, not
    // encryption: production callers must validate their own data protocol.
    public async ValueTask SendPayload(ReadOnlyMemory<byte> packet, CancellationToken token)
    {
        AcquireOperation();
        try {
            lock (gate) if (pathAttached) throw new InvalidOperationException("负载已转交给受管路径");
            await SendPayloadCore(packet, token);
        }
        finally { await ReleaseReference(); }
    }
    async ValueTask SendPayloadCore(ReadOnlyMemory<byte> packet, CancellationToken token)
    {
        var endpoint = Selected ?? throw new IOException("没有经过验证的直连路径");
        if (packet.Length is < 1 or > ProbeSize || packet.Span.StartsWith("SLP2"u8) || packet.Span.StartsWith("SLG3"u8)||packet.Span.StartsWith("SLW4"u8)) throw new ArgumentException("负载大小或保留前缀无效");
        await socket.Send(packet, endpoint, token);
    }
    public async ValueTask<TraversalDatagram> ReceivePayload(CancellationToken token)
    {
        AcquireOperation();
        bool entered = false;
        try {
            lock (gate) { if (pathAttached || payloadReaders != 0) throw new InvalidOperationException("负载接收者必须唯一"); payloadReaders++; entered = true; }
            return await payloads.Reader.ReadAsync(token);
        } finally { if (entered) lock (gate) payloadReaders--; await ReleaseReference(); }
    }
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        await ReleaseReference();
    }
}
