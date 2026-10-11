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
    ValueTask Send(ReadOnlyMemory<byte> packet, IPEndPoint remote, CancellationToken token);
    ValueTask<TraversalDatagram> Receive(CancellationToken token);
}

// Exclusive, unconnected socket: STUN, checks and application datagrams retain
// one binding. Never share a Windows UDP port using SO_REUSEADDR.
public sealed class TraversalSocket : ITraversalSocket
{
    readonly Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    public Guid Id { get; } = Guid.NewGuid();
    public IPEndPoint Local => (IPEndPoint)socket.LocalEndPoint!;
    public TraversalSocket(IPEndPoint local)
    {
        try { socket.ExclusiveAddressUse = true; socket.Bind(local); socket.ReceiveBufferSize = 1 << 20; }
        catch { socket.Dispose(); throw; }
    }
    public async ValueTask Send(ReadOnlyMemory<byte> packet, IPEndPoint remote, CancellationToken token)
        => _ = await socket.SendToAsync(packet, SocketFlags.None, remote, token);
    public async ValueTask<TraversalDatagram> Receive(CancellationToken token)
    {
        byte[] buffer = new byte[4096];
        var result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), token);
        return new(buffer[..result.ReceivedBytes], (IPEndPoint)result.RemoteEndPoint);
    }
    public void Dispose() => socket.Dispose();
}

// One shared limiter for all attempts on a machine, not one budget per peer.
// Data packets do not use this limiter; this bounds control probes only.
public sealed class TraversalResources(int maximumSockets = 8, int packetsPerSecond = 60, int burst = 8)
{
    public static TraversalResources Shared { get; } = new();
    readonly object gate = new();
    double tokens = burst;
    long tick = Stopwatch.GetTimestamp();
    int sockets;
    public IDisposable Acquire()
    {
        lock (gate) {
            if (sockets >= maximumSockets) throw new IOException("打洞资源已满，请等待其他尝试结束");
            sockets++; return new Lease(this);
        }
    }
    public bool TrySend()
    {
        lock (gate) {
            long now = Stopwatch.GetTimestamp(); tokens = Math.Min(burst, tokens + Stopwatch.GetElapsedTime(tick, now).TotalSeconds * packetsPerSecond); tick = now;
            if (tokens < 1) return false; tokens--; return true;
        }
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
public sealed class UdpTraversal : IAsyncDisposable
{
    const int ProbeSize = 1400, MacSize = 32;
    sealed class Candidate(IPEndPoint endpoint, bool learned) { public IPEndPoint Endpoint = endpoint; public byte[] Nonce = RandomNumberGenerator.GetBytes(16); public bool Learned = learned, Triggered; }
    sealed record Pending(IPEndPoint Target, byte[] Request, TaskCompletionSource<IPEndPoint> Reply);
    readonly ITraversalSocket socket;
    readonly TraversalResources resources;
    readonly IDisposable lease;
    readonly Guid generation;
    readonly byte localSlot, remoteSlot;
    readonly byte[] attempt, key;
    readonly object gate = new();
    readonly Dictionary<string, Candidate> candidates = [];
    readonly ConcurrentDictionary<string, Pending> queries = new();
    readonly Channel<TraversalDatagram> payloads = Channel.CreateBounded<TraversalDatagram>(new BoundedChannelOptions(128) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true, SingleWriter = true });
    readonly CancellationTokenSource stop = new();
    readonly Task receiving;
    readonly SemaphoreSlim observing = new(1, 1);
    PunchBudget budget = new();
    IPEndPoint? selected;
    long started;
    int sent, authenticated, learned, begun, disposed;
    string failure = "";
    public Guid SocketId => socket.Id;
    public IPEndPoint Local => socket.Local;
    public IPEndPoint? Selected { get { lock (gate) return selected; } }

    public UdpTraversal(ITraversalSocket socket, Guid networkGeneration, Guid attemptId, int localSlot, int remoteSlot, byte[] sharedKey, TraversalResources? resources = null)
    {
        try {
        if (networkGeneration == Guid.Empty || attemptId == Guid.Empty || sharedKey.Length != 32 || localSlot is < 1 or > 254 || remoteSlot is < 1 or > 254 || localSlot == remoteSlot)
            throw new ArgumentException("打洞会话身份无效");
        this.resources = resources ?? TraversalResources.Shared; lease = this.resources.Acquire();
        this.socket = socket; generation = networkGeneration; attempt = attemptId.ToByteArray(); this.localSlot = (byte)localSlot; this.remoteSlot = (byte)remoteSlot;
        key = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedKey, 32, attempt, "streamlink-udp-check-v1"u8.ToArray());
        receiving = Receive();
        } catch { socket.Dispose(); lease?.Dispose(); throw; }
    }
    static bool ValidEndpoint(IPEndPoint ep)
    {
        if (ep.AddressFamily != AddressFamily.InterNetwork || ep.Port is < 1 or > 65535) return false;
        byte first = ep.Address.GetAddressBytes()[0]; return first is > 0 and < 224 && !ep.Address.Equals(IPAddress.Broadcast);
    }
    public async Task<NatObservation> Observe(IPEndPoint server, CancellationToken token)
    {
        if (!ValidEndpoint(server)) throw new ArgumentException("反射服务器地址无效");
        await observing.WaitAsync(token);
        try {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            byte[] request = Stun.Request(); string id = Convert.ToHexString(request.AsSpan(8, 12));
            var completion = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
            queries[id] = new(server, request, completion);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token); deadline.CancelAfter(3500);
            try {
                for (;;) {
                    if (resources.TrySend()) await socket.Send(request, server, deadline.Token);
                    var finished = await Task.WhenAny(completion.Task, Task.Delay(700, deadline.Token));
                    deadline.Token.ThrowIfCancellationRequested();
                    if (finished == completion.Task) return new(socket.Id, generation, "udp", Local, server, await completion.Task, DateTimeOffset.UtcNow);
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
        byte[] packet = RandomNumberGenerator.GetBytes(ProbeSize); "SLP1"u8.CopyTo(packet);
        packet[4] = kind; packet[5] = localSlot; packet[6] = remoteSlot; packet[7] = 0;
        attempt.CopyTo(packet, 8); nonce.CopyTo(packet, 24);
        HMACSHA256.HashData(key, packet.AsSpan(0, ProbeSize - MacSize), packet.AsSpan(ProbeSize - MacSize)); return packet;
    }
    bool ValidProbe(byte[] packet) => packet.Length == ProbeSize && packet.AsSpan(0, 4).SequenceEqual("SLP1"u8) && packet[4] is 1 or 2 &&
        packet[5] == remoteSlot && packet[6] == localSlot && packet[7] == 0 && packet.AsSpan(8, 16).SequenceEqual(attempt) &&
        CryptographicOperations.FixedTimeEquals(packet.AsSpan(ProbeSize - MacSize), HMACSHA256.HashData(key, packet.AsSpan(0, ProbeSize - MacSize)));
    async Task Check(byte kind, byte[] nonce, IPEndPoint remote)
    {
        lock (gate) {
            if (!InWindow() || sent >= budget.MaximumPackets || !resources.TrySend()) return;
            sent++;
        }
        try { await socket.Send(Encode(kind, nonce), remote, stop.Token); }
        catch (SocketException ex) { lock (gate) failure = "send-" + ex.SocketErrorCode; }
    }
    async Task Receive()
    {
        try {
            while (!stop.IsCancellationRequested) {
                TraversalDatagram message;
                try { message = await socket.Receive(stop.Token); }
                catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize) { continue; }
                byte[] packet = message.Data;
                if (packet.Length >= 20 && packet.AsSpan(4, 4).SequenceEqual(new byte[] { 0x21, 0x12, 0xa4, 0x42 }) &&
                    queries.TryGetValue(Convert.ToHexString(packet.AsSpan(8, 12)), out var pending)) {
                    if (message.Source.Equals(pending.Target)) { try { pending.Reply.TrySetResult(Stun.Parse(packet, pending.Request)); } catch (IOException) { } }
                    continue;
                }
                if (packet.Length >= 4 && packet.AsSpan(0, 4).SequenceEqual("SLP1"u8)) {
                    Candidate? candidate; bool trigger = false;
                    lock (gate) {
                        if (!InWindow() || !ValidProbe(packet)) continue;
                        authenticated++;
                        if (packet[4] == 2) {
                            if (candidates.TryGetValue(message.Source.ToString(), out candidate) && packet.AsSpan(24, 16).SequenceEqual(candidate.Nonce)) selected ??= message.Source;
                            continue;
                        }
                        candidate = Add(message.Source, true);
                        if (candidate != null && !candidate.Triggered) { candidate.Triggered = true; trigger = true; }
                    }
                    if (candidate != null) {
                        await Check(2, packet.AsSpan(24, 16).ToArray(), message.Source);
                        if (trigger) await Check(1, candidate.Nonce, candidate.Endpoint);
                    }
                    continue;
                }
                lock (gate) if (selected != null && message.Source.Equals(selected) && packet.Length <= ProbeSize) payloads.Writer.TryWrite(message);
            }
        } catch (Exception ex) when (stop.IsCancellationRequested && ex is OperationCanceledException or ObjectDisposedException or SocketException) { }
        catch (Exception ex) {
            lock (gate) failure = "receive-" + ex.GetType().Name;
            foreach (var query in queries.Values) query.Reply.TrySetException(ex);
        } finally { payloads.Writer.TryComplete(); }
    }
    public async Task<PunchResult> Punch(IEnumerable<IPEndPoint> endpoints, PunchBudget? limits, CancellationToken token)
    {
        var input = endpoints.ToArray(); var settings = limits ?? new();
        if (settings.DurationMs is < 100 or > 10000 || settings.MaximumPackets is < 2 or > 256 || settings.MaximumCandidates is < 1 or > 8 || input.Length > settings.MaximumCandidates || input.Any(ep => !ValidEndpoint(ep))) throw new ArgumentException("打洞预算或候选无效");
        if (Interlocked.Exchange(ref begun, 1) != 0) throw new InvalidOperationException("每轮打洞需要新的会话，不能重用过期凭据");
        lock (gate) { budget = settings; started = Stopwatch.GetTimestamp(); foreach (var endpoint in input) Add(endpoint, false); }
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
        bool success = false;
        try { while (true) {
            token.ThrowIfCancellationRequested(); stop.Token.ThrowIfCancellationRequested();
            Candidate[] pending;
            lock (gate) {
                if (selected != null || !InWindow() || receiving.IsCompleted) { success = selected != null; return new(success, selected?.ToString() ?? "", success ? "" : failure.Length > 0 ? failure : sent >= budget.MaximumPackets ? "probe-budget-exhausted" : "no-verified-path", sent, authenticated, learned, Stopwatch.GetElapsedTime(started).TotalMilliseconds); }
                pending = candidates.Values.ToArray();
            }
            foreach (var candidate in pending) await Check(1, candidate.Nonce, candidate.Endpoint);
            await Task.Delay(200, cancellation.Token);
        } } finally { if (!success) lock (gate) started = 0; }
    }
    // These methods retain the verified socket. They provide transport, not
    // encryption: production callers must validate their own data protocol.
    public async ValueTask SendPayload(ReadOnlyMemory<byte> packet, CancellationToken token)
    {
        var endpoint = Selected ?? throw new IOException("没有经过验证的直连路径");
        if (packet.Length is < 1 or > ProbeSize || packet.Span.StartsWith("SLP1"u8)) throw new ArgumentException("负载大小或保留前缀无效");
        await socket.Send(packet, endpoint, token);
    }
    public ValueTask<TraversalDatagram> ReceivePayload(CancellationToken token) => payloads.Reader.ReadAsync(token);
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stop.Cancel(); socket.Dispose();
        try { await receiving; } finally { lease.Dispose(); CryptographicOperations.ZeroMemory(key); stop.Dispose(); }
    }
}
