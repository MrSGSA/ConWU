using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Channels;

namespace StreamLink.Core;

public sealed record NativePathDiagnostics(Guid AttemptId, Guid LeaseId, Guid AttachId, string Local, string Peer,
    bool CaptureArmed, bool StartAcknowledged, bool NativeExited, int BridgeProbeAttempts,
    int AuthenticatedProbeReceives, bool PayloadQualified, double RemainingMs);

public sealed class NativePathVerificationException(string reason, NativePathDiagnostics diagnostic, Exception inner)
    : IOException($"Native 路径验证未完成：{reason}; attempt={diagnostic.AttemptId:N}; lease={diagnostic.LeaseId:N}; attach={diagnostic.AttachId:N}; " +
        $"local={diagnostic.Local}; peer={diagnostic.Peer}; armed={diagnostic.CaptureArmed}; started={diagnostic.StartAcknowledged}; " +
        $"bridgeProbes={diagnostic.BridgeProbeAttempts}; authenticatedProbes={diagnostic.AuthenticatedProbeReceives}; remainingMs={diagnostic.RemainingMs:F0}", inner)
{
    public string Reason { get; } = reason;
    public NativePathDiagnostics Diagnostic { get; } = diagnostic;
}

// One authorized native attachment and one loopback bridge. The native child
// remains the sole raw capture owner; this class never binds the helper's TCP P.
// Prepared paths are caller-owned, then transferred to MeshRouter after Qualify.
[SupportedOSPlatform("windows")]
public sealed class NativeDatagramPath : IMeshDatagramPath, ITraversalControlledPath, IPreparedMeshPath
{
    const int ProbeSize = TraversalLimits.UdpRequiredPayload;
    readonly object gate = new();
    readonly Socket bridge;
    readonly CancellationTokenSource stop = new();
    readonly Channel<byte[]> incoming = Channel.CreateBounded<byte[]>(128);
    readonly Channel<byte[]> outgoing = Channel.CreateBounded<byte[]>(128);
    readonly TaskCompletionSource proof = new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly byte[] digest, key, challenge = RandomNumberGenerator.GetBytes(16);
    readonly bool client;
    readonly ValidatedPathIdentity identity;
    readonly string configuration;
    IPEndPoint? application;
    NativeAttachment? native;
    Task receiver = Task.CompletedTask, sender = Task.CompletedTask;
    Task? starting, closing;
    int failed, qualified, reading, bridgeProbeAttempts, authenticatedProbeReceives;
    bool disposed;
    public TraversalControlRound ControlRound { get; }
    public TraversalAttemptContext Context { get; }
    public ValidatedPathIdentity Identity => Volatile.Read(ref qualified) != 0 && native != null
        ? identity with { AttachId = native.AttachId, ActualLocal = Copy(identity.ActualLocal), ActualRemote = Copy(identity.ActualRemote) }
        : throw new InvalidOperationException("Native 路径尚未完成本轮认证与包长检查");
    public bool Failed => Volatile.Read(ref failed) != 0 || native?.Exited == true;
    public bool Armed => !Volatile.Read(ref disposed) && native?.Armed == true && !Failed;
    public bool Started => native?.Started == true;
    public bool Closed { get { lock (gate) return closing?.IsCompleted == true; } }
    public TimeSpan RemainingAttemptTime => native?.RemainingRound ?? TimeSpan.Zero;
    public Guid AttachId => native?.AttachId ?? Guid.Empty;
    public int ProcessId => native?.ProcessId ?? 0;
    // Bridge sends are not physical SYN counters. Start acknowledges the worker
    // command, not the peer handshake; only an authenticated full payload proves it.
    public NativePathDiagnostics Diagnostics => new(Context.AttemptId, identity.LeaseId, AttachId,
        identity.ActualLocal.ToString(), identity.ActualRemote.ToString(), native?.Armed == true, Started, native?.Exited != false,
        Volatile.Read(ref bridgeProbeAttempts), Volatile.Read(ref authenticatedProbeReceives), Volatile.Read(ref qualified) != 0,
        RemainingAttemptTime.TotalMilliseconds);
    public IPEndPoint BridgeEndpoint => Copy((IPEndPoint)bridge.LocalEndPoint!);
    static IPEndPoint Copy(IPEndPoint ep) => new(IPAddress.Parse(ep.Address.ToString()), ep.Port);

    NativeDatagramPath(TcpEndpointLease lease, Guid generation, TraversalAttemptContext context,
        IPEndPoint peer, ReadOnlySpan<byte> sharedKey, string sessionRoot, TraversalResources resources)
    {
        if (context.Profile != TraversalProfile.FakeTcpHttpSo || sharedKey.Length != 32 || generation != lease.NetworkGeneration)
            throw new ArgumentException("Native 受管路径需要已协商的 SO profile、成员密钥及当前资源代次");
        digest = PathNomination.ContextDigest(context); Context = context; client = context.ProtocolClient;
        key = new byte[32]; HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedKey, key, digest, "streamlink-native-path-check-v1"u8);
        identity = new(Guid.NewGuid(), context.AttemptId, lease.Id, null, generation, lease.Local, Copy(peer), context.Profile, PathQualification.MtuQualified);
        ControlRound = new(resources);
        configuration = Path.Combine(sessionRoot, "managed-raw-" + Guid.NewGuid().ToString("N") + ".conf");
        bridge = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try {
            bridge.ExclusiveAddressUse = true; bridge.DontFragment = true;
            bridge.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        } catch { bridge.Dispose(); CryptographicOperations.ZeroMemory(key); throw; }
    }

    public static async Task<NativeDatagramPath> Prepare(string executable, string sessionRoot,
        TcpEndpointLease lease, Guid generation, TraversalAttemptContext context, IPEndPoint peer,
        byte[] sharedKey, CancellationToken token, TraversalResources? resources = null,
        IDictionary<string, string>? environment = null)
    {
        Directory.CreateDirectory(sessionRoot);
        var path = new NativeDatagramPath(lease, generation, context, peer, sharedKey, sessionRoot, resources ?? TraversalResources.Shared);
        byte[] rawSecret = new byte[32]; HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedKey, rawSecret, path.digest, "streamlink-native-outer-v1"u8);
        string rawKey = Convert.ToHexString(rawSecret); CryptographicOperations.ZeroMemory(rawSecret);
        try {
            if (path.client) {
                // Native owns its UDP listener. A collision before its bind fails
                // preparation; no reuse/second owner is permitted by this bridge.
                using var free = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                free.ExclusiveAddressUse = true; free.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                path.application = Copy((IPEndPoint)free.LocalEndPoint!);
            }
            string bind = path.client ? path.application!.ToString() : lease.Local.ToString();
            string target = path.client ? peer.ToString() : path.BridgeEndpoint.ToString();
            await File.WriteAllTextAsync(path.configuration,
                $"{(path.client ? "-c" : "-s")}\n-l {bind}\n-r {target}\n-k {rawKey}\n--raw-mode faketcp\n--fix-gro\n--seq-mode 3\n--fake-http test.ustc.edu.cn\n--log-level 4\n", token);
            path.native = await NativeAttachment.Launch(lease, generation, executable, ["--conf-file", path.configuration], peer,
                !path.client, Path.ChangeExtension(path.configuration, ".log"), token, environment, [rawKey], simultaneousOpen: true, startImmediately: false);
            path.native.ProcessExited += path.Fault;
            if (path.native.Exited) throw new IOException("Native exited during preparation");
            path.receiver = path.ReceiveLoop(); path.sender = path.SendLoop();
            return path;
        } catch { await path.DisposeAsync(); throw; }
    }

    // Both endpoints must be Prepared before the authenticated coordinator calls
    // this. The router receives only the remainder of NativeAttachment's clock.
    public Task StartAndQualify(CancellationToken token)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed, this);
            return starting ??= Qualify(token);
        }
    }
    public async Task<IMeshDatagramPath> Activate(CancellationToken token) { await StartAndQualify(token); return this; }
    async Task Qualify(CancellationToken token)
    {
        try {
            using var startDeadline = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
            startDeadline.CancelAfter(TraversalLimits.SoRoundMs);
            await native!.Start(startDeadline.Token);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
            if (RemainingAttemptTime <= TimeSpan.Zero) throw new TimeoutException("Native round expired before path check");
            deadline.CancelAfter(RemainingAttemptTime);
            while (!proof.Task.IsCompleted) {
                IPEndPoint? target; lock (gate) target = application;
                if (target != null) await SendProbe(1, challenge, target, deadline.Token);
                await Task.WhenAny(proof.Task, Task.Delay(200, deadline.Token));
                deadline.Token.ThrowIfCancellationRequested();
            }
            await proof.Task;
            if (RemainingAttemptTime <= TimeSpan.Zero) throw new TimeoutException("Native round expired after path check");
            Volatile.Write(ref qualified, 1);
        } catch (Exception ex) when ((ex is OperationCanceledException or TimeoutException) && !token.IsCancellationRequested && !Volatile.Read(ref disposed)) {
            var diagnostic = Diagnostics;
            string reason = diagnostic.NativeExited ? "native-exited" : diagnostic.RemainingMs <= 0 ? "round-expired" : "path-pump-stopped";
            Fault(); throw new NativePathVerificationException(reason, diagnostic, ex);
        } catch { Fault(); throw; }
    }
    byte[] Probe(byte kind, ReadOnlySpan<byte> nonce)
    {
        byte[] frame = new byte[ProbeSize]; "SLF1"u8.CopyTo(frame); frame[4] = kind; frame[5] = (byte)(client ? 1 : 2);
        digest.CopyTo(frame, 8); nonce.CopyTo(frame.AsSpan(40, 16));
        HMACSHA256.HashData(key, frame.AsSpan(0, ProbeSize - 32), frame.AsSpan(ProbeSize - 32)); return frame;
    }
    bool ValidProbe(ReadOnlySpan<byte> frame)
    {
        if (frame.Length != ProbeSize || !frame[..4].SequenceEqual("SLF1"u8) || frame[4] is < 1 or > 2 ||
            frame[5] != (client ? 2 : 1) || frame[6] != 0 || frame[7] != 0 || !frame.Slice(8, 32).SequenceEqual(digest)) return false;
        Span<byte> tag = stackalloc byte[32]; HMACSHA256.HashData(key, frame[..^32], tag);
        return CryptographicOperations.FixedTimeEquals(tag, frame[^32..]);
    }
    async Task SendProbe(byte kind, ReadOnlyMemory<byte> nonce, IPEndPoint target, CancellationToken token)
    {
        // Old/replayed probes cannot keep amplifying after this round's deadline.
        if (RemainingAttemptTime <= TimeSpan.Zero || !ControlRound.TrySend(ProbeSize, kind == 2)) return;
        Interlocked.Increment(ref bridgeProbeAttempts);
        await SendOnce(Probe(kind, nonce.Span), target, token);
    }
    async Task ReceiveLoop()
    {
        byte[] buffer = new byte[2048];
        try {
            while (true) {
                var read = await bridge.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), stop.Token);
                var source = (IPEndPoint)read.RemoteEndPoint;
                if (!Started || !source.Address.Equals(IPAddress.Loopback)) continue;
                IPEndPoint? expected; lock (gate) expected = application;
                if (expected != null && !source.Equals(expected)) continue;
                var frame = buffer.AsMemory(0, read.ReceivedBytes);
                if (ValidProbe(frame.Span)) {
                    // A server learns its dynamic native UDP source ONLY after
                    // per-member, per-attempt authentication. The native raw
                    // receive filter separately remains the authorized exact tuple.
                    if (RemainingAttemptTime <= TimeSpan.Zero) continue;
                    Interlocked.Increment(ref authenticatedProbeReceives);
                    if (expected == null) { lock (gate) application = Copy(source); }
                    if (buffer[4] == 1) await SendProbe(2, frame.Slice(40, 16), source, stop.Token);
                    else if (frame.Span.Slice(40, 16).SequenceEqual(challenge)) proof.TrySetResult();
                } else if (Volatile.Read(ref qualified) != 0 && expected != null && frame.Length <= ProbeSize && frame.Span.StartsWith("SLM4"u8))
                    incoming.Writer.TryWrite(frame.ToArray()); // one sole receiver, bounded; MeshLink verifies AEAD
            }
        } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (stop.IsCancellationRequested) { }
        catch { Fault(); }
        finally { incoming.Writer.TryComplete(); }
    }
    async Task SendOnce(ReadOnlyMemory<byte> frame, IPEndPoint target, CancellationToken token)
    {
        try { await bridge.SendToAsync(frame, SocketFlags.None, target, token); }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.NoBufferSpaceAvailable or SocketError.WouldBlock or SocketError.TimedOut or SocketError.ConnectionReset or SocketError.ConnectionRefused) {
            // Drop a transiently blocked datagram, never retransmit business.
        }
    }
    async Task SendLoop()
    {
        try {
            await foreach (var packet in outgoing.Reader.ReadAllAsync(stop.Token)) {
                IPEndPoint? target; lock (gate) target = application;
                if (target != null) await SendOnce(packet, target, stop.Token);
            }
        } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch { Fault(); }
    }
    public bool TrySend(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length is < MeshLink.Overhead or > ProbeSize || Volatile.Read(ref qualified) == 0 || Failed) return false;
        lock (gate) return !disposed && outgoing.Writer.TryWrite(datagram.ToArray());
    }
    public async ValueTask<ReadOnlyMemory<byte>> Receive(CancellationToken token)
    {
        if (Interlocked.Exchange(ref reading, 1) != 0) throw new InvalidOperationException("Native 路径只能有一个业务接收者");
        try { return await incoming.Reader.ReadAsync(token); }
        finally { Volatile.Write(ref reading, 0); }
    }
    void Fault()
    {
        Interlocked.Exchange(ref failed, 1); proof.TrySetCanceled();
        try { stop.Cancel(); } catch (ObjectDisposedException) { }
    }
    public ValueTask DisposeAsync()
    {
        lock (gate) { if (closing != null) return new(closing); disposed = true; closing = Close(); return new(closing); }
    }
    async Task Close()
    {
        stop.Cancel(); proof.TrySetCanceled(); outgoing.Writer.TryComplete();
        try {
            if (starting != null) try { await starting; } catch { }
            await Task.WhenAll(receiver, sender);
        } finally {
            bridge.Dispose(); incoming.Writer.TryComplete();
            try { if (native != null) { native.ProcessExited -= Fault; await native.DisposeAsync(); } }
            finally { CryptographicOperations.ZeroMemory(key); File.Delete(configuration); stop.Dispose(); }
        }
    }
}
