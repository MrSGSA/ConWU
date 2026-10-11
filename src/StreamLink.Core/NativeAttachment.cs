using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace StreamLink.Core;

// A process attachment owns a separate Lease reference until confirmed process
// exit. Not yet a validated path: callers must authenticate the actual transport.
[SupportedOSPlatform("windows")]
public sealed class NativeAttachment : IDisposable, IAsyncDisposable
{
    readonly int Size;
    readonly IDisposable reference;
    readonly TcpCaptureOwner.Session? brokerSession;
    readonly NativeRawChannel? rawChannel;
    readonly ChildJob job;
    readonly NamedPipeServerStream pipe;
    readonly byte[] identity;
    readonly CancellationTokenSource stopping = new();
    readonly SemaphoreSlim control = new(1, 1);
    Process? process;
    Task heartbeat = Task.CompletedTask;
    int disposed, childExited, childId;
    long startTimestamp;
    uint request = 1;
    public Guid AttachId { get; }
    public Guid? CaptureOwnerId => brokerSession?.CaptureOwnerId;
    public Guid LeaseId { get; }
    public bool Armed { get; private set; }
    public bool Started { get; private set; }
    // Start transmission, not the acknowledgement, begins the one round clock.
    // Preparation and duplicate Start never reset it. Authentication/nomination
    // must use the remaining interval instead of allocating another eight seconds.
    public TimeSpan RemainingRound => Volatile.Read(ref startTimestamp) is var stamp && stamp != 0
        ? TimeSpan.FromMilliseconds(TraversalLimits.SoRoundMs) - Stopwatch.GetElapsedTime(stamp) : TimeSpan.Zero;
    // Read on every datagram (sometimes several times). ChildJob enables exit
    // notifications, and Launch checks HasExited once after registering ours.
    // Keep kernel process queries on startup/teardown, off the packet hot path.
    public bool Exited => Volatile.Read(ref childExited) != 0 || process == null;
    public int ProcessId => childId;
    public event Action? ProcessExited;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);

    NativeAttachment(TcpEndpointLease lease, Guid generation, IPEndPoint peer, bool server, bool simultaneousOpen, TcpCaptureOwner? captureOwner, string? fairnessKey)
    {
        bool v6 = lease.Local.AddressFamily == AddressFamily.InterNetworkV6;
        Size = v6 ? 144 : 96;
        if (peer.AddressFamily != lease.Local.AddressFamily || peer.Equals(lease.Reflector) || peer.Equals(lease.Local) ||
            v6 && (!Ipv6Direct.UnscopedUnicast(peer.Address) || captureOwner == null))
            throw new ArgumentException("Native peer and helper require distinct same-family tuples; IPv6 requires the capture broker");
        if (captureOwner != null) {
            if (!ReferenceEquals(captureOwner.Lease, lease)) throw new ArgumentException("Capture owner does not hold this lease");
            brokerSession = captureOwner.Register(generation, peer, fairnessKey); reference = brokerSession; AttachId = brokerSession.AttachId;
        } else { var owned = lease.AcquireNativeAttachment(generation); reference = owned; AttachId = owned.AttachId; }
        LeaseId = lease.Id;
        try {
            job = new();
            string name = "StreamLink.Attach." + Guid.NewGuid().ToString("N");
            pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance, Size * 2, Size * 2);
            PipeName = name;
            identity = new byte[Size]; "SLNA"u8.CopyTo(identity);
            BinaryPrimitives.WriteUInt16LittleEndian(identity.AsSpan(4), (ushort)(v6 ? 2 : TraversalLimits.NativeAbi));
            BinaryPrimitives.WriteUInt32LittleEndian(identity.AsSpan(8), (uint)Size);
            AttachId.TryWriteBytes(identity.AsSpan(16)); lease.Id.TryWriteBytes(identity.AsSpan(32));
            generation.TryWriteBytes(identity.AsSpan(48));
            Endpoint(identity, 64, lease.Local, v6 ? 96 : 64); Endpoint(identity, 70, lease.Reflector, v6 ? 112 : 70); Endpoint(identity, 76, peer, v6 ? 128 : 76);
            identity[82] = (byte)(server ? 2 : 1); identity[83] = (byte)(simultaneousOpen ? 2 : 1); // same HTTP data profile
            BinaryPrimitives.WriteUInt32LittleEndian(identity.AsSpan(84), 10000);
            BinaryPrimitives.WriteUInt32LittleEndian(identity.AsSpan(88), 1); // immutable capture descriptor
            if (brokerSession != null) {
                identity[92] = 1; // authorized brokered data pipe, not an environment skip-bind flag
                rawChannel = new(name, brokerSession);
                rawChannel.Faulted += () => { if (Volatile.Read(ref disposed) == 0 && process is { HasExited: false }) try { process.Kill(); } catch (InvalidOperationException) { } };
            }
        } catch { pipe?.Dispose(); reference.Dispose(); job?.Dispose(); throw; }
    }
    string PipeName { get; }
    static void Endpoint(byte[] frame, int offset, IPEndPoint ep, int addressOffset)
    {
        ep.Address.GetAddressBytes().CopyTo(frame, addressOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(offset + 4), checked((ushort)ep.Port));
    }

    public static async Task<NativeAttachment> Launch(TcpEndpointLease lease, Guid generation,
        string executable, IEnumerable<string> arguments, IPEndPoint peer, bool server,
        string? logPath, CancellationToken token, IDictionary<string, string>? environment = null,
        IEnumerable<string>? secrets = null, bool simultaneousOpen = false, bool startImmediately = true, TcpCaptureOwner? captureOwner = null, string? fairnessKey = null)
    {
        var owner = new NativeAttachment(lease, generation, peer, server, simultaneousOpen, captureOwner, fairnessKey);
        try {
            owner.process = owner.job.Start(executable, arguments.Concat(["--managed-pipe", owner.PipeName]), logPath, environment, secrets);
            owner.childId = owner.process.Id;
            if (owner.rawChannel != null) {
                byte[] authorization = (byte[])owner.identity.Clone();
                BinaryPrimitives.WriteUInt16LittleEndian(authorization.AsSpan(6), 1);
                BinaryPrimitives.WriteUInt32LittleEndian(authorization.AsSpan(12), 1);
                owner.rawChannel.Start(owner.process.Id, authorization);
            }
            owner.process.Exited += (_, _) => { Volatile.Write(ref owner.childExited, 1); owner.reference.Dispose(); owner.ProcessExited?.Invoke(); };
            if (owner.process.HasExited) { owner.reference.Dispose(); throw new IOException("Native process exited before Attach"); }
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(20000);
            await owner.pipe.WaitForConnectionAsync(deadline.Token);
            if (!GetNamedPipeClientProcessId(owner.pipe.SafePipeHandle, out uint pid) || pid != owner.process.Id)
                throw new IOException("AttachUnauthorized: pipe client is not the launched process");
            await owner.Exchange(1, 2, deadline.Token); owner.Armed = true;
            if (startImmediately) await owner.Start(deadline.Token);
            owner.heartbeat = owner.KeepControlAlive();
            return owner;
        } catch (Exception ex) {
            await owner.DisposeAsync();
            if (peer.AddressFamily == AddressFamily.InterNetworkV6 && ex is EndOfStreamException)
                throw new IOException("Native ABI 2 IPv6 接入未获确认；请核对原生组件版本和 broker 授权记录", ex);
            throw;
        }
    }
    // Prepare (Launch with startImmediately=false) establishes capture ownership
    // only. The pair coordinator calls Start after both peers report Ready.
    public async Task Start(CancellationToken token)
    {
        if (!Armed) throw new InvalidOperationException("CaptureNotReady");
        try { await Exchange(3, 7, token); }
        catch { pipe.Dispose(); throw; } // ambiguous control reply cannot be reused
    }
    async Task Exchange(ushort type, ushort expected, CancellationToken token)
    {
        await control.WaitAsync(token);
        try {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0 && type != 4, this);
        if (type == 3 && Started) return; // duplicate Start reuses this attachment
        byte[] message = (byte[])identity.Clone();
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(6), type);
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(12), request++);
        if (type == 3) { brokerSession?.Start(); Interlocked.CompareExchange(ref startTimestamp, Stopwatch.GetTimestamp(), 0); }
        await pipe.WriteAsync(message, token);
        byte[] reply = new byte[Size]; await pipe.ReadExactlyAsync(reply, token);
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(6), expected);
        if (!reply.AsSpan().SequenceEqual(message)) throw new IOException("AttachStale: ABI/identity/tuple/request mismatch");
        if (type == 3) Started = true;
        } finally { control.Release(); }
    }
    async Task KeepControlAlive()
    {
        try {
            while (true) {
                await Task.Delay(2000, stopping.Token);
                using var timeout = new CancellationTokenSource(3000);
                // Once issued, complete the reply or fault the pipe. Never cancel
                // halfway then reuse an ambiguous response for another request.
                await Exchange(6, 6, timeout.Token);
            }
        } catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
        catch {
            pipe.Dispose(); // native independently stops when this handle closes
            if (process is { HasExited: false }) try { process.Kill(); } catch (InvalidOperationException) { }
        }
    }
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        brokerSession?.Revoke(); // serialized with injection; keep the tuple reserved until child exit
        stopping.Cancel();
        try {
            await heartbeat;
            if (Armed && process is { HasExited: false } && pipe.IsConnected) {
                try { using var timeout = new CancellationTokenSource(3000); await Exchange(4, 5, timeout.Token); }
                catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException) { }
            }
        } finally {
            pipe.Dispose();
            // Closing the non-inherited Job handle kills only owned children.
            // Release the Lease only on actual exit, never on the IPC timeout.
            var child = process;
            if (child != null) {
                try { if (!child.HasExited) { child.Kill(); await child.WaitForExitAsync(); } }
                finally { if (child.HasExited) { Volatile.Write(ref childExited, 1); reference.Dispose(); } }
            } else reference.Dispose();
            if (rawChannel != null) await rawChannel.DisposeAsync();
            job.Dispose(); stopping.Dispose();
        }
    }
    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
}
