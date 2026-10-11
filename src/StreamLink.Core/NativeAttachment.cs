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
    const int Size = 96;
    readonly TcpEndpointLease.NativeReference reference;
    readonly ChildJob job;
    readonly NamedPipeServerStream pipe;
    readonly byte[] identity;
    readonly CancellationTokenSource stopping = new();
    Process? process;
    Task heartbeat = Task.CompletedTask;
    int disposed;
    uint request = 1;
    public Guid AttachId => reference.AttachId;
    public Guid LeaseId { get; }
    public bool Armed { get; private set; }
    public bool Started { get; private set; }
    public bool Exited => process == null || process.HasExited;
    public int ProcessId => process?.Id ?? 0;
    public event Action? ProcessExited;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);

    NativeAttachment(TcpEndpointLease lease, Guid generation, IPEndPoint peer, bool server)
    {
        if (peer.AddressFamily != AddressFamily.InterNetwork || peer.Equals(lease.Reflector) || peer.Equals(lease.Local))
            throw new ArgumentException("Native peer and helper must be distinct IPv4 tuples");
        reference = lease.AcquireNativeAttachment(generation); LeaseId = lease.Id;
        try {
            job = new();
            string name = "StreamLink.Attach." + Guid.NewGuid().ToString("N");
            pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance, Size * 2, Size * 2);
            PipeName = name;
            identity = new byte[Size]; "SLNA"u8.CopyTo(identity);
            BinaryPrimitives.WriteUInt16LittleEndian(identity.AsSpan(4), TraversalLimits.NativeAbi);
            BinaryPrimitives.WriteUInt32LittleEndian(identity.AsSpan(8), Size);
            reference.AttachId.TryWriteBytes(identity.AsSpan(16)); lease.Id.TryWriteBytes(identity.AsSpan(32));
            generation.TryWriteBytes(identity.AsSpan(48));
            Endpoint(identity, 64, lease.Local); Endpoint(identity, 70, lease.Reflector); Endpoint(identity, 76, peer);
            identity[82] = (byte)(server ? 2 : 1); identity[83] = 1; // legacy HTTP data profile
            BinaryPrimitives.WriteUInt32LittleEndian(identity.AsSpan(84), 10000);
            BinaryPrimitives.WriteUInt32LittleEndian(identity.AsSpan(88), 1); // immutable capture descriptor
        } catch { reference.Dispose(); job?.Dispose(); throw; }
    }
    string PipeName { get; }
    static void Endpoint(byte[] frame, int offset, IPEndPoint ep)
    {
        ep.Address.GetAddressBytes().CopyTo(frame, offset);
        BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(offset + 4), checked((ushort)ep.Port));
    }

    public static async Task<NativeAttachment> Launch(TcpEndpointLease lease, Guid generation,
        string executable, IEnumerable<string> arguments, IPEndPoint peer, bool server,
        string? logPath, CancellationToken token, IDictionary<string, string>? environment = null,
        IEnumerable<string>? secrets = null)
    {
        var owner = new NativeAttachment(lease, generation, peer, server);
        try {
            owner.process = owner.job.Start(executable, arguments.Concat(["--managed-pipe", owner.PipeName]), logPath, environment, secrets);
            owner.process.Exited += (_, _) => { owner.reference.Dispose(); owner.ProcessExited?.Invoke(); };
            if (owner.process.HasExited) { owner.reference.Dispose(); throw new IOException("Native process exited before Attach"); }
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(8000);
            await owner.pipe.WaitForConnectionAsync(deadline.Token);
            if (!GetNamedPipeClientProcessId(owner.pipe.SafePipeHandle, out uint pid) || pid != owner.process.Id)
                throw new IOException("AttachUnauthorized: pipe client is not the launched process");
            await owner.Exchange(1, 2, deadline.Token); owner.Armed = true;
            await owner.Exchange(3, 7, deadline.Token); owner.Started = true;
            owner.heartbeat = owner.KeepControlAlive();
            return owner;
        } catch { await owner.DisposeAsync(); throw; }
    }
    async Task Exchange(ushort type, ushort expected, CancellationToken token)
    {
        byte[] message = (byte[])identity.Clone();
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(6), type);
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(12), request++);
        await pipe.WriteAsync(message, token);
        byte[] reply = new byte[Size]; await pipe.ReadExactlyAsync(reply, token);
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(6), expected);
        if (!reply.AsSpan().SequenceEqual(message)) throw new IOException("AttachStale: ABI/identity/tuple/request mismatch");
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
        stopping.Cancel();
        try {
            await heartbeat;
            if (Started && process is { HasExited: false } && pipe.IsConnected) {
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
                finally { if (child.HasExited) reference.Dispose(); }
            } else reference.Dispose();
            job.Dispose(); stopping.Dispose();
        }
    }
    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
}
