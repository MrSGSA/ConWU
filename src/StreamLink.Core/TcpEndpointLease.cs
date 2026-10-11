using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using StreamLink.Core;

namespace StreamLink.Core;

public sealed class TcpEndpointBusyException(IPEndPoint local, SocketException error)
    : IOException($"EndpointBusy：无法独占绑定 TCP {local}（{error.SocketErrorCode}）；端口被占用或仍在内核退役中", error)
{
    public IPEndPoint Local { get; } = new(local.Address, local.Port);
    public SocketError SocketError { get; } = error.SocketErrorCode;
}

// One exclusive kernel TCP reflection flow; helper health and ownership differ.
// Observing a mapped endpoint alone does not validate a FakeTCP candidate.
// A path reference must be retained BEFORE releasing an attempt. Only a future
// authenticated coordinator may decide to retain a path; this class does not.
public sealed class TcpEndpointLease : IDisposable
{
    static readonly TraversalResources sockets = new(TraversalLimits.TcpResources);
    readonly IDisposable quota;
    readonly object gate = new();
    readonly Socket socket;
    readonly NetworkStream stream;
    readonly SemaphoreSlim io = new(1);
    int references = 1;
    bool retired, disposed, faulted;
    Guid attachment;
    public Guid Id { get; } = Guid.NewGuid();
    public Guid NetworkGeneration { get; }
    readonly IPEndPoint local, reflector;
    public IPEndPoint Local => new(local.Address, local.Port);
    public IPEndPoint Reflector => new(reflector.Address, reflector.Port);
    public bool Closed { get { lock (gate) return disposed; } }
    public bool QueryUsable { get { lock (gate) return !faulted && !disposed; } }
    public int ReferenceCount { get { lock (gate) return references; } }
    TcpEndpointLease(Socket socket, IPEndPoint reflector, Guid generation, IDisposable quota)
    {
        this.quota = quota;
        this.socket = socket; stream = new(socket, false);
        local = (IPEndPoint)socket.LocalEndPoint!; this.reflector = new(reflector.Address, reflector.Port); NetworkGeneration = generation;
    }
    public static async Task<TcpEndpointLease> Open(IPEndPoint local, IPEndPoint reflector, Guid generation, CancellationToken token)
    {
        if (local.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) || reflector.AddressFamily != local.AddressFamily || generation == Guid.Empty ||
            local.AddressFamily == AddressFamily.InterNetworkV6 && (!Ipv6Direct.UnscopedUnicast(local.Address) || !Ipv6Direct.UnscopedUnicast(reflector.Address)))
            throw new ArgumentException("Explicit same-family endpoints and a network generation are required");
        var quota = sockets.Acquire(); Socket? socket = null;
        try {
            socket = new Socket(local.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
            if (local.AddressFamily == AddressFamily.InterNetworkV6) socket.DualMode = false;
            try { socket.Bind(local); }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied) { throw new TcpEndpointBusyException(local, ex); }
            await socket.ConnectAsync(reflector, token);
            return new(socket, reflector, generation, quota);
        } catch { socket?.Dispose(); quota.Dispose(); throw; }
    }
    public Reference AcquireAttempt(Guid expectedGeneration)
    {
        lock (gate) {
            if (expectedGeneration != NetworkGeneration || retired || faulted || disposed) throw new InvalidOperationException("Lease unavailable for this attempt generation");
            references++; return new(this, false);
        }
    }
    public NativeReference AcquireNativeAttachment(Guid expectedGeneration)
    {
        lock (gate) {
            if (expectedGeneration != NetworkGeneration || retired || disposed || attachment != Guid.Empty)
                throw new InvalidOperationException("Endpoint is retired, stale, or already has a native capture owner");
            // QueryUnusable does not close the source resource or a healthy path.
            attachment = Guid.NewGuid(); references++; return new(this, attachment);
        }
    }
    public sealed class NativeReference : IDisposable
    {
        readonly TcpEndpointLease owner;
        bool released;
        public Guid AttachId { get; }
        internal NativeReference(TcpEndpointLease owner, Guid id) { this.owner = owner; AttachId = id; }
        // Caller must FIRST confirm child exit/Detach. A timeout alone is not proof.
        public void Dispose()
        {
            lock (owner.gate) { if (released) return; released = true; owner.attachment = Guid.Empty; }
            owner.Release();
        }
    }
    void Release()
    {
        lock (gate) {
            if (--references != 0) return;
            disposed = true;
            // This closes the helper TCP flow, not a transferred raw session.
            try { stream.Dispose(); socket.Dispose(); io.Dispose(); } finally { quota.Dispose(); }
        }
    }
    public void Dispose()
    {
        lock (gate) { if (retired) return; retired = true; }
        Release();
    }
    async Task<StunResult> Pulse(CancellationToken token)
    {
        // Callers hold a transient reference for the entire async operation,
        // including time queued on io, so final cleanup cannot race a receiver.
        await io.WaitAsync(token);
        try {
            lock (gate) if (faulted) throw new IOException("Reflection flow must be replaced after a failed transaction");
            try {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(3000);
                byte[] request = Stun.Request(), header = new byte[20];
                await stream.WriteAsync(request, deadline.Token); await stream.ReadExactlyAsync(header, deadline.Token);
                int size = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
                if (size > 4096) throw new IOException("Oversized STUN response");
                byte[] packet = new byte[20 + size]; header.CopyTo(packet, 0);
                await stream.ReadExactlyAsync(packet.AsMemory(20), deadline.Token);
                return new("tcp", Reflector.ToString(), Local, Stun.Parse(packet, request, Local.AddressFamily));
            } catch { lock (gate) faulted = true; throw; }
        } finally { io.Release(); }
    }
    public sealed class Reference : IDisposable
    {
        readonly TcpEndpointLease owner;
        bool released;
        public bool IsPathReference { get; }
        internal Reference(TcpEndpointLease owner, bool path) { this.owner = owner; IsPathReference = path; }
        public Reference RetainPath(Guid expectedGeneration)
        {
            lock (owner.gate) {
                if (released || owner.retired || owner.faulted || expectedGeneration != owner.NetworkGeneration)
                    throw new InvalidOperationException("Canceled, retired, or wrong-generation attempt cannot retain a path");
                owner.references++; return new(owner, true);
            }
        }
        public async Task<StunResult> Observe(CancellationToken token)
        {
            lock (owner.gate) {
                if (released || owner.faulted) throw new InvalidOperationException("Released or faulted lease reference");
                owner.references++;
            }
            try { return await owner.Pulse(token); }
            finally { owner.Release(); }
        }
        public void Dispose()
        {
            lock (owner.gate) { if (released) return; released = true; }
            owner.Release();
        }
    }
}
