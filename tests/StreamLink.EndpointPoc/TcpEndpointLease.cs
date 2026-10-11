using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using StreamLink.Core;

namespace StreamLink.EndpointPoc;

// Experimental, test-only owner. One exclusive kernel TCP reflection flow.
// NOT a FakeTCP candidate: no WinDivert capture/injection or NAT classification.
// A path reference must be retained BEFORE releasing an attempt. Only a future
// authenticated coordinator may decide to retain a path; this class does not.
sealed class TcpEndpointLease : IDisposable
{
    readonly object gate = new();
    readonly Socket socket;
    readonly NetworkStream stream;
    readonly SemaphoreSlim io = new(1);
    int references = 1;
    bool retired, disposed, faulted;
    public Guid Id { get; } = Guid.NewGuid();
    public Guid NetworkGeneration { get; }
    public IPEndPoint Local { get; }
    public IPEndPoint Reflector { get; }
    public bool Closed { get { lock (gate) return disposed; } }
    TcpEndpointLease(Socket socket, IPEndPoint reflector, Guid generation)
    {
        this.socket = socket; stream = new(socket, false);
        Local = (IPEndPoint)socket.LocalEndPoint!; Reflector = reflector; NetworkGeneration = generation;
    }
    public static async Task<TcpEndpointLease> Open(IPEndPoint local, IPEndPoint reflector, Guid generation, CancellationToken token)
    {
        if (local.AddressFamily != AddressFamily.InterNetwork || reflector.AddressFamily != AddressFamily.InterNetwork || generation == Guid.Empty)
            throw new ArgumentException("Explicit IPv4 endpoints and a network generation are required");
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
        try {
            socket.Bind(local); await socket.ConnectAsync(reflector, token);
            return new(socket, reflector, generation);
        } catch { socket.Dispose(); throw; }
    }
    public Reference AcquireAttempt(Guid expectedGeneration)
    {
        lock (gate) {
            if (expectedGeneration != NetworkGeneration || retired || faulted || disposed) throw new InvalidOperationException("Lease unavailable for this attempt generation");
            references++; return new(this, false);
        }
    }
    void Release()
    {
        lock (gate) {
            if (--references != 0) return;
            disposed = true;
            // This closes the helper TCP flow, not a transferred raw session.
            stream.Dispose(); socket.Dispose(); io.Dispose();
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
                return new("tcp", Reflector.ToString(), Local, Stun.Parse(packet, request));
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
