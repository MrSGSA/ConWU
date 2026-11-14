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
    readonly TcpHelperLedger.Handle accounting;
    IDisposable? observer;
    readonly string observerDll;
    long lastObservationAttempt = Environment.TickCount64;
    readonly TcpHelperLedger ledger;
    readonly object gate = new();
    readonly Socket socket;
    readonly NetworkStream stream;
    readonly SemaphoreSlim io = new(1);
    int references = 1;
    bool retired, disposed, faulted;
    Guid attachment;
    public Guid Id { get; }
    public Guid NetworkGeneration { get; }
    readonly IPEndPoint local, reflector;
    public IPEndPoint Local => new(local.Address, local.Port);
    public IPEndPoint Reflector => new(reflector.Address, reflector.Port);
    public bool Closed { get { lock (gate) return disposed; } }
    public bool QueryUsable { get { lock (gate) return !faulted && !disposed; } }
    public int ReferenceCount { get { lock (gate) return references; } }
    TcpEndpointLease(Socket socket, IPEndPoint reflector, Guid generation, IDisposable quota, Guid id,
        TcpHelperLedger ledger, TcpHelperLedger.Handle accounting, IDisposable? observer, string observerDll)
    {
        this.observerDll = observerDll;
        Id = id; this.ledger = ledger; this.accounting = accounting; this.observer = observer;
        this.quota = quota;
        this.socket = socket; stream = new(socket, false);
        local = (IPEndPoint)socket.LocalEndPoint!; this.reflector = new(reflector.Address, reflector.Port); NetworkGeneration = generation;
    }
    public static Task<TcpEndpointLease> Open(IPEndPoint local, IPEndPoint reflector, Guid generation, CancellationToken token)
        => Open(local, reflector, generation, token, TcpHelperPurpose.RetainedEndpoint);
    public static Task<TcpEndpointLease> Open(IPEndPoint local, IPEndPoint reflector, Guid generation, CancellationToken token,
        TcpHelperPurpose purpose) => OpenAccounted(local, reflector, generation, token, purpose, TcpHelperLedger.Shared);
    internal static async Task<TcpEndpointLease> OpenAccounted(IPEndPoint local, IPEndPoint reflector, Guid generation, CancellationToken token,
        TcpHelperPurpose purpose, TcpHelperLedger ledger, string? observerDll = null)
    {
        if (local.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) || reflector.AddressFamily != local.AddressFamily || generation == Guid.Empty ||
            local.AddressFamily == AddressFamily.InterNetworkV6 && (!Ipv6Direct.UnscopedUnicast(local.Address) || !Ipv6Direct.UnscopedUnicast(reflector.Address)))
            throw new ArgumentException("Explicit same-family endpoints and a network generation are required");
        await ledger.Admit(token);
        var quota = sockets.Acquire(); Socket? socket = null;
        TcpHelperLedger.Handle? accounting = null; IDisposable? observer = null;
        try {
            socket = new Socket(local.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
            if (local.AddressFamily == AddressFamily.InterNetworkV6) socket.DualMode = false;
            try { socket.Bind(local); }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied) { throw new TcpEndpointBusyException(local, ex); }
            Guid id = Guid.NewGuid();
            var bound = (IPEndPoint)socket.LocalEndPoint!;
            accounting = ledger.Register(id, generation, purpose, bound, reflector);
            string dll = observerDll ?? Path.Combine(AppContext.BaseDirectory, "components", "WinDivert.dll");
            if (OperatingSystem.IsWindows() && File.Exists(dll)) {
                try { observer = new WinDivertHelperObserver(dll, bound, reflector, accounting); }
                catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception or ArgumentException or EntryPointNotFoundException or DllNotFoundException or BadImageFormatException) {
                    accounting.Observation(ObservationFailure(ex));
                }
            } else accounting.Observation("Unavailable:observer-component-or-platform");
            accounting.State("Connecting");
            await socket.ConnectAsync(reflector, token);
            accounting.State("Connected");
            return new(socket, reflector, generation, quota, id, ledger, accounting, observer, dll);
        } catch { socket?.Dispose(); try { observer?.Dispose(); } finally { accounting?.Dispose(); quota.Dispose(); } throw; }
    }
    static string ObservationFailure(Exception ex) => ex is System.ComponentModel.Win32Exception windows
        ? "Unavailable:Win32:" + windows.NativeErrorCode : "Unavailable:" + ex.GetType().Name;
    void RetryObservation()
    {
        // The ordinary helper can predate the native driver's startup. Later
        // queries may observe it once the already-installed driver is ready,
        // without pretending the missed SYN/earlier packets were captured.
        long now = Environment.TickCount64;
        if (observer != null || now - lastObservationAttempt < 5000) return;
        lastObservationAttempt = now;
        if (!OperatingSystem.IsWindows() || !File.Exists(observerDll)) return;
        try {
            observer = new WinDivertHelperObserver(observerDll, Local, Reflector, accounting);
            accounting.Observation("WindowsNetworkLayer:ExactHelperTuple:SniffOnly:HeaderCounters:StartedAfterConnect");
        } catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception or ArgumentException or EntryPointNotFoundException or DllNotFoundException or BadImageFormatException) {
            accounting.Observation(ObservationFailure(ex));
        }
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
            try { stream.Dispose(); socket.Dispose(); io.Dispose(); }
            finally { try { observer?.Dispose(); } finally { accounting.Dispose(); quota.Dispose(); } }
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
            RetryObservation();
            await ledger.Admit(token);
            try {
                accounting.Query(false);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(3000);
                byte[] request = Stun.Request(), header = new byte[20];
                await stream.WriteAsync(request, deadline.Token); await stream.ReadExactlyAsync(header, deadline.Token);
                int size = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
                if (size > 4096) throw new IOException("Oversized STUN response");
                byte[] packet = new byte[20 + size]; header.CopyTo(packet, 0);
                await stream.ReadExactlyAsync(packet.AsMemory(20), deadline.Token);
                return new("tcp", Reflector.ToString(), Local, Stun.Parse(packet, request, Local.AddressFamily));
            } catch { accounting.Query(true); lock (gate) faulted = true; throw; }
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
