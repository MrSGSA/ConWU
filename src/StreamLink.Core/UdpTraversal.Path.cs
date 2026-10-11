using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;

namespace StreamLink.Core;

public sealed partial class UdpTraversal
{
    int references = 1, payloadReaders;
    bool pathAttached, resourceClosed;
    public bool Closed { get { lock (gate) return resourceClosed; } }
    public TimeSpan RemainingAttemptTime { get { lock (gate) return started == 0 ? TimeSpan.Zero : TimeSpan.FromMilliseconds(budget.DurationMs) - Stopwatch.GetElapsedTime(started); } }
    void AcquireOperation(bool retained = false)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(resourceClosed || !retained && disposed != 0, this);
            references++;
        }
    }
    ValueTask ReleaseReference()
    {
        lock (gate) { if (--references != 0) return ValueTask.CompletedTask; resourceClosed = true; }
        return new(CloseResource());
    }
    async Task CloseResource()
    {
        stop.Cancel();
        // Hold the data port until the exact gateway lease has been retired, so
        // another socket cannot acquire it during asynchronous mapping cleanup.
        try { await CloseGateway(); }
        finally {
            socket.Dispose();
            try { await receiving; }
            finally { lease.Dispose(); CryptographicOperations.ZeroMemory(key); observing.Dispose(); stop.Dispose(); }
        }
    }
    public IMeshDatagramPath RetainPath(Guid expectedGeneration, Guid pathId)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed != 0 || resourceClosed, this);
            if (expectedGeneration != generation || pathId == Guid.Empty || pathAttached || payloadReaders != 0 ||
                selected == null || receiving.IsCompleted || RemainingAttemptTime <= TimeSpan.Zero || !socket.DontFragment || !GatewayEligible)
                throw new InvalidOperationException("UDP 路径尚未通过同 socket 无分片检查，或接收者已被占用");
            var identity = new ValidatedPathIdentity(pathId, new Guid(attempt), SocketId, null, generation,
                new IPEndPoint(Local.Address, Local.Port), new IPEndPoint(selected.Address, selected.Port), TraversalProfile.UdpDirect, PathQualification.MtuQualified);
            references++; pathAttached = true;
            try { return new UdpPath(this, identity, round); }
            catch { references--; pathAttached = false; throw; }
        }
    }
    sealed class UdpPath : IMeshDatagramPath, ITraversalControlledPath
    {
        readonly UdpTraversal owner;
        readonly object gate = new();
        readonly Channel<byte[]> sending = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(128) { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
        readonly CancellationTokenSource stop = new();
        readonly Task sender;
        Task? closing;
        TaskCompletionSource? readFinished;
        bool disposed, reading;
        int failed;
        public ValidatedPathIdentity Identity { get; }
        public TraversalControlRound ControlRound { get; }
        public bool Failed => Volatile.Read(ref failed) != 0 || owner.receiving.IsCompleted;
        public UdpPath(UdpTraversal owner, ValidatedPathIdentity identity, TraversalControlRound round)
        { this.owner = owner; Identity = identity; ControlRound = round; sender = Send(); }
        async Task Send()
        {
            try {
                await foreach (byte[] packet in sending.Reader.ReadAllAsync(stop.Token)) {
                    try { await owner.SendPayloadCore(packet, stop.Token); }
                    catch (SocketException ex) when (ex.SocketErrorCode is SocketError.NoBufferSpaceAvailable or SocketError.WouldBlock or SocketError.TimedOut or SocketError.ConnectionReset or SocketError.ConnectionRefused) {
                        // Transient pressure/ICMP loses this datagram. Do not
                        // retransmit business or tear down an otherwise live path.
                    }
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch { Interlocked.Exchange(ref failed, 1); sending.Writer.TryComplete(); }
        }
        public bool TrySend(ReadOnlySpan<byte> packet)
        {
            if (packet.Length is < 1 or > ProbeSize) return false;
            lock (gate) return !disposed && !Failed && sending.Writer.TryWrite(packet.ToArray());
        }
        public async ValueTask<ReadOnlyMemory<byte>> Receive(CancellationToken token)
        {
            lock (gate) {
                ObjectDisposedException.ThrowIf(disposed, this);
                if (reading) throw new InvalidOperationException("UDP 路径只能有一个接收者");
                owner.AcquireOperation(retained: true); reading = true; readFinished = new(TaskCreationOptions.RunContinuationsAsynchronously);
            }
            try {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
                return (await owner.payloads.Reader.ReadAsync(linked.Token)).Data;
            } finally {
                TaskCompletionSource done; lock (gate) { reading = false; done = readFinished!; }
                try { await owner.ReleaseReference(); } finally { done.TrySetResult(); }
            }
        }
        public ValueTask DisposeAsync()
        {
            lock (gate) {
                if (closing != null) return new(closing);
                disposed = true; closing = Close(); return new(closing);
            }
        }
        async Task Close()
        {
            stop.Cancel(); sending.Writer.TryComplete();
            try { await sender; }
            finally {
                Task read; lock (gate) read = readFinished?.Task ?? Task.CompletedTask;
                await read;
                lock (owner.gate) owner.pathAttached = false;
                await owner.ReleaseReference();
                stop.Dispose();
            }
        }
    }
}
