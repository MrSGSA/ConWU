using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// The shared gateway socket has exactly one receiver, including idle time.
// Solicited replies go to one serialized exchange; other datagrams are only
// bounded hints to existing leases. No application callback performs I/O here.
internal sealed class PortControlChannel : IDisposable
{
    readonly Socket socket;
    readonly object gate = new();
    readonly CancellationTokenSource stop = new();
    readonly Task receiver;
    readonly Dictionary<Guid, Action<ReadOnlyMemory<byte>>> subscribers = [];
    Pending? pending;
    Exception? failure;
    bool disposed;
    public Exception? Failure { get { lock (gate) return failure; } }
    public PortControlChannel(Socket socket) { this.socket = socket; receiver = Receive(); }
    public void Subscribe(Guid id, Action<ReadOnlyMemory<byte>> callback)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (subscribers.Count >= 32) throw new IOException("共享网关通知租约资源已满");
            subscribers.Add(id, callback);
        }
    }
    public void Unsubscribe(Guid id) { lock (gate) subscribers.Remove(id); }
    public void MulticastNotification(ReadOnlyMemory<byte> packet)
    {
        Action<ReadOnlyMemory<byte>>[] listeners;
        lock (gate) { if (disposed) return; listeners = subscribers.Values.ToArray(); }
        // Never feed multicast into the solicited-response matcher.
        foreach (var listener in listeners) listener(packet);
    }
    public Pending Expect(byte[] request, PortControlKind kind, IPAddress? external)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (failure != null) throw new IOException("网关控制接收器失效", failure);
            if (pending != null) throw new InvalidOperationException("网关交换必须串行");
            return pending = new(this, request, kind, external);
        }
    }
    async Task Receive()
    {
        byte[] packet = new byte[1101];
        try {
            while (true) {
                int length;
                try { length = await socket.ReceiveAsync(packet, SocketFlags.None, stop.Token); }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.MessageSize) { continue; }
                if (length > 1100) continue;
                Action<ReadOnlyMemory<byte>>[] listeners;
                lock (gate) {
                    if (pending is { } p && p.Parse(packet.AsSpan(0, length)) is { } reply) {
                        pending = null; p.Done.TrySetResult(reply); continue;
                    }
                    listeners = subscribers.Values.ToArray();
                }
                foreach (var listener in listeners) listener(packet.AsMemory(0, length));
            }
        } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (Exception ex) {
            lock (gate) { failure = ex; pending?.Done.TrySetException(new IOException("网关控制接收器失效", ex)); pending = null; }
        }
    }
    public void Dispose()
    {
        lock (gate) { if (disposed) return; disposed = true; pending?.Done.TrySetCanceled(); pending = null; subscribers.Clear(); }
        stop.Cancel(); receiver.GetAwaiter().GetResult(); stop.Dispose();
    }
    internal sealed class Pending(PortControlChannel owner, byte[] request, PortControlKind kind, IPAddress? external) : IDisposable
    {
        internal readonly TaskCompletionSource<PortControlReply> Done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<PortControlReply> Result => Done.Task;
        internal PortControlReply? Parse(ReadOnlySpan<byte> packet) => kind == PortControlKind.Pcp
            ? PortControlProtocol.ParsePcp(packet, request) : PortControlProtocol.ParsePmp(packet, request, external);
        public void Dispose() { lock (owner.gate) { if (owner.pending == this) owner.pending = null; Done.TrySetCanceled(); } }
    }
}
