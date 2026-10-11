using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// Keeps the original binding and sole receiver. The flow is joined before the
// underlying socket is closed, including packets already dequeued by the pacer.
public sealed class PacedTraversalSocket : ITraversalSocket
{
    readonly ITraversalSocket inner;
    readonly EgressPacer.Flow flow;
    readonly CancellationTokenSource stop = new();
    Exception? fatal;
    int disposed;
    public Guid Id => inner.Id;
    public IPEndPoint Local => inner.Local;
    public bool DontFragment => inner.DontFragment;
    public PacedTraversalSocket(ITraversalSocket inner, EgressPacer pacer, string peer)
    {
        this.inner = inner;
        try { flow = pacer.Register(peer, SendNow); }
        catch { inner.Dispose(); stop.Dispose(); throw; }
    }
    bool SendNow(ReadOnlyMemory<byte> packet, object? context)
    {
        try { inner.Send(packet, (IPEndPoint)context!, stop.Token).AsTask().GetAwaiter().GetResult(); return true; }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.NoBufferSpaceAvailable or SocketError.WouldBlock or SocketError.TimedOut or SocketError.ConnectionReset or SocketError.ConnectionRefused) { throw; }
        catch (Exception ex) { Volatile.Write(ref fatal, ex); throw; }
    }
    public ValueTask Send(ReadOnlyMemory<byte> packet, IPEndPoint remote, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this); token.ThrowIfCancellationRequested();
        if (Volatile.Read(ref fatal) is {} ex) return ValueTask.FromException(ex);
        bool data = packet.Length >= MeshLink.Overhead && packet.Span[..4].SequenceEqual("SLM4"u8) && packet.Span[4] == 4;
        int overhead = Local.AddressFamily == AddressFamily.InterNetworkV6 ? 48 : 28;
        // Checks retain completion/errors (notably MessageSize). Business sends
        // are lossy enqueue attempts; never wait for another datagram's delivery.
        TaskCompletionSource? completion = data ? null : new(TaskCreationOptions.RunContinuationsAsynchronously);
        bool queued = flow.TrySend(packet.Span, packet.Length + overhead, new IPEndPoint(remote.Address, remote.Port),
            priority: !data, token: token, completion: completion);
        if (!queued) return data ? ValueTask.CompletedTask : ValueTask.FromException(new SocketException((int)SocketError.NoBufferSpaceAvailable));
        return completion == null ? ValueTask.CompletedTask : new(completion.Task.WaitAsync(token));
    }
    public ValueTask<TraversalDatagram> Receive(CancellationToken token) => inner.Receive(token);
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stop.Cancel(); flow.Dispose(); inner.Dispose(); stop.Dispose();
    }
}
