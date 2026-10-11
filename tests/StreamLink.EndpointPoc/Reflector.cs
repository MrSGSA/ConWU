using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace StreamLink.EndpointPoc;

// Default loopback; the explicit two-machine profile binds only its test IP.
sealed class Reflector : IAsyncDisposable
{
    readonly TcpListener listener;
    readonly CancellationTokenSource stop = new();
    readonly List<Task> connections = [];
    readonly Task accepting;
    public int Accepted, Active, Requests;
    public bool Silent;
    public IPEndPoint Endpoint => (IPEndPoint)listener.LocalEndpoint;
    public Reflector(IPEndPoint? endpoint = null) { listener = new(endpoint ?? new(IPAddress.Loopback, 0)); listener.Start(); accepting = Accept(); }
    async Task Accept()
    {
        while (!stop.IsCancellationRequested) {
            var socket = await listener.AcceptSocketAsync(stop.Token);
            Interlocked.Increment(ref Accepted); connections.Add(Serve(socket));
        }
    }
    async Task Serve(Socket socket)
    {
        Interlocked.Increment(ref Active);
        try {
            using (socket) using (var stream = new NetworkStream(socket, false)) {
                var remote = (IPEndPoint)socket.RemoteEndPoint!;
                while (!stop.IsCancellationRequested) {
                    byte[] request = new byte[20]; await stream.ReadExactlyAsync(request, stop.Token);
                    Interlocked.Increment(ref Requests); if (Silent) continue;
                    byte[] response = new byte[32]; request.CopyTo(response, 0);
                    response[0] = 1; response[1] = 1; response[3] = 12; response[21] = 0x20; response[23] = 8; response[25] = 1;
                    BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(26), (ushort)(remote.Port ^ 0x2112));
                    BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(28), BinaryPrimitives.ReadUInt32BigEndian(remote.Address.GetAddressBytes()) ^ 0x2112a442);
                    await stream.WriteAsync(response, stop.Token);
                }
            }
        } catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException) { }
        finally { Interlocked.Decrement(ref Active); }
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel(); listener.Stop();
        try { await accepting; } catch (Exception ex) when (ex is SocketException or OperationCanceledException) { }
        await Task.WhenAll(connections); stop.Dispose();
    }
}
