using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// Keep the actual STUN TCP flow alive; do not depend on an unrelated HTTP host.
public sealed class TcpBinding : IDisposable
{
    readonly Socket socket;
    readonly NetworkStream stream;
    readonly string server;
    TcpBinding(Socket socket, string server) { this.socket = socket; this.server = server; stream = new NetworkStream(socket, false); }
    public static async Task<(TcpBinding Binding, StunResult Result)> Connect(int port, IPAddress? local, Action<string> log, CancellationToken token, IEnumerable<string>? servers = null)
    {
        foreach (var server in servers ?? Stun.TcpServers)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = false, LingerState = new LingerOption(true, 0) };
            TcpBinding? connection = null;
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(4000);
                var endpoint = await Stun.Resolve(server, timeout.Token);
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                socket.Bind(new IPEndPoint(local ?? Stun.LocalAddress(endpoint), port));
                await socket.ConnectAsync(endpoint, timeout.Token);
                connection = new TcpBinding(socket, server);
                return (connection, await connection.Pulse(timeout.Token));
            }
            catch (Exception) when (!token.IsCancellationRequested) { connection?.Dispose(); socket.Dispose(); log($"TCP STUN {server} 重试其他服务"); }
            catch { connection?.Dispose(); socket.Dispose(); throw; }
        }
        throw new IOException("无法建立持续 TCP STUN 会话");
    }
    public async Task<StunResult> Pulse(CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(4000); token = timeout.Token;
        byte[] request = Stun.Request(), header = new byte[20];
        await stream.WriteAsync(request, token);
        await stream.ReadExactlyAsync(header, token);
        int size = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
        if (size > 4096) throw new IOException("STUN 响应过大");
        var packet = new byte[size + 20]; header.CopyTo(packet, 0);
        await stream.ReadExactlyAsync(packet.AsMemory(20), token);
        return new StunResult("tcp", server, (IPEndPoint)socket.LocalEndPoint!, Stun.Parse(packet, request));
    }
    public void Dispose() { stream.Dispose(); socket.Dispose(); }
}
