using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace StreamLink.Core;

// Keep the actual STUN TCP flow alive; do not depend on an unrelated HTTP host.
public sealed class TcpBinding : IDisposable
{
    readonly Socket socket;
    readonly NetworkStream stream;
    readonly string server;
    static int fallbackOffset;
    TcpBinding(Socket socket, string server) { this.socket = socket; this.server = server; stream = new NetworkStream(socket, false); }
    public static async Task<(TcpBinding Binding, StunResult Result)> Connect(int port, IPAddress? local, Action<string> log, CancellationToken token, IEnumerable<string>? servers = null)
    {
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        string[] choices = (servers ?? Stun.TcpServers).Distinct(StringComparer.OrdinalIgnoreCase).Take(256).ToArray();
        if (choices.Length == 0) throw new IOException("TCP STUN 列表为空");
        using var round = CancellationTokenSource.CreateLinkedTokenSource(token); round.CancelAfter(TimeSpan.FromSeconds(12));
        using var preferredStop = CancellationTokenSource.CreateLinkedTokenSource(round.Token);
        // Only ONE socket ever uses the actual source port. Other sockets screen
        // server health on ephemeral ports; their observed endpoints are discarded.
        var preferred = Open(choices[0], port, local, preferredStop.Token);
        var ready = Channel.CreateBounded<string>(new BoundedChannelOptions(3) { FullMode = BoundedChannelFullMode.Wait });
        string[] tail = choices.Skip(1).ToArray();
        // Rotate the tail between rounds so a long list with a dead prefix does
        // not permanently starve later servers. The remembered first choice stays first.
        int offset = tail.Length == 0 ? 0 : (int)((uint)(Interlocked.Add(ref fallbackOffset, 12) - 12) % (uint)tail.Length);
        tail = tail.Skip(offset).Concat(tail.Take(offset)).ToArray();
        int next = -1;
        async Task Screen()
        {
            await Task.Delay(350, round.Token);
            while (Interlocked.Increment(ref next) is int index && index < tail.Length) {
                string candidate = tail[index];
                try {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(round.Token); timeout.CancelAfter(2000);
                    await Stun.Query(true, candidate, 0, timeout.Token, local);
                    await ready.Writer.WriteAsync(candidate, round.Token);
                } catch (Exception ex) when (!round.IsCancellationRequested && ex is SocketException or IOException or OperationCanceledException or ArgumentException) { }
                await Task.Delay(150, round.Token);
            }
        }
        async Task ScreenAll()
        {
            try { await Task.WhenAll(Enumerable.Range(0, Math.Min(3, tail.Length)).Select(_ => Screen())); }
            finally { ready.Writer.TryComplete(); }
        }
        Task screening = ScreenAll(); TcpBinding? winner = null;
        try {
            Task<bool> available = ready.Reader.WaitToReadAsync(round.Token).AsTask();
            await Task.WhenAny(preferred, available);
            if (preferred.IsCompleted) {
                try { var first = await preferred; winner = first.Binding; return first; }
                catch (Exception ex) when (!round.IsCancellationRequested) { log("TCP STUN 首选服务失败：" + Failure(ex)); }
            } else if (await available) {
                preferredStop.Cancel();
                try { var first = await preferred; winner = first.Binding; return first; }
                catch (Exception) when (!round.IsCancellationRequested) { log("TCP STUN 切换到已通过检查的备用服务"); }
            } else {
                var first = await preferred; winner = first.Binding; return first;
            }
            // The preferred socket has been fully closed before rebinding.
            while (await ready.Reader.WaitToReadAsync(round.Token)) {
                while (ready.Reader.TryRead(out string? candidate)) {
                    try { var result = await Open(candidate, port, local, round.Token); winner = result.Binding; return result; }
                    catch (Exception ex) when (!round.IsCancellationRequested) { log("TCP STUN 固定端口复核失败：" + Failure(ex)); }
                }
            }
            throw new IOException("没有可用的 TCP STUN 服务");
        } catch (OperationCanceledException) when (!token.IsCancellationRequested) {
            throw new IOException("TCP STUN 本轮 12 秒预算已用尽，将在后台重试");
        } finally {
            round.Cancel(); preferredStop.Cancel();
            try { var first = await preferred; if (!ReferenceEquals(first.Binding, winner)) first.Binding.Dispose(); } catch { }
            try { await screening; } catch (OperationCanceledException) { }
        }
    }
    static string Failure(Exception ex) => ex is OperationCanceledException ? "超时" : ex is SocketException socket ? socket.SocketErrorCode.ToString() : ex.Message;
    static async Task<(TcpBinding Binding, StunResult Result)> Open(string server, int port, IPAddress? local, CancellationToken token)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = false, LingerState = new LingerOption(true, 0) };
        TcpBinding? connection = null;
        try {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(4000);
            var endpoint = await Stun.Resolve(server, timeout.Token);
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.Bind(new IPEndPoint(local ?? Stun.LocalAddress(endpoint), port));
            await socket.ConnectAsync(endpoint, timeout.Token);
            connection = new TcpBinding(socket, server);
            return (connection, await connection.Pulse(timeout.Token));
        } catch { connection?.Dispose(); socket.Dispose(); throw; }
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
