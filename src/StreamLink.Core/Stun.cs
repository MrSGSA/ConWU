using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace StreamLink.Core;

public sealed record StunResult(string Protocol, string Server, IPEndPoint Local, IPEndPoint Public);

// RFC 8489 framing/transaction checks. No third-party implementation is copied.
public static class Stun
{
    public static readonly string[] TcpServers = new[] { "fwa.lifesizecloud.com:3478", "stun.nextcloud.com:3478", "stun.sipnet.com:3478", "global.turn.twilio.com:3478" }.Concat(StunCatalog.Snapshot()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    public static readonly string[] UdpServers = ["stun.miwifi.com:3478", "stun.chat.bilibili.com:3478", "stun.hitv.com:3478", "stun.nextcloud.com:3478"];
    public static byte[] Request()
    {
        var bytes = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, 1);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4), 0x2112a442);
        RandomNumberGenerator.Fill(bytes.AsSpan(8));
        return bytes;
    }

    public static IPEndPoint Parse(ReadOnlySpan<byte> data, ReadOnlySpan<byte> request)
    {
        if (request.Length != 20 || data.Length < 20 || BinaryPrimitives.ReadUInt16BigEndian(data) != 0x0101 ||
            BinaryPrimitives.ReadUInt32BigEndian(data[4..]) != 0x2112a442 || !data.Slice(8, 12).SequenceEqual(request.Slice(8, 12)))
            throw new IOException("STUN 消息类型、Cookie 或事务 ID 不符");
        int length = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        if ((length & 3) != 0 || data.Length != 20 + length) throw new IOException("STUN 长度无效");
        IPEndPoint? mapped = null;
        for (int pos = 20; pos < data.Length;)
        {
            if (data.Length - pos < 4) throw new IOException("STUN 属性头截断");
            int type = BinaryPrimitives.ReadUInt16BigEndian(data[pos..]);
            int size = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 2)..]);
            int next = pos + 4 + ((size + 3) & ~3);
            if (next > data.Length) throw new IOException("STUN 属性截断");
            var value = data.Slice(pos + 4, size);
            if ((type == 0x20 || type == 1) && size >= 2 && value[1] == 1)
            {
                if (size != 8) throw new IOException("STUN IPv4 属性长度无效");
                int port = BinaryPrimitives.ReadUInt16BigEndian(value[2..]);
                uint address = BinaryPrimitives.ReadUInt32BigEndian(value[4..]);
                if (type == 0x20) { port ^= 0x2112; address ^= 0x2112a442; }
                byte[] addr = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(addr, address);
                if (port == 0) throw new IOException("STUN 端口为零");
                mapped = new IPEndPoint(new IPAddress(addr), port);
                if (type == 0x20) return mapped;
            }
            pos = next;
        }
        return mapped ?? throw new IOException("STUN 未返回 IPv4 映射");
    }

    public static async Task<IPEndPoint> Resolve(string server, CancellationToken token)
    {
        var parts = server.Split(':');
        if (parts.Length != 2 || !int.TryParse(parts[1], out int port) || port is < 1 or > 65535) throw new ArgumentException("服务器格式应为 host:port");
        var ip = (await Dns.GetHostAddressesAsync(parts[0], token)).FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork);
        return new IPEndPoint(ip ?? throw new IOException("服务器没有 IPv4 地址"), port);
    }

    public static IPAddress LocalAddress(IPEndPoint remote)
    {
        using var route = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        route.Connect(remote);
        return ((IPEndPoint)route.LocalEndPoint!).Address;
    }

    public static async Task<StunResult> Query(bool tcp, string server, int sourcePort, CancellationToken token, IPAddress? local = null)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(4));
        token = timeout.Token;
        var remote = await Resolve(server, token);
        using var socket = new Socket(AddressFamily.InterNetwork, tcp ? SocketType.Stream : SocketType.Dgram, tcp ? ProtocolType.Tcp : ProtocolType.Udp);
        if (tcp) { socket.ExclusiveAddressUse = false; socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true); socket.LingerState = new LingerOption(true, 0); }
        socket.Bind(new IPEndPoint(local ?? LocalAddress(remote), sourcePort));
        await socket.ConnectAsync(remote, token);
        var req = Request();
        IPEndPoint endpoint;
        if (tcp)
        {
            using var stream = new NetworkStream(socket, false);
            await stream.WriteAsync(req, token);
            byte[] header = new byte[20];
            await stream.ReadExactlyAsync(header, token);
            int length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
            if (length > 4096) throw new IOException("STUN 消息过大");
            var packet = new byte[20 + length];
            header.CopyTo(packet, 0);
            await stream.ReadExactlyAsync(packet.AsMemory(20), token);
            endpoint = Parse(packet, req);
        }
        else
        {
            byte[] data = new byte[4096];
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            for (int attempt = 0; ; attempt++)
            {
                await socket.SendAsync(req, SocketFlags.None, token);
                using var retry = CancellationTokenSource.CreateLinkedTokenSource(token);
                retry.CancelAfter(900);
                try
                {
                    int count = await socket.ReceiveAsync(data, SocketFlags.None, retry.Token);
                    endpoint = Parse(data.AsSpan(0, count), req);
                    break;
                }
                catch (OperationCanceledException) when (!token.IsCancellationRequested && attempt < 2) { }
            }
        }
        return new StunResult(tcp ? "tcp" : "udp", server, (IPEndPoint)socket.LocalEndPoint!, endpoint);
    }

    public static async Task<StunResult> First(bool tcp, int port, Action<string> log, CancellationToken token, IPAddress? local = null)
    {
        foreach (var server in tcp ? TcpServers : UdpServers)
        {
            try { return await Query(tcp, server, port, token, local); }
            catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or SocketException or OperationCanceledException)
            { log($"STUN {server} 暂不可用，切换服务"); }
        }
        throw new IOException("所有 STUN 服务均未响应");
    }
}
