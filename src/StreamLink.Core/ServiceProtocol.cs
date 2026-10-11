using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;

namespace StreamLink.Core;
public sealed record ControlRequest(string Command, DeviceProfile? Profile = null, string Invite = "", string Service = "", string Pin = "", int Mbps = 50, string Mode = "faketcp", int PeerSlot = 0);
public sealed record ControlReply(bool Ok, string Error, DeviceProfile? Profile, SessionStatus? Status, string Invite, string[] Logs, string Quality = "", string Version = "0.2.0", int PathSelectionVersion = 0, int TcpObserverVersion = 0, int PortControlVersion = 0, int UdpIpv6Version = 0);
public static class ServiceProtocol
{
    public const string PipeName = "StreamLink-Control-v2";
    public static async Task<T> Read<T>(Stream stream, CancellationToken token)
    {
        byte[] head = new byte[4]; await stream.ReadExactlyAsync(head, token); int length = BinaryPrimitives.ReadInt32LittleEndian(head);
        if (length is < 1 or > 65536) throw new IOException("控制消息大小无效");
        byte[] bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, token); return JsonSerializer.Deserialize<T>(bytes) ?? throw new IOException("控制消息为空");
    }
    public static async Task Write<T>(Stream stream, T message, CancellationToken token)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(message); if (bytes.Length > 65536) throw new IOException("控制消息过大");
        byte[] head = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(head, bytes.Length); await stream.WriteAsync(head, token); await stream.WriteAsync(bytes, token);
    }
    public static async Task<ControlReply> Call(ControlRequest request, CancellationToken token = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(45000);
        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(3000, timeout.Token);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        ControlServerIdentity.Verify(pipe);
        await Write(pipe, request, timeout.Token);
        var reply = await Read<ControlReply>(pipe, timeout.Token); await pipe.WriteAsync(new byte[] { 1 }, timeout.Token); return reply;
    }
}
