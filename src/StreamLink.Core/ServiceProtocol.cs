using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;

namespace StreamLink.Core;
public sealed record ControlRequest(string Command, DeviceProfile? Profile = null, string Invite = "", string Service = "", string Pin = "", int Mbps = 50, string Mode = "faketcp", int PeerSlot = 0, Guid OperationId = default, Guid CancelOperationId = default);
public sealed record ControlOperationStatus(Guid Id, string Command, string Phase, bool Completed, bool Cancelable, string Error = "");
public sealed record ControlReply(bool Ok, string Error, DeviceProfile? Profile, SessionStatus? Status, string Invite, string[] Logs, string Quality = "", string Version = "0.2.0", int PathSelectionVersion = 0, int TcpObserverVersion = 0, int PortControlVersion = 0, int UdpIpv6Version = 0, int FakeTcpIpv6Version = 0, int EgressPacingVersion = 0, int TcpCalibrationVersion = 0, int TcpPredictionVersion = 0, int TcpPeerReflexiveVersion = 0, int UdpExplorationVersion = 0, int QualityFeedbackVersion = 0, int StandbyPathsVersion = 0,int PathDiagnosticsVersion=0,int AutoQualityVersion=0, ControlOperationStatus? Operation = null, int ControlOperationsVersion = 0, int ManualQualityVersion = 0,int LegacyEgressPacingVersion=0,bool ServiceReady=false,int UdpEmpiricalStabilityVersion=0);
public static class ServiceProtocol
{
    public const int MaximumMessageBytes = 65536;
    public const int MaximumUiMessageBytes=1_048_576;
    static int Limit<T>() => typeof(T)==typeof(ControlReply)||typeof(T)==typeof(ControlRequest)||typeof(T)==typeof(LocalHostRequest)||typeof(T)==typeof(LocalHostReply)?6_000_000:
        typeof(T)==typeof(UiControlRequest)||typeof(T)==typeof(UiControlReply)?MaximumUiMessageBytes:MaximumMessageBytes;
    public static string PipeName => WindowsInstance.Name + "-Control-v2";
    public static async Task<T> Read<T>(Stream stream, CancellationToken token)
    {
        byte[] head = new byte[4]; await stream.ReadExactlyAsync(head, token); int length = BinaryPrimitives.ReadInt32LittleEndian(head);
        if (length < 1 || length > Limit<T>()) throw new IOException("控制消息大小无效");
        byte[] bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, token); return JsonSerializer.Deserialize<T>(bytes) ?? throw new IOException("控制消息为空");
    }
    public static async Task Write<T>(Stream stream, T message, CancellationToken token)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(message); if (bytes.Length > Limit<T>()) throw new IOException("控制消息过大");
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
