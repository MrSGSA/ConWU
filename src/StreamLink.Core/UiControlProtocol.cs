using System.IO.Pipes;

namespace StreamLink.Core;
public sealed record UiPeerDto(int Slot,string Name,string VirtualIp,bool Connected,bool Degraded,double? RttMs,string Phase);
public sealed record UiStatusDto(string Version,string DeviceName,string VirtualIp,string State,bool ServiceReady,bool NetworkEnabled,int DirectPeers,int TotalPeers,UiPeerDto[] Peers,string LogLevel);
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record UiConfigPatch(string? DeviceName=null,string? LogLevel=null);
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record UiControlRequest(string Method,UiConfigPatch? Patch=null,Guid OperationId=default);
public sealed record UiControlReply(bool Ok,string Error,UiStatusDto? Status,int Api=1);
public static class UiControlProtocol
{
    public const string PipeName="StreamLink-UI-v1";
    public static async Task<UiControlReply> Call(UiControlRequest request,CancellationToken token=default)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(20000);
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
        using var pipe=new NamedPipeClientStream(".",PipeName,PipeDirection.InOut,PipeOptions.Asynchronous,System.Security.Principal.TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(3000,deadline.Token);ControlServerIdentity.Verify(pipe);
        await ServiceProtocol.Write(pipe,request,deadline.Token);return await ServiceProtocol.Read<UiControlReply>(pipe,deadline.Token);
    }
}
