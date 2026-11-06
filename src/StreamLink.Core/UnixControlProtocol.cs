using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace StreamLink.Core;

public sealed record LocalHostRequest(UiControlRequest? Ui=null, ControlRequest? Admin=null, bool OpenPanel=false);
public sealed record LocalHostReply(UiControlReply? Ui=null, ControlReply? Admin=null, string Panel="", string Error="");

public static class UnixControlProtocol
{
    [StructLayout(LayoutKind.Sequential)] struct Credentials {public int Pid; public uint Uid; public uint Gid;}
    [DllImport("libc",SetLastError=true)] static extern int getsockopt(int socket,int level,int option,out Credentials value,ref uint length);
    public static string SocketPath=>Path.Combine(Environment.GetEnvironmentVariable("STREAMLINK_PROFILE_ROOT")??"/var/lib/streamlink","control.sock");
    public static void Authenticate(Socket socket) {
        uint length=12;
        if(getsockopt((int)socket.Handle,1,17,out var peer,ref length)!=0||length!=12||peer.Uid!=LinuxPlatform.geteuid())
            throw new UnauthorizedAccessException("本机控制接口的用户身份不一致");
    }
    public static async Task<LocalHostReply> Call(LocalHostRequest request,CancellationToken token=default) {
        if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException();
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(25000);
        using var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(SocketPath),timeout.Token);Authenticate(socket);
        using var stream=new NetworkStream(socket,false);
        await ServiceProtocol.Write(stream,request,timeout.Token);
        return await ServiceProtocol.Read<LocalHostReply>(stream,timeout.Token);
    }
}
