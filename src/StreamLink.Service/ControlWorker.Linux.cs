using System.Net.Sockets;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    public Func<string>? OpenLocalPanel {get;set;}
    public Task<UiControlReply> HandleLocalUi(UiControlRequest request,CancellationToken token=default)
        => HandleUi(request,LinuxPlatform.UserIdentity,token);
    async Task RunLinuxControl(CancellationToken token) {
        string path=UnixControlProtocol.SocketPath;
        if(path.Length>100)throw new IOException("本机控制套接字路径过长");
        // runtime.lock was exclusively acquired before removing our stale socket.
        if(File.Exists(path))File.Delete(path);
        using var listener=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(path));File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        listener.Listen(8);using var slots=new SemaphoreSlim(8,8);var clients=new List<Task>();
        try {
            if(profile.PendingMembership!=null){var resumed=await Handle(new("membership-resume"),token);if(!resumed.Ok)Log(resumed.Error);}
            while(!token.IsCancellationRequested) {
                await slots.WaitAsync(token);Socket client;
                try{client=await listener.AcceptAsync(token);}catch{slots.Release();throw;}
                clients.RemoveAll(t=>t.IsCompleted);
                clients.Add(Task.Run(async()=>{try{await ServeLinux(client,token);}finally{client.Dispose();slots.Release();}},CancellationToken.None));
            }
        }catch(OperationCanceledException)when(token.IsCancellationRequested){}
        finally {await Task.WhenAll(clients);File.Delete(path);}
    }
    async Task ServeLinux(Socket socket,CancellationToken stop) {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(stop);timeout.CancelAfter(20000);
        try {
            UnixControlProtocol.Authenticate(socket);
            using var stream=new NetworkStream(socket,false);
            var request=await ServiceProtocol.Read<LocalHostRequest>(stream,timeout.Token);
            if((request.Ui!=null?1:0)+(request.Admin!=null?1:0)+(request.OpenPanel?1:0)!=1)throw new IOException("控制请求应只包含一项操作");
            LocalHostReply reply;
            if(request.OpenPanel)reply=new(Panel:OpenLocalPanel?.Invoke()??"",Error:OpenLocalPanel==null?"WebUI 未启用":"");
            else if(request.Ui is {} ui) {
                var handling=HandleLocalUi(ui,stop);
                if(ui.Method!="status"&&ui.OperationId!=Guid.Empty&&await Task.WhenAny(handling,Task.Delay(700,timeout.Token))!=handling) {
                    reply=new(Ui:await HandleLocalUi(new("status",OperationId:ui.OperationId){NetworkId=ui.NetworkId},stop));
                    _=handling.ContinueWith(t=>Log("本机控制操作异常："+t.Exception!.GetBaseException().GetType().Name),TaskContinuationOptions.OnlyOnFaulted);
                }else reply=new(Ui:await handling);
            }else reply=new(Admin:await Handle(request.Admin!,stop));
            await ServiceProtocol.Write(stream,reply,timeout.Token);
        }catch(Exception ex)when(ex is IOException or OperationCanceledException or SocketException or UnauthorizedAccessException or System.Text.Json.JsonException) {
            if(!stop.IsCancellationRequested)Log("本机控制请求未完成："+ex.GetType().Name);
        }
    }
}
