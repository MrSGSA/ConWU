using StreamLink.Core;
using StreamLink.Discovery;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    CoordinatorStatus coordinatorStatus=new(false,false,"未启用",[]);
    Task? coordinating;
    CancellationTokenSource? coordinatorStop;
    void StartCoordinator() {
        if(coordinating is {IsCompleted:false})return;
        coordinatorStop?.Dispose();coordinatorStop=CancellationTokenSource.CreateLinkedTokenSource(disposing.Token);
        var token=coordinatorStop.Token;
        coordinating=Task.Run(()=>RunCoordinator(token),CancellationToken.None);
    }
    async Task RunCoordinator(CancellationToken token) {
        CoordinationHost? host=null;CoordinatorSettings? applied=null;long retry=0;
        try {
            while(!token.IsCancellationRequested) {
                CoordinatorSettings desired;lock(sync)desired=profile.Coordinator;
                if(desired!=applied||desired.Enabled&&host==null&&Environment.TickCount64>=retry) {
                    if(host!=null){await host.DisposeAsync();host=null;}
                    applied=desired;
                    try {
                        if(desired.Enabled) {
                            Volatile.Write(ref coordinatorStatus,new(true,false,"正在启动",[]));
                            host=CoordinationHost.Create(new(Path.Combine(ProfileStore.Root,"coordination"),desired.ListenUrl,
                                desired.CertificateFile,desired.CertificateKeyFile,desired.TrustCloudflare));
                            await host.Start(token);
                            Volatile.Write(ref coordinatorStatus,new(true,true,"运行中",host.Addresses));
                            Log("本机协调服务已启动；成员身份与数据连接独立运行");
                        }else Volatile.Write(ref coordinatorStatus,new(false,false,"未启用",[]));
                    }catch(Exception ex)when(!token.IsCancellationRequested) {
                        if(host!=null){await host.DisposeAsync();host=null;}
                        retry=Environment.TickCount64+15000;
                        Volatile.Write(ref coordinatorStatus,new(true,false,"启动失败："+ex.Message,[]));
                        Log("本机协调服务启动失败："+ex.Message);
                    }
                }
                await Task.Delay(1000,token);
            }
        }catch(OperationCanceledException)when(token.IsCancellationRequested){}
        finally {if(host!=null)await host.DisposeAsync();Volatile.Write(ref coordinatorStatus,new(applied?.Enabled==true,false,"已停止",[]));}
    }
    async Task StopCoordinator() {
        coordinatorStop?.Cancel();if(coordinating!=null)await coordinating;
        coordinating=null;coordinatorStop?.Dispose();coordinatorStop=null;
    }
}
