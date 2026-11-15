using System.Net;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    CancellationTokenSource? compactPunchStop;
    Task? compactPunch;
    bool uiCompactPunch;
    void StopCompactPunch()
    {
        compactPunchStop?.Cancel();
        if(compactPunch!=null){retiredEntryPublishers.RemoveAll(task=>task.IsCompleted);retiredEntryPublishers.Add(compactPunch);compactPunch=null;}
        compactPunchStop?.Dispose();compactPunchStop=null;
    }
    void StartCompactPunch(CompactDirectCode code,long expires)
    {
        StopCompactPunch();var runner=meshRunner??throw new IOException("本机网络工作线程尚未就绪");
        uiCompactPunch=true;
        compactPunchStop=CancellationTokenSource.CreateLinkedTokenSource(disposing.Token);
        compactPunchStop.CancelAfter(TimeSpan.FromSeconds(Math.Max(1,expires-DateTimeOffset.UtcNow.ToUnixTimeSeconds())));
        var token=compactPunchStop.Token;
        compactPunch=Task.Run(async()=>{
            using var client=CreatePkarrClient();
            try{await CompactPunchDiscovery.Listen(client,code,expires,runner.Punch,Log,token);}
            catch(OperationCanceledException)when(token.IsCancellationRequested){}
        });
    }
    async Task JoinUiPunchInvitation(UiNetworkAction action,CompactDirectCode compact,Operation operation)
    {
        var token=operation.Stop.Token;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(65000);
        await CloseUiPair(token);uiPairOwner=false;uiPairService=uiPairPin="";uiExpectedNetwork=action.ExpectedNetwork;uiPairKey=new(profile.NodeSigningPrivate,profile.AutoConfigureJoin);
        uiCompactInvitation=true;uiEntrySources=[new(ExistingEntry.NetworkOwner,compact.Endpoint)];
        uiCompactPunch=true;
        string folder=Path.Combine(store.DirectoryPath,"sessions","pair-"+Guid.NewGuid().ToString("N"));
        var temporary=MeshIdentity.Create("","","mimic",direct:true);
        DirectPairClient? client=null;IMappedMeshTransport? transport=null;
        try{
            // A reachable host still needs only ordinary outbound traffic.
            // Do not make working direct pairing depend on guest STUN/UPnP.
            SetOperation(operation,"优先连接直连码中的主机入口",true);
            using(var primary=CancellationTokenSource.CreateLinkedTokenSource(deadline.Token)){
                primary.CancelAfter(8000);
                DirectPairClient? direct=null;
                try{
                    direct=new DirectPairClient(_=>(meshRuntime??MeshRuntimeServices.Default).Transport(new(folder,temporary,IPEndPoint.Parse(compact.Endpoint),false,0,null,"error"){PairingBootstrap=true}));
                    uiExpectedRejoin=MeshRejoin.Create(profile.RejoinCredential,compact.RoomCode,uiPairKey);
                    var ticket=await direct.Join(compact.RoomCode,uiPairKey,profile.DeviceName,primary.Token,profile.RequestedVirtualIp,uiExpectedRejoin);
                    uiPairClient=direct;direct=null;uiRoom=ticket;PairSnapshot("申请已发送，等待主机同意；请核对双方校验码");return;
                }catch(Exception error)when(!deadline.IsCancellationRequested&&error is IOException or OperationCanceledException){
                    Log("主机入口尚未完成直接配对，继续协同探测；未授予成员权限");
                }finally{direct?.Dispose();}
            }
            if(!OperatingSystem.IsWindows())throw new IOException("主机入口尚未接通；此直连码的首次主动协同目前需要 Windows 客户端");
            SetOperation(operation,"准备本机同端口候选，协助主机双向探测",true);
            transport=await(meshRuntime??MeshRuntimeServices.Default).MimicPairClient(folder,temporary,IPEndPoint.Parse(compact.Endpoint),Log,deadline.Token,profile.OrderedTcp());
            var candidate=transport.PublicEndpoint;
            var owned=transport;client=new DirectPairClient(_=>owned);transport=null;
            // The transport now belongs to DirectPairClient, including its
            // temporary lease and maintenance. No identity is granted here.
            using(var discovery=CreatePkarrClient()){
                SetOperation(operation,"通过 PKARR 交换首次探测候选；配对数据仍直接传输",true);
                await CompactPunchDiscovery.Publish(discovery,compact,candidate,deadline.Token);
            }
            SetOperation(operation,"等待主机主动探测并完成直接配对",true);
            uiExpectedRejoin=MeshRejoin.Create(profile.RejoinCredential,compact.RoomCode,uiPairKey);
            Exception? last=null;
            for(int attempt=0;attempt<3;attempt++){
                try{
                    var ticket=await client.Join(compact.RoomCode,uiPairKey,profile.DeviceName,deadline.Token,profile.RequestedVirtualIp,uiExpectedRejoin);
                    uiPairClient=client;client=null;uiRoom=ticket;PairSnapshot("申请已发送，等待主机同意；请核对双方校验码");return;
                }catch(IOException error){last=error;deadline.Token.ThrowIfCancellationRequested();}
            }
            throw new IOException("双向探测暂未完成直接配对，请检查双方候选、网络和 PKARR 状态",last);
        }catch(OperationCanceledException)when(!token.IsCancellationRequested){ResetUiPair("本轮双向探测已超时，未授予成员权限");throw new IOException("首次双向探测超时，网络条件可能仍限制直连，请稍后重试");}
        catch{ResetUiPair("首次双向探测未完成，未授予成员权限");throw;}
        finally{client?.Dispose();transport?.Dispose();}
    }
}
