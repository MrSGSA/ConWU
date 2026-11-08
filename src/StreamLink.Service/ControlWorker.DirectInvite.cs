using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    async Task JoinUiInvitation(UiNetworkAction action,Operation operation)
    {
        RequireUiNetwork(action.ExpectedNetwork);
        if(profile.Mesh!=null||profile.Pair!=null)throw new IOException("需要退出当前网络后才能申请加入");
        var invitation=DirectPairInvitation.Import(action.Code);
        RequireSavedProtocol(invitation.Mode);
        if(action.Mode!=invitation.Mode)throw new IOException("邀请的连接协议与本机设置不同，请在连接设置中选择与主机相同的协议");
        var token=operation.Stop.Token;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(30000);
        SetOperation(operation,"解析邀请中的主机入口",false);
        var resolutions=await uiEntryResolver.Value.Resolve(invitation.Entries,invitation.Mode,deadline.Token);
        var endpoints=resolutions.SelectMany(e=>e.Endpoints).Distinct().Take(8).ToArray();
        if(endpoints.Length==0)throw new IOException("邀请中的主机入口未解析成功，请检查订阅或让主机重新生成邀请。"+string.Join("；",resolutions.Select(r=>r.Error).Where(e=>e.Length>0).Distinct().Take(2)));
        await CloseUiPair(token);
        uiPairOwner=false;uiPairService=uiPairPin="";uiExpectedNetwork=action.ExpectedNetwork;uiPairKey=new(profile.NodeSigningPrivate,profile.AutoConfigureJoin);
        var temporary=MeshIdentity.Create("","",invitation.Mode,direct:true);
        var folder=Path.Combine(store.DirectoryPath,"sessions","pair-"+Guid.NewGuid().ToString("N"));
        try {
            foreach(var endpoint in endpoints){
                deadline.Token.ThrowIfCancellationRequested();
                SetOperation(operation,"连接邀请中的主机入口",false);
                using var attempt=CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);attempt.CancelAfter(endpoints.Length==1?12000:4000);
                var client=new DirectPairClient(local=>(meshRuntime??MeshRuntimeServices.Default).Transport(new(folder,temporary,IPEndPoint.Parse(endpoint),false,0,null,"error")),targetNetwork:invitation.Network);
                try {
                    uiExpectedRejoin=MeshRejoin.Create(profile.RejoinCredential?.Network==invitation.Network?profile.RejoinCredential:null,invitation.Capability,uiPairKey);
                    var room=await client.Join(invitation.Capability,uiPairKey,profile.DeviceName,attempt.Token,profile.RequestedVirtualIp,uiExpectedRejoin);
                    if(room.Room!=invitation.Room||room.HostCommitment!=invitation.HostCommitment||room.Expires!=invitation.Expires)throw new CryptographicException("主机回应与邀请不符");
                    uiRoom=room;uiPairClient=client;uiApprovalExpected=invitation;
                    PairSnapshot("申请已发送，等待主机同意；请核对双方校验码");return;
                }catch(Exception ex)when(ex is IOException or CryptographicException or OperationCanceledException){
                    client.Dispose();if(deadline.IsCancellationRequested)throw;
                }
            }
            throw new IOException("主机入口未回应，请确认主机已连接网络、邀请有效且映射指向 ConWU");
        }catch(OperationCanceledException)when(!token.IsCancellationRequested){ResetUiPair("本轮邀请连接超时");throw new IOException("本轮主机入口检查已超时，请稍后重试；未授予成员权限");}
        catch{ResetUiPair("加入申请未完成，请检查主机入口后重试");throw;}
    }
}
