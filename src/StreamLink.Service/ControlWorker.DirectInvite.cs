using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    async Task OpenUiDirectInvitation(MeshProfile network,Operation operation)
    {
        var entries=await PrepareUiInvitationEntries(operation);var token=operation.Stop.Token;
        await CloseUiPair(token);uiPairOwner=true;uiPairService=uiPairPin="";uiExpectedNetwork=network.Pair.Network;uiPairKey=new(profile.NodeSigningPrivate,profile.AutoConfigureJoin);uiPairClient=uiDirectHost;
        try{
            var opened=await uiDirectHost.CreateInvitation(uiPairKey,profile.DeviceName,token);uiRoom=opened.Ticket;uiRejoinLocator=opened.Capability;
            uiApprovalCode=DirectPairInvitation.Issue(network,entries.Concat(PkarrHints(profile)).Distinct().ToArray(),uiRoom,opened.Capability);
            PairSnapshot("等待设备申请；核对校验码后由主机批准");
        }catch{await CloseUiPair(token);throw;}
    }
    async Task OpenUiCompactInvitation(Operation operation)
    {
        var entries=await PrepareUiInvitationEntries(operation);
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(operation.Stop.Token);deadline.CancelAfter(30000);
        SetOperation(operation,"解析当前主机入口，生成可手输的直连码",true);
        EntryResolution[] resolutions;
        var sources=entries.Where(e=>ExistingEntryResolver.Kind(e.Source)!="PKARR").ToArray();
        try{resolutions=meshRuntime?.ResolveEntries is {} resolve?await resolve(sources,profile.TransportMode,deadline.Token):await uiEntryResolver.Value.Resolve(sources,profile.TransportMode,deadline.Token);}
        catch(OperationCanceledException)when(!operation.Stop.IsCancellationRequested){throw new IOException("解析当前主机入口超时，请检查地址或订阅后重试；原配对会话保持不变");}
        var endpoint=resolutions.SelectMany(r=>r.Endpoints).FirstOrDefault();
        if(endpoint==null)throw new IOException("暂未取得可编码的 IPv4 入口，请检查主机地址或订阅后重试。"+string.Join("；",resolutions.Select(r=>r.Error).Where(e=>e.Length>0).Distinct().Take(2)));
        // Resolve before replacing the old room. A failed source fetch cannot
        // invalidate an invitation that is already in use.
        _=CompactDirectCode.Issue(endpoint,profile.TransportMode,"000000");
        await OpenDirectShortPair(operation.Stop.Token,publish:false);
        uiCompactInvitation=true;uiEntrySources=entries;
        uiApprovalCode=CompactDirectCode.Issue(endpoint,profile.TransportMode,uiRoom!.Code);
        PairSnapshot("直连码有效 5 分钟；另一台输入后仍需核对双方校验码并由主机批准");
    }
    async Task<ExistingEntry[]> PrepareUiInvitationEntries(Operation operation)
    {
        var token=operation.Stop.Token;
        if(!profile.Enabled)throw new IOException("请先连接本机网络，再生成直连邀请");
        if(networkContext){
            long deadline=Environment.TickCount64+15000;
            while(meshRunner?.ReceiverReady!=true){
                token.ThrowIfCancellationRequested();if(Environment.TickCount64>=deadline)throw new IOException("本机接收入口仍在启动，请查看连接状态后再次生成邀请");
                SetOperation(operation,"等待本机接收入口准备，再生成邀请",true);await Task.Delay(100,token);
            }
        }else if(meshRunner==null)throw new IOException("请先连接本机网络，再生成直连邀请");
        if(!profile.UsesExistingEntriesOnly&&meshRunner is {} autonomous&&autonomous.PreparedInvitationEntries.Length==0){
            autonomous.RequestInvitationEntry();long deadline=Environment.TickCount64+30000;
            while(autonomous.PreparedInvitationEntries.Length==0){
                token.ThrowIfCancellationRequested();if(Environment.TickCount64>=deadline)throw new IOException("暂未取得可分享的主机入口，当前网络仍保留。请等待入口准备，或检查入口设置后重新生成直连码");
                SetOperation(operation,"正在准备直连邀请所需的主机入口",true);await Task.Delay(100,token);
            }
        }
        var entries=profile.UsesExistingEntriesOnly?profile.ExistingEntries.Where(e=>e.PeerSlot==0).ToArray():[];
        if(entries.Length==0)entries=meshRunner?.PreparedInvitationEntries??[];
        if(entries.Length==0)throw new IOException("尚未取得可分享的主机入口，请等待入口准备后重新生成直连码");
        return entries;
    }

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
                    uiRoom=room;uiPairClient=client;uiApprovalExpected=invitation;uiEntrySources=invitation.Entries.ToArray();
                    PairSnapshot("申请已发送，等待主机同意；请核对双方校验码");return;
                }catch(Exception ex)when(ex is IOException or CryptographicException or OperationCanceledException){
                    client.Dispose();if(deadline.IsCancellationRequested)throw;
                }
            }
            throw new IOException("主机入口未回应，请确认主机已连接网络、邀请有效且映射指向 ConWU");
        }catch(OperationCanceledException)when(!token.IsCancellationRequested){ResetUiPair("本轮邀请连接超时");throw new IOException("本轮主机入口检查已超时，请稍后重试；未授予成员权限");}
        catch{ResetUiPair("加入申请未完成，请检查主机入口后重试");throw;}
    }
    async Task JoinUiCompactInvitation(UiNetworkAction action,Operation operation)
    {
        RequireUiNetwork(action.ExpectedNetwork);
        if(profile.Mesh!=null||profile.Pair!=null)throw new IOException("需要退出当前网络后才能申请加入");
        var compact=CompactDirectCode.Import(action.Code);RequireSavedProtocol(compact.Mode);
        if(action.Mode!=compact.Mode)throw new IOException("直连码协议与本机设置不同，请使用相同协议");
        await JoinUiDirectShort(action with{Code=compact.RoomCode,Mode=compact.Mode},operation,[new(ExistingEntry.NetworkOwner,compact.Endpoint)],invitation:true);
    }
}
