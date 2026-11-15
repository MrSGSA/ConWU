using System.Net;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    async Task<bool> OpenCoordinatorPunchInvitation(string endpoint,Operation operation)
    {
        if(profile.UsesExistingEntriesOnly||!TransportModes.TcpAssistance(profile.TransportMode)||profile.CoordinationService.Length==0||
            !(meshRuntime??MeshRuntimeServices.Default).SupportsTcpAssist(profile.TransportMode))return false;
        var services=meshRuntime??MeshRuntimeServices.Default;
        PunchAssistClient? assist=null;
        PunchAssistState? opening=null;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(operation.Stop.Token);deadline.CancelAfter(10000);
        try{
            var service=new Uri(profile.CoordinationService);
            if(service.AbsolutePath!="/")throw new IOException("首次协同需要协调监听的直接地址，不能使用 HTTP 路径代理");
            SetOperation(operation,"检查协调服务器的自主打洞辅助能力",true);
            assist=services.PunchAssistClient(profile.CoordinationService,profile.CoordinationPin,false);
            await assist.RequireSupport(deadline.Token,profile.TransportMode);
            var address=await assist.ResolveEndpoint(deadline.Token);
            if(!PortControlRoute.GlobalV4(address.Address))throw new IOException("辅助直连码需要公网 IPv4 协调入口");
            var state=opening=await assist.Create(new(endpoint,uiRoom!.Code,uiPairKey!.Commitment,profile.TransportMode,Ready:false),deadline.Token);
            uiApprovalCode=CompactDirectCode.Issue(address.ToString(),profile.TransportMode,state.Room,coordinatorPunch:true);
            var runner=meshRunner??throw new IOException("本机网络接收器尚未就绪");
            StopCompactPunch();
            compactPunchStop=CancellationTokenSource.CreateLinkedTokenSource(disposing.Token);
            compactPunchStop.CancelAfter(TimeSpan.FromSeconds(Math.Max(1,uiRoom.Expires-DateTimeOffset.UtcNow.ToUnixTimeSeconds())));
            var owned=assist;assist=null;opening=null;var token=compactPunchStop.Token;
            compactPunch=Task.Run(async()=>{
                using(owned){try{
                    var ready=await owned.Wait(state,endpoint,token,(peer,ct)=>runner.PreparePunch(peer,false,ct),owner:true);
                    token.ThrowIfCancellationRequested();
                    await runner.StartPunch(PunchAssistProtocol.Candidate(ready.GuestEndpoint),token);
                    Log("协调辅助已同步所选协议的双向探测；等待直接配对与主机审批，尚未判定穿透成功");
                    // Let a delayed guest retrieve the same scheduled round.
                    // Approval/reset cancels this wait and retires the room.
                    await Task.Delay(30000,token);
                }catch(OperationCanceledException)when(token.IsCancellationRequested){}
                catch(Exception error)when(error is IOException or HttpRequestException or FormatException or OperationCanceledException){Log("协调辅助首次探测未完成："+error.GetType().Name+"；原网络保留，请重新生成直连码");}
                finally{using var cleanup=new CancellationTokenSource(2000);try{await owned.Close(state,cleanup.Token);}catch(Exception error)when(error is IOException or HttpRequestException or OperationCanceledException){}}
                }
            });
            PairSnapshot("直连码有效 5 分钟；协调服务器仅协助自主打洞，仍需核对校验码并由主机批准");
            return true;
        }catch(Exception error)when(!operation.Stop.IsCancellationRequested&&error is IOException or HttpRequestException or OperationCanceledException or System.Net.Sockets.SocketException or FormatException){
            Log("协调辅助尚未就绪，保留普通直连码路径："+error.GetType().Name);return false;
        }finally{
            if(assist!=null&&opening!=null){using var cleanup=new CancellationTokenSource(2000);try{await assist.Close(opening,cleanup.Token);}catch(Exception error)when(error is IOException or HttpRequestException or OperationCanceledException){}}
            assist?.Dispose();
        }
    }

    async Task JoinCoordinatorPunchInvitation(UiNetworkAction action,CompactDirectCode code,Operation operation)
    {
        if(!TransportModes.TcpAssistance(code.Mode))throw new IOException("此直连码的协议不支持 TCP 协调辅助");
        if(!PortControlRoute.GlobalV4(IPEndPoint.Parse(code.Endpoint).Address))throw new FormatException("辅助直连码需要公网 IPv4 协调地址");
        var token=operation.Stop.Token;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(65000);
        await CloseUiPair(token);uiPairOwner=false;uiPairService=uiPairPin="";uiExpectedNetwork=action.ExpectedNetwork;
        uiPairKey=new(profile.NodeSigningPrivate,profile.AutoConfigureJoin);uiCompactInvitation=true;uiEntrySources=[];
        var services=meshRuntime??MeshRuntimeServices.Default;
        using var assist=services.PunchAssistClient("https://"+code.Endpoint+"/","",true);
        IMappedMeshTransport? transport=null;DirectPairClient? pairing=null;
        try{
            SetOperation(operation,"联系直连码中的协调节点；仅交换打洞候选",true);
            var state=await assist.Join(new(code.RoomCode,Guid.NewGuid().ToString("N"),uiPairKey.Commitment,code.Mode),deadline.Token);
            string folder=Path.Combine(store.DirectoryPath,"sessions","pair-"+Guid.NewGuid().ToString("N"));
            var temporary=MeshIdentity.Create("","",code.Mode,direct:true);
            uiExpectedRejoin=MeshRejoin.Create(profile.RejoinCredential,state.HostRoom,uiPairKey);
            using(var primary=CancellationTokenSource.CreateLinkedTokenSource(deadline.Token)){
                primary.CancelAfter(8000);DirectPairClient? direct=null;
                try{
                    SetOperation(operation,"优先直接连接主机候选；无需从机映射",true);
                    direct=new DirectPairClient(_=>services.Transport(new(folder,temporary,PunchAssistProtocol.Candidate(state.HostEndpoint),false,0,null,"error"){PairingBootstrap=true}));
                    var directTicket=await direct.Join(state.HostRoom,uiPairKey,profile.DeviceName,primary.Token,profile.RequestedVirtualIp,uiExpectedRejoin);
                    if(directTicket.HostCommitment!=state.Commitment)throw new System.Security.Cryptography.CryptographicException("直接配对回应与辅助会话不符");
                    uiRoom=directTicket;uiPairClient=direct;direct=null;PairSnapshot("申请已通过直连发送；请核对双方校验码，等待主机批准");return;
                }catch(Exception error)when(!deadline.IsCancellationRequested&&error is IOException or OperationCanceledException){Log("主机候选暂未完成直接配对，继续协调辅助；未授予成员权限");}
                finally{direct?.Dispose();}
            }
            SetOperation(operation,"从实际源端口向协调节点观察映射，准备同步探测",true);
            transport=await services.TcpPairClient(folder,temporary,PunchAssistProtocol.Candidate(state.HostEndpoint),Log,deadline.Token,[code.Endpoint]);
            var candidate=transport.PublicEndpoint;var owned=transport;pairing=new DirectPairClient(_=>owned);transport=null;
            if(owned is not IMeshPunchTransport punching)throw new IOException("此传输组件尚不支持协同探测");
            state=await assist.Wait(state,candidate.ToString(),deadline.Token,(peer,ct)=>punching.PreparePunch(peer,true,ct));
            await punching.StartPunch(PunchAssistProtocol.Candidate(state.HostEndpoint),ReadOnlyMemory<byte>.Empty,deadline.Token);
            SetOperation(operation,"已同步双向探测，等待主机直接回应配对",true);
            var ticket=await pairing.Join(state.HostRoom,uiPairKey,profile.DeviceName,deadline.Token,profile.RequestedVirtualIp,uiExpectedRejoin);
            if(ticket.HostCommitment!=state.Commitment)throw new System.Security.Cryptography.CryptographicException("直接配对回应与辅助会话不符，请重新核对直连码");
            uiRoom=ticket;uiPairClient=pairing;pairing=null;
            PairSnapshot("申请已通过直连发送；请核对双方校验码，等待主机批准");
        }catch(OperationCanceledException)when(!token.IsCancellationRequested){ResetUiPair("协调辅助探测超时，未授予成员权限");throw new IOException("本轮协调辅助未能建立直连；严格 NAT 仍可能限制穿透，请稍后重试");}
        catch{ResetUiPair("协调辅助未完成直接配对，未授予成员权限");throw;}
        finally{pairing?.Dispose();transport?.Dispose();}
    }
}
