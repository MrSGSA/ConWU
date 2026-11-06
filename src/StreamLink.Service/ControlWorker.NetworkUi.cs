using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    PairRoomTicket? uiRoom;
    PairRoomState? uiRoomState;
    PairKeyExchange? uiPairKey;
    IShortPairClient? uiPairClient;
    readonly DirectPairHost uiDirectHost=new();
    byte[]? uiExchange;
    bool uiPairOwner, uiRevealed;
    string uiPairService = "", uiPairPin = "", uiPendingInvite = "", uiExpectedNetwork = "";
    UiPairingDto? uiPairSnapshot;
    EntryResolution[] uiEntryResolutions=[];
    readonly Lazy<ExistingEntryResolver> uiEntryResolver=new(()=>new());
    string uiApprovalCode="";
    string uiRejoinLocator="";
    string uiPendingCipher="";
    MeshRejoinProof? uiExpectedRejoin;
    DirectPairInvitation? uiApprovalExpected;

    static UiNetworkSettings PublicSettings(DeviceProfile p) => p.SavedNetworkSettings??LegacyPublicSettings(p);
    static ExistingEntry[] SavedEntries(ExistingEntry[] entries,bool guest) => entries.Select(e=>guest&&e.PeerSlot==1?e with{PeerSlot=ExistingEntry.NetworkOwner}:e).Distinct().ToArray();
    static UiNetworkSettings LegacyPublicSettings(DeviceProfile p) => new(p.Mesh is {Pair.Direct:false} m?m.Pair.Service:p.CoordinationService, p.Mesh is {Pair.Direct:false} n?n.Pair.CertificatePin:p.CoordinationPin, p.ManualEndpoint, p.PathSelection, p.AllowManualQualityRequests, p.ListenPort, p.SourcePort) {
        ConnectionSource=p.ManualEndpoint.Length>0?"existing":p.ConnectionSource,
        DirectMode=p.Mesh?.Pair.Direct??p.DirectMode,
        ExistingEntries=p.ExistingEntries.Length>0?p.ExistingEntries:p.ManualEndpoint.Length>0?[new(0,p.ManualEndpoint)]:[],
        TcpStun=p.TcpStun,UdpStun=p.UdpStun,RequestedVirtualIp=p.RequestedVirtualIp,EntryRefreshSeconds=p.EntryRefreshSeconds
    };
    static string SettingsRevision(DeviceProfile p) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(PublicSettings(p))));
    void RequireUiNetwork(string expected)
    {
        if ((profile.Mesh?.Pair.Network ?? "") != expected) throw new IOException("网络已改变，请刷新后重新确认操作");
    }
    void PairSnapshot(string state)
    {
        Volatile.Write(ref uiPairSnapshot, new(uiRoom != null, uiPairOwner, uiPairOwner ? (uiApprovalCode.Length>0?uiApprovalCode:uiRoom?.Code??"") : "",
            uiExchange == null ? "" : PairKeyExchange.Verification(uiExchange), uiRoomState?.Candidate ?? "",
            uiPairOwner ? uiRoomState?.GuestName ?? "" : uiRoom?.HostName ?? "", uiRoom?.Expires ?? 0, state) {ProposedIp=ProposedUiIp(),ReplacingSlot=RejoiningSlot()});
    }
    int RejoiningSlot(){try{return uiPairOwner?RejoiningMember()?.Slot??0:0;}catch(CryptographicException){return 0;}}
    MeshMember? RejoiningMember() => profile.Mesh is {IsOwner:true} owner && uiRoomState is {} pair
        ? MeshRejoin.Resolve(owner,pair.Rejoin,uiRejoinLocator.Length>0?uiRejoinLocator:uiRoom?.Code??"",pair.GuestCommitment,profile.RejoinHistory) : null;
    string ProposedUiIp() {try{
        if(!uiPairOwner||uiRoomState?.Candidate.Length is not >0||profile.Mesh==null)return "";
        var prior=RejoiningMember();
        string oldIp=prior==null?"":MeshAddressing.Address(profile.Mesh.Pair.Network,prior);
        return oldIp.Length>0&&(uiRoomState!.RequestedIp.Length==0||uiRoomState.RequestedIp==oldIp)?oldIp:MeshAddressing.Next(profile.Mesh,uiRoomState!.RequestedIp);
    }catch(Exception ex)when(ex is FormatException or IOException or CryptographicException){return ex.Message;} }
    void ResetUiPair(string state)
    {
        uiRoom = null; uiRoomState = null; uiRevealed = false; uiPendingInvite = ""; uiPendingCipher=""; uiApprovalCode=""; uiRejoinLocator=""; uiApprovalExpected=null;uiExpectedRejoin=null;
        uiPairKey?.Dispose(); uiPairKey = null; uiPairClient?.Dispose(); uiPairClient = null;
        if (uiExchange != null) CryptographicOperations.ZeroMemory(uiExchange);
        uiExchange = null; PairSnapshot(state);
    }
    async Task CloseUiPair(CancellationToken token)
    {
        // Keep an already issued member if an approval reply was lost. Revoking
        // that credential is a separate, explicit owner action.
        try {
            if (uiPairOwner && uiRoom != null && uiPairClient != null){
                using var cleanup=CancellationTokenSource.CreateLinkedTokenSource(token);cleanup.CancelAfter(3000);
                Task? closing=null;
                try { closing=uiPairClient.Close(uiRoom,cleanup.Token);await closing.WaitAsync(cleanup.Token); }
                catch (IOException) { }
                catch (OperationCanceledException) when(!token.IsCancellationRequested){
                    Log("配对码服务器清理暂未确认，已结束本机配对等待；服务器房间将自动过期");
                    if(closing!=null)_=closing.ContinueWith(t=>{_=t.Exception;},CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
                }
            }
        } finally { ResetUiPair("已取消配对"); }
        token.ThrowIfCancellationRequested();
    }
    async Task OpenUiRoom(string service, string pin, CancellationToken token,bool verified=false,string? expectedNetwork=null)
    {
        await CloseUiPair(token);
        uiPairOwner = true; uiPairService = service; uiPairPin = pin;
        uiExpectedNetwork = expectedNetwork??profile.Mesh!.Pair.Network;
        uiPairKey = new(); var client = new ShortPairClient(service,pin);uiPairClient=client;
        try { if(!verified)await client.RequireMeshSupport(token,true);uiRoom = await uiPairClient.Create(uiPairKey, profile.DeviceName, token); if(expectedNetwork==null)PairSnapshot("等待另一台设备输入配对码"); }
        catch { ResetUiPair("创建配对码未完成，请重试邀请"); throw; }
    }
    async Task ApplyUiNetwork(UiNetworkAction action, Operation operation)
    {
        var token = operation.Stop.Token;
        if (action.Service is null || action.Service.Length > 2048 || action.CertificatePin is null || action.CertificatePin.Length > 128 || action.Code is null || action.Code.Length > (action.Action is "join-direct" or "join-invitation"?DirectInvitation.MaximumCode:6) || action.Verification is null || action.Verification.Length > 6 || action.Candidate is null || action.Candidate.Length > 32)
            throw new FormatException("网络操作参数无效");
        if(action.Action!="settings"&&(action.Patch!=null||action.AutoStart!=null||action.ExpectedAutoStart!=null))throw new FormatException("全局设置字段只能用于保存设置");
        switch (action.Action)
        {
            case "join-invitation":
                await JoinUiInvitation(action,operation);break;
            case "join-direct-short":
                RequireUiNetwork(action.ExpectedNetwork);
                if((profile.Mesh!=null||profile.Pair!=null)&&!action.ConfirmReplace)throw new IOException("替换网络需要明确确认");
                if(action.Mode is not ("faketcp" or "udp"))throw new FormatException("网络承载无效");
                RequireSavedProtocol(action.Mode);
                var entries=PublicSettings(profile).ExistingEntries.Where(e=>e.PeerSlot==ExistingEntry.NetworkOwner||e.PeerSlot==1&&profile.Mesh?.IsOwner!=true).ToArray();
                if(entries.Length==0)throw new IOException("短配对码需要目标主机入口，请先在设置中填写；长邀请可以自动带入入口");
                using(var resolver=new ExistingEntryResolver())using(var connectionDeadline=CancellationTokenSource.CreateLinkedTokenSource(token)){
                    connectionDeadline.CancelAfter(18000);
                    var resolved=await resolver.Resolve(entries,action.Mode,connectionDeadline.Token);
                    var endpoints=resolved.SelectMany(e=>e.Endpoints).Distinct().Take(8).ToArray();
                    if(endpoints.Length==0)throw new IOException("目标主机入口未解析成功，请在设置中检查地址");
                    await CloseUiPair(token);uiPairOwner=false;uiPairService=uiPairPin="";uiExpectedNetwork=action.ExpectedNetwork;uiPairKey=new();
                    var temporary=MeshIdentity.Create("","",action.Mode,direct:true);
                    var folder=Path.Combine(ProfileStore.Root,"sessions","pair-"+Guid.NewGuid().ToString("N"));
                    using var attempt=CancellationTokenSource.CreateLinkedTokenSource(connectionDeadline.Token);attempt.CancelAfter(15000);
                    try{
                        IOException? last=null;
                        foreach(var endpoint in endpoints){
                            attempt.Token.ThrowIfCancellationRequested();
                            uiPairClient=new DirectPairClient(local=>(meshRuntime??MeshRuntimeServices.Default).Transport(new(folder,temporary,System.Net.IPEndPoint.Parse(endpoint),false,0,null,"error")));
                            try{uiExpectedRejoin=MeshRejoin.Create(profile.RejoinCredential,action.Code,uiPairKey);uiRoom=await uiPairClient.Join(action.Code,uiPairKey,profile.DeviceName,attempt.Token,profile.RequestedVirtualIp,uiExpectedRejoin);break;}
                            catch(IOException ex){last=ex;uiPairClient.Dispose();uiPairClient=null;}
                        }
                        if(uiRoom==null)throw last??new IOException("没有可回应配对的主机入口");
                        PairSnapshot("正在等待主机同意，请核对双方校验码");
                    }
                    catch(OperationCanceledException)when(!token.IsCancellationRequested){ResetUiPair("主机入口配对超时");throw new IOException("本轮主机入口配对超时，请检查入口后重试；原网络已保留");}
                    catch{ResetUiPair("主机入口配对未完成");throw;}
                }
                break;
            case "invite-short":
                RequireUiNetwork(action.ExpectedNetwork);
                if(profile.Mesh is not {IsOwner:true,Pair.DirectBootstrap:true})throw new IOException("请先创建新版无服务器网络；已有服务器网络仍使用原六位码");
                if(!profile.Enabled||meshRunner==null)throw new IOException("请先连接本机网络，再生成配对码");
                await CloseUiPair(token);uiPairOwner=true;uiPairService=uiPairPin="";uiExpectedNetwork=profile.Mesh.Pair.Network;uiPairKey=new();uiPairClient=uiDirectHost;
                try{uiRoom=await uiPairClient.Create(uiPairKey,profile.DeviceName,token);PairSnapshot("请另一台设备填写本机入口和六位配对码，双方核对校验码后批准");}catch{ResetUiPair("配对码生成未完成，请稍后重试");throw;}break;
            case "create-direct":
                RequireUiNetwork(action.ExpectedNetwork);
                if(profile.Mesh!=null||profile.Pair!=null)throw new IOException("请先删除或退出当前网络");
                if(action.Mode is not ("faketcp" or "udp"))throw new FormatException("网络承载无效");
                RequireSavedProtocol(action.Mode);
                if(!profile.ExistingEntries.Any(e=>e.PeerSlot==0))throw new IOException("主机需先填写本机的已有入口，供其他设备连接");
                var directNext=PersonalFeature.EnhancedPreset(ProfileChanges.Copy(profile));
                directNext.Mesh=MeshIdentity.Create("","",action.Mode,profile.RequestedVirtualIp,direct:true);directNext.RejoinHistory=[];directNext.RejoinCredential=null;
                directNext.Pair=null;directNext.Enabled=false;directNext.Slot=1;directNext.LastEntry=0;
                directNext.ConnectionSource="existing";directNext.DirectMode=true;
                directNext.SelectTransport(action.Mode=="udp"?"udp-only":"faketcp-only");
                directNext.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();directNext.NetworkCreatedHere=true;
                directNext.ExistingEntries=directNext.ExistingEntries.Where(e=>e.PeerSlot==0).ToArray();
                directNext.Validate();await PersonalPacketAdapters.Preflight(directNext,token);
                await CloseUiPair(token);await End(token);
                lock(sync){store.BackupLegacy(profile);directNext.Enabled=true;directNext.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();store.Save(directNext);profile=directNext;}
                Begin();break;
            case "join-direct":
                RequireUiNetwork(action.ExpectedNetwork);
                if((profile.Mesh!=null||profile.Pair!=null)&&!action.ConfirmReplace)throw new IOException("替换网络需要明确确认");
                var imported=DirectInvitation.Import(action.Code);
                RequireSavedProtocol(imported.Mesh.Pair.Mode);
                var joined=PersonalFeature.EnhancedPreset(ProfileChanges.Copy(profile));
                joined.Mesh=imported.Mesh;joined.Pair=null;joined.Enabled=false;joined.Slot=1;joined.LastEntry=0;joined.RejoinHistory=[];joined.RejoinCredential=null;
                joined.ConnectionSource="existing";joined.DirectMode=true;
                joined.SelectTransport(imported.Mesh.Pair.Mode=="udp"?"udp-only":"faketcp-only");
                joined.ExistingEntries=ExistingEntry.ForJoinedNetwork(joined.ExistingEntries).Concat(imported.Entries).Distinct().ToArray();
                joined.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();joined.NetworkCreatedHere=false;
                joined.Validate();await PersonalPacketAdapters.Preflight(joined,token);
                await CloseUiPair(token);await End(token);
                lock(sync){store.BackupLegacy(profile);joined.Enabled=true;joined.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();store.Save(joined);profile=joined;}
                Begin();ResetUiPair("邀请已导入，正在验证主机入口");break;
            case "create":
            case "join":
                RequireUiNetwork(action.ExpectedNetwork);
                if ((profile.Mesh != null || profile.Pair != null) && !action.ConfirmReplace) throw new IOException("替换网络需要明确确认");
                if (action.Mode is not ("faketcp" or "udp")) throw new FormatException("网络承载无效");
                RequireSavedProtocol(action.Mode);
                SetOperation(operation,"检查 HTTPS 协调服务",true);
                using (var check = new ShortPairClient(action.Service, action.CertificatePin)) await check.RequireMeshSupport(token,true,profile.RequestedVirtualIp.Length>0,action.Action=="join"&&profile.RejoinCredential!=null);
                if (action.Action == "create") {
                    var mesh = MeshIdentity.Create(action.Service, action.CertificatePin, action.Mode,profile.RequestedVirtualIp);
                    var next = ProfileChanges.Copy(profile);
                    next.Mesh = mesh; next.Pair = null; next.Enabled = false; next.Slot = 1; next.LastEntry = 0;next.RejoinHistory=[];next.RejoinCredential=null;
                    next.SelectTransport(action.Mode == "udp" ? "udp-only" : "faketcp-only");
                    next = PersonalFeature.EnhancedPreset(next);
                    next.CoordinationService=action.Service;next.CoordinationPin=action.CertificatePin;
                    next.DirectMode=false;
                    next.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();next.NetworkCreatedHere=true;
                    next.ExistingEntries=next.ExistingEntries.Where(e=>e.PeerSlot==0).ToArray();
                    next.Validate(); await PersonalPacketAdapters.Preflight(next, token);
                    SetOperation(operation,"向 HTTPS 协调服务申请配对码",true);
                    await OpenUiRoom(action.Service,action.CertificatePin,token,true,mesh.Pair.Network);
                    try {
                        SetOperation(operation, "保存新网络", false); await End(token);
                        lock (sync) { store.BackupLegacy(profile); next.Enabled=true;next.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();store.Save(next); profile = next; }
                        Begin();PairSnapshot("等待另一台设备输入配对码");
                    }catch{ResetUiPair("创建网络未完成，请重试");throw;}
                } else {
                    await CloseUiPair(token);
                    uiPairOwner = false; uiPairService = action.Service; uiPairPin = action.CertificatePin;
                    uiExpectedNetwork = action.ExpectedNetwork; uiPairKey = new(); uiPairClient = new ShortPairClient(action.Service, action.CertificatePin);
                    SetOperation(operation,"向 HTTPS 协调服务发送加入申请",true);
                    try { uiExpectedRejoin=MeshRejoin.Create(profile.RejoinCredential,action.Code,uiPairKey);uiRoom = await uiPairClient.Join(action.Code, uiPairKey, profile.DeviceName, token,profile.RequestedVirtualIp,uiExpectedRejoin); PairSnapshot("正在等待主机同意，请核对双方校验码"); }
                    catch { ResetUiPair("加入申请未完成"); throw; }
                }
                break;
            case "invite":
                RequireUiNetwork(action.ExpectedNetwork);
                var network = profile.Mesh ?? throw new IOException("请先创建网络");
                if (!network.IsOwner) throw new IOException("只有创建者可以邀请成员");
                if(network.Pair.Direct){
                    if(!profile.Enabled||meshRunner==null)throw new IOException("请先连接本机网络，再生成直连邀请");
                    await CloseUiPair(token);uiPairOwner=true;uiPairService=uiPairPin="";uiExpectedNetwork=network.Pair.Network;uiPairKey=new();uiPairClient=uiDirectHost;
                    try{var opened=await uiDirectHost.CreateInvitation(uiPairKey,profile.DeviceName,token);uiRoom=opened.Ticket;uiRejoinLocator=opened.Capability;uiApprovalCode=DirectPairInvitation.Issue(network,profile.ExistingEntries,uiRoom,opened.Capability);PairSnapshot("等待设备申请；核对校验码后由主机批准");}
                    catch{await CloseUiPair(token);throw;}
                    break;
                }
                await OpenUiRoom(network.Pair.Service, network.Pair.CertificatePin, token); break;
            case "pair-poll":
                await PollUiPair(operation); break;
            case "approve":
                RequireUiNetwork(uiExpectedNetwork);
                if (!uiPairOwner || uiRoom == null || uiRoomState == null || uiExchange == null || profile.Mesh?.IsOwner != true ||
                    action.Candidate != uiRoomState.Candidate || action.Verification != PairKeyExchange.Verification(uiExchange))
                    throw new IOException("配对申请或校验码已改变，请重新核对");
                if(action.ProposedIp.Length>0 && action.ProposedIp!=ProposedUiIp())throw new IOException("预分配 IP 已改变，请重新核对加入申请");
                if (uiPendingInvite.Length == 0) lock (sync) {
                    var prior=RejoiningMember();
                    if(profile.Mesh.Directory?.ReservedAddresses!=null && uiRoomState.Addressing!=1)throw new IOException("申请设备版本不支持此网络的自定义 IP，请先更新对端");
                    if(prior==null && uiRoomState.RequestedIp.Length>0 && profile.Mesh.Directory is {ReservedAddresses:null,Members.Length:>1} &&
                        uiRoomState.RequestedIp!=MeshIdentity.Address(profile.Mesh.Pair.Network,profile.Mesh.Directory.NextSlot))
                        throw new IOException("现有多设备网络保持原地址分配。请先创建使用自定义 IP 的新网络，再让各台新版设备加入");
                    var admitted=ProfileChanges.Copy(profile);
                    string issued=admitted.Mesh!.Pair.Direct?DirectInvitation.Issue(admitted.Mesh,admitted.ExistingEntries,uiRoomState.RequestedIp,prior):MeshIdentity.Export(prior==null?MeshIdentity.Issue(admitted.Mesh,uiRoomState.RequestedIp):MeshIdentity.Replace(admitted.Mesh,prior,uiRoomState.RequestedIp));
                    if(prior!=null){
                        int nextSlot=admitted.Mesh.Directory!.NextSlot-1;
                        admitted.ExistingEntries=admitted.ExistingEntries.Select(e=>e.PeerSlot==prior.Slot?e with{PeerSlot=nextSlot}:e).Distinct().ToArray();
                        admitted.RejoinHistory=MeshRejoin.Remember(admitted.Mesh,admitted.RejoinHistory,prior,admitted.Mesh.Directory.Members.Single(m=>m.Slot==nextSlot));
                    }
                    string pendingCipher=PairKeyExchange.EncryptInvitation(uiExchange,issued,uiRoom.Room,uiRoomState.Candidate);
                    store.Save(admitted);profile=admitted;uiPendingInvite=issued;uiPendingCipher=pendingCipher;
                    meshRunner?.UpdateDirectory(admitted.Mesh.Directory!);meshRunner?.UpdateEntries(admitted);
                    if(prior!=null)Log("已批准设备重新加入，旧成员授权已撤销并替换；虚拟 IP "+MeshAddressing.Address(admitted.Mesh.Pair.Network,admitted.Mesh.Directory!.Members[^1]));
                }
                await uiPairClient!.Approve(uiRoom, uiRoomState.Candidate, uiPendingCipher, token);
                ResetUiPair("已批准设备加入"); break;
            case "reject":
                RequireUiNetwork(uiExpectedNetwork);
                if(!uiPairOwner||uiRoom==null||uiRoomState==null||action.Candidate!=uiRoomState.Candidate)throw new IOException("加入申请已改变，请重新核对");
                if(uiPendingInvite.Length>0)throw new IOException("此申请已签发授权，正在确认交付结果；如需撤销，请从设备列表移出");
                try {await uiPairClient!.Finish(uiRoom,true,token);}catch(IOException){await uiPairClient!.Close(uiRoom,token);}
                ResetUiPair("已拒绝加入申请");break;
            case "pair-cancel":
                if(!uiPairOwner&&uiRoom!=null&&uiPairClient!=null)await uiPairClient.Finish(uiRoom,false,token);
                await CloseUiPair(token); break;
            case "revoke":
                RequireUiNetwork(action.ExpectedNetwork);
                lock (sync) {
                    var current = profile.Mesh ?? throw new IOException("尚未加入网络");
                    var revoked=ProfileChanges.Copy(profile);MeshIdentity.Revoke(revoked.Mesh!,action.PeerSlot);
                    revoked.RejoinHistory=revoked.RejoinHistory.Where(h=>h.CurrentSlot!=action.PeerSlot).ToArray();
                    store.Save(revoked);profile=revoked;meshRunner?.UpdateDirectory(revoked.Mesh!.Directory!);
                }
                break;
            case "settings":
                var settings = action.Settings ?? throw new FormatException("设置为空");
                var updated = action.Patch?.ApplyTo(profile)??ProfileChanges.Copy(profile);
                if (action.ExpectedRevision != SettingsRevision(profile)) throw new IOException("连接设置已改变；草稿已保留，请刷新后核对");
                if (updated.Mesh!=null && (settings.DirectMode!=updated.Mesh.Pair.Direct || !updated.Mesh.Pair.Direct && (settings.Service != PublicSettings(updated).Service || settings.CertificatePin != PublicSettings(updated).CertificatePin))) throw new IOException("当前网络的组网方式不能通过设置替换；请先删除或退出网络，再创建或加入新网络");
                updated.ManualEndpoint = settings.ManualEndpoint; updated.SelectTransport(settings.PathSelection);
                updated.ConnectionSource=settings.ConnectionSource;updated.ExistingEntries=settings.ExistingEntries;
                updated.EntryRefreshSeconds=settings.EntryRefreshSeconds;
                updated.DirectMode=settings.DirectMode;
                if(settings.DirectMode&&settings.ConnectionSource!="existing")throw new FormatException("无服务器组网需要选择已有入口");
                ExistingEntryResolver.Validate(settings.ExistingEntries);
                if(updated.Mesh!=null && settings.ExistingEntries.Any(e=>e.PeerSlot!=0 && e.PeerSlot!=ExistingEntry.NetworkOwner && updated.Mesh.Directory?.Members.Any(m=>m.Slot==e.PeerSlot&&m.Slot!=updated.Mesh.Self.Slot)!=true&&!PublicSettings(profile).ExistingEntries.Contains(e)))throw new FormatException("入口归属设备已不在当前网络中");
                if(updated.Mesh==null||updated.Mesh.Pair.Direct){updated.CoordinationService=settings.Service;updated.CoordinationPin=settings.CertificatePin;}
                updated.RequestedVirtualIp=settings.RequestedVirtualIp;
                updated.TcpStun=settings.TcpStun is {Length:0}?Stun.TcpServers.ToArray():settings.TcpStun??updated.TcpStun;updated.UdpStun=settings.UdpStun is {Length:0}?Stun.UdpServers.ToArray():settings.UdpStun??updated.UdpStun;
                updated.AllowManualQualityRequests = settings.AllowManualQualityRequests;
                updated.ListenPort = settings.ListenPort; updated.SourcePort = settings.SourcePort;
                if((action.AutoStart==null)!=(action.ExpectedAutoStart==null))throw new FormatException("启动设置需要对应的前置值");
                if(action.ExpectedAutoStart!=null&&StartupSettings.Read().AutoStart!=action.ExpectedAutoStart)throw new IOException("开机启动设置已改变；草稿已保留，请核对后重试");
                if(action.AutoStart!=null)updated.AutoStart=action.AutoStart.Value;
                updated.Validate();
                var savedEntries=SavedEntries(settings.ExistingEntries,updated.Mesh?.IsOwner==false);
                if(!savedEntries.Where(e=>e.PeerSlot>0).SequenceEqual(PublicSettings(profile).ExistingEntries.Where(e=>e.PeerSlot>0)))updated.SavedPeerEntryNetwork=updated.Mesh?.Pair.Network??"";
                updated.SavedNetworkSettings=settings with {ExistingEntries=savedEntries,TcpStun=updated.TcpStun.ToArray(),UdpStun=updated.UdpStun.ToArray()};
                updated.ExistingEntries=RuntimeEntries(updated);
                bool changeStartup=action.AutoStart!=null&&updated.AutoStart!=StartupSettings.Read().AutoStart;
                bool startupApplied=false;
                bool previousStartup=changeStartup?StartupSettings.Read().AutoStart:false;
                bool restart = ProfileChanges.Impact(profile, updated) == ProfileChangeImpact.RestartNetwork;
                bool resume = profile.Enabled;
                if (restart && resume && !action.ConfirmReplace) throw new IOException("连接方式、端口或承载设置需要重建连接，请确认后保存");
                if (restart) { SetOperation(operation, "重建受影响资源", false); await End(token,phase=>SetOperation(operation,phase,false)); }
                try { if(changeStartup){StartupSettings.Set(updated.AutoStart);startupApplied=true;}lock (sync) { PreserveLatestDirectory(updated);store.Save(updated); profile = updated; if (!restart && runningProfile is {} active) {active.AllowManualQualityRequests = updated.AllowManualQualityRequests;active.EntryRefreshSeconds=updated.EntryRefreshSeconds;active.TcpStun=updated.TcpStun.ToArray();active.UdpStun=updated.UdpStun.ToArray();active.ConnectionSource=updated.ConnectionSource;active.ManualEndpoint=updated.ManualEndpoint;active.ExistingEntries=updated.ExistingEntries.ToArray();} } }
                catch { if(startupApplied)StartupSettings.Set(previousStartup);if (restart && resume) Begin(); throw; }
                if (!restart) meshRunner?.UpdateEntries(updated);
                if (restart && resume) Begin();
                break;
            case "resolve-entries":
                var sources=action.Settings??throw new FormatException("请先填写入口");
                Volatile.Write(ref uiEntryResolutions,await uiEntryResolver.Value.Resolve(sources.ExistingEntries,sources.PathSelection=="udp-only"?"udp":"faketcp",token));
                break;
            case "startup-enable":
            case "startup-disable":
                bool autoStart=action.Action=="startup-enable",previousStartupOnly=StartupSettings.Read().AutoStart;
                StartupSettings.Set(autoStart);
                try{lock(sync){var startup=ProfileChanges.Copy(profile);startup.AutoStart=autoStart;store.Save(startup);profile=startup;}}
                catch{StartupSettings.Set(previousStartupOnly);throw;}
                break;
            case "leave":
                RequireUiNetwork(action.ExpectedNetwork);
                if(!action.ConfirmReplace)throw new IOException("退出网络需要确认");
                await CloseUiPair(token);
                // Remove every issued member before deleting an owner's local
                // credentials. Server-backed revocation must be published first;
                // a failed publish leaves the network intact for a safe retry.
                if(profile.Mesh is {IsOwner:true,Directory:{} currentDirectory} owner && currentDirectory.Members.Length>1){
                    var retired=ProfileChanges.Copy(profile);
                    foreach(var member in currentDirectory.Members.Where(m=>m.Slot!=owner.Self.Slot))MeshIdentity.Revoke(retired.Mesh!,member.Slot);
                    retired.RejoinHistory=[];
                    if(!owner.Pair.Direct){
                        SetOperation(operation,"向协调服务器提交成员撤销",true);
                        using var client=new MeshDiscoveryClient(owner);
                        try{await SaveRevocation(client,retired.Mesh!.Directory!,token);}
                        catch(OperationCanceledException)when(!token.IsCancellationRequested){throw new IOException("协调服务器未及时确认成员撤销，当前网络仍保留。请检查 HTTPS 协调服务后重试删除。");}
                    }
                    else if(meshRunner!=null)await meshRunner.NotifyDirectClosure(retired.Mesh!.Directory!,token);
                    lock(sync){store.Save(retired);profile=retired;meshRunner?.UpdateDirectory(retired.Mesh!.Directory!);}
                }
                SetOperation(operation,"停止本机网络并回收资源",false);
                await End(token,phase=>SetOperation(operation,phase,false));
                lock(sync){var left=ProfileChanges.Copy(profile);left.RejoinCredential=MeshRejoin.Retain(profile.Mesh);left.RejoinHistory=[];left.Mesh=null;left.Pair=null;left.Enabled=false;left.NetworkEstablishedAt=0;RestoreSavedNetworkSettings(left);store.Save(left);profile=left;}
                break;
            default: throw new FormatException("不支持的网络操作");
        }
    }

    async Task SaveRevocation(MeshDiscoveryClient client,MeshDirectory directory,CancellationToken token)
    {
        // The server accepts the same revision/signature idempotently. Reuse
        // this exact table if a transient error loses its acknowledgement.
        for(int attempt=0;;attempt++){
            try{await client.SaveDirectory(directory,token);return;}
            catch(OperationCanceledException)when(attempt==0&&!token.IsCancellationRequested){ }
            catch(HttpRequestException ex)when(attempt==0&&!token.IsCancellationRequested&&
                (ex.StatusCode is System.Net.HttpStatusCode.RequestTimeout or System.Net.HttpStatusCode.BadGateway or System.Net.HttpStatusCode.ServiceUnavailable or System.Net.HttpStatusCode.GatewayTimeout||
                ex.StatusCode==null&&ex.HttpRequestError is HttpRequestError.ConnectionError or HttpRequestError.ResponseEnded)){ }
            Log("协调服务器成员撤销请求暂未完成，复用同一签名成员表重试（1/1）");
            await Task.Delay(250,token);
        }
    }
    async Task PollUiPair(Operation operation)
    {
        if (uiRoom == null) return;
        var token = operation.Stop.Token;
        if (uiRoom.Expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) { ResetUiPair("配对码已过期，请重新邀请"); return; }
        RequireUiNetwork(uiExpectedNetwork);
        SetOperation(operation,uiPairClient is ShortPairClient?"读取 HTTPS 协调服务中的配对状态":"读取目标主机的配对状态",true);
        var received = await uiPairClient!.Poll(uiRoom, uiPairOwner, token);
        if(!uiPairOwner&&uiExpectedRejoin!=null&&(uiPairClient is DirectPairClient?received.RejoinDigest!=MeshRejoin.Fingerprint(uiExpectedRejoin):received.Rejoin!=uiExpectedRejoin))throw new IOException("主机或协调服务未保留重新加入证明，请将两端及协调服务更新至 1.0.3 后重试");
        if(received.Outcome.Length>0){ResetUiPair(received.Outcome=="Rejected"?"主机已拒绝加入申请":"申请方已取消加入");return;}
        PairKeyExchange.ValidateState(uiRoom, uiRoomState, received, uiPairKey!, uiPairOwner); uiRoomState = received;
        if (!uiRevealed && (uiPairOwner ? received.Candidate.Length > 0 : received.HostPublic.Length > 0)) {
            received = await uiPairClient.Reveal(uiRoom, uiPairOwner, uiPairKey!, token);
            PairKeyExchange.ValidateState(uiRoom, uiRoomState, received, uiPairKey!, uiPairOwner);
            uiRoomState = received; uiRevealed = true;
        }
        if (uiExchange == null && received.HostPublic.Length > 0 && received.GuestPublic.Length > 0)
            uiExchange = uiPairKey!.Derive(uiPairOwner ? received.GuestPublic : received.HostPublic, uiPairOwner ? received.GuestCommitment : uiRoom.HostCommitment, uiRoom.Room, received.Candidate, uiPairOwner);
        PairSnapshot(uiExchange == null ? "等待对端交换公钥" : "请双方核对校验码；一致后由创建者批准");
        if (!received.Approved || uiExchange == null) return;
        bool directPair=uiPairClient is DirectPairClient or DirectPairHost;
        string invitation = PairKeyExchange.DecryptInvitation(uiExchange, received.Ciphertext, uiRoom.Room, received.Candidate,directPair?DirectPairWire.MaximumCipher:6000);
        if (uiPairOwner) {
            if (uiPendingInvite.Length == 0 || invitation != uiPendingInvite) throw new CryptographicException("批准凭据与当前申请不符");
            ResetUiPair("已确认设备获准加入"); return;
        }
        var directImport=directPair?DirectInvitation.Import(invitation):default;
        var mesh = directPair?directImport.Mesh:MeshIdentity.Import(invitation);
        RequireSavedProtocol(mesh.Pair.Mode);
        if(profile.RequestedVirtualIp.Length>0 && mesh.LocalIp!=profile.RequestedVirtualIp)throw new IOException("主机未采用申请的虚拟 IP，请更新主机或改为自动分配后重新申请；原网络已保留");
        if (!directPair&&(new Uri(mesh.Pair.Service) != new Uri(uiPairService) || !mesh.Pair.CertificatePin.Equals(uiPairPin, StringComparison.OrdinalIgnoreCase))) throw new CryptographicException("邀请的协调身份不符");
        if(directPair&&uiApprovalExpected is {} expected&&(mesh.Pair.Network!=expected.Network||mesh.OwnerKey!=expected.OwnerKey||mesh.Pair.Mode!=expected.Mode))throw new CryptographicException("获批的网络身份与直连邀请不符");
        var next = ProfileChanges.Copy(profile); next.Mesh = mesh; next.Pair = null; next.Enabled = false; next.Slot = 1; next.LastEntry = 0;next.RejoinCredential=null;next.RejoinHistory=[];
        next.SelectTransport(mesh.Pair.Mode == "udp" ? "udp-only" : "faketcp-only");
        next = PersonalFeature.EnhancedPreset(next);
        next.CoordinationService=uiPairService;next.CoordinationPin=uiPairPin;
        next.DirectMode=directPair;if(directPair)next.ConnectionSource="existing";
        next.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();next.NetworkCreatedHere=false;
        next.ExistingEntries=ExistingEntry.ForJoinedNetwork(PublicSettings(profile).ExistingEntries);
        if(directPair)next.ExistingEntries=next.ExistingEntries.Concat(directImport.Entries).Distinct().ToArray();
        next.Validate(); await PersonalPacketAdapters.Preflight(next, token);
        SetOperation(operation, "保存配对并启动网络", false); await End(token);
        lock (sync) { store.BackupLegacy(profile);next.Enabled=true;next.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();store.Save(next);profile=next; }
        Begin(); ResetUiPair("配对成功，正在建立直连");
    }

    // HTTP discovery may finish while a UI draft is being validated or while
    // End waits for resources. Never save that draft's older signed membership.
    void PreserveLatestDirectory(DeviceProfile updated)
    {
        ProfileChanges.PreserveLatestDirectory(profile,updated);
    }
}
