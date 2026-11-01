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

    static UiNetworkSettings PublicSettings(DeviceProfile p) => new(p.Mesh is {Pair.Direct:false} m?m.Pair.Service:p.CoordinationService, p.Mesh is {Pair.Direct:false} n?n.Pair.CertificatePin:p.CoordinationPin, p.ManualEndpoint, p.PathSelection, p.AllowManualQualityRequests, p.ListenPort, p.SourcePort) {
        ConnectionSource=p.ManualEndpoint.Length>0?"existing":p.ConnectionSource,
        DirectMode=p.Mesh?.Pair.Direct??p.DirectMode,
        ExistingEntries=p.ExistingEntries.Length>0?p.ExistingEntries:p.ManualEndpoint.Length>0?[new(0,p.ManualEndpoint)]:[],
        TcpStun=p.TcpStun,UdpStun=p.UdpStun,RequestedVirtualIp=p.RequestedVirtualIp
    };
    static string SettingsRevision(DeviceProfile p) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(PublicSettings(p))));
    void RequireUiNetwork(string expected)
    {
        if ((profile.Mesh?.Pair.Network ?? "") != expected) throw new IOException("网络已改变，请刷新后重新确认操作");
    }
    void PairSnapshot(string state)
    {
        Volatile.Write(ref uiPairSnapshot, new(uiRoom != null, uiPairOwner, uiPairOwner ? uiRoom?.Code ?? "" : "",
            uiExchange == null ? "" : PairKeyExchange.Verification(uiExchange), uiRoomState?.Candidate ?? "",
            uiPairOwner ? uiRoomState?.GuestName ?? "" : uiRoom?.HostName ?? "", uiRoom?.Expires ?? 0, state) {ProposedIp=ProposedUiIp()});
    }
    string ProposedUiIp() {try{return uiPairOwner && uiRoomState?.Candidate.Length>0 && profile.Mesh!=null ? MeshAddressing.Next(profile.Mesh,uiRoomState.RequestedIp):"";}catch(FormatException ex){return ex.Message;}catch(IOException ex){return ex.Message;} }
    void ResetUiPair(string state)
    {
        uiRoom = null; uiRoomState = null; uiRevealed = false; uiPendingInvite = "";
        uiPairKey?.Dispose(); uiPairKey = null; uiPairClient?.Dispose(); uiPairClient = null;
        if (uiExchange != null) CryptographicOperations.ZeroMemory(uiExchange);
        uiExchange = null; PairSnapshot(state);
    }
    async Task CloseUiPair(CancellationToken token)
    {
        // Keep an already issued member if an approval reply was lost. Revoking
        // that credential is a separate, explicit owner action.
        if (uiPairOwner && uiRoom != null && uiPairClient != null)
            try { await uiPairClient.Close(uiRoom, token); } catch (IOException) { }
        ResetUiPair("已取消配对");
    }
    async Task OpenUiRoom(string service, string pin, CancellationToken token,bool verified=false)
    {
        await CloseUiPair(token);
        uiPairOwner = true; uiPairService = service; uiPairPin = pin;
        uiExpectedNetwork = profile.Mesh!.Pair.Network;
        uiPairKey = new(); var client = new ShortPairClient(service,pin);uiPairClient=client;
        try { if(!verified)await client.RequireMeshSupport(token,true);uiRoom = await uiPairClient.Create(uiPairKey, profile.DeviceName, token); PairSnapshot("等待另一台设备输入配对码"); }
        catch { ResetUiPair("创建配对码未完成，请重试邀请"); throw; }
    }
    async Task ApplyUiNetwork(UiNetworkAction action, Operation operation)
    {
        var token = operation.Stop.Token;
        if (action.Service is null || action.Service.Length > 2048 || action.CertificatePin is null || action.CertificatePin.Length > 128 || action.Code is null || action.Code.Length > (action.Action=="join-direct"?DirectInvitation.MaximumCode:6) || action.Verification is null || action.Verification.Length > 6 || action.Candidate is null || action.Candidate.Length > 32)
            throw new FormatException("网络操作参数无效");
        switch (action.Action)
        {
            case "join-direct-short":
                RequireUiNetwork(action.ExpectedNetwork);
                if((profile.Mesh!=null||profile.Pair!=null)&&!action.ConfirmReplace)throw new IOException("替换网络需要明确确认");
                if(action.Mode is not ("faketcp" or "udp"))throw new FormatException("网络承载无效");
                var entries=profile.ExistingEntries.Where(e=>e.PeerSlot==ExistingEntry.NetworkOwner||e.PeerSlot==1&&profile.Mesh?.IsOwner!=true).ToArray();
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
                            try{uiRoom=await uiPairClient.Join(action.Code,uiPairKey,profile.DeviceName,attempt.Token);break;}
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
                if(!profile.ExistingEntries.Any(e=>e.PeerSlot==0))throw new IOException("主机需先填写本机的已有入口，供其他设备连接");
                var directNext=PersonalFeature.EnhancedPreset(ProfileChanges.Copy(profile));
                directNext.Mesh=MeshIdentity.Create("","",action.Mode,profile.RequestedVirtualIp,direct:true);
                directNext.Pair=null;directNext.Enabled=false;directNext.Slot=1;directNext.LastEntry=0;
                directNext.ConnectionSource="existing";directNext.DirectMode=true;
                directNext.SelectTransport(action.Mode=="udp"?"udp-only":"faketcp-only");
                directNext.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();directNext.NetworkCreatedHere=true;
                directNext.ExistingEntries=directNext.ExistingEntries.Where(e=>e.PeerSlot==0).ToArray();
                directNext.Validate();await PersonalPacketAdapters.Preflight(directNext,token);
                await CloseUiPair(token);await End(token);
                lock(sync){store.BackupLegacy(profile);directNext.Enabled=true;store.Save(directNext);profile=directNext;}
                Begin();break;
            case "join-direct":
                RequireUiNetwork(action.ExpectedNetwork);
                if((profile.Mesh!=null||profile.Pair!=null)&&!action.ConfirmReplace)throw new IOException("替换网络需要明确确认");
                var imported=DirectInvitation.Import(action.Code);
                var joined=PersonalFeature.EnhancedPreset(ProfileChanges.Copy(profile));
                joined.Mesh=imported.Mesh;joined.Pair=null;joined.Enabled=false;joined.Slot=1;joined.LastEntry=0;
                joined.ConnectionSource="existing";joined.DirectMode=true;
                joined.SelectTransport(imported.Mesh.Pair.Mode=="udp"?"udp-only":"faketcp-only");
                joined.ExistingEntries=ExistingEntry.ForJoinedNetwork(joined.ExistingEntries).Concat(imported.Entries).Distinct().ToArray();
                joined.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();joined.NetworkCreatedHere=false;
                joined.Validate();await PersonalPacketAdapters.Preflight(joined,token);
                await CloseUiPair(token);await End(token);
                lock(sync){store.BackupLegacy(profile);joined.Enabled=true;store.Save(joined);profile=joined;}
                Begin();ResetUiPair("邀请已导入，正在验证主机入口");break;
            case "create":
            case "join":
                RequireUiNetwork(action.ExpectedNetwork);
                if ((profile.Mesh != null || profile.Pair != null) && !action.ConfirmReplace) throw new IOException("替换网络需要明确确认");
                if (action.Mode is not ("faketcp" or "udp")) throw new FormatException("网络承载无效");
                using (var check = new ShortPairClient(action.Service, action.CertificatePin)) await check.RequireMeshSupport(token,true,profile.RequestedVirtualIp.Length>0);
                if (action.Action == "create") {
                    var mesh = MeshIdentity.Create(action.Service, action.CertificatePin, action.Mode,profile.RequestedVirtualIp);
                    var next = ProfileChanges.Copy(profile);
                    next.Mesh = mesh; next.Pair = null; next.Enabled = false; next.Slot = 1; next.LastEntry = 0;
                    next.SelectTransport(action.Mode == "udp" ? "udp-only" : "faketcp-only");
                    next = PersonalFeature.EnhancedPreset(next);
                    next.CoordinationService=action.Service;next.CoordinationPin=action.CertificatePin;
                    next.DirectMode=false;
                    next.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();next.NetworkCreatedHere=true;
                    next.ExistingEntries=next.ExistingEntries.Where(e=>e.PeerSlot==0).ToArray();
                    next.Validate(); await PersonalPacketAdapters.Preflight(next, token);
                    SetOperation(operation, "保存新网络", false); await End(token);
                    lock (sync) { store.BackupLegacy(profile); store.Save(next); profile = next; }
                    await OpenUiRoom(action.Service, action.CertificatePin, token,true);
                    lock (sync) { profile.Enabled = true; store.Save(profile); } Begin();
                } else {
                    await CloseUiPair(token);
                    uiPairOwner = false; uiPairService = action.Service; uiPairPin = action.CertificatePin;
                    uiExpectedNetwork = action.ExpectedNetwork; uiPairKey = new(); uiPairClient = new ShortPairClient(action.Service, action.CertificatePin);
                    try { uiRoom = await uiPairClient.Join(action.Code, uiPairKey, profile.DeviceName, token,profile.RequestedVirtualIp); PairSnapshot("正在等待主机同意，请核对双方校验码"); }
                    catch { ResetUiPair("加入申请未完成"); throw; }
                }
                break;
            case "invite":
                RequireUiNetwork(action.ExpectedNetwork);
                var network = profile.Mesh ?? throw new IOException("请先创建网络");
                if (!network.IsOwner) throw new IOException("只有创建者可以邀请成员");
                if(network.Pair.Direct){
                    await CloseUiPair(token);
                    lock(sync){
                        var copy=ProfileChanges.Copy(profile);
                        var code=DirectInvitation.Issue(copy.Mesh!,copy.ExistingEntries);
                        store.Save(copy);profile=copy;meshRunner?.UpdateDirectory(copy.Mesh!.Directory!);
                        Volatile.Write(ref uiPairSnapshot,new(true,true,code,"","","",DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),"直连邀请已授权一台设备；请私下发送，勿重复使用") {Direct=true});
                    }
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
                    if(profile.Mesh.Directory?.ReservedAddresses!=null && uiRoomState.Addressing!=1)throw new IOException("申请设备版本不支持此网络的自定义 IP，请先更新对端");
                    if(uiRoomState.RequestedIp.Length>0 && profile.Mesh.Directory is {ReservedAddresses:null,Members.Length:>1} &&
                        uiRoomState.RequestedIp!=MeshIdentity.Address(profile.Mesh.Pair.Network,profile.Mesh.Directory.NextSlot))
                        throw new IOException("现有多设备网络保持原地址分配。请先创建使用自定义 IP 的新网络，再让各台新版设备加入");
                    uiPendingInvite = profile.Mesh.Pair.Direct?DirectInvitation.Issue(profile.Mesh,profile.ExistingEntries):MeshIdentity.Export(MeshIdentity.Issue(profile.Mesh,uiRoomState.RequestedIp));
                    store.Save(profile); meshRunner?.UpdateDirectory(profile.Mesh.Directory!);
                }
                await uiPairClient!.Approve(uiRoom, uiRoomState.Candidate, PairKeyExchange.EncryptInvitation(uiExchange, uiPendingInvite, uiRoom.Room, uiRoomState.Candidate), token);
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
                    MeshIdentity.Revoke(current, action.PeerSlot); store.Save(profile); meshRunner?.UpdateDirectory(current.Directory!);
                }
                break;
            case "settings":
                var settings = action.Settings ?? throw new FormatException("设置为空");
                var updated = ProfileChanges.Copy(profile);
                if (action.ExpectedRevision != SettingsRevision(updated)) throw new IOException("连接设置已改变；草稿已保留，请刷新后核对");
                if (updated.Mesh!=null && (settings.DirectMode!=updated.Mesh.Pair.Direct || !updated.Mesh.Pair.Direct && (settings.Service != PublicSettings(updated).Service || settings.CertificatePin != PublicSettings(updated).CertificatePin))) throw new IOException("当前网络的组网方式不能通过设置替换；请先删除或退出网络，再创建或加入新网络");
                updated.ManualEndpoint = settings.ManualEndpoint; updated.SelectTransport(settings.PathSelection);
                updated.ConnectionSource=settings.ConnectionSource;updated.ExistingEntries=settings.ExistingEntries;
                updated.DirectMode=settings.DirectMode;
                if(settings.DirectMode&&settings.ConnectionSource!="existing")throw new FormatException("无服务器组网需要选择已有入口");
                ExistingEntryResolver.Validate(settings.ExistingEntries);
                if(updated.Mesh!=null && settings.ExistingEntries.Any(e=>e.PeerSlot!=0 && !(e.PeerSlot==ExistingEntry.NetworkOwner&&!updated.Mesh.IsOwner) && updated.Mesh.Directory?.Members.Any(m=>m.Slot==e.PeerSlot&&m.Slot!=updated.Mesh.Self.Slot)!=true))throw new FormatException("入口归属设备已不在当前网络中");
                if(updated.Mesh==null){updated.CoordinationService=settings.Service;updated.CoordinationPin=settings.CertificatePin;}
                updated.RequestedVirtualIp=settings.RequestedVirtualIp;
                updated.TcpStun=settings.TcpStun is {Length:0}?Stun.TcpServers.ToArray():settings.TcpStun??updated.TcpStun;updated.UdpStun=settings.UdpStun is {Length:0}?Stun.UdpServers.ToArray():settings.UdpStun??updated.UdpStun;
                updated.AllowManualQualityRequests = settings.AllowManualQualityRequests;
                updated.ListenPort = settings.ListenPort; updated.SourcePort = settings.SourcePort;
                updated.Validate();
                bool restart = ProfileChanges.Impact(profile, updated) == ProfileChangeImpact.RestartNetwork;
                bool resume = profile.Enabled;
                if (restart && resume && !action.ConfirmReplace) throw new IOException("端口或承载设置需要重建连接，请确认后保存");
                if (restart) { SetOperation(operation, "重建受影响资源", false); await End(token); }
                try { lock (sync) { PreserveLatestDirectory(updated);store.Save(updated); profile = updated; if (!restart && runningProfile is {} active) {active.AllowManualQualityRequests = updated.AllowManualQualityRequests;active.TcpStun=updated.TcpStun.ToArray();active.UdpStun=updated.UdpStun.ToArray();} } }
                catch { if (restart && resume) Begin(); throw; }
                if (restart && resume) Begin();
                break;
            case "resolve-entries":
                var sources=action.Settings??throw new FormatException("请先填写入口");
                using(var resolver=new ExistingEntryResolver())Volatile.Write(ref uiEntryResolutions,await resolver.Resolve(sources.ExistingEntries,sources.PathSelection=="udp-only"?"udp":"faketcp",token));
                break;
            case "startup-enable":
            case "startup-disable":
                bool autoStart=action.Action=="startup-enable",previousStartup=StartupSettings.Read().AutoStart;
                StartupSettings.Set(autoStart);
                try{lock(sync){var startup=ProfileChanges.Copy(profile);startup.AutoStart=autoStart;store.Save(startup);profile=startup;}}
                catch{StartupSettings.Set(previousStartup);throw;}
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
                    if(!owner.Pair.Direct){using var client=new MeshDiscoveryClient(owner);await client.SaveDirectory(retired.Mesh!.Directory!,token);}
                    else if(meshRunner!=null)await meshRunner.NotifyDirectClosure(retired.Mesh!.Directory!,token);
                    lock(sync){store.Save(retired);profile=retired;meshRunner?.UpdateDirectory(retired.Mesh!.Directory!);}
                }
                await End(token);
                lock(sync){var left=ProfileChanges.Copy(profile);left.CoordinationService=PublicSettings(profile).Service;left.CoordinationPin=PublicSettings(profile).CertificatePin;left.Mesh=null;left.Pair=null;left.Enabled=false;left.NetworkEstablishedAt=0;left.ExistingEntries=left.ExistingEntries.Where(e=>e.PeerSlot==0).ToArray();store.Save(left);profile=left;}
                break;
            default: throw new FormatException("不支持的网络操作");
        }
    }

    async Task PollUiPair(Operation operation)
    {
        if (uiRoom == null) return;
        var token = operation.Stop.Token;
        if (uiRoom.Expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) { ResetUiPair("配对码已过期，请重新邀请"); return; }
        RequireUiNetwork(uiExpectedNetwork);
        var received = await uiPairClient!.Poll(uiRoom, uiPairOwner, token);
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
        if(!directPair&&profile.RequestedVirtualIp.Length>0 && mesh.LocalIp!=profile.RequestedVirtualIp)throw new IOException("主机未采用申请的虚拟 IP，请更新主机或改为自动分配后重新申请；原网络已保留");
        if (!directPair&&(new Uri(mesh.Pair.Service) != new Uri(uiPairService) || !mesh.Pair.CertificatePin.Equals(uiPairPin, StringComparison.OrdinalIgnoreCase))) throw new CryptographicException("邀请的协调身份不符");
        var next = ProfileChanges.Copy(profile); next.Mesh = mesh; next.Pair = null; next.Enabled = false; next.Slot = 1; next.LastEntry = 0;
        next.SelectTransport(mesh.Pair.Mode == "udp" ? "udp-only" : "faketcp-only");
        next = PersonalFeature.EnhancedPreset(next);
        next.CoordinationService=uiPairService;next.CoordinationPin=uiPairPin;
        next.DirectMode=directPair;if(directPair)next.ConnectionSource="existing";
        next.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();next.NetworkCreatedHere=false;
        next.ExistingEntries=ExistingEntry.ForJoinedNetwork(next.ExistingEntries);
        if(directPair)next.ExistingEntries=next.ExistingEntries.Concat(directImport.Entries).Distinct().ToArray();
        next.Validate(); await PersonalPacketAdapters.Preflight(next, token);
        SetOperation(operation, "保存配对并启动网络", false); await End(token);
        lock (sync) { store.BackupLegacy(profile); store.Save(next); profile = next; profile.Enabled = true; store.Save(profile); }
        Begin(); ResetUiPair("配对成功，正在建立直连");
    }

    // HTTP discovery may finish while a UI draft is being validated or while
    // End waits for resources. Never save that draft's older signed membership.
    void PreserveLatestDirectory(DeviceProfile updated)
    {
        ProfileChanges.PreserveLatestDirectory(profile,updated);
    }
}
