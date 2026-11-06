using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    void StoreMembership(MeshDirectory directory, bool clearPending=false)
    {
        CancellationTokenSource? revokedStop=null;
        lock(sync){
            var next=ProfileChanges.Copy(profile);
            var mesh=next.Mesh??throw new IOException("网络已改变");
            if(mesh.Directory is {} prior){
                if(prior.Revision>directory.Revision){MeshIdentity.ValidateSuccessor(prior,directory);directory=prior;}
                else MeshIdentity.ValidateSuccessor(directory,prior);
            }
            mesh.Directory=directory;
            next.RejoinHistory=next.RejoinHistory.Where(h=>directory.Members.Any(m=>m.Slot==h.CurrentSlot)).ToArray();
            next.ExistingEntries=RuntimeEntries(next);
            if(clearPending)next.PendingMembership=null;
            if(!directory.Members.Contains(mesh.Self))next.Enabled=false;
            store.Save(next);profile=next;
            if(directory.Members.Contains(mesh.Self)){meshRunner?.UpdateDirectory(directory);meshRunner?.UpdateEntries(next);}else revokedStop=runStop;
        }
        revokedStop?.Cancel();
    }
    async Task RefreshMembership(CancellationToken token)
    {
        var mesh=ProfileChanges.Copy(profile).Mesh??throw new IOException("尚未加入网络");
        using var client=new MeshDiscoveryClient(mesh);
        MeshSnapshot? remote;
        try{remote=await client.Read(token);}
        catch(OperationCanceledException ex)when(!token.IsCancellationRequested){throw new IOException("HTTPS 协调服务确认成员信息超时；已有网络与设置保持不变，请稍后重试。",ex);}
        catch(HttpRequestException ex){throw new IOException("HTTPS 协调服务无法确认成员信息"+(ex.StatusCode is {} code?$"（HTTP {(int)code}）":"（"+ex.HttpRequestError+"）")+"；已有网络与设置保持不变。",ex);}
        if(remote==null)throw new IOException("协调服务未保存此网络，请恢复服务器数据；本机网络身份仍保留");
        StoreMembership(remote.Directory);
        if(profile.Mesh?.CanManage!=true)throw new IOException("本机已不在有效成员表中，不能继续管理网络；可退出后重新申请加入");
    }
    void StageMembership(MeshProfile before,MeshDirectory proposed,string action,PairRoomTicket? room=null,string candidate="",string cipher="",MeshRejoinHistory[]? history=null)
    {
        lock(sync){
            if(profile.PendingMembership!=null)throw new IOException("前一次网络变更尚待确认，请先继续确认");
            if(profile.Mesh?.Pair.Network!=before.Pair.Network || MeshGovernance.Head(profile.Mesh.Directory!)!=MeshGovernance.Head(before.Directory!))
                throw new IOException("成员信息刚刚更新，请重新核对后操作");
            var next=ProfileChanges.Copy(profile);
            next.PendingMembership=new(action=="create"?"":MeshGovernance.Head(before.Directory!),proposed,action){Room=room,Candidate=candidate,Ciphertext=cipher,RejoinHistory=history??[]};
            store.Save(next);profile=next;
        }
    }
    async Task ResumeMembership(Operation operation)
    {
        var pending=profile.PendingMembership??throw new IOException("当前没有待确认的网络变更");
        var mesh=ProfileChanges.Copy(profile).Mesh!;
        SetOperation(operation,"确认网络成员变更；已有直连继续运行",false);
        using var client=new MeshDiscoveryClient(mesh);
        MeshDirectory committed;
        try{
            // Reuse precisely the persisted proposal after timeout or restart.
            committed=await client.CommitMembership(new(pending.ExpectedHead,pending.Proposed),operation.Stop.Token);
        }catch(MeshMembershipConflictException conflict){
            StoreMembership(conflict.Current,true);
            ResetUiPair("成员信息已更新，请重新生成配对码并核对申请");
            throw;
        }catch(Exception ex)when(ex is HttpRequestException or OperationCanceledException){
            string reason=ex is HttpRequestException {StatusCode:{} code}?$"（HTTP {(int)code}）":"";
            throw new IOException("HTTPS 协调服务尚未确认本次网络变更"+reason+"，操作记录已保留；请使用“继续确认”，不会重复添加设备。",ex);
        }
        StoreMembership(committed);
        committed=profile.Mesh!.Directory!;
        lock(sync){
            var next=ProfileChanges.Copy(profile);
            next.RejoinHistory=next.RejoinHistory.Concat(pending.RejoinHistory).Distinct()
                .Where(h=>committed.Members.Any(m=>m.Slot==h.CurrentSlot)).TakeLast(32).ToArray();
            if(pending.Action=="create")next.Enabled=committed.Members.Contains(next.Mesh!.Self)&&!committed.Closed;
            store.Save(next);profile=next;
        }
        if(pending.Action=="approve"){
            var added=MeshGovernance.Unpack(pending.Proposed.Governance!).Changes[^1].Added!;
            bool remains=committed.Members.Contains(added),expired=pending.Room==null||pending.Room.Expires<=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if(remains&&!expired){
                SetOperation(operation,"成员已获准，正在交付加入凭据",false);
                using var pair=new ShortPairClient(mesh.Pair.Service,mesh.Pair.CertificatePin);
                try{await pair.Approve(pending.Room!,pending.Candidate,pending.Ciphertext,operation.Stop.Token);}
                catch(PairRoomUnavailableException){expired=true;}
                catch(IOException ex){
                    try{var roomState=await pair.Poll(pending.Room!,true,operation.Stop.Token);expired=roomState.Outcome.Length>0;}
                    catch(PairRoomUnavailableException){expired=true;}
                    catch(IOException){ }
                    if(!expired)throw new IOException("成员已获准，但加入凭据尚未确认送达；请继续确认。不要重复批准新成员。",ex);
                }
            }
            ClearPendingMembership();ResetUiPair(remains&&!expired?"已批准设备加入，享有同等管理权限":"成员变更已确认，但配对已结束或成员已被移除；请检查设备列表后重新邀请");
            if(remains&&expired)Log("成员已获准，但配对房间已结束；请先从设备列表移除尚未使用的成员，再让该设备重新申请");
        }else if(pending.Action is "leave" or "close"){
            await CloseUiPair(operation.Stop.Token);
            await ForgetLocalNetwork(operation);
        }else{
            ClearPendingMembership();
            if(pending.Action=="create"&&profile.Enabled)Begin();
        }
    }
    void ClearPendingMembership(){lock(sync){var next=ProfileChanges.Copy(profile);next.PendingMembership=null;store.Save(next);profile=next;}}
    async Task ForgetLocalNetwork(Operation operation)
    {
        SetOperation(operation,"停止本机网络并保留用户设置",false);
        await End(operation.Stop.Token,phase=>SetOperation(operation,phase,false));
        lock(sync){
            var left=ProfileChanges.Copy(profile);left.RejoinCredential=MeshRejoin.Retain(profile.Mesh);
            left.RejoinHistory=[];left.PendingMembership=null;left.Mesh=null;left.Pair=null;left.Enabled=false;left.NetworkEstablishedAt=0;
            RestoreSavedNetworkSettings(left);store.Save(left);profile=left;
        }
    }
    async Task ApproveEqualMember(UiNetworkAction action,Operation operation)
    {
        if(uiRoomState?.Governance!=1)throw new IOException("申请设备尚不支持成员平等管理，请先更新该设备再申请");
        await RefreshMembership(operation.Stop.Token);
        if(action.ProposedIp.Length==0 || action.ProposedIp!=ProposedUiIp())throw new IOException("预分配 IP 已改变，请重新核对加入申请");
        var before=ProfileChanges.Copy(profile).Mesh!;
        var admitted=ProfileChanges.Copy(profile);var prior=RejoiningMember();
        var enrollment=prior==null?MeshIdentity.Issue(admitted.Mesh!,uiRoomState!.RequestedIp):MeshIdentity.Replace(admitted.Mesh!,prior,uiRoomState!.RequestedIp);
        var history=prior==null?admitted.RejoinHistory:MeshRejoin.Remember(admitted.Mesh!,admitted.RejoinHistory,prior,enrollment.Member);
        string cipher=PairKeyExchange.EncryptInvitation(uiExchange!,MeshIdentity.Export(enrollment),uiRoom!.Room,uiRoomState!.Candidate);
        StageMembership(before,admitted.Mesh!.Directory!,"approve",uiRoom,uiRoomState.Candidate,cipher,history);
        await ResumeMembership(operation);
    }
}
