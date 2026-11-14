using System.Collections.Concurrent;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    readonly ConcurrentDictionary<string,Task<NetworkDepartureReceipt>> departingMembers=new();
    Task? departureDelivery;
    CancellationTokenSource? departureDeliveryStop;
    readonly SemaphoreSlim departureWake=new(0,1);

    bool MatchesDeparture(DirectPairRequest request)
    {
        if(request.Method!="member-leave"||request.Departure is not {} notice||request.TargetNetwork!=notice.Network||
            profile.Mesh is not {IsOwner:true,IsDecentralized:false} owner||owner.Pair.Network!=notice.Network)return false;
        notice.Validate(owner.OwnerKey);
        var current=owner.Directory!.Members.FirstOrDefault(m=>m.Slot==notice.Member.Slot);
        return current==null||current==notice.Member;
    }
    byte[] HandleDeparture(DirectPairRequest request)
    {
        try{
            if(!MatchesDeparture(request))return DirectPairWire.Encode(new DirectPairReply(request.Id,"退出通知与当前网络不符"));
            if(departingMembers.Count>=32){foreach(var old in departingMembers.Where(p=>p.Value.IsCompleted).Take(16))departingMembers.TryRemove(old.Key,out _);}
            string key=$"{request.Departure!.Network}/{request.Departure.Member.Slot}/{request.Departure.Nonce}";
            if(departingMembers.Count>=32&&!departingMembers.ContainsKey(key))return DirectPairWire.Encode(new DirectPairReply(request.Id,"退出通知暂忙，请稍后重试"));
            var task=departingMembers.GetOrAdd(key,_=>Task.Run(()=>AcceptDeparture(request.Departure,disposing.Token)));
            if(task.IsFaulted||task.IsCanceled){departingMembers.TryRemove(key,out _);return DirectPairWire.Encode(new DirectPairReply(request.Id,"成员清理暂未完成，请稍后重试"));}
            return DirectPairWire.Encode(new DirectPairReply(request.Id){Departure=task.IsCompletedSuccessfully?task.Result:null});
        }catch(Exception error)when(error is CryptographicException or FormatException or ArgumentException){return DirectPairWire.Encode(new DirectPairReply(request.Id,"退出通知校验失败"));}
    }
    async Task<NetworkDepartureReceipt> AcceptDeparture(NetworkDeparture notice,CancellationToken token)
    {
        await requests.WaitAsync(token);
        try{
            DeviceProfile next;bool changed;
            lock(sync){
                if(profile.Mesh is not {IsOwner:true,IsDecentralized:false} owner||owner.Pair.Network!=notice.Network)throw new IOException("网络已改变");
                notice.Validate(owner.OwnerKey);
                var member=owner.Directory!.Members.FirstOrDefault(m=>m.Slot==notice.Member.Slot);
                if(member!=null&&member!=notice.Member)throw new CryptographicException("成员身份已改变");
                next=ProfileChanges.Copy(profile);changed=member!=null;
                if(changed){
                    MeshIdentity.Revoke(next.Mesh!,member!.Slot);
                    next.RejoinHistory=next.RejoinHistory.Where(h=>h.CurrentSlot!=member.Slot).ToArray();
                    next.ExistingEntries=next.ExistingEntries.Where(e=>e.PeerSlot!=member.Slot).ToArray();
                    if(next.SavedNetworkSettings is {} saved)next.SavedNetworkSettings=saved with{ExistingEntries=saved.ExistingEntries.Where(e=>e.PeerSlot!=member.Slot).ToArray()};
                    next.PkarrPeers=next.PkarrPeers.Where(p=>p.Slot!=member.Slot).ToArray();
                    store.Save(next);profile=next;
                }
            }
            if(changed){
                try{if(meshRunner!=null)await meshRunner.NotifyDirectClosure(next.Mesh!.Directory!,token);}
                finally{meshRunner?.UpdateDirectory(next.Mesh!.Directory!);meshRunner?.UpdateEntries(next);PublishReply();}
                Log("已收到从机本人签名的退出通知，已删除其成员记录；网络保留，等待新的从机加入");
            }
            return NetworkDepartureReceipt.Create(next.Mesh!,notice);
        }finally{requests.Release();}
    }
    void StartDepartureDelivery()
    {
        if(networkContext||departureDelivery is {IsCompleted:false})return;
        departureDeliveryStop=CancellationTokenSource.CreateLinkedTokenSource(disposing.Token);
        store.DeviceStore.DepartureQueued+=WakeDepartureDelivery;
        departureDelivery=Task.Run(()=>DeliverDepartures(departureDeliveryStop.Token));
    }
    void WakeDepartureDelivery(){try{departureWake.Release();}catch(SemaphoreFullException){}catch(ObjectDisposedException){} }
    async Task DeliverDepartures(CancellationToken token)
    {
        string readFailure="";
        while(!token.IsCancellationRequested){
            try{
                var queued=store.DeviceStore.ReadDepartures();readFailure="";
                foreach(var item in queued){
                    token.ThrowIfCancellationRequested();
                    try{
                        using var attempt=CancellationTokenSource.CreateLinkedTokenSource(token);attempt.CancelAfter(12000);
                        await NetworkDepartureDelivery.Deliver(item,store.DeviceStore.DirectoryPath,meshRuntime??MeshRuntimeServices.Default,attempt.Token);
                        store.DeviceStore.CompleteDeparture(item.Notice.Nonce);
                        Log("主机已确认清除退出设备的从机记录："+item.Name);
                    }catch(Exception)when(!token.IsCancellationRequested){/* A native helper or unreachable host must not stop delivery of other durable notices. */}
                }
            }catch(Exception error)when(!token.IsCancellationRequested){
                string reason=error.GetType().Name;
                if(readFailure!=reason){readFailure=reason;Log("读取待发送的退出通知失败，将稍后重试（"+reason+"）");}
            }
            await departureWake.WaitAsync(TimeSpan.FromSeconds(30),token);
        }
    }
    async Task StopDepartureDelivery()
    {
        store.DeviceStore.DepartureQueued-=WakeDepartureDelivery;
        departureDeliveryStop?.Cancel();
        if(departureDelivery!=null)try{await departureDelivery;}catch(OperationCanceledException){}
        departureDeliveryStop?.Dispose();departureDeliveryStop=null;departureDelivery=null;
    }
}
