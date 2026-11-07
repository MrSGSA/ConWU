using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PairPollPriority() {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var store=new ProfileStore();var owner=MeshIdentity.Create("https://example.com/","","faketcp");
        store.Save(new DeviceProfile{Mesh=owner,Enabled=false});string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        using var worker=new ControlWorker();worker.StartLocal();
        const BindingFlags flags=BindingFlags.Instance|BindingFlags.NonPublic;
        void Set(string name,object value)=>typeof(ControlWorker).GetField(name,flags)!.SetValue(worker,value);
        SlowPairPoll Seed(bool blockCancellation=false) {
            typeof(ControlWorker).GetMethod("ResetUiPair",flags)!.Invoke(worker,["fixture reset"]);
            var client=new SlowPairPoll{BlockCancellation=blockCancellation};var key=new PairKeyExchange();
            Set("uiPairClient",client);Set("uiPairKey",key);Set("uiPairOwner",true);Set("uiExpectedNetwork",owner.Pair.Network);
            Set("uiRoom",new PairRoomTicket(Guid.NewGuid().ToString("N"),"123456","fixture-token",key.Commitment,"fixture",DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds()));
            return client;
        }
        Task<UiControlReply> Poll(Guid id)=>worker.HandleUi(new("network",OperationId:id,Network:new("pair-poll"){Background=true}),sid,default);
        var first=Seed();Guid firstId=Guid.NewGuid();var polling=Poll(firstId);
        await first.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var denied=await worker.HandleUi(new("patch",Patch:new(DeviceName:"unauthorized"),OperationId:Guid.NewGuid()),"S-1-5-21-1-2-3-9999",default);
        Check(!denied.Ok&&!first.Cancelled&&!polling.IsCompleted,"unauthorized requests cannot interrupt an authenticated pairing poll");
        var invalid=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("delete-network",ExpectedNetwork:owner.Pair.Network,ConfirmReplace:true){Background=true}),sid,default);
        Check(!invalid.Ok&&!first.Cancelled&&store.Load().Mesh!=null,"a mutation cannot claim automatic-observation scheduling or cancel the active read");
        var clock=Stopwatch.StartNew();
        var renamed=await worker.HandleUi(new("patch",Patch:new(DeviceName:"foreground action"),OperationId:Guid.NewGuid()),sid,default).WaitAsync(TimeSpan.FromSeconds(2));
        var yielded=await polling.WaitAsync(TimeSpan.FromSeconds(2));
        Check(renamed.Ok&&first.Cancelled&&clock.ElapsedMilliseconds<1500,"explicit save preempts a slow automatic pairing read rather than waiting for its network timeout");
        Check(yielded.Ok&&yielded.Operation is {Completed:true,Error:"",Phase:"后台轮询已让出"},"superseded automatic reads finish without a misleading user cancellation error");
        var duplicate=await Poll(firstId);
        Check(duplicate.Ok&&first.Reads==1&&store.Load().DeviceName=="foreground action","a repeated observation ID cannot restart the canceled read or undo the explicit action");

        var critical=Seed();var criticalId=Guid.NewGuid();var committing=Poll(criticalId);
        await critical.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        // Exercise the actual scheduler's transaction boundary without issuing
        // real membership credentials from a synthetic remote pairing client.
        var operations=(System.Collections.IDictionary)typeof(ControlWorker).GetField("operations",flags)!.GetValue(worker)!;
        typeof(ControlWorker).GetMethod("SetOperation",flags)!.Invoke(worker,[operations[criticalId],"保存配对并启动网络",false]);
        var queued=worker.HandleUi(new("patch",Patch:new(DeviceName:"after commit"),OperationId:Guid.NewGuid()),sid,default);
        await Task.Delay(100);
        Check(!queued.IsCompleted&&!critical.Cancelled,"an observation already inside a non-cancelable membership transaction is never preempted");
        critical.Release.TrySetResult();await committing;await queued.WaitAsync(TimeSpan.FromSeconds(2));

        var blocked=Seed(true);var blockedRead=Poll(Guid.NewGuid());await blocked.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Guid explicitId=Guid.NewGuid();
        var explicitAction=Task.Run(()=>worker.HandleUi(new("patch",Patch:new(DeviceName:"cancel callbacks released"),OperationId:explicitId),sid,default));
        try {
            await blocked.CancellationEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            var watching=await Task.Run(()=>worker.HandleUi(new("status",OperationId:explicitId),sid,default)).WaitAsync(TimeSpan.FromSeconds(2));
            Check(watching.Ok&&watching.Status!.ServiceReady&&watching.Operation is {Completed:false},"slow cancellation callbacks do not hold the operation lock or block fresh backend status");
        }finally{blocked.CancellationRelease.TrySetResult();}
        Check((await explicitAction.WaitAsync(TimeSpan.FromSeconds(2))).Ok&&(await blockedRead).Ok,"foreground operation completes after its cancellation callback joins");

        var leaving=Seed();var reading=Poll(Guid.NewGuid());await leaving.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        string settings=JsonSerializer.Serialize((await worker.HandleUi(new("status"),sid,default)).Status!.Settings);
        var deleted=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("delete-network",ExpectedNetwork:owner.Pair.Network,ConfirmReplace:true)),sid,default).WaitAsync(TimeSpan.FromSeconds(2));
        await reading;
        Check(deleted.Ok&&deleted.Status!.NetworkId.Length==0&&leaving.Cancelled&&leaving.Disposed,"network deletion preempts the read and closes its pairing room promptly");
        Check(JsonSerializer.Serialize(deleted.Status!.Settings)==settings,"priority exit preserves all independent saved settings");
        await worker.StopLocal();
    }
    sealed class SlowPairPoll:IShortPairClient {
        public TaskCompletionSource Entered {get;}=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release {get;}=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource CancellationEntered {get;}=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource CancellationRelease {get;}=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Cancelled,Disposed,BlockCancellation;public int Reads;
        public async Task<PairRoomState> Poll(PairRoomTicket room,bool owner,CancellationToken token){
            var waiting=Release.Task.WaitAsync(token);
            using var registration=token.Register(()=>{if(BlockCancellation){CancellationEntered.TrySetResult();if(!CancellationRelease.Task.Wait(TimeSpan.FromSeconds(8)))throw new TimeoutException("fixture cancellation callback not released");}});
            Reads++;Entered.TrySetResult();try{await waiting;}catch(OperationCanceledException){Cancelled=true;throw;}throw new IOException("fixture read completed");
        }
        public Task Close(PairRoomTicket room,CancellationToken token)=>Task.CompletedTask;
        public void Dispose(){Disposed=true;CancellationRelease.TrySetResult();}
        public Task<PairRoomTicket> Create(PairKeyExchange key,string name,CancellationToken token)=>throw new NotSupportedException();
        public Task<PairRoomTicket> Join(string code,PairKeyExchange key,string name,CancellationToken token,string requestedIp="",MeshRejoinProof? rejoin=null)=>throw new NotSupportedException();
        public Task<PairRoomState> Reveal(PairRoomTicket room,bool owner,PairKeyExchange key,CancellationToken token)=>throw new NotSupportedException();
        public Task<PairRoomState> Approve(PairRoomTicket room,string candidate,string cipher,CancellationToken token)=>throw new NotSupportedException();
        public Task<PairRoomState> Finish(PairRoomTicket room,bool owner,CancellationToken token)=>throw new NotSupportedException();
    }
}
