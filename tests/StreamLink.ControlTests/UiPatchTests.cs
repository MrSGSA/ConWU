using System.Reflection;
using System.Security.Principal;
using StreamLink.Core;
using StreamLink.Service;

static class UiPatchTests
{
    public static async Task Run(ControlWorker worker,Action<bool,string> check)
    {
        const BindingFlags Flags=BindingFlags.Instance|BindingFlags.NonPublic;
        void Set(string name,object? value)=>typeof(ControlWorker).GetField(name,Flags)!.SetValue(worker,value);
        var gate=(SemaphoreSlim)typeof(ControlWorker).GetField("requests",Flags)!.GetValue(worker)!;
        var method=typeof(ControlWorker).GetMethod("HandleUi",Flags)!;
        string sid=WindowsIdentity.GetCurrent().User!.Value;var store=new ProfileStore();store.AuthorizeUiUser(sid);
        Task<UiControlReply> Ui(UiControlRequest request)=>(Task<UiControlReply>)method.Invoke(worker,[request,sid,CancellationToken.None])!;
        var before=(await worker.Handle(new("status"))).Profile!;
        using var stop=new CancellationTokenSource();var held=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Set("running",held.Task);Set("runStop",stop);
        var settings=ProfileChanges.Copy(before);settings.ManagedEgressMbps=before.ManagedEgressMbps==17?18:17;
        settings.TcpStun=["new-admin-stun.example:3478"];settings.AllowManualQualityRequests=!before.AllowManualQualityRequests;
        Task<ControlReply>? admin=null;Task<UiControlReply>? patchTask=null;
        Guid id=Guid.NewGuid();var patch=new UiControlRequest("patch",new("atomic UI name",null,before.DeviceName),id);
        try{
            admin=worker.Handle(new("save",settings));
            check(stop.IsCancellationRequested&&!admin.IsCompleted,"admin save holds serial gate while the old worker is still exiting");
            patchTask=Ui(patch);check(!patchTask.IsCompleted,"UI patch queues behind the in-progress admin mutation");
            held.TrySetResult();var adminResult=await admin.WaitAsync(TimeSpan.FromSeconds(2));var result=await patchTask.WaitAsync(TimeSpan.FromSeconds(2));
            var actual=(await worker.Handle(new("status"))).Profile!;
            check(adminResult.Ok&&result.Ok&&actual.DeviceName=="atomic UI name","queued patch changes its one intended field");
            check(actual.ManagedEgressMbps==settings.ManagedEgressMbps&&actual.TcpStun.SequenceEqual(settings.TcpStun)&&actual.AllowManualQualityRequests==settings.AllowManualQualityRequests,
                "UI patch cannot roll back new network, STUN or diagnostic settings");
            actual.UdpStun=["new-unrelated-stun.example:3478"];
            check((await worker.Handle(new("save",actual))).Ok,"unrelated configuration change between retries");
            var duplicate=await Ui(patch);
            check(duplicate.Ok&&duplicate.Operation?.Id==id&&duplicate.Operation.Completed,"same original patch+ID remains idempotent across unrelated changes");
            check(!(await Ui(patch with{Patch=patch.Patch! with{DeviceName="different"}})).Ok,"same ID with a different patch is rejected");
            var conflict=new UiControlRequest("patch",new("cannot overwrite",null,"obsolete base"),Guid.NewGuid());
            var rejected=await Ui(conflict);var rejectedAgain=await Ui(conflict);
            check(!rejected.Ok&&!rejectedAgain.Ok&&rejected.Error==rejectedAgain.Error,"failed duplicate cannot be reported as success");
            check((await worker.Handle(new("status"))).Profile!.DeviceName=="atomic UI name","conflicting same-field update preserves current value");
        }finally{
            held.TrySetResult();
            await Task.WhenAll(new Task?[]{admin,patchTask}.OfType<Task>()).WaitAsync(TimeSpan.FromSeconds(3));
        }
        using var liveStop=new CancellationTokenSource();var live=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Set("running",live.Task);Set("runStop",liveStop);var active=ProfileChanges.Copy((await worker.Handle(new("status"))).Profile!);Set("runningProfile",active);
        try{
            var result=await Ui(new("patch",new(LogLevel:"debug"),Guid.NewGuid())).WaitAsync(TimeSpan.FromSeconds(1));
            check(result.Ok&&!liveStop.IsCancellationRequested&&!live.Task.IsCompleted&&active.LogLevel=="debug","metadata patch leaves healthy worker and its resource reference alive");
        }finally{live.TrySetResult();await worker.StopLocal();}
        await gate.WaitAsync();Task<UiControlReply>? queued=null;
        using(var caller=new CancellationTokenSource()){
            var accepted=(Task<UiControlReply>)method.Invoke(worker,[new UiControlRequest("patch",new("must stop with service"),Guid.NewGuid()),sid,caller.Token])!;
            caller.Cancel();gate.Release();
            var result=await accepted.WaitAsync(TimeSpan.FromSeconds(2));
            check(!result.Ok&&result.Status?.DeviceName!="must stop with service"&&result.Error.Contains("后台正在停止"),"service lifetime cancellation stops queued UI work without committing a late mutation");
        }
        await gate.WaitAsync();
        try{
            queued=Ui(new("patch",new("revoked caller"),Guid.NewGuid()));
            store.AuthorizeUiUser("S-1-5-21-111-222-333-444");
        }finally{gate.Release();}
        try{var denied=await queued!.WaitAsync(TimeSpan.FromSeconds(2));check(!denied.Ok&&denied.Status==null,"queued UI mutation rechecks authorization and returns no status after revocation");}
        finally{store.AuthorizeUiUser(sid);}
    }
}
