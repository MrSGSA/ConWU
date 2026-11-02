using System.Reflection;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;
if(args is ["--unproven-owner-child",var ownershipOutput]){await UnprovenOwnershipTests.Child(ownershipOutput);return 0;}

if(args.Length==4&&args[0]=="--ui-linked-client"){
    WindowsInstance.ConfigureValidation(args[3]);await LinkedUserTests.Child(args[1],args[2]);return 0;
}
// Isolate BOTH profile and pipe names, not only the protected configuration.
// A local test must never bind or talk to the installed product's UI pipe.
WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
int checks=0,failures=0;
void Check(bool ok,string reason){checks++;if(!ok){failures++;Console.Error.WriteLine(reason);}}
T Field<T>(ControlWorker worker,string name)=>(T)typeof(ControlWorker).GetField(name,BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(worker)!;
void Set(ControlWorker worker,string name,object value)=>typeof(ControlWorker).GetField(name,BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(worker,value);
await UnprovenOwnershipTests.Run(Check);
string isolated=WindowsInstance.ProfileRoot;
Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",isolated);
try {
    using var worker=new ControlWorker();
    worker.StartLocal();
    await UiBoundaryTests.Run(worker,Check);
    await UiPatchTests.Run(worker,Check);
    var first=await worker.Handle(new("status"));
    string originalName=first.Profile!.DeviceName;
    first.Profile.DeviceName="mutated external reply";
    Check((await worker.Handle(new("status"))).Profile!.DeviceName==originalName,"Status reply must not expose mutable runtime profile reference");
    var gate=Field<SemaphoreSlim>(worker,"requests");
    await gate.WaitAsync();
    var read=worker.Handle(new("status"));
    bool responsive=await Task.WhenAny(read,Task.Delay(250))==read;
    gate.Release();await read;
    Check(responsive,"Status must remain responsive while management gate is occupied");
    var stop=new CancellationTokenSource();
    var held=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    Set(worker,"runStop",stop);Set(worker,"running",held.Task);
    var updated=JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize((await worker.Handle(new("status"))).Profile))!;
    updated.DeviceName="hot metadata";updated.LogLevel="off";
    var save=worker.Handle(new("save",updated));
    bool hot=await Task.WhenAny(save,Task.Delay(250))==save;
    bool undisturbed=!stop.IsCancellationRequested;
    held.TrySetResult();var saved=await save;
    Check(saved.Ok&&hot&&undisturbed,"Metadata save must not cancel or await network worker");
    Check(saved.Profile!.DeviceName=="hot metadata","Metadata must persist");
    var activeProfile=ProfileChanges.Copy(saved.Profile);Set(worker,"runningProfile",activeProfile);
    using var nextStop=new CancellationTokenSource();var nextHeld=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    Set(worker,"runStop",nextStop);Set(worker,"running",nextHeld.Task);
    var servers=ProfileChanges.Copy(saved.Profile);servers.TcpStun=["tcp.example.com:3478"];servers.UdpStun=["udp.example.com:3478"];
    Check(ProfileChanges.Impact(saved.Profile,servers)==ProfileChangeImpact.NextAttempt,"STUN edits classify as next-attempt input rather than a whole-network rebuild");
    var serversSaved=await worker.Handle(new("save",servers)).WaitAsync(TimeSpan.FromSeconds(1));
    Check(serversSaved.Ok&&!nextStop.IsCancellationRequested&&!nextHeld.Task.IsCompleted&&activeProfile.TcpStun.SequenceEqual(servers.TcpStun)&&activeProfile.UdpStun.SequenceEqual(servers.UdpStun),"saving STUN lists preserves live owner/Active and passes immutable array replacements to subsequent collection");
    var entrySettings=ProfileChanges.Copy(serversSaved.Profile!);entrySettings.ConnectionSource="existing";entrySettings.ExistingEntries=[new(0,"203.0.113.1:44680")];
    Check(ProfileChanges.Impact(serversSaved.Profile!,entrySettings)==ProfileChangeImpact.NextAttempt,"entry changes do not require Wintun reconstruction");
    var entriesSaved=await worker.Handle(new("save",entrySettings)).WaitAsync(TimeSpan.FromSeconds(1));
    Check(entriesSaved.Ok&&!nextStop.IsCancellationRequested&&!nextHeld.Task.IsCompleted,"saving a source retains the live network owner");
    var portSettings=ProfileChanges.Copy(entriesSaved.Profile!);portSettings.ListenPort++;
    var slowSave=worker.Handle(new("save",portSettings));
    await Task.Delay(16000);
    Check(!slowSave.IsCompleted&&nextStop.IsCancellationRequested,"slow safe shutdown remains one pending save beyond the former 15-second timeout");
    nextHeld.TrySetResult();
    Check((await slowSave.WaitAsync(TimeSpan.FromSeconds(2))).Ok,"original save completes after resource join without a second click");
    var extension=JsonSerializer.Deserialize<DeviceProfile>("{\"FutureOption\":{\"explicitDisabled\":true}}")!;
    Check(JsonSerializer.Serialize(extension).Contains("FutureOption"),"Unknown future profile fields must roundtrip");
    await worker.StopLocal();
    // Retries with one authenticated local OperationId are idempotent; a
    // different payload cannot reuse that ID to repeat/replace an operation.
    Guid createId=Guid.NewGuid();var create=new ControlRequest("create",Service:"https://example.com/",OperationId:createId);
    var created=await worker.Handle(create);var repeated=await worker.Handle(create);
    Check(created.Ok&&repeated.Ok&&created.Profile!.Pair==repeated.Profile!.Pair&&repeated.Operation?.Id==createId,"Duplicate operation must not recreate identity");
    Check(!(await worker.Handle(create with{Service="https://different.example/"})).Ok,"Different request cannot reuse operation ID");
    var priorPair=(await worker.Handle(new("status"))).Profile!.Pair;
    Guid queuedId=Guid.NewGuid();await gate.WaitAsync();
    var queued=worker.Handle(new("create",Service:"https://example.com/",OperationId:queuedId));
    Check((await worker.Handle(new("status"))).Operation?.Phase=="排队","Queued operation exposes stage");
    var canceled=await worker.Handle(new("cancel",CancelOperationId:queuedId));
    var canceledResult=await queued.WaitAsync(TimeSpan.FromSeconds(1));gate.Release();
    Check(canceled.Ok&&!canceledResult.Ok&&(await worker.Handle(new("status"))).Profile!.Pair==priorPair,"Cancel queued operation must not change paired identity");
    // A caller timeout does not close a still-held native/resource owner.
    var heldAgain=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var stopAgain=new CancellationTokenSource();
    Set(worker,"running",heldAgain.Task);Set(worker,"runStop",stopAgain);
    using(var deadline=new CancellationTokenSource(100)){
        var stopped=await worker.Handle(new("stop"),deadline.Token).WaitAsync(TimeSpan.FromSeconds(1));
        Check(!stopped.Ok&&stopAgain.IsCancellationRequested&&!heldAgain.Task.IsCompleted,"Caller cancellation must propagate while retaining unfinished network task");
        Check((await worker.Handle(new("status"))).Operation?.Completed==true,"Canceled wait has a terminal operation result");
    }
    bool lockStillHeld=false;try{using var collision=new ControlWorker();}catch(IOException){lockStillHeld=true;}
    Check(lockStillHeld,"Timed-out stop must retain runtime ownership");
    worker.Dispose();lockStillHeld=false;try{using var collision=new ControlWorker();}catch(IOException){lockStillHeld=true;}
    Check(lockStillHeld,"Dispose cannot release the single-instance lock before held work exits");
    heldAgain.TrySetResult();
    bool released=false;
    for(int n=0;n<100&&!released;n++){try{using var fresh=new ControlWorker();released=true;}catch(IOException){await Task.Delay(10);}}
    Check(released,"Completed held work eventually releases retained ownership");
} finally {
    Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",null);
    // Leave the protected temporary profile for evidence; no private content is
    // printed or copied into the tracked test report.
}
Console.WriteLine(JsonSerializer.Serialize(new {scope="isolated Windows control worker; no driver or production service",checks,failures,status=failures==0?"Pass":"Fail"}));
return failures==0?0:1;
