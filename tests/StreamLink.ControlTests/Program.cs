using System.Reflection;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

int checks=0,failures=0;
void Check(bool ok,string reason){checks++;if(!ok){failures++;Console.Error.WriteLine(reason);}}
T Field<T>(ControlWorker worker,string name)=>(T)typeof(ControlWorker).GetField(name,BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(worker)!;
void Set(ControlWorker worker,string name,object value)=>typeof(ControlWorker).GetField(name,BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(worker,value);
string isolated=Path.Combine(Path.GetTempPath(),"StreamLink-control-"+Guid.NewGuid().ToString("N"));
Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",isolated);
try {
    using var worker=new ControlWorker();
    worker.StartLocal();
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
