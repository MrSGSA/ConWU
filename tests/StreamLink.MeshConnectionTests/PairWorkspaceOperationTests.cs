using System.Collections;
using System.Reflection;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PairWorkspaceOperations()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        using var host=new WorkspaceNode(Path.Combine(ProfileStore.Root,"operation-owner"),"Owner");
        var created=await host.Action("",new("create-direct"){Name="original"});Check(created.Ok,created.Error);
        string id=created.Status!.SelectedNetworkId,network=created.Status.NetworkId;
        var workspace=typeof(ControlWorker).GetField("workspace",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(host.Worker)!;
        var dictionary=(IEnumerable)workspace.GetType().GetField("networks",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(workspace)!;
        object? context=null;foreach(var pair in dictionary){var type=pair!.GetType();if((string)type.GetProperty("Key")!.GetValue(pair)! == id)context=type.GetProperty("Value")!.GetValue(pair);}
        var gate=(SemaphoreSlim)context!.GetType().GetProperty("Actions")!.GetValue(context)!;
        await gate.WaitAsync();
        try{
            var operation=Guid.NewGuid();var request=new UiControlRequest("network",OperationId:operation,Network:new("rename-network",ExpectedNetwork:network){Name="queued"}){NetworkId=id};
            var queued=host.Ui(request);await Task.Delay(100);Check(!queued.IsCompleted,"target operation really waits behind the network gate");
            var replay=await host.Ui(request);Check(replay.Ok&&replay.Operation is {Completed:false},"same pending operation ID returns pending status without duplicate mutation");
            var altered=await host.Ui(request with{Network=request.Network! with{Name="different"}});Check(!altered.Ok&&altered.Error.Contains("操作ID"),"same operation ID with different payload is rejected");
            var canceled=await host.Ui(new UiControlRequest("cancel",OperationId:Guid.NewGuid(),CancelOperationId:operation){NetworkId=id});Check(canceled.Ok,"queued operation accepts explicit cancellation");
            var result=await queued.WaitAsync(TimeSpan.FromSeconds(5));Check(!result.Ok&&result.Error.Contains("取消"),"canceled waiter returns without performing mutation");
        }finally{gate.Release();}
        var status=await host.State();Check(status.Networks.Single(n=>n.Id==id).Name=="original","canceled rename left network name unchanged");
        await gate.WaitAsync();
        try{
            var request=new UiControlRequest("network",OperationId:Guid.NewGuid(),Network:new("rename-network",ExpectedNetwork:network){Name="during-stop"}){NetworkId=id};
            var queued=host.Ui(request);await Task.Delay(100);Check(!queued.IsCompleted,"shutdown fixture has an admitted queued operation");
            var stopping=host.Worker.StopLocal();await Task.Delay(100);
            var rejected=await host.Ui(new UiControlRequest("network",OperationId:Guid.NewGuid(),Network:new("rename-network",ExpectedNetwork:network){Name="too-late"}){NetworkId=id});
            Check(!rejected.Ok&&rejected.Error.Contains("停止"),"new mutation is rejected after stop closes admission");
            gate.Release();var completed=await queued.WaitAsync(TimeSpan.FromSeconds(10));await stopping.WaitAsync(TimeSpan.FromSeconds(20));
            Check(completed.Ok||completed.Error.Contains("停止")||completed.Error.Contains("取消"),"previously admitted operation has a defined terminal outcome before stop completes");
        }finally{if(gate.CurrentCount==0)gate.Release();}
    }
}
