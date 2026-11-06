using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task ControlLifecycle()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");
        var store=new ProfileStore();store.Save(new DeviceProfile{Mesh=owner,Enabled=true,ConnectionSource="existing"});
        string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
        var services=new MeshRuntimeServices(m=>new OwnerOnlyDiscovery(m),_=>Task.FromResult<IPacketAdapter>(new MemoryAdapter()),
            (_,_,_)=>throw new Exception("entry-only fixture cannot probe"),r=>new ForwardingTransport(r.Target),(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),
            (_,_,remote)=>{if(remote.Length==0){entered.Set();if(!release.Wait(TimeSpan.FromSeconds(15)))throw new TimeoutException("owned firewall fixture not released");}},
            (_,_)=>{},Path.Combine(ProfileStore.Root,"sessions")){
            Candidates=(_,_,_,_)=>throw new Exception("entry-only fixture cannot allocate candidates"),NetworkWake=()=>new MeshNetworkWake(false)
        };
        using var worker=new ControlWorker(services);worker.StartLocal();
        using var serverStop=new CancellationTokenSource();
        var server=(Task)typeof(ControlWorker).GetMethod("RunUiControl",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(worker,[serverStop.Token])!;
        async Task<UiControlReply> Call(UiControlRequest request,int milliseconds=2500){
            using var deadline=new CancellationTokenSource(milliseconds);
            using var pipe=new NamedPipeClientStream(".",UiControlProtocol.PipeName,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification);
            await pipe.ConnectAsync(2000,deadline.Token);await ServiceProtocol.Write(pipe,request,deadline.Token);
            return await ServiceProtocol.Read<UiControlReply>(pipe,deadline.Token);
        }
        Guid leaving=Guid.NewGuid(),patching=Guid.NewGuid();string saved="";
        try{
            await Until(()=>(worker.Handle(new("status")).GetAwaiter().GetResult().Status?.Connection?.Phase)=="Idle","isolated real runner becomes ready before lifecycle testing");
            saved=JsonSerializer.Serialize((await Call(new("status"))).Status!.Settings);
            var accepted=await Call(new("network",OperationId:leaving,Network:new("delete-network",ExpectedNetwork:owner.Pair.Network,ConfirmReplace:true)));
            Check(accepted.Ok&&accepted.Operation is {Completed:false},"real network exit acknowledges before a synchronous owned-firewall cleanup returns");
            Check(await Task.Run(()=>entered.Wait(TimeSpan.FromSeconds(3))),"real runner reaches its owned-rule-and-record cleanup stage");
            var clock=Stopwatch.StartNew();
            for(int i=0;i<5;i++){
                var status=await Call(new("status",OperationId:leaving),1500);
                Check(status.Ok&&status.Status!.ServiceReady&&status.Status.Connection?.Phase=="Releasing"&&status.Status.DirectPeers==0&&status.Operation is {Completed:false}&&status.Operation.Id==leaving,"fresh authenticated stopping status and correct operation remain available during slow owned cleanup "+i);
            }
            Check(clock.ElapsedMilliseconds<2500,"normal status reads are not delayed by the blocked Windows cleanup stage");
            var queued=await Call(new("patch",Patch:new(DeviceName:"Queued user rename"),OperationId:patching));
            Check(queued.Ok&&queued.Operation is {Completed:false}&&queued.Operation.Id==patching,"another explicit mutation queues while status polling stays independent");
            release.Set();
            using var completion=new CancellationTokenSource(6000);
            while((await Call(new("status",OperationId:patching))).Operation?.Completed!=true)await Task.Delay(30,completion.Token);
            var final=await Call(new("status",OperationId:leaving));
            Check(final.Operation is {Completed:true,Error:""}&&final.Status!.NetworkId.Length==0&&final.Status.DeviceName=="Queued user rename","original leave and queued mutation complete without duplicate execution or service restart");
            Check(JsonSerializer.Serialize(final.Status!.Settings)==saved,"slow real exit preserves independent user settings");
        }finally{release.Set();await worker.StopLocal();serverStop.Cancel();await server.WaitAsync(TimeSpan.FromSeconds(4));}
    }
}
