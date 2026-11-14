using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using StreamLink.Core;
using StreamLink.Service;

static class UiResponsivenessTests
{
    public static async Task<int> Run()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var store=new ProfileStore();store.Save(new DeviceProfile{Enabled=false});
        store.AuthorizeUiUser(WindowsIdentity.GetCurrent().User!.Value);
        using var worker=new ControlWorker();worker.StartLocal();
        using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
        using var cancellation=new CancellationTokenSource();
        using var callback=cancellation.Token.Register(()=>{entered.Set();release.Wait(TimeSpan.FromSeconds(12));});
        typeof(ControlWorker).GetField("runStop",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(worker,cancellation);
        await using var pipe=new UiPipeFixture(worker,false);
        var id=Guid.NewGuid();var clock=Stopwatch.StartNew();
        var stop=pipe.Call(new("stop",OperationId:id),default);int result=0;
        try{
            if(!await Task.Run(()=>entered.Wait(TimeSpan.FromSeconds(4))))throw new Exception("blocking cancellation callback was not entered");
            var accepted=await stop.WaitAsync(TimeSpan.FromSeconds(2));
            if(!accepted.Ok||accepted.Operation is not {Completed:false} operation||operation.Id!=id)throw new Exception("mutation did not acknowledge while cancellation was still blocked");
            Console.WriteLine("PASS real restricted pipe acknowledges mutation before its synchronous cancellation callback returns");
            using var deadline=new CancellationTokenSource(1500);
            var status=await pipe.Call(new("status",OperationId:id),deadline.Token);
            if(!status.Ok||status.Status==null||status.Operation?.Completed!=false||release.IsSet)throw new Exception("status cannot be read during blocked resource cancellation");
            Console.WriteLine("PASS fresh status and operation progress remain available during a blocked network stop");
        }catch(Exception error){Console.Error.WriteLine("FAIL "+error.Message);result=1;}
        finally{release.Set();await stop.WaitAsync(TimeSpan.FromSeconds(5));}
        using(var deadline=new CancellationTokenSource(3000)){
            UiControlReply reply;
            do{await Task.Delay(30,deadline.Token);reply=await pipe.Call(new("status",OperationId:id),deadline.Token);}while(reply.Operation?.Completed!=true);
            if(reply.Operation.Error.Length>0){Console.Error.WriteLine("FAIL stop result: "+reply.Operation.Error);result=1;}
            else Console.WriteLine("PASS original operation completes once after the blocked callback is released");
        }
        Console.WriteLine("UI responsiveness elapsedMs="+clock.ElapsedMilliseconds);
        await worker.StopLocal();return result;
    }
}
