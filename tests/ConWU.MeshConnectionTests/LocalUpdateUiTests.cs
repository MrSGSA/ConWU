using System.Diagnostics;
using System.Net;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task LocalUpdateUi()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var store=new ProfileStore();string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        using var handler=new UpdateHandler(Task.CompletedTask);using var http=new HttpClient(handler);using var client=new ReleaseUpdateClient(http);
        using var monitor=new ReleaseUpdateMonitor(client,"1.4.1","windows","x64");await monitor.Check();
        var host=new LocalUpdateHostFixture();using var worker=new ControlWorker(store,updateMonitor:monitor){LocalUpdateHostFactory=()=>host};worker.EnablePairNetworks();
        string before=JsonSerializer.Serialize(worker.ProfileSnapshot());
        UiControlRequest Download()=>new("update-download",OperationId:Guid.NewGuid()){LocalUpdate=new("2.0.0")};
        var denied=await worker.HandleUi(Download(),"S-1-5-21-1-2-3-9999",default);
        Check(!denied.Ok&&denied.Status==null&&host.Downloads==0,"only the authorized local user can prepare an installation");
        foreach(var malformed in new[]{Download() with{Patch=new(DeviceName:"forbidden")},Download() with{NetworkId=Guid.NewGuid().ToString("N")},Download() with{UuTakeover=new(new(true),"")},new UiControlRequest("patch",new(DeviceName:"forbidden")){LocalUpdate=new("2.0.0")}}){
            Check(!(await worker.HandleUi(malformed,sid,default)).Ok&&host.Downloads==0,"installer admission rejects mixed commands and network targeting");
        }
        using var cancelled=new CancellationTokenSource();var clock=Stopwatch.StartNew();
        var admitted=await worker.HandleUi(Download(),sid,cancelled.Token);cancelled.Cancel();
        Check(admitted.Ok&&admitted.Status!.LocalUpdate?.State=="Downloading"&&clock.ElapsedMilliseconds<1000,"installer download admission is quick and returns device-level state");
        var live=await worker.HandleUi(new("status"),sid,default);
        Check(live.Ok&&live.Status!.WorkspaceVersion==2&&live.Status.LocalUpdate!.State=="Downloading","workspace status remains usable while the downloader waits");
        host.Ready.SetResult();using var timeout=new CancellationTokenSource(5000);
        while((live=await worker.HandleUi(new("status"),sid,default)).Status!.LocalUpdate?.CanInstall!=true)await Task.Delay(20,timeout.Token);
        Check(host.Downloads==1&&JsonSerializer.Serialize(worker.ProfileSnapshot())==before,"closing a download request neither cancels the package nor changes profiles");
        var status=live.Status!.LocalUpdate!;
        var stale=await worker.HandleUi(new("update-install"){LocalUpdate=new(status.Version,Guid.NewGuid().ToString("N"))},sid,default);
        Check(!stale.Ok&&host.Launches==0,"a stale install ticket cannot execute any package");
        var install=await worker.HandleUi(new("update-install"){LocalUpdate=new(status.Version,status.Ticket)},sid,default);
        while(host.Launches==0)await Task.Delay(20,timeout.Token);
        Check(install.Ok&&host.Caller==sid&&host.Before is {Networks.Length:0},"confirmed installs preserve the real local-user SID and the independent network inventory");
        var mutation=await worker.HandleUi(new("patch",new(DeviceName:"during-install")),sid,default);
        Check(!mutation.Ok&&JsonSerializer.Serialize(worker.ProfileSnapshot())==before,"new configuration mutations are rejected once local installation starts");
        Check((await worker.HandleUi(new("status"),sid,default)).Ok,"installing never disables read-only status");
        Console.WriteLine($"PASS {checks} local update service checks; no MSI or production service launched");
    }
    sealed class LocalUpdateHostFixture:ILocalUpdateHost
    {
        public bool Supported=>true;public int Downloads,Launches;public string Caller="";public UpdateRecoveryState? Before;
        public TaskCompletionSource Ready=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<PreparedLocalUpdate> Download(ReleaseUpdateStatus release,Action<long,long> progress,CancellationToken token){Interlocked.Increment(ref Downloads);await Ready.Task.WaitAsync(token);return new(Guid.NewGuid().ToString("N"),release.LatestVersion,"isolated","isolated.msi",new string('A',64),4096);}
        public Task Launch(PreparedLocalUpdate prepared,string callerSid,UpdateRecoveryState before,CancellationToken token){Caller=callerSid;Before=before;Interlocked.Increment(ref Launches);return Task.CompletedTask;}
        public LocalUpdateStatus? ReadExternalStatus()=>null;
        public void ReportRecovery(UpdateRecoveryState state){}
        public void Dispose(){}
    }
}
