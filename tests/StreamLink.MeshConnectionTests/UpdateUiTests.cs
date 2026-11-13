using System.Diagnostics;
using System.Net;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task UpdateUi()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var store=new ProfileStore();string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        var ready=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var handler=new UpdateHandler(ready.Task);using var http=new HttpClient(handler);using var client=new ReleaseUpdateClient(http);
        using var monitor=new ReleaseUpdateMonitor(client,"1.3.1","windows","x64");
        using var worker=new ControlWorker(store,updateMonitor:monitor);worker.EnablePairNetworks();
        string profile=JsonSerializer.Serialize(worker.ProfileSnapshot());
        var initial=(await worker.HandleUi(new("status"),sid,default)).Status!;
        var denied=await worker.HandleUi(new("update-check"),"S-1-5-21-1-2-3-9999",default);
        Check(!denied.Ok&&denied.Status==null&&handler.Calls==0,"unauthorized callers cannot trigger update checks or read their state");
        var malformed=await worker.HandleUi(new("update-check",Patch:new(DeviceName:"must not change")),sid,default);
        Check(!malformed.Ok&&handler.Calls==0,"update checks reject smuggled network/device mutations");
        var clock=Stopwatch.StartNew();
        var began=await worker.HandleUi(new("update-check",OperationId:Guid.NewGuid()),sid,default);
        Check(began.Ok&&began.Operation?.Completed==true&&began.Status?.Update?.State=="Checking"&&clock.ElapsedMilliseconds<1000,"HTTP waits cannot block the update command or enter the foreground network queue");
        var live=await worker.HandleUi(new("status"),sid,default);
        Check(live.Ok&&live.Status!.SettingsRevision==initial.SettingsRevision,"status and settings remain immediately available while an update request is pending");
        ready.SetResult();await monitor.Check();
        var completed=(await worker.HandleUi(new("status"),sid,default)).Status!;
        Check(completed.WorkspaceVersion==2&&completed.Update?.State=="Available"&&completed.Update.Package?.Name.EndsWith("-x64.msi")==true,"workspace snapshots expose the device-wide update rather than a network's empty status");
        Check(JsonSerializer.Serialize(worker.ProfileSnapshot())==profile&&completed.SettingsRevision==initial.SettingsRevision,"update checks never write profiles, identities, settings or revisions");
        Console.WriteLine($"PASS {checks} update UI contract checks; isolated HTTP and profile store");
    }
    sealed class UpdateHandler(Task ready):HttpMessageHandler
    {
        public int Calls;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            Interlocked.Increment(ref Calls);await ready.WaitAsync(token);
            return new(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(new{tag_name="v2.0.0",draft=false,prerelease=false,
                html_url=ReleaseUpdateClient.Repository+"/releases/tag/v2.0.0",body="Update fixture",assets=new[]{new{name="ConWU-2.0.0-x64.msi",size=12345,
                    browser_download_url=ReleaseUpdateClient.Repository+"/releases/download/v2.0.0/ConWU-2.0.0-x64.msi"}}}))};
        }
    }
}
