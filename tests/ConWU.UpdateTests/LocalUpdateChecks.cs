using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

static class LocalUpdateChecks
{
    public static async Task<int> Run()
    {
        int checks=0;void Check(bool value,string label){if(!value)throw new Exception(label);checks++;Console.WriteLine("PASS "+label);}
        async Task Until(Func<bool> condition){using var deadline=new CancellationTokenSource(5000);while(!condition())await Task.Delay(10,deadline.Token);}
        var package=new ReleaseUpdatePackage("ConWU-2.0.0-x64.msi",ReleaseUpdateClient.Repository+"/releases/download/v2.0.0/ConWU-2.0.0-x64.msi",4096,new string('a',64));
        var release=new ReleaseUpdateStatus("1.4.1","windows"){UpdateAvailable=true,LatestVersion="2.0.0",ReleaseUrl=ReleaseUpdateClient.Repository+"/releases/tag/v2.0.0",Package=package};
        var before=new UpdateRecoveryState(true,"1.4.1",[new("local-profile","network-id",true,true),new("stopped","other-network",false,false)]);
        var host=new UpdateHost();using(var manager=new LocalUpdateManager(host)){
            manager.StartRecoveryMonitor(()=>before);manager.BeginDownload(release);
            Check(manager.Status.State=="Downloading"&&!manager.Status.CanInstall&&host.Launches==0,"downloads never stop or install the running backend");
            bool rejected=false;try{manager.BeginDownload(release);}catch(IOException){rejected=true;}Check(rejected,"concurrent download admission is bounded");
            await Until(()=>host.Progress!=null);host.Progress!(2048,4096);Check(manager.Status.DownloadedBytes==2048,"download progress is available independently of the UI request");
            host.Ready.SetResult();await Until(()=>manager.Status.CanInstall);
            string ticket=manager.Status.Ticket;host.External=new(true,"Completed","old result"){Ticket=Guid.NewGuid().ToString("N")};
            await Task.Delay(1100);Check(manager.Status.State=="Ready"&&manager.Status.Ticket==ticket,"an old updater result cannot overwrite a newly prepared package");
            rejected=false;try{await manager.Confirm(Guid.NewGuid().ToString("N"),"authorized-sid",before);}catch(IOException){rejected=true;}Check(rejected&&host.Launches==0,"install confirmation is bound to the exact prepared ticket");
            await manager.Confirm(ticket,"authorized-sid",before);
            Check(host.Launches==1&&host.Caller=="authorized-sid"&&host.Before==before&&manager.Status.State=="Installing","one confirmation hands the authorized user and enabled-network snapshot to an independent host");
            host.External=new(true,"Completed","restored"){Ticket=ticket};await Until(()=>manager.Status.State=="Completed");
            Check(!manager.Status.Busy&&!manager.Status.CanInstall,"independent installer completion reaches observers without reopening the original page");
        }
        Check(host.Disposed&&host.Launches==1,"disposing the service-side monitor does not relaunch the installer");
        var recovered=new UpdateHost();recovered.Prepared=new(Guid.NewGuid().ToString("N"),"2.0.0","private-dir","local-package",new string('a',64),4096);
        using(var manager=new LocalUpdateManager(recovered))Check(manager.Status.CanInstall&&manager.Status.Ticket==recovered.Prepared.Ticket,"downloaded packages waiting for confirmation survive a backend restart");
        var failed=new UpdateHost{FailLaunch=true};failed.Ready.SetResult();using(var manager=new LocalUpdateManager(failed)){
            manager.BeginDownload(release);await Until(()=>manager.Status.CanInstall);await manager.Confirm(manager.Status.Ticket,"authorized-sid",before);
            Check(manager.Status.State=="Error"&&!manager.Status.Busy,"failure before launching leaves the old backend available and exposes a retryable error");
        }
        Check(OfficialUpdatePackage.Validate(release,".msi")==package,"full-package validation accepts only official version-bound metadata");
        var noV=release with{ReleaseUrl=ReleaseUpdateClient.Repository+"/releases/tag/2.0.0",Package=package with{Url=package.Url.Replace("/v2.0.0/","/2.0.0/")}};
        Check(OfficialUpdatePackage.Validate(noV,".msi").Url.Contains("/2.0.0/"),"official tags with and without v are supported");
        foreach(var bad in new[]{release with{Package=package with{Sha256=""}},release with{Package=package with{Url="https://evil.example/package.msi"}},release with{LatestVersion="2.0.1"},release with{Package=package with{Name="../other.msi"}}}){
            bool rejected=false;try{OfficialUpdatePackage.Validate(bad,".msi");}catch(IOException){rejected=true;}Check(rejected,"rejects incomplete or mismatched local-install metadata");
        }
        string root=Path.GetFullPath(Path.Combine("artifacts","uu-remote-lab","download-tests",Guid.NewGuid().ToString("N")));Directory.CreateDirectory(root);
        byte[] bytes=Enumerable.Range(0,4096).Select(n=>(byte)n).ToArray();var payload=package with{Sha256=Convert.ToHexString(SHA256.HashData(bytes))};
        using(var http=new HttpClient(new Handler((_,_)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new ByteArrayContent(bytes)})))){
            long count=0;string target=Path.Combine(root,"verified.msi");await OfficialUpdatePackage.Download(payload,target,(done,_)=>count=done,default,http);
            Check(File.ReadAllBytes(target).SequenceEqual(bytes)&&count==bytes.Length&&!File.Exists(target+".partial"),"only a complete length-and-hash-verified package becomes installable");
        }
        foreach(bool wrongHash in new[]{false,true}){
            string target=Path.Combine(root,wrongHash?"wrong-hash.msi":"truncated.msi");bool rejected=false;
            using var http=new HttpClient(new Handler((_,_)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new ByteArrayContent(wrongHash?bytes:bytes[..^1])})));
            try{await OfficialUpdatePackage.Download(wrongHash?payload with{Sha256=new string('0',64)}:payload,target,(_,_)=>{},default,http);}catch(IOException){rejected=true;}
            Check(rejected&&!File.Exists(target)&&!File.Exists(target+".partial"),"corrupt or truncated downloads never replace the working installation");
        }
        int redirects=0;using(var http=new HttpClient(new Handler((_,_)=>{redirects++;return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Redirect){Headers={Location=new Uri("https://evil.example/package")}});}))) {
            bool rejected=false;try{await OfficialUpdatePackage.Download(payload,Path.Combine(root,"redirect.msi"),(_,_)=>{},default,http);}catch(IOException){rejected=true;}
            Check(rejected&&redirects==1,"foreign redirect destinations are rejected before any request to them");
        }
        return checks;
    }
    sealed class UpdateHost:ILocalUpdateHost
    {
        public bool Supported=>true;
        public TaskCompletionSource Ready=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Action<long,long>? Progress;
        public PreparedLocalUpdate? Prepared;
        public LocalUpdateStatus? External;
        public int Launches;public string Caller="";public UpdateRecoveryState? Before;public bool Disposed,FailLaunch;
        public async Task<PreparedLocalUpdate> Download(ReleaseUpdateStatus release,Action<long,long> progress,CancellationToken token){Progress=progress;await Ready.Task.WaitAsync(token);return new(Guid.NewGuid().ToString("N"),release.LatestVersion,"private-dir","local-package",release.Package!.Sha256,release.Package.Bytes);}
        public PreparedLocalUpdate? RestorePrepared()=>Prepared;
        public Task Launch(PreparedLocalUpdate prepared,string callerSid,UpdateRecoveryState before,CancellationToken token){if(FailLaunch)throw new IOException("fixture launch failure");Launches++;Caller=callerSid;Before=before;return Task.CompletedTask;}
        public LocalUpdateStatus? ReadExternalStatus()=>External;
        public void ReportRecovery(UpdateRecoveryState state){}
        public void Dispose()=>Disposed=true;
    }
}
