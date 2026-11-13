using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using StreamLink.Core;

int checks=0;
void Check(bool value,string name){if(!value)throw new Exception(name);checks++;Console.WriteLine("PASS "+name);}
JsonObject Release(string version="1.3.2",string[]? names=null)=>new(){
    ["tag_name"]="v"+version,["draft"]=false,["prerelease"]=false,["html_url"]=ReleaseUpdateClient.Repository+"/releases/tag/v"+version,["body"]="修复说明",
    ["assets"]=new JsonArray((names??["ConWU-"+version+"-x64.msi","ConWU-"+version+"-linux-x64.tar.gz","ConWU-"+version+"-android-arm64-v8a.apk"]).Select(name=>(JsonNode?)new JsonObject{
        ["name"]=name,["size"]=12345,["state"]="uploaded",["digest"]="sha256:"+new string('a',64),
        ["browser_download_url"]=ReleaseUpdateClient.Repository+"/releases/download/v"+version+"/"+name
    }).ToArray())
};
async Task<ReleaseUpdateStatus> Read(JsonNode node,string platform="windows",string arch="x64",string current="1.3.1+source"){
    using var http=new HttpClient(new Handler((_,_)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(node.ToJsonString(),Encoding.UTF8,"application/json")})));
    using var client=new ReleaseUpdateClient(http);return await client.Check(current,platform,arch);
}
foreach(var (platform,arch,suffix) in new[]{("windows","x64","x64.msi"),("linux","x64","linux-x64.tar.gz"),("android","arm64","android-arm64-v8a.apk")}){
    var result=await Read(Release(),platform,arch);
    Check(result.UpdateAvailable&&result.State=="Available"&&result.Package!.Name.EndsWith(suffix)&&result.Package.Sha256==new string('A',64),"selects the correct official-release attachment for "+platform);
}
Check((await Read(Release(),"android","x64")).State=="NoPackage","an Android x64 client is never offered an arm64 or Windows installer");
Check((await Read(Release(),"ios","arm64")).Message.Contains("原安装渠道"),"iOS update notices use the original installation channel");
Check(!(await Read(Release(),current:"1.3.2+other-source")).UpdateAvailable,"build metadata cannot manufacture a newer release");
Check(!(await Read(Release(),current:"1.4.0-preview.1")).UpdateAvailable,"a preview newer than the formal release is never downgraded");
var universal=Release(names:["ConWU-1.3.2-android-universal.apk"]);
Check((await Read(universal,"android","arm64")).Package!.Name.EndsWith("universal.apk"),"universal Android packages are valid fallbacks");
var cases=new List<(string Name,Action<JsonObject> Corrupt)>{
    ("draft",r=>r["draft"]=true),("prerelease",r=>r["prerelease"]=true),
    ("invalid semantic version",r=>r["tag_name"]="v1.03.2"),
    ("wrong repository",r=>r["html_url"]="https://github.com/attacker/ConWU/releases/tag/v1.3.2"),
    ("foreign download",r=>r["assets"]![0]!["browser_download_url"]="https://attacker.example/setup.msi"),
    ("redirect-like download",r=>r["assets"]![0]!["browser_download_url"]=ReleaseUpdateClient.Repository+"/releases/download/v1.3.2/ConWU-1.3.2-x64.msi?redirect=bad"),
    ("malformed digest",r=>r["assets"]![0]!["digest"]="sha256:not-a-digest"),
    ("ambiguous duplicate",r=>((JsonArray)r["assets"]!).Add(r["assets"]![0]!.DeepClone()))
};
foreach(var (name,corrupt) in cases){var data=Release();corrupt(data);bool rejected=false;try{await Read(data);}catch(FormatException){rejected=true;}Check(rejected,"rejects "+name+" metadata");}
var large=Release();large["body"]=new string('x',300000);bool oversized=false;try{await Read(large);}catch(FormatException){oversized=true;}Check(oversized,"limits decompressed response size before parsing");

var clock=new Clock();var ready=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);int calls=0;bool fail=false;
using var handler=new Handler(async(request,token)=>{
    Interlocked.Increment(ref calls);
    Check(request.RequestUri!.AbsoluteUri==ReleaseUpdateClient.Feed&&request.Headers.Authorization==null&&request.Method==HttpMethod.Get,"queries only public metadata without device identity or credentials");
    await ready.Task.WaitAsync(token);
    return fail?new(HttpStatusCode.ServiceUnavailable):new(HttpStatusCode.OK){Content=new StringContent(Release().ToJsonString())};
});
using var sharedHttp=new HttpClient(handler);using var sharedClient=new ReleaseUpdateClient(sharedHttp);
using var monitor=new ReleaseUpdateMonitor(sharedClient,"1.3.1","android","arm64",clock);
using var cancel=new CancellationTokenSource();
var first=monitor.Check(token:cancel.Token);var second=monitor.Check(force:true);
Check(monitor.Status.State=="Checking","an unfinished request immediately exposes checking state without waiting on HTTP");
cancel.Cancel();bool cancelled=false;try{await first;}catch(OperationCanceledException){cancelled=true;}Check(cancelled,"one caller can cancel its own wait");
ready.SetResult();var available=await second;
Check(calls==1&&available.State=="Available","caller cancellation preserves the one shared request and other observers");
await monitor.Check();await monitor.Check(force:true);Check(calls==1,"automatic checks cache results and manual requests have a cooldown");
clock.Advance(TimeSpan.FromMinutes(2));fail=true;
var failed=await monitor.Check(force:true);
Check(failed.State=="Error"&&failed.UpdateAvailable&&failed.Package==available.Package,"a transient check failure retains the previously verified update and leaves connectivity independent");
clock.Advance(TimeSpan.FromMinutes(2));await monitor.Check();Check(calls==2,"failed automatic checks respect a bounded retry interval");
clock.Advance(TimeSpan.FromMinutes(16));fail=false;await monitor.Check();Check(calls==3&&monitor.Status.State=="Available","automatic retry clears the previous error after recovery");
Console.WriteLine($"PASS {checks} update detection checks; isolated HTTP fixtures");

sealed class Handler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> send):HttpMessageHandler
{protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>send(request,token);}
sealed class Clock:TimeProvider
{DateTimeOffset now=DateTimeOffset.UtcNow;public override DateTimeOffset GetUtcNow()=>now;public void Advance(TimeSpan value)=>now+=value;}
