using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;
using StreamLink.Web;

if(args is ["--ui-responsiveness"])return await UiResponsivenessTests.Run();
if(args is ["--browser-fixture",var assetRoot,..var fixtureOptions]) {
 WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
 var fixtureStore=new ProfileStore();var fixtureProfile=fixtureStore.Load();fixtureProfile.CoordinatorRoleVersion=1;fixtureStore.Save(fixtureProfile);
 using var fixture=new ControlWorker();if(fixtureOptions.Contains("--pair-workspace"))fixture.EnablePairNetworks();fixture.StartLocal();
 string sid=WindowsIdentity.GetCurrent().User!.Value;new ProfileStore().AuthorizeUiUser(sid);
 await using var pipe=new UiPipeFixture(fixture,fixtureOptions.Contains("--deferred"));
 await using var panel=await WebPanel.Start(pipe.Call,Path.GetFullPath(assetRoot));
 while(await Console.In.ReadLineAsync() is {} input){
  if(input=="open")Console.WriteLine(panel.OpenLink());
  else if(input=="seed-network"){
   // One-member, disabled mesh: exercises UI deletion without opening Wintun
   // or contacting a public coordinator. Never applied to the daily instance.
   var seeded=await fixture.Handle(new("mesh-create",Service:"https://example.com/"));
   Console.WriteLine(seeded.Ok?"seeded":"seed-failed");
  }else if(input=="seed-guest-network"){
   var owner=MeshIdentity.Create("https://example.com/","","faketcp");
   var invite=MeshIdentity.Export(MeshIdentity.Issue(owner));
   var seeded=await fixture.Handle(new("mesh-join",Invite:invite));
   Console.WriteLine(seeded.Ok?"seeded":"seed-failed");
  }else if(input=="quit")break;
  await Console.Out.FlushAsync();
 }
 await fixture.StopLocal();return 0;
}
var root=Path.GetFullPath(args.FirstOrDefault()??"src/ConWU.Web/wwwroot");
int checks=0,failures=0,calls=0;
string? backendFailure=null;
var clock=new PanelClock();
void Check(bool ok,string name){checks++;if(!ok){failures++;Console.Error.WriteLine("FAIL "+name);}}
ReplyBudgetTests.Run(Check);
await RemoteAdminTests.Run(root,Check);
await ProgressQueryTests.Run(root,Check);
Task<UiControlReply> Backend(UiControlRequest request,CancellationToken token){Interlocked.Increment(ref calls);if(backendFailure!=null)throw backendFailure=="Stopped"?new UiBackendException("Stopped","个人后台已停止"):new IOException("private backend details");return Task.FromResult(new UiControlReply(true,"",null));}
await using(var panel=await WebPanel.Start(Backend,root,clock)) {
 using var client=new HttpClient(new HttpClientHandler{UseCookies=true,AllowAutoRedirect=false}){BaseAddress=new(panel.Origin)};
 async Task<HttpResponseMessage> Send(string method,string path,object? body=null,string? origin=null,string? csrf=null,string? host=null){
  var req=new HttpRequestMessage(new HttpMethod(method),path);if(body!=null)req.Content=JsonContent.Create(body);
  if(origin!=null)req.Headers.Add("Origin",origin);if(csrf!=null)req.Headers.Add("X-StreamLink-CSRF",csrf);if(host!=null)req.Headers.Host=host;
  return await client.SendAsync(req);
 }
 var staticPage=await Send("GET","/");Check(staticPage.IsSuccessStatusCode&&staticPage.Headers.Contains("Content-Security-Policy"),"static page and restrictive CSP");
 Check((await Send("GET","/api/status")).StatusCode==HttpStatusCode.Unauthorized,"loopback alone grants no control");
 Check((await Send("GET","/",host:"attacker.example")).StatusCode==HttpStatusCode.Forbidden,"DNS rebinding Host denied");
 var ticket=new Uri(panel.OpenLink()).Fragment[1..];
 Check((await Send("POST","/api/session",new{ticket},"https://attacker.example")).StatusCode==HttpStatusCode.Forbidden,"cross-origin bootstrap denied");
 var boot=await Send("POST","/api/session",new{ticket},panel.Origin);Check(boot.IsSuccessStatusCode,"one-use local bootstrap");
 string csrf=(await boot.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("csrf").GetString()!;
 var cookie=boot.Headers.GetValues("Set-Cookie").Single();Check(cookie.Contains("httponly",StringComparison.OrdinalIgnoreCase)&&cookie.Contains("samesite=strict",StringComparison.OrdinalIgnoreCase),"HttpOnly SameSite cookie");
 Check((await Send("POST","/api/session",new{ticket},panel.Origin)).StatusCode==HttpStatusCode.Unauthorized,"bootstrap replay rejected");
 Check((await Send("GET","/api/status")).IsSuccessStatusCode&&calls==1,"authenticated status routed to restricted interface");
 var request=new UiControlRequest("stop",OperationId:Guid.NewGuid());
 Check((await Send("POST","/api/command",request,panel.Origin)).StatusCode==HttpStatusCode.Forbidden,"missing CSRF rejected");
 Check((await Send("POST","/api/command",request,"https://attacker.example",csrf)).StatusCode==HttpStatusCode.Forbidden,"cross-site mutation rejected");
 Check((await Send("POST","/api/command",request,panel.Origin,csrf)).IsSuccessStatusCode&&calls==2,"authenticated command forwarded once");
 Check((await Send("POST","/api/command",request,panel.Origin,csrf)).StatusCode==HttpStatusCode.Conflict&&calls==2,"operation replay never forwarded");
 int beforeOversize=calls;
 using var oversizedClient=new HttpClient(new HttpClientHandler{UseCookies=false}){BaseAddress=new(panel.Origin)};
 using(var oversizedRequest=new HttpRequestMessage(HttpMethod.Post,"/api/command")){
  oversizedRequest.Content=new StringContent(new string('x',ServiceProtocol.MaximumUiMessageBytes+1),System.Text.Encoding.UTF8,"application/json");
  oversizedRequest.Headers.Add("Origin",panel.Origin);oversizedRequest.Headers.Add("X-StreamLink-CSRF",csrf);oversizedRequest.Headers.Add("Cookie",cookie.Split(';')[0]);
  try {using var oversized=await oversizedClient.SendAsync(oversizedRequest);Check((oversized.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.RequestEntityTooLarge)&&calls==beforeOversize,"oversized UI request rejected before dispatch");}
  catch(HttpRequestException){Check(calls==beforeOversize,"oversized UI connection rejected before dispatch");}
 }
 var largerUiRequest=new UiControlRequest("network",OperationId:Guid.NewGuid(),Network:new UiNetworkAction("test"){Entry=new string('x',70000)});
 using(var largerUiReply=await Send("POST","/api/command",largerUiRequest,panel.Origin,csrf))
  Check(largerUiReply.IsSuccessStatusCode&&calls==beforeOversize+1,"UI request above old 64 KiB limit reaches restricted backend");
 var priorCsrf=csrf;
 var secondTicket=new Uri(panel.OpenLink()).Fragment[1..];
 using(var secondSession=await Send("POST","/api/session",new{ticket=secondTicket},panel.Origin))csrf=(await secondSession.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("csrf").GetString()!;
 var currentRequest=new UiControlRequest("stop",OperationId:Guid.NewGuid());int beforeSessionChange=calls;
 using(var oldSessionReply=await Send("POST","/api/command",currentRequest,panel.Origin,priorCsrf)){
  var body=await oldSessionReply.Content.ReadFromJsonAsync<JsonElement>();
  Check(oldSessionReply.StatusCode==HttpStatusCode.Forbidden&&body.GetProperty("code").GetString()=="SessionChanged"&&calls==beforeSessionChange,"another tab's session rotation rejects stale CSRF before recording or dispatching a mutation");
 }
 using(var currentSession=await Send("GET","/api/session"))Check((await currentSession.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("csrf").GetString()==csrf,"an authenticated old tab can read the current session token");
 Check((await Send("POST","/api/command",currentRequest,panel.Origin,csrf)).IsSuccessStatusCode&&calls==beforeSessionChange+1,"the same unsubmitted operation ID can be sent once after explicit session resynchronization");
 Check((await Send("POST","/api/command",currentRequest,panel.Origin,csrf)).StatusCode==HttpStatusCode.Conflict&&calls==beforeSessionChange+1,"session recovery never permits a second dispatch of an accepted operation");
 request=currentRequest;
 Check((await Send("POST","/api/command",new{method="save",operationId=Guid.NewGuid(),profile=new{Enabled=true}},panel.Origin,csrf)).StatusCode==HttpStatusCode.BadRequest,"arbitrary whole-profile payload denied by schema");
 Check((await Send("GET","/api/status?token=secret")).StatusCode==HttpStatusCode.Forbidden,"URL token parameters disallowed");
 Check((await Send("GET","/ConWU.Core.dll")).StatusCode==HttpStatusCode.NotFound,"non-whitelisted filesystem resource inaccessible");
 backendFailure="Stopped";
 var stopped=await Send("GET","/api/status");var stoppedBody=await stopped.Content.ReadFromJsonAsync<JsonElement>();
 Check(stopped.StatusCode==HttpStatusCode.ServiceUnavailable&&stoppedBody.GetProperty("code").GetString()=="Stopped"&&stoppedBody.GetProperty("error").GetString()=="个人后台已停止","stopped backend is distinguishable from missing authorization");
 backendFailure="Unknown";
 var unknown=await Send("GET","/api/status");string unknownBody=await unknown.Content.ReadAsStringAsync();
 Check(unknown.StatusCode==HttpStatusCode.ServiceUnavailable&&!unknownBody.Contains("private backend details"),"unrecognized backend exception remains sanitized");
 backendFailure=null;Check((await Send("GET","/api/status")).IsSuccessStatusCode,"existing panel session recovers when backend returns");
 clock.Advance(TimeSpan.FromMinutes(25));Check((await Send("GET","/api/status")).IsSuccessStatusCode,"authenticated activity renews the panel idle timeout");
 clock.Advance(TimeSpan.FromMinutes(10));Check((await Send("GET","/api/status")).IsSuccessStatusCode,"active panel continues beyond the old fixed 30 minute limit");
 Check((await Send("POST","/api/command",request,panel.Origin,csrf)).StatusCode==HttpStatusCode.Conflict,"session renewal preserves command replay history");
 clock.Advance(TimeSpan.FromMinutes(31));Check((await Send("GET","/api/status")).StatusCode==HttpStatusCode.Unauthorized,"idle panel still expires after 30 minutes");
 var expiredTicket=new Uri(panel.OpenLink()).Fragment[1..];clock.Advance(TimeSpan.FromSeconds(61));
 Check((await Send("POST","/api/session",new{ticket=expiredTicket},panel.Origin)).StatusCode==HttpStatusCode.Unauthorized,"one-use ticket still expires after 60 seconds");
 var freshTicket=new Uri(panel.OpenLink()).Fragment[1..];
 var freshBoot=await Send("POST","/api/session",new{ticket=freshTicket},panel.Origin);
 csrf=(await freshBoot.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("csrf").GetString()!;
 for(int i=0;i<16;i++){clock.Advance(TimeSpan.FromMinutes(29));Check((await Send("GET","/api/status")).IsSuccessStatusCode,"active session bounded renewal "+i);}
 clock.Advance(TimeSpan.FromMinutes(17));Check((await Send("GET","/api/status")).StatusCode==HttpStatusCode.Unauthorized,"active session expires at the absolute eight hour limit");
}

// Explicit port remains stable over reopen; an occupied port fails, never
// silently changes the bookmarked address. Use an isolated port on the host.
int fixedPort;
await using(var chosen=await WebPanel.Start(Backend,root)) fixedPort=new Uri(chosen.Origin).Port;
for(int round=0;round<2;round++) {
 await using var fixedPanel=await WebPanel.Start(Backend,root,port:fixedPort);
 Check(new Uri(fixedPanel.Origin).Port==fixedPort,"explicit WebUI port survives reopen "+round);
 bool occupied=false;
 try { await using var collision=await WebPanel.Start(Backend,root,port:fixedPort); }
 catch(IOException) { occupied=true; }
 Check(occupied,"occupied WebUI port fails without random fallback "+round);
}

WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
using(var worker=new ControlWorker()) {
 worker.StartLocal();var store=new ProfileStore();string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
 var method=typeof(ControlWorker).GetMethod("HandleUi",BindingFlags.Instance|BindingFlags.NonPublic)!;
 Task<UiControlReply> Ui(UiControlRequest request)=>(Task<UiControlReply>)method.Invoke(worker,[request,sid,CancellationToken.None])!;
 var created=await worker.Handle(new("mesh-create",Service:"https://example.com/"));Check(created.Ok,"isolated real service mesh created without network start");
 var before=(await Ui(new("status"))).Status!;
 var settings=before.Settings! with{AllowManualQualityRequests=true};
 var good=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:settings,ExpectedRevision:before.SettingsRevision)));
 Check(good.Ok&&good.Status!.Settings!.AllowManualQualityRequests,"restricted settings save persists allowed fields");
 Check(!(await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:settings with{ListenPort=45001},ExpectedRevision:before.SettingsRevision)))).Ok,"stale network settings rejected");
 Check(!(await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("create",Service:"https://example.com/",ExpectedNetwork:before.NetworkId)))).Ok,"network replacement requires explicit confirmation before I/O");
 Check(!(await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("approve",Verification:"123456",Candidate:Guid.NewGuid().ToString("N"))))).Ok,"approval without authenticated exchange rejected");
 Check(!(await Ui(new("mesh-invite"))).Ok&&!(await Ui(new("save"))).Ok,"legacy privileged methods stay inaccessible");
 Check(!(await Ui(new("retry",OperationId:Guid.NewGuid()))).Ok,"retry cannot start a stopped network or open an adapter");
 foreach(string selected in new[]{"udp-only","faketcp-only"}) {
  var current=(await Ui(new("status"))).Status!;
  var changed=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:current.Settings! with{PathSelection=selected},ExpectedRevision:current.SettingsRevision)));
  Check(changed.Ok && changed.Status!.Settings!.PathSelection==selected && changed.Status.NetworkId==before.NetworkId,"restricted UI switches fixed protocol without changing pairing: "+selected);
  var loaded=new ProfileStore().Load();loaded.RequireFixedTransport();
  Check(loaded.PathSelection==selected && !loaded.Enabled,"UI protocol choice persists while idle without starting an adapter");
 }
 var batchBefore=(await Ui(new("status"))).Status!;
 var batchSettings=batchBefore.Settings! with{ListenPort=45002};
 var rejectedBatch=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:batchSettings,ExpectedRevision:batchBefore.SettingsRevision){Patch=new(DeviceName:"Must-Not-Save",LogLevel:"invalid",ExpectedDeviceName:batchBefore.DeviceName)}));
 var batchUnchanged=(await Ui(new("status"))).Status!;
 Check(!rejectedBatch.Ok&&batchUnchanged.DeviceName==batchBefore.DeviceName&&batchUnchanged.Settings!.ListenPort==batchBefore.Settings!.ListenPort,"invalid global batch does not partially write name or network settings");
 var batch=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:batchSettings,ExpectedRevision:batchBefore.SettingsRevision){Patch=new(DeviceName:"Batch-Device",LogLevel:"warn",ExpectedDeviceName:batchBefore.DeviceName,ExpectedLogLevel:batchBefore.LogLevel)}));
 Check(batch.Ok&&batch.Status!.DeviceName=="Batch-Device"&&batch.Status.LogLevel=="warn"&&batch.Status.Settings!.ListenPort==45002,"one restricted batch saves name, logging and network settings together");
 Check(!(await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:batchSettings,ExpectedRevision:batchBefore.SettingsRevision){Patch=new(DeviceName:"Stale-Write")}))).Ok,"global batch rejects stale configuration revision");
 Check(!(await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("pair-poll"){AutoStart=true,ExpectedAutoStart=false}))).Ok,"global startup fields rejected on unrelated actions");
 var fixedStatus=(await Ui(new("status"))).Status!;
 Check(!(await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:fixedStatus.Settings! with{PathSelection="prefer-faketcp"},ExpectedRevision:fixedStatus.SettingsRevision)))).Ok,"UI API rejects removed automatic fallback even when requested directly");
 var full=(await worker.Handle(new("status"))).Profile!;var json=JsonSerializer.Serialize((await Ui(new("status"))).Status);
 foreach(var secret in new[]{full.Mesh!.OwnerPrivate,full.Mesh.SigningPrivate,full.Mesh.ExchangePrivate,full.Mesh.Pair.Secret})Check(!json.Contains(secret),"secret absent from expanded DTO");
 await worker.StopLocal();
}
Console.WriteLine(JsonSerializer.Serialize(new{scope="actual loopback HTTP + isolated Windows service, no physical link claim",checks,failures,status=failures==0?"Pass":"Fail"}));
return failures==0?0:1;

sealed class PanelClock:TimeProvider
{
 long timestamp;
 public override long TimestampFrequency=>1000;
 public override long GetTimestamp()=>Interlocked.Read(ref timestamp);
 public void Advance(TimeSpan duration)=>Interlocked.Add(ref timestamp,(long)duration.TotalMilliseconds);
}
