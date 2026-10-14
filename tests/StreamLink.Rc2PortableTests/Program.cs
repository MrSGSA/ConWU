using System.Text.Json;
using StreamLink.Core;

int checks=0;
void Check(bool value,string reason){if(!value)throw new Exception(reason);checks++;}
void Reject(Action action,string reason){bool rejected=false;try{action();}catch(IOException){rejected=true;}Check(rejected,reason);}
UiStatusDto State(string name="before",string level="info",int version=2)=>new("rc2",name,"10.1.2.1","ready",true,true,0,0,[],level,version);
var draft=new UiSettingsDraft();draft.Observe(State());draft.EditName("my edit");
for(int n=0;n<3;n++)draft.Observe(State());
Check(draft.DeviceName=="my edit"&&draft.NameDirty,"three polls do not discard an unfocused dirty name");
draft.EditLevel("debug");draft.Observe(State());var patch=draft.CreatePatch();
Check(patch.DeviceName=="my edit"&&patch.LogLevel=="debug"&&patch.ExpectedDeviceName=="before"&&patch.ExpectedLogLevel=="info","edited fields carry their own original preconditions");
draft.Observe(State() with{TotalPeers=7});Check(!draft.Conflict,"unrelated status updates are not setting conflicts");
draft.Observe(State("admin name"));Check(draft.Conflict&&draft.DeviceName=="my edit"&&draft.LogLevel=="debug","external update does not silently destroy the draft");
Reject(()=>draft.CreatePatch(),"same-field conflict requires explicit review");
draft.Discard();Check(!draft.Dirty&&draft.DeviceName=="admin name"&&draft.LogLevel=="info","explicit discard adopts latest remote state");
draft.EditLevel("error");patch=draft.CreatePatch();Check(patch.DeviceName==null&&patch.ExpectedDeviceName==null&&patch.LogLevel=="error","unchanged fields are not resubmitted");
draft.Reset(State("admin name","error"));Check(!draft.Dirty,"successful save acknowledgement resets the draft");
var legacy=new UiSettingsDraft();legacy.Observe(State(version:1));legacy.EditName("legacy edit");
string wire=JsonSerializer.Serialize(legacy.CreatePatch());Check(!wire.Contains("Expected"),"new client omits unsupported null precondition members for v1 Disallow schemas");
var profile=new DeviceProfile{DeviceName="before",LogLevel="info",ManagedEgressMbps=17};profile.Validate();
var updated=new UiConfigPatch("after",null,"before").ApplyTo(profile);
Check(updated.DeviceName=="after"&&profile.DeviceName=="before"&&updated.ManagedEgressMbps==17,"patch copies current profile without mutating caller or unrelated settings");
Reject(()=>new UiConfigPatch("after",null,"wrong").ApplyTo(profile),"service side detects stale edited-field base");
Check(UiAuthorizationPolicy.SelectForInstall("A",null)=="A","administrator upgrade preserves A instead of selecting installer B");
Check(UiAuthorizationPolicy.SelectForInstall("A","A")=="A","explicit same-user reinstall is allowed");
Reject(()=>UiAuthorizationPolicy.SelectForInstall("A","B"),"installation cannot silently change an existing authorization");
Reject(()=>UiAuthorizationPolicy.SelectForInstall(null,null),"first installation requires explicit user selection");
Check(UiAuthorizationPolicy.SelectForInstall(null,"A")=="A","first install uses the explicitly selected and externally resolved SID");
Console.WriteLine(JsonSerializer.Serialize(new{status="Pass",checks,scope="Actual portable draft/patch/authorization policy helpers; no UI desktop, UAC, service or driver"}));
