using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;
using StreamLink.ResearchAdapters;

if(args.Length!=1)throw new ArgumentException("Fresh result JSON path required");
if(File.Exists(args[0]))throw new IOException("Do not overwrite earlier evidence");
int checks=0;
void Check(bool ok,string message){if(!ok)throw new Exception(message);checks++;Console.WriteLine("PASS "+message);}
void Reject(Action action,string message){try{action();}catch(Exception e)when(e is IOException or JsonException or FormatException){Check(true,message);return;}throw new Exception(message);}
Check(PersonalFeature.Enabled,"test binary is the actual compile-time personal edition");
Check(WindowsInstance.Name=="StreamLink-PersonalFeature"&&ServiceProtocol.PipeName!= "StreamLink-Control-v2"&&UiControlProtocol.PipeName!="StreamLink-UI-v1","service and both pipe identities isolate the stable instance");
Check(ProfileStore.Root==PersonalFeature.DataRoot&&new DeviceProfile().SourcePort!=42691,"default profile and raw source endpoint isolate 0.3.2");
var p=new DeviceProfile {AllowUdpFallback=false};p.CapabilityIntents[nameof(DeviceProfile.TcpPeerReflexive)]=false;
var enhanced=PersonalFeature.EnhancedPreset(p);
Check(enhanced.TraversalMode=="tcp-udp"&&enhanced.AllowUdpFallback&&!enhanced.TcpPeerReflexive&&!p.AllowUdpFallback,"enhancement preserves explicit disable without mutating input");
Check(!enhanced.UdpExploration&&!enhanced.TcpPortPrediction&&!enhanced.PathDiagnostics,"preset never grants high-cost or load permissions");
var selected=ProfileChanges.Copy(p);selected.AdapterBackend=PacketAdapterBackend.StreamLinkTun;selected.Validate();
Check(ProfileChanges.Impact(p,selected)==ProfileChangeImpact.RestartNetwork,"typed backend changes participate in resource lifecycle");
var roundTrip=JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(selected))!;
Check(roundTrip.AdapterBackend==PacketAdapterBackend.StreamLinkTun,"typed backend survives persistence");
Reject(()=>JsonSerializer.Deserialize<DeviceProfile>("{\"AdapterBackend\":2}"),"numeric provider bypass rejected");
Reject(()=>JsonSerializer.Deserialize<DeviceProfile>("{\"AdapterBackend\":\"arbitrary-dll\"}"),"arbitrary provider path rejected");
Reject(()=>PacketAdapterProviders.RequireProduction(new(PacketAdapterProviders.NativeExperimental,2,1280,true,true,true)),"standard production admission remains unchanged");
var identity=new TunPackageIdentity(1,new string('a',40),"win-x64",2,1,1280,@"ROOT\StreamLinkTun","StreamLinkTun",
    new[]{"StreamLinkTun.sys","StreamLinkTun.inf","StreamLinkTun.cat","streamlink-tun-research.dll"}.Select(n=>new TunPackageMember(n,new string('b',64))).ToArray());
PersonalTunAdmission.ValidateIdentity(identity);checks++;
Reject(()=>PersonalTunAdmission.ValidateIdentity(identity with{SourceCommit=null!}),"null commit fails closed");
Reject(()=>PersonalTunAdmission.ValidateIdentity(identity with{Files=[null!,null!,null!,null!]}),"null package members fail closed");
Reject(()=>PersonalTunAdmission.ValidateIdentity(identity with{UserAbi=2}),"descriptor ABI2 does not substitute for user ABI1");
var now=DateTimeOffset.UtcNow;var approval=new TunTargetApproval(1,"machine",new string('c',64),@"ROOT\STREAMLINKTUN\0000","personal-target-after-kernel-gate",now.AddDays(1),new string('d',64));
PersonalTunAdmission.ValidateApproval(approval,"machine",approval.PackageHash,now);checks++;
Reject(()=>PersonalTunAdmission.ValidateApproval(approval,"other",approval.PackageHash,now),"approval cannot move to another host");
Reject(()=>PersonalTunAdmission.ValidateApproval(approval with{DeviceInstanceId=null!},"machine",approval.PackageHash,now),"missing actual device identity rejected");
Reject(()=>PersonalTunAdmission.ValidateApproval(approval with{ExpiresUtc=now.AddDays(91)},"machine",approval.PackageHash,now),"unbounded approval expiry rejected");
Reject(()=>PersonalTunAdmission.Inspect(AppContext.BaseDirectory,Path.GetTempPath(),default).GetAwaiter().GetResult(),"user-writable research DLL directory rejected before loading");
var state=new UiStatusDto("personal","device","10.1.1.1","Stopped",true,false,0,0,[],"info") {Adapter=new(PacketAdapterProviders.NativeExperimental,null,"Blocked","unsigned"),PersonalFeatureEdition=true};
string dto=JsonSerializer.Serialize(state);
Check(!dto.Contains("OwnerKey")&&!dto.Contains("PrivateKey")&&!dto.Contains("MachineGuid"),"runtime UI status exposes no network secrets or target identity secret");
WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
using(var worker=new ControlWorker()){
    worker.StartLocal();var before=await worker.Handle(new("status"));
    var changed=ProfileChanges.Copy(before.Profile!);changed.AdapterBackend=PacketAdapterBackend.StreamLinkTun;
    var failed=await worker.Handle(new("save",changed));
    Check(!failed.Ok&&failed.Profile!.AdapterBackend==PacketAdapterBackend.OfficialWintun,"failed self-TUN admission preserves stored backend before network teardown");
    var preset=await worker.Handle(new("personal-preset"));
    Check(preset.Ok&&preset.Profile!.TcpPeerReflexive&&preset.Profile.TraversalMode=="tcp-udp","real control command saves effective enhanced preset");
    var ready=await worker.Handle(new("personal-check"));Check(!ready.Ok&&ready.Error.Contains("先创建或加入"),"unpaired configuration cannot skip coordinator checks and claim prepared");
    await worker.StopLocal();
}
Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(args[0]))!);
File.WriteAllText(args[0],JsonSerializer.Serialize(new{status="Pass",checks,evidenceLevel="UserModeRealIO",scope="typed profile/control/persistence/admission refusal on actual Windows; no kernel installation, TUN I/O or new public NAT coverage"},new JsonSerializerOptions{WriteIndented=true}));
