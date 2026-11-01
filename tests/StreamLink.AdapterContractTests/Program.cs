using System.Net;
using System.Text.Json;
using StreamLink.Core;

if(args is ["--wintun-lease-child",var leaseNetwork]){Environment.ExitCode=WintunUpgradeTests.LeaseChild(leaseNetwork);return;}
if(args is ["--wintun-upgrade",var upgradeComponents,var upgradeOutput]){WintunUpgradeTests.Run(Path.GetFullPath(upgradeComponents),Path.GetFullPath(upgradeOutput));return;}

if(args is ["--lifecycle-watchdog-hang"]) { Console.WriteLine("intentional isolated watchdog child");Console.Out.Flush();Thread.Sleep(Timeout.Infinite);return; }
if(args is ["--lifecycle-axes-contract",var axesOutput]){NativeLifecycleTests.AxesContractTest(Path.GetFullPath(axesOutput));return;}
if(args is ["--bridge-open-diagnostics",var bridge, var bridgeOutput]){BridgeOpenDiagnostics.Run(Path.GetFullPath(bridge),Path.GetFullPath(bridgeOutput));return;}
if(args is ["--native-lifecycle-pf2",var pf2Components,"--output",var pf2Output]){await NativeLifecycleTests.RunPf2(Path.GetFullPath(pf2Components),Path.GetFullPath(pf2Output));return;}
if(args is ["--native-lifecycle-pf2-child",var pf2ChildComponents,"--output",var pf2ChildOutput]){await NativeLifecycleTests.RunPf2(Path.GetFullPath(pf2ChildComponents),Path.GetFullPath(pf2ChildOutput),true);return;}
if(args is ["--lifecycle-watchdog-selftest",var watchdogOutput]) { await NativeLifecycleTests.WatchdogSelfTest(watchdogOutput);return; }
if(args is ["--native-lifecycle-v2-child",var v2Components,"--output",var v2Output,"--rounds",var v2Rounds]){Environment.ExitCode=await NativeLifecycleTests.RunV2Child(Path.GetFullPath(v2Components),Path.GetFullPath(v2Output),int.Parse(v2Rounds));return;}
if(args is ["--native-lifecycle-v2",var v2Root,"--output",var v2File,"--rounds",var v2Count]){try{await NativeLifecycleTests.RunV2(Path.GetFullPath(v2Root),Path.GetFullPath(v2File),int.Parse(v2Count));}catch(Exception ex){Console.Error.WriteLine(ex);Environment.ExitCode=1;}return;}
if(args is ["--native-lifecycle-child",var childComponents,"--output",var childOutput,"--iteration",var iterationText]) {
    Environment.ExitCode=await NativeLifecycleTests.RunChild(Path.GetFullPath(childComponents),Path.GetFullPath(childOutput),int.Parse(iterationText));return;
}
if(args is ["--native-lifecycle",var components,"--output",var output,"--rounds",var roundText]) { try{await NativeLifecycleTests.Run(Path.GetFullPath(components),Path.GetFullPath(output),int.Parse(roundText));}catch(Exception ex){Console.Error.WriteLine(ex);Environment.ExitCode=1;}return; }
int checks=0;
void Check(bool ok,string reason){if(!ok)throw new Exception(reason);checks++;}
IPAddress Ip(string text)=>IPAddress.Parse(text);
var overlay=Ip("10.217.141.0");
OverlayConflict[] Routes(params (string,int)[] entries)=>OverlayRouteConflicts.Evaluate(overlay,[],entries.Select(p=>new OverlayRoutePrefix("foreign",Ip(p.Item1),p.Item2)));
Check(Routes(("0.0.0.0",0)).Length==0,"default route alone is not a subnet conflict");
Check(Routes(("10.217.141.0",24)).Single().Severity=="Block","same prefix must block");
Check(Routes(("10.217.141.9",32)).Single().Severity=="Block","more-specific foreign route must block");
Check(Routes(("10.217.0.0",16)).Single().Severity=="Warning","parent prefix is diagnosed without claiming immediate interception");
Check(Routes(("0.0.0.0",1),("128.0.0.0",1)).Single().Reason=="VpnDefaultCoverage","VPN halves produce diagnostic warning");
Check(Routes(("10.217.142.0",24)).Length==0,"sibling subnet must not conflict");
var address=OverlayRouteConflicts.Evaluate(overlay,[new("other",Ip("10.217.141.8"),24)],[]);
Check(address.Single().Severity=="Block","existing host in overlay is blocked");
Check(OverlayRouteConflicts.Evaluate(overlay,[new("owned",Ip("10.217.141.8"),24)],[new("owned",overlay,24)],new HashSet<string>{"owned"}).Length==0,"explicit verified ownership is required for exclusion");
PacketAdapterProviders.RequireProduction(new(PacketAdapterProviders.OfficialWintun,2,1280,true,true,false));
bool rejected=false;try{PacketAdapterProviders.RequireProduction(new(PacketAdapterProviders.NativeExperimental,1,1280,true,true,true));}catch(IOException){rejected=true;}
Check(rejected,"unsigned/unpromoted driver cannot replace official default provider");
using(IPacketAdapter fake=new Fixture()){
    Check(fake.Descriptor.Experimental&&fake.Descriptor.Provider=="unidentified-fixture","memory adapter cannot impersonate production driver");
    using var canceled=new CancellationTokenSource();canceled.Cancel();bool canceledRead=false;
    try{fake.Read(new byte[1280],canceled.Token);}catch(OperationCanceledException){canceledRead=true;}
    Check(canceledRead,"common adapter read observes cancellation");
}
var actual=OverlayRouteConflicts.Inspect(Ip("203.0.113.0"));
Check(actual.All(c=>c.Severity is "Block" or "Warning"),"real Windows address and route table read succeeds without mutation");
Console.WriteLine(JsonSerializer.Serialize(new{scope="adapter contracts and subnet models + actual read-only Windows route table; no driver loaded",checks,status="Pass"}));

sealed class Fixture:IPacketAdapter{
    public int Read(byte[] buffer)=>0;public bool Write(byte[] packet)=>true;public void Dispose(){}
}
