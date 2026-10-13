using System.Net;
using System.Text.Json;
using StreamLink.Core;

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
