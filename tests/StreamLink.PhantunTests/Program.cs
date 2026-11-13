using System.Net;
using System.Text.Json;
using StreamLink.Core;

if(args is ["--native",var components]){await NativeChecks.Run(Path.GetFullPath(components));return;}
if(args is ["--native",var nativeComponents,var nativeMode]){await NativeChecks.Run(Path.GetFullPath(nativeComponents),nativeMode);return;}
if(args is ["--node"]){await NativeNode.Run();return;}
if(args is ["--control-node"]){await ControlNode.Run();return;}
if(args.Length is 1 or 2&&args[0]=="--identities"){
    string mode=args.Length==2?args[1]:"phantun";if(!TransportModes.PacketCarrier(mode))throw new FormatException("test carrier required");
    var owners=Enumerable.Range(0,2).Select(_=>MeshIdentity.Create("","",mode,direct:true,pairwise:true)).ToArray();
    var guests=owners.Select(owner=>MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)))).ToArray();
    Console.WriteLine(JsonSerializer.Serialize(new{owners,guests}));return;
}
var checks=new List<string>();
void Check(bool value,string name){if(!value)throw new IOException(name);checks.Add(name);}
void Reject(Action action,string name){try{action();}catch(Exception error)when(error is FormatException or IOException){checks.Add(name);return;}throw new IOException(name+" was accepted");}
foreach(string mode in new[]{"faketcp","udp","tcp","https","phantun","mimic","tcpraw"}){
    string code=CompactDirectCode.Issue("203.0.113.19:49197",mode,"123456");
    var decoded=CompactDirectCode.Import(code.ToLowerInvariant());
    Check(code.Replace("-","").Length==16&&decoded.Mode==mode&&decoded.RoomCode=="123456"&&decoded.Endpoint=="203.0.113.19:49197","16-symbol code preserves "+mode);
}
var profile=new DeviceProfile();profile.SelectTransport("phantun-only");profile.RequireFixedTransport();
Check(profile.TransportMode=="phantun"&&!profile.AllowUdpFallback,"Phantun has fixed protocol without fallback");
Check(profile.Selection().Allows(TraversalProfile.LegacyExplicit)&&!profile.Selection().Allows(TraversalProfile.FakeTcpHttpSo)&&!profile.Selection().Allows(TraversalProfile.UdpDirect),"Phantun cannot start another traversal protocol");
Reject(()=>new PathSelection(PathPolicy.PhantunOnly,true).Validate(),"Phantun rejects UDP fallback");
Check(TransportModes.OutboundGuest("phantun")&&!TransportModes.ManagedCandidates("phantun"),"Phantun guest is outbound and never opens the FakeTCP-SO factory");
var owner=MeshIdentity.Create("","","phantun",direct:true,pairwise:true);
var guest=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));
var settings=new UiNetworkSettings(PathSelection:"phantun-only"){ConnectionSource="existing",DirectMode=true,DiscoveryMode="existing",ExistingEntries=[new(0,"https://entry.example.test/current#streamlink1")]};
var approved=ApprovedNetworkSettings.Create(owner,settings,"Phantun test");
var inherited=approved.ForGuest(guest,new UiNetworkSettings(ListenPort:49197,SourcePort:49201));
Check(inherited.PathSelection=="phantun-only"&&inherited.ListenPort==49197&&inherited.SourcePort==49201&&inherited.ExistingEntries.Single().PeerSlot==ExistingEntry.NetworkOwner,"approved settings retain local ports and bind the host subscription");
var bound=new DeviceProfile{Mesh=owner};bound.SelectTransport("phantun-only");
Reject(()=>ConnectionSettings.Apply(bound,settings with{PathSelection="faketcp-only"}),"paired Phantun cannot silently switch wire protocol");
Check(bound.TransportMode=="phantun"&&bound.PathSelection=="phantun-only","rejected protocol edit leaves settings intact");
using(var resolver=new ExistingEntryResolver()){
    var result=await resolver.Resolve([new(0,"tcp://203.0.113.19:49197")],"phantun",CancellationToken.None);
    Check(result.Single().Error.Length==0&&result.Single().Endpoints.Single()=="203.0.113.19:49197","TCP entry scheme works for Phantun");
    var mismatch=await resolver.Resolve([new(0,"udp://203.0.113.19:49197")],"phantun",CancellationToken.None);
    Check(mismatch.Single().Error.Length>0,"UDP entry cannot masquerade as Phantun");
}
foreach(string mode in new[]{"mimic","tcpraw"}){
    var fixedProfile=new DeviceProfile();fixedProfile.SelectTransport(mode+"-only");fixedProfile.RequireFixedTransport();
    Check(fixedProfile.TransportMode==mode&&TransportModes.OutboundGuest(mode)&&!TransportModes.ManagedCandidates(mode),mode+" is independent outbound-guest carrier");
    Reject(()=>new PathSelection(TransportModes.FixedPolicy(mode),true).Validate(),mode+" rejects fallback");
    var host=MeshIdentity.Create("","",mode,direct:true,pairwise:true);var client=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(host)));
    var cfg=ConnectionSettings.Normalize(settings with{PathSelection=mode+"-only",PortControlMapping=true});
    var imported=ApprovedNetworkSettings.Create(host,cfg).ForGuest(client,new UiNetworkSettings(ListenPort:49223,SourcePort:49224));
    Check(imported.PathSelection==mode+"-only"&&imported.ListenPort==49223&&!imported.PortControlMapping,mode+" imports host policy while retaining device-local mapping permission");
    var hostProfile=new DeviceProfile{Mesh=host};hostProfile.SelectTransport(mode+"-only");
    Reject(()=>ConnectionSettings.Apply(hostProfile,cfg with{PathSelection="phantun-only"}),mode+" cannot silently change a paired wire protocol");
    var mapProfile=new DeviceProfile();ConnectionSettings.Apply(mapProfile,cfg);Check(mapProfile.PortControlMapping,mode+" mapping preference is applied locally");
}
await SharedReceiverChecks.Run(Check);
Console.WriteLine(JsonSerializer.Serialize(new{status="Pass",checks=checks.Count,cases=checks}));
