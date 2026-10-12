using System.Text.Json;
using StreamLink.Core;

if(args.Length!=3)throw new ArgumentException("url certificate-pin output-json");
if(!Uri.TryCreate(args[0],UriKind.Absolute,out var address)||address.Scheme!="https"||!System.Net.IPAddress.TryParse(address.Host,out var ip)||!System.Net.IPAddress.IsLoopback(ip))throw new ArgumentException("Explicit loopback HTTPS candidate endpoint required");
using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(90));var token=deadline.Token;
int checks=0;
void Check(bool yes,string what){if(!yes)throw new IOException(what);checks++;Console.WriteLine("PASS "+what);}
var a=MeshIdentity.Create(args[0],args[1],"faketcp");
var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;
using var ca=new MeshDiscoveryClient(a);using var cb=new MeshDiscoveryClient(b);
await ca.SaveDirectory(a.Directory!,token);
var capsA=new MeshTraversalCapabilities(1,1,ca.BootId,[TraversalProfile.FakeTcpHttpSo],
    StandbyPaths:1,PathDiagnostics:1,DiagnosticMbps:50,AutoQuality:1);
var capsB=capsA with{BootId=cb.BootId};
MeshAnnouncement Node(MeshProfile p,MeshTraversalCapabilities caps,int port)=>new(p.Self.Slot,p.Self.Device,1,
    DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(),"192.0.2.1:"+port,"isolated-coordinator-test",caps);
var na=Node(a,capsA,40001);var nb=Node(b,capsB,40002);
await ca.Publish(na,token);await cb.Publish(nb,token);
var sa=await ca.WaitForChanges(token);var sb=await cb.WaitForChanges(token);
Check(sa!=null&&sb!=null,"real Linux executable exposes authenticated watch over pinned TLS");
Check(ca.SupportsAutoQuality&&cb.SupportsAutoQuality&&ca.SupportsPathDiagnostics&&cb.SupportsStandbyPaths,
    "actual server independently declares diagnostic/standby/automatic quality permission");
var theirs=sa!.Nodes.Single(n=>n.Slot==b.Self.Slot);
var opened=MeshMetadata.Open(a,b.Self,theirs);
Check(opened.Slot==nb.Slot&&opened.Device==nb.Device&&opened.Endpoint==nb.Endpoint&&opened.Traversal?.BootId==capsB.BootId&&opened.Traversal.AutoQuality==1,
    "signed encrypted endpoint announcement survives actual Linux persistence/API");
long seq=0,utc=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
var candidate=new MeshTraversalCandidate(Guid.NewGuid(),1,"192.0.2.1:41001",null,utc,utc+120,CandidatePurpose.SimultaneousOpen,Standby:true);
await using var offer=MeshTraversalAttempt.Offer(a,b.Self,capsA,capsB,TraversalProfile.FakeTcpHttpSo,candidate,1,()=>++seq,
    coordinatorStandby:ca.SupportsStandbyPaths,coordinatorDiagnostics:ca.SupportsPathDiagnostics,coordinatorAutoQuality:ca.SupportsAutoQuality);
await ca.PublishTraversal([offer.Outbound!],token);
var response=await cb.WaitForChanges(token);
Check(response?.Traversal?.Any(m=>m.AttemptId==offer.AttemptId&&m.Stage==MeshTraversalStage.Offer)==true,
    "signed standby offer reaches the authorized peer through real server");
await using var oldPeer=MeshTraversalAttempt.Offer(a,b.Self,capsA,capsB with{AutoQuality=0},TraversalProfile.FakeTcpHttpSo,
    candidate with{Id=Guid.NewGuid()},2,()=>++seq,coordinatorStandby:true,coordinatorDiagnostics:true,coordinatorAutoQuality:true);
Check(!oldPeer.AutoQualityNegotiated,"new server does not turn an old peer diagnostic capability into automatic selection permission");
var third=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));third.Directory=a.Directory;b.Directory=a.Directory;
await ca.SaveDirectory(a.Directory!,token);
var directory=await cb.Read(token);
Check(directory?.Directory.Members.Length==3,"actual server accepts owner-signed membership expansion without traffic forwarding");
var wrong=new HttpRequestMessage(HttpMethod.Get,args[0]+"v3/mesh/"+a.Pair.Network);
wrong.Headers.Authorization=new("Bearer",new string('0',64));
// Use the same public test certificate pin instead of changing global trust.
using var h=new HttpClientHandler{ServerCertificateCustomValidationCallback=(_,cert,_,_)=>cert!=null&&
    Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cert.RawData))==args[1]};
using var bad=new HttpClient(h);using var rejected=await bad.SendAsync(wrong,token);
Check(rejected.StatusCode==System.Net.HttpStatusCode.Unauthorized,"known network still rejects a different authorization token");
await File.WriteAllTextAsync(args[2],JsonSerializer.Serialize(new{status="Pass",checks,clientCore=typeof(MeshDiscoveryClient).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false).Cast<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion,
    scope="explicit loopback candidate HTTPS/control API only; no business data, public NAT, Windows driver or production switch",
    relay=false,oldProductionChanged=false},new JsonSerializerOptions{WriteIndented=true}),token);
