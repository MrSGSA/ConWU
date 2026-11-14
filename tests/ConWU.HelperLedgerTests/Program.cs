using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.EndpointPoc;

if(args.Length is not (2 or 4)||args[0]!="--output"||args.Length==4&&args[2]!="--observer")throw new ArgumentException("--output path [--observer existing-WinDivert.dll]");
string output=Path.GetFullPath(args[1]);string? dll=args.Length==4?Path.GetFullPath(args[3]):null;
int checks=0;var rows=new List<object>();using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(90));
void Check(bool ok,string text){if(!ok)throw new IOException(text);checks++;Console.WriteLine("PASS "+text);}
async Task Until(Func<bool> check){using var timeout=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);timeout.CancelAfter(2500);while(!check())await Task.Delay(10,timeout.Token);}
var local=new IPEndPoint(IPAddress.Parse("192.0.2.1"),40001);var remote=new IPEndPoint(IPAddress.Parse("198.51.100.1"),3478);
var ledger=new TcpHelperLedger();var model=ledger.Register(Guid.NewGuid(),Guid.NewGuid(),TcpHelperPurpose.ServerScreening,local,remote);
byte[] syn=TcpShapeSyn.Create(local,remote,1,1);
Check(WinDivertHelperObserver.TryHeader(syn,local,remote,out bool outbound,out byte flags,out int payload)&&outbound&&flags==2&&payload==0,"header parser identifies exact IPv4 helper SYN");
model.Packet(outbound,syn.Length,flags,payload);
byte[] response=TcpShapeSyn.Create(remote,local,2,2);response[33]=0x12;
Check(WinDivertHelperObserver.TryHeader(response,local,remote,out outbound,out flags,out payload)&&!outbound&&flags==0x12,"reverse tuple is inbound even if platform labels loopback outbound");
model.Packet(outbound,response.Length,flags,payload);
var wrong=(byte[])syn.Clone();wrong[23]++;Check(!WinDivertHelperObserver.TryHeader(wrong,local,remote,out _,out _,out _),"same source port to another remote is excluded");
var fragments=(byte[])syn.Clone();fragments[6]=0x20;Check(!WinDivertHelperObserver.TryHeader(fragments,local,remote,out _,out _,out _),"fragmented input cannot claim a complete helper packet");
var malformed=(byte[])syn.Clone();malformed[32]=0x10;Check(!WinDivertHelperObserver.TryHeader(malformed,local,remote,out _,out _,out _),"invalid TCP header length is rejected");
foreach(int n in Enumerable.Range(0,65))model.Packet(true,40,0x10,0);
var overloaded=ledger.Snapshot();Check(overloaded.RecentOutboundPackets==66&&overloaded.OutboundPackets==66&&overloaded.InboundPackets==1,"observed packets are counted independently of transactions and directions");
using(var cancelled=new CancellationTokenSource(120)){
 bool wasCancelled=false;try{await ledger.Admit(cancelled.Token);}catch(OperationCanceledException){wasCancelled=true;}
 Check(wasCancelled&&ledger.Snapshot().AdmissionWaits>0,"excess observed kernel overhead defers optional transactions with cancellable waiting");
}
Check(ledger.Snapshot().Queries==0,"kernel ACK observations are never reported as STUN queries");
Check(ledger.Snapshot().PendingTransactions==0,"cancelled admission leaves no waiting transaction resource");
model.Dispose();model.Dispose();Check(ledger.Snapshot().OpenResources==0&&!ledger.Snapshot().CompleteWireAudit,"retirement is idempotent and makes no physical wire completeness claim");
await Task.Delay(1100,stop.Token);Check(ledger.Snapshot().RecentOutboundPackets==0,"expired packet buckets cannot permanently suppress queries");
for(int i=0;i<70;i++){using var h=ledger.Register(Guid.NewGuid(),Guid.NewGuid(),TcpHelperPurpose.OneShotQuery,local,remote);}
Check(ledger.Snapshot().Resources.Length==4&&ledger.Snapshot().Created==71,"retired diagnostic history is bounded and status exports only four recent resources");
var fair=new TcpHelperLedger();await fair.Admit(stop.Token);await fair.Admit(stop.Token);
var order=new List<int>();
async Task Turn(int i){await fair.Admit(stop.Token);lock(order)order.Add(i);}
await Task.WhenAll(Turn(0),Turn(1),Turn(2));
Check(order.SequenceEqual([0,1,2])&&fair.Snapshot().PendingTransactions==0,"concurrent helper transactions receive FIFO admission without leaking queue owners");
var sharedControls=new TraversalResources();var mixed=new TcpHelperLedger(null,sharedControls);
using(var mixResource=mixed.Register(Guid.NewGuid(),Guid.NewGuid(),TcpHelperPurpose.ServerScreening,local,remote)){
 for(int i=0;i<8;i++)Check(sharedControls.TrySend(40),"controlled native/UDP admission is registered once");
 for(int i=0;i<53;i++)mixResource.Packet(true,40,0x10,0);
 using var cancel=new CancellationTokenSource(120);bool cancelled=false;
 try{await mixed.Admit(cancel.Token);}catch(OperationCanceledException){cancelled=true;}
 var state=mixed.Snapshot();
 Check(cancelled&&state.RecentOutboundPackets==53&&state.RecentScheduledControlAdmissions==8&&state.PendingTransactions==0,
    "helper defers when kernel observations plus scheduled controls reach the common envelope, without relabeling admissions as wire packets");
 Check(state.ObservableResources==0&&state.UnobservableResources==1,
    "compact status distinguishes an unavailable observer from observed zero traffic");
}

for(int round=0;round<6;round++){
 var actual=new TcpHelperLedger();await using var reflector=new Reflector();
 var owner=await TcpEndpointLease.OpenAccounted(new(IPAddress.Loopback,0),reflector.Endpoint,Guid.NewGuid(),stop.Token,TcpHelperPurpose.LegacyEntry,actual,dll??Path.Combine(Path.GetTempPath(),"streamlink-helper-no-dll"));
 var attempt=owner.AcquireAttempt(owner.NetworkGeneration);var retained=attempt.RetainPath(owner.NetworkGeneration);
 try{
  var initial=actual.Snapshot();Check(initial.OpenResources==1&&initial.Resources.Single().ResourceId==owner.Id&&initial.Resources.Single().State=="Connected","actual helper registers the same exclusive resource before query");
  var first=await attempt.Observe(stop.Token);attempt.Dispose();owner.Dispose();
  var second=await retained.Observe(stop.Token);
  Check(first.Local.Equals(second.Local)&&first.Public.Equals(second.Public)&&reflector.Accepted==1&&reflector.Requests==2,"active reference keeps one socket while accounting records two real STUN exchanges");
  Check(actual.Snapshot().Queries==2&&actual.Snapshot().QueryFailures==0&&actual.Snapshot().OpenResources==1,"query ledger remains separate from packet/header observations");
  if(dll!=null){
   await Until(()=>actual.Snapshot().OutboundPackets>=3&&actual.Snapshot().InboundPackets>=3);
   var counters=actual.Snapshot();var resource=counters.Resources.Single();
   Check(resource.Observation.StartsWith("WindowsNetworkLayer:")&&resource.SynPackets>=2&&resource.OutboundBytes>=40&&resource.InboundBytes>=40,"real sniff observer sees SYN and both directions without diverting helper traffic");
   Check(resource.Local==owner.Local.ToString()&&resource.Reflector==owner.Reflector.ToString(),"observer is bound to exact retained local and remote tuple");
  }else Check(actual.Snapshot().Resources.Single().Observation.StartsWith("Unavailable:")&&actual.Snapshot().OutboundPackets==0,"missing observer reports unavailable evidence instead of zero wire traffic");
  rows.Add(new{round,scope=dll==null?"actual loopback Winsock/STUN; observer unavailable":"actual loopback Winsock/STUN and already-installed WinDivert NETWORK SNIFF; not WAN or physical NIC",snapshot=actual.Snapshot()});
 }finally{attempt.Dispose();owner.Dispose();retained.Dispose();}
 Check(owner.Closed&&actual.Snapshot().OpenResources==0,"last path owner joins observation and closes resource exactly once");
}

// Cancellation in the admission wait has not written the stream. The next
// query on the same helper must still succeed, unlike a partial query timeout.
await using(var reflector=new Reflector()){
 var actual=new TcpHelperLedger();using var owner=await TcpEndpointLease.OpenAccounted(new(IPAddress.Loopback,0),reflector.Endpoint,Guid.NewGuid(),stop.Token,TcpHelperPurpose.RetainedEndpoint,actual);
 using var reference=owner.AcquireAttempt(owner.NetworkGeneration);
 var noise=actual.Register(Guid.NewGuid(),Guid.NewGuid(),TcpHelperPurpose.ServerScreening,local,remote);
 for(int i=0;i<60;i++)noise.Packet(true,40,0x10,0);
 using(var cancel=new CancellationTokenSource(100)){bool cancelled=false;try{await reference.Observe(cancel.Token);}catch(OperationCanceledException){cancelled=true;}
 Check(cancelled&&owner.QueryUsable&&actual.Snapshot().Queries==0&&reflector.Requests==0,"cancelled admission neither sends a query nor poisons the helper stream");}
 await Task.Delay(1100,stop.Token);await reference.Observe(stop.Token);Check(owner.QueryUsable&&reflector.Requests==1,"previously deferred exact helper continues with a valid transaction");noise.Dispose();
}
if(dll!=null){
 string lateRoot=Path.Combine(Path.GetTempPath(),"streamlink-helper-late-"+Guid.NewGuid().ToString("N"));
 Directory.CreateDirectory(lateRoot);string lateDll=Path.Combine(lateRoot,"WinDivert.dll");
 try{
  var actual=new TcpHelperLedger();await using var reflector=new Reflector();
  using var owner=await TcpEndpointLease.OpenAccounted(new(IPAddress.Loopback,0),reflector.Endpoint,Guid.NewGuid(),stop.Token,TcpHelperPurpose.LegacyEntry,actual,lateDll);
  using var reference=owner.AcquireAttempt(owner.NetworkGeneration);await reference.Observe(stop.Token);
  Check(actual.Snapshot().OutboundPackets==0&&actual.Snapshot().Resources.Single().Observation.StartsWith("Unavailable:"),"helper can connect before observer component without claiming packet evidence");
  File.Copy(dll,lateDll);await Task.Delay(5100,stop.Token);await reference.Observe(stop.Token);
  await Until(()=>actual.Snapshot().OutboundPackets>0&&actual.Snapshot().InboundPackets>0);
  Check(actual.Snapshot().Resources.Single().Observation.EndsWith("StartedAfterConnect")&&reflector.Accepted==1&&reflector.Requests==2,"late observer attaches to already-owned helper and labels its incomplete start window");
 }finally{File.Delete(lateDll);Directory.Delete(lateRoot);}
}
await using(var silent=new Reflector{Silent=true}){
 var actual=new TcpHelperLedger();using var owner=await TcpEndpointLease.OpenAccounted(new(IPAddress.Loopback,0),silent.Endpoint,Guid.NewGuid(),stop.Token,TcpHelperPurpose.OneShotQuery,actual);
 using var reference=owner.AcquireAttempt(owner.NetworkGeneration);using var cancel=new CancellationTokenSource(200);bool cancelled=false;
 try{await reference.Observe(cancel.Token);}catch(OperationCanceledException){cancelled=true;}
 Check(cancelled&&!owner.QueryUsable&&actual.Snapshot().QueryFailures==1&&actual.Snapshot().Queries==1&&silent.Requests==1,"timeout after actual query marks precisely that helper unusable");
}
var failed=new TcpHelperLedger();using(var listener=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)){
 listener.Bind(new IPEndPoint(IPAddress.Loopback,0));var refused=(IPEndPoint)listener.LocalEndPoint!;bool rejected=false;
 try{using var unused=await TcpEndpointLease.OpenAccounted(new(IPAddress.Loopback,0),refused,Guid.NewGuid(),stop.Token,TcpHelperPurpose.ServerScreening,failed);}catch(SocketException){rejected=true;}
 Check(rejected&&failed.Snapshot().Created==1&&failed.Snapshot().OpenResources==0&&failed.Snapshot().Resources.Single().Closed,"failed connect retires accounting and exclusive quota without a surviving observer");
}
var legacy=new LegacyTransportLedger();var compatibility=new List<LegacyTransportLedger.Handle>();var helperIdentity=Guid.NewGuid();
try{
 for(int i=0;i<LegacyTransportLedger.CompatibilityLimit;i++)compatibility.Add(legacy.Acquire("faketcp",i==0,i==0?"192.0.2.1:11010":"","198.51.100.1:40001",helperIdentity));
 bool rejected=false;try{using var tooMany=legacy.Acquire("faketcp",false,"","198.51.100.1:40001",Guid.Empty);}catch(IOException){rejected=true;}
 Check(rejected&&legacy.Snapshot().OpenResources==32&&legacy.Snapshot().Limit==32,"eight pair networks have a bounded allowance for listeners, Active/Candidate and transient enrollment resources");
 Check(legacy.Snapshot().Resources.All(r=>r.HelperResourceId==helperIdentity)&&legacy.Snapshot().Resources.Count(r=>r.Listener.Length>0)==1,"P helper lineage and Q listener are separate; client source port is never invented");
}finally{foreach(var h in compatibility){h.Dispose();h.Dispose();}}
Check(legacy.Snapshot().OpenResources==0&&!legacy.Snapshot().CompleteWireAudit,"prepared compatibility resources retire idempotently without claiming packet totals");
var childInfo=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell","v1.0","powershell.exe")){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden};
foreach(string arg in new[]{"-NoProfile","-NonInteractive","-Command","Start-Sleep -Seconds 2"})childInfo.ArgumentList.Add(arg);
using(var child=Process.Start(childInfo)!){
 var h=legacy.Acquire("faketcp",false,"","198.51.100.1:40001",Guid.Empty);h.Started(child);h.Dispose();
 Check(legacy.Snapshot().OpenResources==1&&legacy.Snapshot().Resources.Single(r=>r.ProcessId==child.Id).State=="Retiring","retirement cannot return quota while an actual owned child is still running");
 await child.WaitForExitAsync(stop.Token);
 Check(legacy.Snapshot().OpenResources==0,"confirmed child exit releases compatibility quota on the next bounded reap");h.Dispose();
}
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{status="Pass",checks,scope="helper lifecycle/parser and real loopback I/O; optional actual WinDivert SNIFF; not whole wire/NAT/WAN",nativePeerTrafficCovered=false,rows},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"PASS {checks} helper accounting checks");
