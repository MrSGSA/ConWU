using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using StreamLink.Core;
using System.Diagnostics;

if(args.Length>0 && args[0]=="--child") { await Task.Delay(60000); return; }
if(args.Length>0 && args[0]=="--child-output") {
    for(int i=0;i<64;i++){Console.Out.WriteLine("stdout "+i+" CHILD_TEST_SECRET");Console.Error.WriteLine("stderr "+i+" CHILD_TEST_SECRET");}
    Console.Out.WriteLine("stdout final");Console.Error.WriteLine("stderr final");return;
}

int passed=0;
void Check(bool yes,string message) { if(!yes) throw new Exception(message); passed++; }
void Reject(Action action,string message) { try {action();} catch(Exception ex) when(ex is IOException or FormatException or ArgumentException) {passed++; return;} throw new Exception(message); }
Check(ReleaseVersion.TryParse("1.0.0-rc.10",out var rc10)&&ReleaseVersion.TryParse("1.0.0-rc.2",out var rc2)&&rc10.CompareTo(rc2)>0,"numeric prerelease ordering failed");
Check(ReleaseVersion.TryParse("1.0.0",out var stable)&&stable.CompareTo(rc10)>0,"stable does not outrank RC");
Check(!ReleaseVersion.TryParse("1.0.0-rc.01",out _)&&!ReleaseVersion.TryParse("01.0.0",out _),"noncanonical semantic version accepted");
var selectedRelease=ReleaseVersion.Latest(new[]{("v1.0.0-rc1",false,false),("v0.5.6-preview",false,true),("v0.5.5",false,false),("v9.0.0",true,false)},false);
Check(selectedRelease?.ToString()=="0.5.5","stable channel selected prerelease or draft");
Check(ReleaseVersion.Latest(new[]{("v1.0.0-rc1",false,true),("v0.5.5",false,false)},true)?.PreRelease=="rc1","preview channel cannot select RC");
Check(ReleaseVersion.TryParse("1.0.0+abc",out var buildA)&&ReleaseVersion.TryParse("1.0.0+def",out var buildB)&&buildA.CompareTo(buildB)==0,"build metadata changed release precedence");
byte[] req=Stun.Request(); byte[] response=new byte[36];
req.CopyTo(response,0); response[0]=1; response[1]=1; response[3]=16;
// Unknown 1-byte attribute plus three padding bytes, followed by XOR-MAPPED.
response[20]=0x80; response[21]=0x22; response[23]=1; response[24]=42;
Array.Resize(ref response,40); response[3]=20;
response[28]=0; response[29]=0x20; response[31]=8; response[33]=1;
BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(34),(ushort)(45678 ^ 0x2112));
BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(36),0xcb007109 ^ 0x2112a442u);
Check(Stun.Parse(response,req).ToString()=="203.0.113.9:45678","STUN padding or XOR decode");
var wrong=(byte[])response.Clone(); wrong[8]^=1; Reject(()=>Stun.Parse(wrong,req),"STUN transaction mismatch accepted");
Reject(()=>Stun.Parse(response[..^1],req),"STUN truncation accepted");
wrong=(byte[])response.Clone(); wrong[31]=12; Reject(()=>Stun.Parse(wrong,req),"STUN malformed attribute accepted");
var invite=Invitation.Create("203.0.113.9:45678","faketcp","test.ustc.edu.cn");
Check(Invitation.Decode(invite.Encode())==invite,"Invite round trip");
Check(invite.RawKey.Length==64 && invite.RawKey!=invite.Secret,"Domain-separated key");
Reject(()=>(invite with {HttpHost="x\r\n--disable-anti-replay"}).Validate(),"Invite config injection accepted");
Reject(()=>(invite with {HttpHost=null!}).Validate(),"Null HTTP Host accepted");
Reject(()=>(invite with {Expires=1}).Validate(),"Expired invitation accepted");
Reject(()=>(invite with {Endpoint="evil.example:443"}).Validate(),"Unexpected hostname accepted");
Reject(()=>Invitation.Decode("SL1."+new string('A',5000)),"Oversized invitation accepted");

// Real fragmented TCP response to exercise ReadExactlyAsync and stream framing.
var listener=new TcpListener(IPAddress.Loopback,0); listener.Start();
int port=((IPEndPoint)listener.LocalEndpoint).Port;
var server=Task.Run(async()=>{using var client=await listener.AcceptTcpClientAsync(); var stream=client.GetStream(); byte[] input=new byte[20]; await stream.ReadExactlyAsync(input); input.AsSpan(8,12).CopyTo(response.AsSpan(8)); for(int i=0;i<response.Length;i+=3) {await stream.WriteAsync(response.AsMemory(i,Math.Min(3,response.Length-i))); await Task.Delay(1);} });
var result=await Stun.Query(true,$"127.0.0.1:{port}",0,CancellationToken.None,IPAddress.Loopback); await server; listener.Stop();
Check(result.Public.ToString()=="203.0.113.9:45678","Fragmented TCP STUN response");

// The quality helper must ignore an unauthorized sender before a valid test.
using var cancel=new CancellationTokenSource();
string key=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
// Isolated logical machines use separate pools; production uses Shared. Consent
// is explicit in this existing socket fixture, never enabled by membership.
QualityDiagnosticPolicy Allowed()=>new(()=>true,new PathDiagnosticResources());
var serving=Quality.Serve("127.0.0.1","127.0.0.1",key,cancel.Token,Allowed());
using(var unauthorized=new UdpClient(AddressFamily.InterNetwork)) {
    unauthorized.Connect(IPAddress.Loopback,Quality.Port);
    await unauthorized.SendAsync(Encoding.UTF8.GetBytes("{\"Op\":\"start\",\"Id\":1,\"Mbps\":50,\"Seconds\":20,\"Count\":0,\"Mac\":null}"));
    using var timeout=new CancellationTokenSource(250);
    try {await unauthorized.ReceiveAsync(timeout.Token);throw new Exception("Unauthorized quality request accepted");} catch(OperationCanceledException) {passed++;}
}
var measured=await Quality.Measure("127.0.0.1",key,5,CancellationToken.None,2,policy:Allowed());
Check(measured.LossPercent==0 && measured.ReceivedMbps>4.7,"Quality loopback measurement");
cancel.Cancel();try{await serving;}catch(OperationCanceledException){}
// Both peers may request traffic, independently of who created the network.
using(var bidirectional=new CancellationTokenSource()) {
    var left=Quality.Serve("127.0.0.1","127.0.0.2",key,bidirectional.Token,Allowed());
    var right=Quality.Serve("127.0.0.2","127.0.0.1",key,bidirectional.Token,Allowed());
    try {
        var toLeft=await Quality.Measure("127.0.0.2",key,2,CancellationToken.None,1,"127.0.0.1",Allowed());
        var toRight=await Quality.Measure("127.0.0.1",key,2,CancellationToken.None,1,"127.0.0.2",Allowed());
        Check(toLeft.LossPercent==0 && toLeft.ReceivedMbps>1.8,"Peer A cannot measure peer B");
        Check(toRight.LossPercent==0 && toRight.ReceivedMbps>1.8,"Peer B cannot measure peer A");
    } finally {bidirectional.Cancel();try{await Task.WhenAll(left,right);}catch(OperationCanceledException){}}
}
Console.WriteLine($"PASS {passed} checks: STUN framing, invitation validation, authenticated quality test.");
if(OperatingSystem.IsWindows())
{
    string directory=Path.Combine(Path.GetTempPath(),"streamlink-job-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
    int pid;
    using(var job=new ChildJob()) {
        var p=job.Start(Environment.ProcessPath!,["--child"],Path.Combine(directory,"child.log")); pid=p.Id;
        Check(!p.HasExited,"Job child failed to start");
    }
    bool exited;
    try {using var p=Process.GetProcessById(pid);exited=p.HasExited;}catch(ArgumentException){exited=true;}
    Check(exited,"Job did not terminate owned process");
    using(var exclusive=File.Open(Path.Combine(directory,"child.log"),FileMode.Open,FileAccess.ReadWrite,FileShare.None))
        Check(exclusive.CanWrite,"Owned-process shutdown kept the log locked");
    File.Delete(Path.Combine(directory,"child.log"));Directory.Delete(directory);
    Console.WriteLine("PASS owned-process shutdown");
    for(int round=0;round<8;round++) {
        string outputLog=Path.Combine(Path.GetTempPath(),"streamlink-child-output-"+Guid.NewGuid().ToString("N")+".log");
        var outputJob=new ChildJob();
        try {
            var outputChild=outputJob.Start(Environment.ProcessPath!,["--child-output"],outputLog,secrets:["CHILD_TEST_SECRET"]);
            Check(outputChild.WaitForExit(10000),"Output child did not exit within its deadline");
            outputJob.Dispose();outputJob.Dispose();
            using(var exclusive=File.Open(outputLog,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
                Check(exclusive.CanWrite,"ChildJob.Dispose returned before releasing the output file");
            string lines=File.ReadAllText(outputLog);
            Check(lines.Contains("stdout final")&&lines.Contains("stderr final")&&lines.Split('\n').Length==131,
                "ChildJob shutdown lost buffered stdout/stderr tail lines");
            Check(!lines.Contains("CHILD_TEST_SECRET")&&lines.Contains("[redacted]"),"Drained child output bypassed credential redaction");
            try{outputJob.Start(Environment.ProcessPath!,["--child"],null);throw new Exception("Disposed ChildJob accepted another process");}
            catch(ObjectDisposedException){passed++;}
        } finally {outputJob.Dispose();File.Delete(outputLog);}
    }
    Console.WriteLine("PASS bounded output drain, immediate log release and repeated shutdown");
    int[] LiveChildren() {
        var live=new List<int>();
        foreach(var candidate in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(Environment.ProcessPath!))) {
            using(candidate)try{if(!candidate.HasExited)live.Add(candidate.Id);}catch(InvalidOperationException){}
        }
        return live.ToArray();
    }
    for(int round=0;round<4;round++) {
        var beforeChildren=LiveChildren();
        string concurrentLog=Path.Combine(Path.GetTempPath(),"streamlink-child-race-"+Guid.NewGuid().ToString("N")+".log");
        using var entered=new ManualResetEventSlim();using var resume=new ManualResetEventSlim();using var closing=new CountdownEvent(2);
        var concurrentJob=new ChildJob();
        var verifyLog=new object();Task closer=Task.CompletedTask,secondCloser=Task.CompletedTask;
        IEnumerable<string> DeferredArguments(){entered.Set();if(!resume.Wait(10000))throw new TimeoutException("Child startup barrier timed out");yield return "--child";}
        Task starter=Task.Run(()=>concurrentJob.Start(Environment.ProcessPath!,DeferredArguments(),concurrentLog));
        try {
            Check(entered.Wait(10000),"Concurrent child did not enter startup");
            void CloseAndCheck(){closing.Signal();concurrentJob.Dispose();lock(verifyLog){using var exclusive=File.Open(concurrentLog,FileMode.Open,FileAccess.ReadWrite,FileShare.None);Check(exclusive.CanWrite,"Concurrent Dispose returned with the child log still open");}}
            closer=Task.Run(CloseAndCheck);secondCloser=Task.Run(CloseAndCheck);
            Check(closing.Wait(10000),"Concurrent child shutdown did not start");resume.Set();
            await Task.WhenAll(starter,closer,secondCloser).WaitAsync(TimeSpan.FromSeconds(15));
            Check(!LiveChildren().Except(beforeChildren).Any(),"Start racing with Dispose left an unowned child process");
            using(var exclusive=File.Open(concurrentLog,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
                Check(exclusive.CanWrite,"Start racing with Dispose left its log open");
        } finally {resume.Set();try{await Task.WhenAll(starter,closer,secondCloser);}finally{concurrentJob.Dispose();File.Delete(concurrentLog);}}
    }
    string failedLog=Path.Combine(Path.GetTempPath(),"streamlink-child-failed-"+Guid.NewGuid().ToString("N")+".log");
    try {
        using var failedJob=new ChildJob();
        try{failedJob.Start(Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N")+".exe"),[],failedLog);throw new Exception("Missing child executable accepted");}
        catch(System.ComponentModel.Win32Exception){passed++;}
        using(var exclusive=File.Open(failedLog,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
            Check(exclusive.CanWrite,"Failed process startup kept its log locked");
    } finally {File.Delete(failedLog);}
    Console.WriteLine("PASS concurrent startup/shutdown and failed-start log cleanup");
    if(WindowsHost.IsAdmin)
    {
        string folder=Path.Combine(Recovery.Root,Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
        string rule="StreamLink-"+Guid.NewGuid().ToString("N");
        try {
            WindowsHost.AddFirewall(rule,"10.129.129.254","10.129.129.253");
            Recovery.Record(folder,rule); File.WriteAllText(Path.Combine(folder,"transport.conf"),"test fixture, no secret");
            Recovery.Recover(_=>{});
            Check(File.Exists(Path.Combine(folder,"transport.conf")),"Recovery touched live owner");
            File.WriteAllText(Path.Combine(folder,"owner.json"),JsonSerializer.Serialize(new {Pid=int.MaxValue-100,StartTicks=0L,Rule=rule}));
            Recovery.Recover(_=>{});
            Check(!File.Exists(Path.Combine(folder,"transport.conf")) && !File.Exists(Path.Combine(folder,"owner.json")),"Stale recovery failed");
            Console.WriteLine("PASS stale-session recovery and live-owner protection");
        } finally {
            WindowsHost.RemoveFirewall(rule);
            foreach(string file in new[]{"owner.json","transport.conf","owned-rule.txt"}) File.Delete(Path.Combine(folder,file));
            Directory.Delete(folder);
        }
    }
}
Console.WriteLine($"TOTAL PASS {passed}");

var pair = Pairing.Create("https://localhost:42860/", "");
Check(Pairing.Import(pair.Invite()) == pair, "Persistent pair invitation roundtrip");
Reject(() => Pairing.Create("http://example.com/", ""), "Insecure discovery accepted");
var one = new NodeAnnouncement(Guid.NewGuid().ToString("N"), 1, 1, DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(), "203.0.113.1:1234", "auto", 0, 0, false);
var two = one with { Device = Guid.NewGuid().ToString("N"), Slot = 2, Endpoint = "203.0.113.2:1234" };
var envelope = pair.Seal(one);
Check(pair.Open(1,envelope)==one,"Encrypted announcement roundtrip");
try { pair.Open(2,envelope); throw new Exception("Cross-slot replay accepted"); } catch(CryptographicException) { passed++; }
var altered=Convert.FromBase64String(envelope.Data); altered[^1]^=1;
try { pair.Open(1,envelope with {Data=Convert.ToBase64String(altered)}); throw new Exception("Tampered metadata accepted"); } catch(CryptographicException) { passed++; }
Reject(()=>pair.Open(1,pair.Seal(one with {Expires=1})),"Expired metadata accepted");
Check(EntryElection.Choose(one,two)==1,"Election tie not deterministic");
Check(EntryElection.Choose(one with {Endpoint=""},two)==2,"NAT-limited creator must use peer entry");
Check(EntryElection.Choose(one,two with {Preference="local"})==2,"Local-entry preference ignored");
Check(EntryElection.Choose(one with {LastEntry=2},two)==2,"Last successful direction ignored");
Check(EntryElection.Choose(one with {LastEntry=2,Preference="local"},two with {LastEntry=2})==1,"Explicit preference must override old history when both entries are candidates");
Check(EntryElection.Choose(one,two,1)==2,"Failed entry not excluded");
Reject(()=>DeviceProfile.ValidateServers(["x:3478\r\n--injected"]),"STUN injection accepted");
Reject(()=>new DeviceProfile {SourcePort=42680,ListenPort=42680}.Validate(),"Overlapping mapping ports accepted");
using(var packet=new MemoryStream()) {
    await ServiceProtocol.Write(packet,new ControlRequest("status"),CancellationToken.None); packet.Position=0;
    Check((await ServiceProtocol.Read<ControlRequest>(packet,CancellationToken.None)).Command=="status","Control framing");
}
if(args.Length==2 && args[0]=="--discovery") {
    using var defaults=JsonDocument.Parse(File.ReadAllText(args[1]));
    var remotePair=Pairing.Create(defaults.RootElement.GetProperty("Service").GetString()!,defaults.RootElement.GetProperty("CertificatePin").GetString()!);
    using var remote=new DiscoveryClient(remotePair); using var timeout=new CancellationTokenSource(30000);
    var node=one with {Revision=DateTime.UtcNow.Ticks}; await remote.Publish(node,timeout.Token);
    Check(await remote.Read(1,timeout.Token)==node,"Public discovery exchange");
    using var unauthorized=new DiscoveryClient(remotePair with {Secret=pair.Secret});
    try {await unauthorized.Read(1,timeout.Token);throw new Exception("Unauthorized discovery read accepted");}catch(HttpRequestException ex) when(ex.StatusCode==HttpStatusCode.Unauthorized){passed++;}
    try {await remote.Publish(node with {Device=two.Device,Revision=node.Revision+1},timeout.Token);throw new Exception("Slot takeover accepted");}catch(HttpRequestException ex) when(ex.StatusCode==HttpStatusCode.Conflict){passed++;}
    try {await remote.Publish(node,timeout.Token);throw new Exception("Old revision accepted");}catch(HttpRequestException ex) when(ex.StatusCode==HttpStatusCode.Conflict){passed++;}
    using var wrongPin=new DiscoveryClient(remotePair with {CertificatePin=new string('0',64)});
    try {await wrongPin.Read(1,timeout.Token);throw new Exception("Bad certificate accepted");}catch(HttpRequestException){passed++;}
}
Console.WriteLine($"TOTAL PASS {passed}: pairing, election, IPC and optional live discovery.");
if(args.Length==1 && args[0]=="--service") {
    for(int i=0;i<10;i++) Check((await ServiceProtocol.Call(new("status"))).Ok,"Service response framing/identity failed");
    using(var pipe=new System.IO.Pipes.NamedPipeClientStream(".",ServiceProtocol.PipeName,System.IO.Pipes.PipeDirection.InOut,System.IO.Pipes.PipeOptions.Asynchronous)) {
        using var timeout=new CancellationTokenSource(5000); await pipe.ConnectAsync(timeout.Token);
        byte[] header=new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(header,1_000_000); await pipe.WriteAsync(header,timeout.Token);
        byte[] data=new byte[1]; int read=await pipe.ReadAtLeastAsync(data,1,false,timeout.Token); Check(read==0,"Oversized control request not rejected");
    }
    Check((await ServiceProtocol.Call(new("status"))).Ok,"Service did not recover after malformed control request");
    Console.WriteLine($"TOTAL PASS {passed}: live SCM service identity, response acknowledgement and malformed request recovery.");
}
