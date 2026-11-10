using System.Net;
using System.Net.WebSockets;
using System.Text.Json;
using ConWU.HttpsPoc;

var json=new JsonSerializerOptions{WriteIndented=true};
string Option(string key,string fallback="")=>Array.IndexOf(args,key) is >=0 and var index&&index+1<args.Length?args[index+1]:fallback;
async Task Write(string path,object value){Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);await File.WriteAllTextAsync(path,JsonSerializer.Serialize(value,json));}
string ReadToken(){string text=File.ReadAllText(Option("--token-file")).Trim();if(!Convert.TryFromBase64String(text,new byte[32],out int used)||used!=32)throw new ArgumentException("Token file must contain one random 32-byte Base64 token");return text;}
try{
if(args.Length==0){Console.WriteLine("self-test --output result.json [--seconds 4] [--rates 50,100,150]\nserver --listen 127.0.0.1:0 --token-file token.private.json --ready ready.json --output server.json [--seconds 180]\nbench --url https://IP:port/conwu/stream --pin SHA256 --token-file token.private.json --mbps 50 --seconds 10 --output result.json");return;}
using var stop=new CancellationTokenSource();Console.CancelKeyPress+=(_,e)=>{e.Cancel=true;stop.Cancel();};
if(args[0]=="server"){
    var endpoint=IPEndPoint.Parse(Option("--listen","127.0.0.1:0"));string token=ReadToken();
    int seconds=int.Parse(Option("--seconds","180"));if(seconds is <1 or >600)throw new ArgumentOutOfRangeException("--seconds");
    await using var server=await ProbeServer.Start(endpoint,token,stop.Token);
    var ready=new{url=server.Url+ProbeProtocol.Path,pin=server.Pin,expiresAt=DateTimeOffset.UtcNow.AddSeconds(seconds),scope="Standalone synthetic HTTPS probe; production ConWU is untouched"};
    await Write(Option("--ready"),ready);Console.WriteLine(JsonSerializer.Serialize(ready));
    try{await Task.Delay(TimeSpan.FromSeconds(seconds),stop.Token);}catch(OperationCanceledException){}
    await Write(Option("--output"),server.Statistics);return;
}
if(args[0]=="bench"){
    using var deadline=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);deadline.CancelAfter(TimeSpan.FromSeconds(100));
    await using var client=await ProbeClient.Connect(Option("--url"),Option("--pin"),ReadToken(),deadline.Token);
    var result=await client.Benchmark(int.Parse(Option("--mbps","50")),int.Parse(Option("--seconds","10")),int.Parse(Option("--payload","1280")),deadline.Token);
    await Write(Option("--output"),result);Console.WriteLine(JsonSerializer.Serialize(result));return;
}
if(args[0]!="self-test")throw new ArgumentException("Unknown probe mode");
var checks=new List<string>();var runs=new List<object>();var missedRates=new List<int>();
void Check(bool valid,string text){if(!valid)throw new Exception(text);checks.Add(text);Console.WriteLine("PASS "+text);}
using var limit=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);limit.CancelAfter(TimeSpan.FromMinutes(3));
string shared=ProbeProtocol.Token();
await using(var server=await ProbeServer.Start(new(IPAddress.Loopback,0),shared,limit.Token)){
    long accepted=server.Accepted;bool rejected=false;
    try{using var wrong=await ProbeClient.Socket(server.Url,new string('0',64),shared,limit.Token);}catch(WebSocketException){rejected=true;}
    Check(rejected&&server.Accepted==accepted,"an untrusted certificate pin fails before any authenticated upgrade");
    rejected=false;try{using var wrong=await ProbeClient.Socket(server.Url,server.Pin,ProbeProtocol.Token(),limit.Token);}catch(WebSocketException){rejected=true;}
    Check(rejected&&server.Accepted==accepted,"a wrong access token cannot open the data endpoint");
    foreach(int size in new[]{64,1280})foreach(bool fragmented in new[]{false,true}){
        await using var client=await ProbeClient.Connect(server.Url,server.Pin,shared,limit.Token);
        await client.CheckPacket(size,fragmented,limit.Token);Check(true,$"authenticated {size}-byte payload survives {(fragmented?"fragmented":"single")} WebSocket framing");
    }
    using(var socket=await ProbeClient.Socket(server.Url,server.Pin,shared,limit.Token)){
        await socket.SendAsync(new byte[1400],WebSocketMessageType.Binary,true,limit.Token);
        var result=await socket.ReceiveAsync(new byte[2048],limit.Token);
        Check(result.MessageType==WebSocketMessageType.Close&&socket.CloseStatus==WebSocketCloseStatus.MessageTooBig,"oversized messages are rejected at the bounded frame reader");
    }
    using(var socket=await ProbeClient.Socket(server.Url,server.Pin,shared,limit.Token)){
        await socket.SendAsync(new byte[64],WebSocketMessageType.Binary,true,limit.Token);
        var result=await socket.ReceiveAsync(new byte[2048],limit.Token);
        Check(result.MessageType==WebSocketMessageType.Close&&socket.CloseStatus==WebSocketCloseStatus.PolicyViolation,"TLS access alone cannot bypass the existing inner datagram authentication");
    }
    int seconds=int.Parse(Option("--seconds","4"));
    foreach(int rate in Option("--rates","50,100,150").Split(',').Select(int.Parse)){
        await using var client=await ProbeClient.Connect(server.Url,server.Pin,shared,limit.Token);
        var run=await client.Benchmark(rate,seconds,1280,limit.Token);runs.Add(run);
        bool met=JsonSerializer.SerializeToElement(run).GetProperty("targetRateMet").GetBoolean();if(!met)missedRates.Add(rate);
        await Write(Option("--output"),new{status="InProgress",checks,runs,missedRates,server=server.Statistics});
        Check(true,$"{rate} Mbps requested-load run returns every authenticated payload");
        Console.WriteLine($"MEASUREMENT targetMbps={rate} targetRateMet={met}");
    }
    await Write(Option("--output"),new{status=missedRates.Count==0?"Pass":"LoadTargetNotMet",functionalStatus="Pass",performanceStatus=missedRates.Count==0?"Pass":"LoadTargetNotMet",missedRates,checks,runs,server=server.Statistics,
        processorCount=Environment.ProcessorCount,scope="Actual loopback TCP/TLS/HTTP1.1 upgrade and production MeshLink encryption. Load qualification is separate from message correctness. No installed service, WAN, NAT, TUN, Moonlight or production protocol change."});
}
Console.WriteLine($"PASS {checks.Count} HTTPS probe checks");
if(missedRates.Count>0){Console.WriteLine("LOAD TARGET NOT MET: "+string.Join(',',missedRates));Environment.ExitCode=2;}
}catch(Exception ex){
    string output=Option("--output");
    if(output.Length>0){
        var report=new Dictionary<string,object?>();
        if(File.Exists(output))try{using var previous=JsonDocument.Parse(await File.ReadAllTextAsync(output));foreach(var item in previous.RootElement.EnumerateObject())report[item.Name]=item.Value.Clone();}catch(JsonException){}
        report["status"]="Fail";report["errorType"]=ex.GetType().Name;report["error"]=ex.GetBaseException().Message;report["checkedAt"]=DateTimeOffset.UtcNow;
        await Write(output,report);
    }
    Console.Error.WriteLine(ex.GetType().Name+": "+ex.GetBaseException().Message);Environment.ExitCode=1;
}
