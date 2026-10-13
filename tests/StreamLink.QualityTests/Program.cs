using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.Core;

int checks=0;
void Check(bool ok,string reason){if(!ok)throw new Exception(reason);checks++;}
const string key="public-fixture-key-not-a-user-secret";
QualityDiagnosticPolicy Allowed()=>new(()=>true,new PathDiagnosticResources());
QualityMessage Sign(QualityMessage m)=>m with{Mac=Quality.Mac(key,m)};
using var socket=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));socket.Connect(IPAddress.Loopback,Quality.Port);
var ep=(IPEndPoint)socket.Client.LocalEndPoint!;
var message=Sign(new("start",1,5,20,0,"",2,DateTimeOffset.UtcNow.AddSeconds(35).ToUnixTimeSeconds(),"127.0.0.1",ep.Port,"127.0.0.1"));
Check(Quality.Valid(message,key),"valid complete message rejected");
foreach(var tampered in new[]{message with{Op="cancel"},message with{Op="done",Count=7},message with{Responder="127.0.0.2"},message with{InitiatorPort=ep.Port+1},message with{Version=1}})
    Check(!Quality.Valid(tampered,key),"operation/count/direction/version must be MAC bound");

var time=new Clock();var shared=new PathDiagnosticResources(time);
using(var manual=shared.TryBeginManual(Guid.NewGuid())!) {
    Check(shared.TryBegin(Guid.NewGuid())==null,"manual load must occupy automatic diagnostic pool");
    using var window=manual.Open(Guid.NewGuid(),64,20000);
    Check(shared.TryBeginManual(Guid.NewGuid())==null,"new IDs cannot allocate a second active window");
}
Check(shared.TryBeginManual(Guid.NewGuid())==null,"new ID cannot bypass manual cooldown");
time.Advance(90001);using(var next=shared.TryBeginManual(Guid.NewGuid()))Check(next!=null,"manual cooldown should expire monotonically");
using(var automatic=new PathDiagnosticResources(time).TryBegin(Guid.NewGuid())!) {
    bool rejected=false;try{using var bad=automatic.Open(Guid.NewGuid(),50,20000);}catch(ArgumentException){rejected=true;}
    Check(rejected,"automatic-v1 15s maximum must not be raised for manual-v2");
}

using(var stop=new CancellationTokenSource()) {
    var server=Quality.Serve("127.0.0.1","127.0.0.1",key,stop.Token); // default deny
    await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(message));
    using(var timeout=new CancellationTokenSource(1500)){
        var data=await socket.ReceiveAsync(timeout.Token);var denied=JsonSerializer.Deserialize<QualityMessage>(data.Buffer)!;
        Check(denied.Op=="denied"&&denied.Error=="RemotePermissionRequired"&&Quality.Valid(denied,key),"membership alone cannot authorize active load");
    }
    stop.Cancel();try{await server;}catch(OperationCanceledException){}
}
using(var stop=new CancellationTokenSource()) {
    var server=Quality.Serve("127.0.0.1","127.0.0.1",key,stop.Token,Allowed());
    await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(message));
    using(var timeout=new CancellationTokenSource(1500)){
        var first=await socket.ReceiveAsync(timeout.Token);Check(first.Buffer.Length==1200&&first.Buffer.AsSpan(0,4).SequenceEqual("SLQ2"u8),"authorized load did not start");
    }
    var canceled=Sign(message with{Op="cancel"});await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(canceled));
    var watch=Stopwatch.StartNew();int late=0;bool done=false;
    while(watch.ElapsedMilliseconds<700){
        using var tick=new CancellationTokenSource(80);
        try{var p=await socket.ReceiveAsync(tick.Token);if(p.Buffer.Length==1200&&watch.ElapsedMilliseconds>250)late++;else if(p.Buffer.Length<1024){var m=JsonSerializer.Deserialize<QualityMessage>(p.Buffer);if(m?.Op=="done"&&Quality.Valid(m,key))done=true;}}
        catch(OperationCanceledException){}
    }
    Check(done&&late==0,"signed cancellation must stop actual datagrams, not only UI wait");
    await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(Sign(message with{Id=2})));
    using(var timeout=new CancellationTokenSource(1500)){
        var response=await socket.ReceiveAsync(timeout.Token);var denied=JsonSerializer.Deserialize<QualityMessage>(response.Buffer)!;
        Check(denied.Op=="denied"&&denied.Error=="DeviceBudgetOrCooldown","completed/canceled measurement cannot be repeated with new IDs");
    }
    stop.Cancel();try{await server;}catch(OperationCanceledException){}
}
Console.WriteLine(JsonSerializer.Serialize(new{scope="actual loopback UDP consent/cancel plus shared budget model; not WAN or Wintun",checks,status="Pass"}));

sealed class Clock:TimeProvider {
    long at;public override long TimestampFrequency=>1000;
    public override long GetTimestamp()=>at;public void Advance(long ms)=>at+=ms;
}
