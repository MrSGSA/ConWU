using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

if(args is ["--native-node",var components]){
    var json=new JsonSerializerOptions(JsonSerializerDefaults.Web);
    var network=JsonSerializer.Deserialize<UuTakeoverNetwork>((await Console.In.ReadLineAsync())!,json)!;
    using var controller=new UuTakeoverController(new WindowsUuTakeoverPlatform(components));
    var settings=new UuTakeoverSettings(true,network.Id);
    using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(180));
    var sync=new object();
    var observe=Task.Run(async()=>{
        try{while(!stop.IsCancellationRequested){
            lock(sync)controller.Refresh(settings,[network],DateTimeOffset.UtcNow);
            Console.WriteLine(JsonSerializer.Serialize(new{eventName="status",status=controller.Status},json));await Console.Out.FlushAsync();
            try{await Task.Delay(500,stop.Token);}catch(OperationCanceledException){}
        }}finally{controller.Dispose();}
    });
    try{while(await Console.In.ReadLineAsync() is {} line){
        lock(sync){switch(line){
            case "disable":settings=settings with{Enabled=false};break;
            case "enable":settings=settings with{Enabled=true};break;
            case "offline":network=network with{Ready=false};break;
            case "online":network=network with{Ready=true};break;
            case "stop":stop.Cancel();break;
        }}
        if(stop.IsCancellationRequested)break;
    }}finally{stop.Cancel();await observe;controller.Dispose();Console.WriteLine(JsonSerializer.Serialize(new{eventName="stopped",status=controller.Status},json));}
    return 0;
}

int checks=0;
void Check(bool value,string message){if(!value)throw new Exception(message);checks++;Console.WriteLine("PASS "+message);}
string id=Guid.NewGuid().ToString("N"),otherId=Guid.NewGuid().ToString("N");
var net=new UuTakeoverNetwork(id,"测试通道","10.203.1.2",["10.203.1.1"],true);
var other=new UuTakeoverNetwork(otherId,"另一通道","10.203.2.2",["10.203.2.1"],true);
var platform=new Platform();
using(var controller=new UuTakeoverController(platform)){
    var now=DateTimeOffset.UtcNow;
    controller.Refresh(new(),[net],now);
    Check(controller.Status.State=="Disabled"&&platform.ProcessQueries==0&&platform.Opened.Count==0,"default off opens no driver or process query");
    controller.Refresh(new(true),[],now);
    Check(controller.Status.State=="WaitingNetwork"&&platform.Opened.Count==0,"no network leaves UU unrestricted");
    controller.Refresh(new(true),[net,other],now);
    Check(controller.Status.State=="WaitingUu"&&controller.Status.Networks.Length==2&&platform.Opened.Count==0,"all healthy networks participate automatically");
    controller.Refresh(new(true,id),[other],now);
    Check(controller.Status.State=="WaitingUu"&&controller.Status.Networks.Single().Id==otherId,"a legacy manual selection no longer limits automatic networks");
    controller.Refresh(new(true,id),[net],now);
    Check(controller.Status.State=="WaitingUu"&&platform.Opened.Count==0,"no UU process creates no restriction");
    platform.Items=[new(123,1,"verified-UU")];controller.Refresh(new(true,id),[net],now);
    Check(controller.Status.RulesActive&&!controller.Status.TrafficObserved&&controller.Status.State=="Ready","active rules are not reported as a working stream");
    platform.Opened[^1].Traffic=new(1000000,10000,500000,true,now.ToUnixTimeMilliseconds());
    controller.Refresh(new(true,id),[net],now.AddSeconds(1));
    Check(controller.Status.State=="Transmitting"&&controller.Status.ReceivedBytes==1000000,"only observed sustained UU data reports transmission");
    platform.Opened[^1].Traffic=platform.Opened[^1].Traffic with{Sustained=false,RecentBytesPerSecond=500};controller.Refresh(new(true,id),[net],now.AddSeconds(2));
    Check(controller.Status.State=="Idle"&&!controller.Status.ReconnectRecommended,"low traffic is not mislabeled as a failed or missing UU connection");
    controller.Refresh(new(true,id),[net with{Ready=false}],now.AddSeconds(2));
    Check(platform.Opened.All(g=>g.Closed)&&!controller.Status.RulesActive,"network loss releases every gate");
    controller.Refresh(new(true,id),[net],now.AddSeconds(3));var before=platform.Opened[^1];
    platform.Items=[new(123,2,"verified-UU")];controller.Refresh(new(true,id),[net],now.AddSeconds(4));
    Check(before.Closed&&platform.Opened.Count==3,"process creation identity change rebuilds a PID rule");
    before=platform.Opened[^1];platform.Items=[];controller.Refresh(new(true,id),[net],now.AddSeconds(5));
    Check(before.Closed&&controller.Status.State=="WaitingUu","UU exit removes its rules");
    platform.Items=[new(321,3,"verified-UU")];platform.Fail=true;controller.Refresh(new(true,id),[net],now.AddSeconds(6));
    int failures=platform.OpenAttempts;controller.Refresh(new(true,id),[net],now.AddSeconds(7));
    Check(controller.Status.State=="Error"&&!controller.Status.RulesActive&&platform.OpenAttempts==failures,"driver failure releases resources and backs off");
    platform.Fail=false;controller.Refresh(new(true,id),[net],now.AddSeconds(12));
    Check(controller.Status.RulesActive,"driver recovery can resume after bounded backoff");
    platform.Opened[^1].Traffic=new(Error:"observer failed");controller.Refresh(new(true,id),[net],now.AddSeconds(13));
    Check(platform.Opened.All(g=>g.Closed)&&controller.Status.State=="Error","observer failure never leaves an unobserved restriction active");
    controller.Refresh(new(false,id),[net],now.AddSeconds(14));
    Check(controller.Status.State=="Disabled"&&!controller.Status.RulesActive,"disable clears both rules and previous error");
    controller.Refresh(new(true,id),[net],now.AddSeconds(15));controller.Dispose();controller.Dispose();
    Check(platform.Opened.All(g=>g.Closed)&&controller.Status.State=="Stopped","shutdown is idempotent and closes every rule");
}
var unsupported=new Platform{Supported=false};using(var controller=new UuTakeoverController(unsupported)){
    controller.Refresh(new(true),[net],DateTimeOffset.UtcNow);
    Check(controller.Status.State=="Unsupported"&&unsupported.OpenAttempts==0,"unsupported platforms never call Windows APIs");
}
var multi=new Platform{Items=[new(123,1,"verified-UU")]};using(var controller=new UuTakeoverController(multi)){
    var now=DateTimeOffset.UtcNow;controller.Refresh(new(true),[net,other],now);
    Check(multi.Opened.Count==1&&multi.Opened[0].Networks.Length==2,"multiple networks share one allow-union gate rather than blocking each other");
    controller.Refresh(new(true),[other,net],now.AddSeconds(1));
    Check(multi.Opened.Count==1,"UI ordering changes do not rebuild capture rules");
    multi.Opened[^1].Traffic=new(100000,10000,50000,true,now.ToUnixTimeMilliseconds()){
        Networks=[new(id,net.Name,net.VirtualIp,true,100000,10000,50000),new(otherId,other.Name,other.VirtualIp)]};
    controller.Refresh(new(true),[net,other],now.AddSeconds(2));
    Check(controller.Status.Networks.Single(n=>n.Id==id).TrafficObserved&&!controller.Status.Networks.Single(n=>n.Id==otherId).TrafficObserved,"UU traffic is attributed to the selected peer without claiming all networks are streaming");
    var previous=multi.Opened[^1];controller.Refresh(new(true),[net with{Ready=false},other],now.AddSeconds(3));
    Check(previous.Closed&&controller.Status.RulesActive&&multi.Opened[^1].Networks.SequenceEqual([otherId]),"one offline network releases its restrictions while another remains available");
    Check(controller.Status.State=="Ready"&&!controller.Status.TrafficObserved,"a topology switch waits for fresh traffic evidence");
    controller.Refresh(new(true),[net,other],now.AddSeconds(4));
    Check(multi.Opened[^1].Networks.Length==2&&controller.Status.RulesActive,"a returning network participates automatically without editing settings");
}
var profile=JsonSerializer.Deserialize<DeviceProfile>("{}")!;
Check(!profile.UuTakeover.Enabled,"older saved settings inherit the disabled default");
var updated=ProfileChanges.Copy(profile);updated.UuTakeover=new(true,id);
Check(ProfileChanges.Impact(profile,updated)!=ProfileChangeImpact.RestartNetwork,"changing takeover does not rebuild a healthy ConWU network");

// Isolated DPAPI profile and restricted UI requests. No production service,
// network adapter, UU process or signed-driver rule is opened by these checks.
string root=Path.GetFullPath(Path.Combine("artifacts","uu-remote-lab","settings-tests",Guid.NewGuid().ToString("N")));
var store=new ProfileStore(root);string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
profile=store.Load();profile.CoordinatorRoleVersion=1;store.Save(profile);
using(var worker=new ControlWorker(store)){
    worker.UuTakeoverPlatformFactory=()=>new Platform();worker.EnablePairNetworks();
    async Task<UiControlReply> Save(UuTakeoverSettings settings,string revision,Guid? operation=null)=>await worker.HandleUi(new("uu-takeover",OperationId:operation??Guid.NewGuid()){UuTakeover=new(settings,revision)},sid,CancellationToken.None);
    string revision=store.Load().UuTakeover.Revision();
    var denied=await worker.HandleUi(new("uu-takeover"){UuTakeover=new(new(true,id),revision)},"S-1-5-21-1-2-3-1234",CancellationToken.None);
    Check(!denied.Ok&&!store.Load().UuTakeover.Enabled,"unauthorized caller cannot change the device option");
    var mixed=await worker.HandleUi(new("uu-takeover",Patch:new(DeviceName:"unexpected")){UuTakeover=new(new(true,id),revision)},sid,CancellationToken.None);
    Check(!mixed.Ok&&!store.Load().UuTakeover.Enabled,"mixed requests cannot smuggle other setting edits");
    var saved=await Save(new(true,id),revision);
    Check(saved.Ok&&store.Load().UuTakeover==new UuTakeoverSettings(true,id)&&saved.Status!.UuTakeover!.Settings.Enabled,"saving exposes persisted device intent immediately");
    var stale=await Save(new(false,id),revision);
    Check(!stale.Ok&&store.Load().UuTakeover.Enabled,"stale settings cannot silently disable newer intent");
    await worker.HandleUi(new("patch",new(DeviceName:"UU setting test",ExpectedDeviceName:store.Load().DeviceName),Guid.NewGuid()),sid,CancellationToken.None);
    Check(store.Load().UuTakeover.Enabled&&store.Load().DeviceName=="UU setting test","saving other settings preserves the independent option");
    var rollback=PairSettingsTransaction.SettingsOnly(store.Load(),profile);
    Check(rollback.UuTakeover.Enabled,"unrelated network transaction rollback cannot lose takeover intent");
    var child=new ProfileStore(Path.Combine(root,"networks",id),store);var childValue=store.Load();childValue.NodeSigningPrivate="";childValue.Device=Guid.NewGuid().ToString("N");child.Save(childValue);
    Check(!child.Load().UuTakeover.Enabled&&store.Load().UuTakeover.Enabled,"network profiles never inherit a device takeover switch");
    var gate=(SemaphoreSlim)typeof(ControlWorker).GetField("requests",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(worker)!;
    await gate.WaitAsync();Guid queuedId=Guid.NewGuid();
    var queued=Save(new(false,id),store.Load().UuTakeover.Revision(),queuedId);
    var watch=Stopwatch.StartNew();var progress=await worker.HandleUi(new("status",OperationId:queuedId),sid,CancellationToken.None);
    Check(watch.ElapsedMilliseconds<1000&&progress.Operation is {Completed:false},"queued save remains observable without blocking status");
    gate.Release();var completed=await queued;
    Check(completed.Ok&&completed.Operation is {Completed:true}&&!store.Load().UuTakeover.Enabled,"queued save completes once and exposes its result");
    var same=await Save(new(false,id),saved.Status!.UuTakeover!.Revision,queuedId);
    Check(same.Ok,"identical operation replay reports its prior result without another write");
    var replay=await Save(new(true,id),store.Load().UuTakeover.Revision(),queuedId);
    Check(!replay.Ok,"an operation ID cannot be reused with a different body");
}
using(var again=new ControlWorker(store))Check(!again.ProfileSnapshot().UuTakeover.Enabled,"device intent persists across backend reopen");
Console.WriteLine(JsonSerializer.Serialize(new{status="Pass",checks,productionSettingsModified=false}));return 0;

sealed class Platform:IUuTakeoverPlatform
{
    public bool Supported{get;set;}=true;
    public UuTakeoverProcess[] Items=[];
    public bool Fail;
    public int ProcessQueries,OpenAttempts;
    public List<Gate> Opened=[];
    public UuTakeoverProcess[] Processes(){ProcessQueries++;return Items;}
    public IUuTakeoverGate Open(IReadOnlyList<UuTakeoverNetwork> networks,UuTakeoverProcess[] processes){OpenAttempts++;if(Fail)throw new IOException("simulated driver fault");var g=new Gate{Networks=networks.Select(n=>n.Id).ToArray()};Opened.Add(g);return g;}
}
sealed class Gate:IUuTakeoverGate
{
    public bool Closed;
    public string[] Networks=[];
    public UuTakeoverTraffic Traffic=new();
    public UuTakeoverTraffic Observe(DateTimeOffset now)=>Traffic;
    public void Dispose()=>Closed=true;
}
