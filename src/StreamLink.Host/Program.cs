using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using StreamLink.Core;
using StreamLink.Service;
using StreamLink.Web;

var json=new JsonSerializerOptions{WriteIndented=true,PropertyNameCaseInsensitive=true};
using var stop=new CancellationTokenSource();
Console.CancelKeyPress+=(_,e)=>{e.Cancel=true;stop.Cancel();};
using var term=OperatingSystem.IsLinux()?PosixSignalRegistration.Create(PosixSignal.SIGTERM,c=>{c.Cancel=true;stop.Cancel();}):null;
void Print(object value)=>Console.WriteLine(JsonSerializer.Serialize(value,json));
async Task<UiControlReply> Call(UiControlRequest request) {
    var result=await UnixControlProtocol.Call(new(Ui:request),stop.Token);
    var reply=result.Ui??throw new IOException(result.Error);
    if(!reply.Ok)throw new IOException(reply.Error);
    return reply;
}
async Task<UiControlReply> Mutate(UiControlRequest request) {
    request=request with{OperationId=Guid.NewGuid()};
    var reply=await Call(request);
    while(reply.Operation is not {Completed:true}) {
        await Task.Delay(400,stop.Token);reply=await Call(new("status",OperationId:request.OperationId));
    }
    if(reply.Operation.Error.Length>0)throw new IOException(reply.Operation.Error);
    return reply;
}
try {
    if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException("此统一 CLI 适用于 Linux；Windows 请使用已安装的服务和 WebUI");
    if(args.Length==0||args[0] is "help" or "--help") {
        Console.WriteLine("""
StreamLink · Linux
  run [--no-web]               运行后台；默认提供仅本机可访问的 WebUI
  status                      查看本机、成员、连接及协调状态
  web                         获取本机 WebUI 的一次性登录链接
  config show                 导出可编辑设置，不含成员密钥
  config apply <文件.json>    合并并保存设置，不填写的字段保持原值
  network create              按已保存的连接设置创建网络
  network join <配对码/邀请>  申请加入网络
  network invite              生成配对码或直连邀请
  network poll                更新加入申请状态
  network approve <校验码>    批准当前申请（须先核对设备与校验码）
  network reject              拒绝当前申请
  network leave <网络ID>      确认退出指定的当前网络
  network close <网络ID>      确认解散指定的整个网络
  network remove <成员Slot>   移除指定成员
  network resume              继续确认未完成的成员变更
  start | stop | retry        启动、暂停或重试本机数据连接

使用同一后台用户操作（系统服务通常使用 sudo）。网络管理和本机协调是独立角色。
首次使用可在 config apply 的 Network.Coordinator 中开启协调服务。
""");return;
    }
    if(args[0]=="run") {
        using var worker=new ControlWorker();WebPanel? panel=null;
        try {
            if(!args.Contains("--no-web")) {
                panel=await WebPanel.Start(worker.HandleLocalUi,Path.Combine(AppContext.BaseDirectory,"wwwroot"),port:WebPanel.DefaultPort);
                worker.OpenLocalPanel=panel.OpenLink;
            }
            await worker.StartAsync(stop.Token);
            Console.WriteLine("StreamLink 已启动。使用 streamlink web 获取登录链接；使用 streamlink status 查看状态。");
            try{await await Task.WhenAny(worker.ExecuteTask!,Task.Delay(Timeout.Infinite,stop.Token));}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        }finally {
            using var shutdown=new CancellationTokenSource(TimeSpan.FromSeconds(65));
            try{await worker.StopAsync(shutdown.Token);}finally{if(panel!=null)await panel.DisposeAsync();}
        }
        return;
    }
    if(args[0]=="web") {var result=await UnixControlProtocol.Call(new(OpenPanel:true),stop.Token);if(result.Error.Length>0)throw new IOException(result.Error);Console.WriteLine(result.Panel);return;}
    var state=(await Call(new("status"))).Status??throw new IOException("后台状态尚未就绪");
    if(args[0]=="status"){Print(state);return;}
    if(args[0] is "start" or "stop" or "retry"){Print(await Mutate(new(args[0])));return;}
    if(args[0]=="config") {
        var settings=new JsonObject{
            ["DeviceName"]=state.DeviceName,["LogLevel"]=state.LogLevel,
            ["AutoStart"]=state.Desktop?.AutoStart??false,["Network"]=JsonSerializer.SerializeToNode(state.Settings,json)
        };
        if(args.Length==2&&args[1]=="show"){Console.WriteLine(settings.ToJsonString(json));return;}
        if(args.Length!=3||args[1]!="apply")throw new ArgumentException("用法：config show 或 config apply 文件.json");
        var input=JsonNode.Parse(await File.ReadAllTextAsync(args[2],stop.Token)) as JsonObject??throw new FormatException("设置需要 JSON 对象");
        void Merge(JsonObject into,JsonObject source){foreach(var pair in source){if(!into.ContainsKey(pair.Key))throw new FormatException("未知设置字段："+pair.Key);if(pair.Value is JsonObject child&&into[pair.Key] is JsonObject target)Merge(target,child);else into[pair.Key]=pair.Value?.DeepClone();}}
        Merge(settings,input);
        var network=settings["Network"]?.Deserialize<UiNetworkSettings>(json)??throw new FormatException("Network 设置为空");
        string name=settings["DeviceName"]!.GetValue<string>(),level=settings["LogLevel"]!.GetValue<string>();bool auto=settings["AutoStart"]!.GetValue<bool>();
        var action=new UiNetworkAction("settings",Settings:network,ExpectedRevision:state.SettingsRevision,ConfirmReplace:true){
            Patch=new(name,level,state.DeviceName,state.LogLevel),
            AutoStart=auto!=state.Desktop?.AutoStart?auto:null,ExpectedAutoStart=auto!=state.Desktop?.AutoStart?state.Desktop?.AutoStart:null
        };
        Print(await Mutate(new("network",Network:action)));return;
    }
    if(args[0]=="network"&&args.Length>=2) {
        string value=args.Length>2?args[2]:"";var settings=state.Settings??throw new IOException("设置尚未就绪");
        string command=args[1] switch {
            "create"=>settings.DirectMode?"create-direct":"create", "join"=>value.Length==6&&value.All(char.IsDigit)?settings.DirectMode?"join-direct-short":"join":"join-invitation",
            "invite"=>"invite","poll"=>"pair-poll","approve"=>"approve","reject"=>"reject","leave"=>"leave","close"=>"delete-network","remove"=>"revoke","resume"=>"membership-resume",
            _=>throw new ArgumentException("未知网络操作")
        };
        if(args[1] is "leave" or "close" && (state.NetworkId.Length==0||value!=state.NetworkId))throw new IOException("请在命令后填写 status 显示的完整当前网络 ID，以确认操作");
        if(args[1]=="approve"&&(state.Pairing?.Verification!=value||value.Length==0))throw new IOException("校验码不匹配，请先运行 network poll 并与申请设备核对");
        int slot=0;if(args[1]=="remove"&&(!int.TryParse(value,out slot)||slot<1))throw new ArgumentException("请填写成员 Slot");
        var action=new UiNetworkAction(command,settings.Service,settings.CertificatePin,args[1]=="join"?value:"",state.NetworkId,true,
            Verification:args[1]=="approve"?value:"",Candidate:state.Pairing?.Candidate??"",PeerSlot:slot,Mode:settings.PathSelection=="udp-only"?"udp":"faketcp",ProposedIp:state.Pairing?.ProposedIp??"");
        Print(await Mutate(new("network",Network:action)));return;
    }
    throw new ArgumentException("未知命令，请运行 streamlink help");
}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
catch(Exception ex){Console.Error.WriteLine(ex.Message);Environment.ExitCode=1;}
