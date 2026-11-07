using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using StreamLink.Core;
using StreamLink.Discovery;
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
        await Task.Delay(400,stop.Token);reply=await Call(new UiControlRequest("status",OperationId:request.OperationId){NetworkId=request.NetworkId});
    }
    if(reply.Operation.Error.Length>0)throw new IOException(reply.Operation.Error);
    return reply;
}
async Task<UiStatusDto> SelectNetwork(string id){
    if(id.Length!=32||!Guid.TryParseExact(id,"N",out var parsed)||parsed==Guid.Empty)throw new ArgumentException("网络配置 ID 必须为 32 位标识");
    var selected=(await Call(new UiControlRequest("status"){NetworkId=id})).Status??throw new IOException("网络状态尚未就绪");
    if(selected.SelectedNetworkId!=id||!selected.Networks.Any(n=>n.Id==id))throw new IOException("未找到指定网络配置");return selected;
}
try {
    if(args.Length>0&&args[0]=="--data"){
        if(args.Length<2||!Path.IsPathFullyQualified(args[1])||!Directory.Exists(args[1]))throw new ArgumentException("--data 需要已存在的绝对目录");
        Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",Path.GetFullPath(args[1]));args=args[2..];
    }
    if(args is ["maintenance","resources","--json"]){
        var maintenanceStore=new ProfileStore();using var held=new FileStream(Path.Combine(ProfileStore.Root,"runtime.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
        LinuxFirewall.Recover();var remaining=LinuxFirewall.RemainingResources();
        Print(new{schemaVersion=1,complete=remaining.Length==0,ownedResources=remaining,tunPersistence="non-persistent; main process exit closes CLOEXEC TUN descriptors",scopes=maintenanceStore.NetworksForMaintenance().Select(p=>new{configurationId=p.ConfigurationId,networkId=p.Profile.Mesh?.Pair.Network??"",adapterScope=p.Profile.AdapterScope})});return;
    }
    if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException("此统一 CLI 适用于 Linux；Windows 请使用已安装的服务和 WebUI");
    if(args.Length==0||args[0] is "help" or "--help") {
        Console.WriteLine("""
ConWU · Linux
  run [--no-web]               运行后台；默认提供仅本机可访问的 WebUI
  status                      查看本机、成员、连接及协调状态
  web                         获取本机 WebUI 的一次性登录链接
  config show                 导出可编辑设置，不含成员密钥
  config apply <文件.json>    合并并保存设置，不填写的字段保持原值
  ddns status                 查看域名发布和成员入口读取状态
  ddns token                  从标准输入读取 API Token 并保存，不回显
  ddns clear-token            清除令牌并停止发布，保留域名发现
  coordinator status          查看协调监听、证书与外部 HTTPS 诊断
  coordinator backup <文件>  离线备份协调数据（先关闭协调角色）
  coordinator inspect <文件> 校验备份格式、校验和及成员签名
  coordinator restore <文件> --confirm-rollback
                              离线恢复；显式确认可能回滚审批和撤销
  上述 backup/restore 可加 --data <目录> 迁移旧独立协调数据
  network list                    列出全部网络及本机配置 ID
  network status <配置ID>         查看指定网络状态
  network create                   使用设备默认设置创建新网络
  network join <入口/配对码/邀请>  创建新关系并申请加入
  network invite|poll|reject|leave|withdraw|close|resume <配置ID>
  network approve <配置ID> <校验码>
  network rename <配置ID> <名称>  修改本机显示名称
  network remove-config <配置ID>  删除指定本机网络配置
  network remove <配置ID> <成员Slot>  撤销指定成员
  start|stop|retry <配置ID>       启动、暂停或重试指定连接
  config show [--network <配置ID>]
  config apply <文件.json> [--network <配置ID>]
  可在命令前使用 --data <已存在的绝对目录> 选择后台数据目录。

使用同一后台用户操作（系统服务通常使用 sudo）。网络管理和本机协调是独立角色。
首次使用可在 config apply 的 Network.Coordinator 中开启协调服务。
""");return;
    }
    if(args[0]=="run") {
        using var worker=new ControlWorker(pairNetworks:true);WebPanel? panel=null;
        try {
            if(!args.Contains("--no-web")) {
                panel=await WebPanel.Start(worker.HandleLocalUi,Path.Combine(AppContext.BaseDirectory,"wwwroot"),port:WebPanel.DefaultPort);
                worker.OpenLocalPanel=panel.OpenLink;
            }
            await worker.StartAsync(stop.Token);
            Console.WriteLine("ConWU 已启动。使用 conwu web 获取登录链接；使用 conwu status 查看状态。");
            try{await await Task.WhenAny(worker.ExecuteTask!,Task.Delay(Timeout.Infinite,stop.Token));}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        }finally {
            using var shutdown=new CancellationTokenSource(TimeSpan.FromSeconds(65));
            try{await worker.StopAsync(shutdown.Token);}finally{if(panel!=null)await panel.DisposeAsync();}
        }
        return;
    }
    if(args[0]=="web") {var result=await UnixControlProtocol.Call(new(OpenPanel:true),stop.Token);if(result.Error.Length>0)throw new IOException(result.Error);Console.WriteLine(result.Panel);return;}
    if(args[0]=="coordinator" && args.Length>=2 && args[1]!="status") {
        Print(CoordinationMaintenance.Execute(args[1..],Path.Combine(ProfileStore.Root,"coordination")));return;
    }
    var state=(await Call(new("status"))).Status??throw new IOException("后台状态尚未就绪");
    if(args is ["ddns","status"]){Print(new{Settings=state.Settings?.Ddns,CredentialConfigured=state.DdnsCredentialConfigured,Status=state.Ddns});return;}
    if(args is ["ddns","token"] or ["ddns","clear-token"]){
        bool clear=args[1]=="clear-token";
        string? credential=null;
        if(!clear){
            if(!Console.IsInputRedirected)throw new IOException("请从私有文件或安全输入管道传入令牌，例如 conwu ddns token < 私有令牌文件；不要把令牌写入命令参数");
            var chars=new char[514];int length=0;
            try {
                while(length<chars.Length){int read=await Console.In.ReadAsync(chars.AsMemory(length),stop.Token);if(read==0)break;length+=read;}
                if(length>=chars.Length)throw new IOException("DDNS 令牌输入过长");
                credential=new string(chars,0,length).Trim();CloudflareDdnsSettings.ValidateToken(credential);
            } finally { Array.Clear(chars); }
            if(credential.Length==0)throw new IOException("DDNS 令牌为空");
        }
        var action=new UiNetworkAction("settings",Settings:state.Settings,ExpectedRevision:state.SettingsRevision){DdnsToken=credential,ClearDdnsToken=clear};
        await Mutate(new("network",Network:action));Console.WriteLine(clear?"DDNS 令牌已清除":"DDNS 令牌已保存；状态与设置导出不会回显令牌");return;
    }
    if(args is ["coordinator","status"]){Print(state.Coordinator??throw new IOException("协调状态尚未就绪"));return;}
    if(args[0]=="status"){Print(state);return;}
    if(args[0] is "start" or "stop" or "retry"){
        if(args.Length!=2)throw new ArgumentException("请明确填写网络配置 ID");
        var selected=await SelectNetwork(args[1]);Print(await Mutate(new UiControlRequest(args[0]){NetworkId=selected.SelectedNetworkId}));return;
    }
    if(args[0]=="config") {
        string configurationId="";var parts=args.ToList();int index=parts.IndexOf("--network");
        if(index>=0){if(index+1>=parts.Count||index!=parts.Count-2)throw new ArgumentException("--network 需要一个配置 ID");configurationId=parts[index+1];parts.RemoveRange(index,2);state=await SelectNetwork(configurationId);}
        args=parts.ToArray();
        var shared=state.DeviceSettings??state.Settings??throw new IOException("设备设置尚未就绪");
        var chosen=state.Settings??throw new IOException("网络设置尚未就绪");
        chosen=chosen with {Coordinator=shared.Coordinator,Ddns=shared.Ddns};
        var settings=new JsonObject{
            ["DeviceName"]=state.DeviceName,["LogLevel"]=state.LogLevel,
            ["AutoStart"]=state.Desktop?.AutoStart??false,["Network"]=JsonSerializer.SerializeToNode(chosen,json)
        };
        if(args.Length==2&&args[1]=="show"){Console.WriteLine(settings.ToJsonString(json));return;}
        if(args.Length!=3||args[1]!="apply")throw new ArgumentException("用法：config show 或 config apply 文件.json");
        var input=JsonNode.Parse(await File.ReadAllTextAsync(args[2],stop.Token)) as JsonObject??throw new FormatException("设置需要 JSON 对象");
        void Merge(JsonObject into,JsonObject source){foreach(var pair in source){if(!into.ContainsKey(pair.Key))throw new FormatException("未知设置字段："+pair.Key);if(pair.Value is JsonObject child&&into[pair.Key] is JsonObject target)Merge(target,child);else into[pair.Key]=pair.Value?.DeepClone();}}
        Merge(settings,input);
        var network=settings["Network"]?.Deserialize<UiNetworkSettings>(json)??throw new FormatException("Network 设置为空");
        string name=settings["DeviceName"]!.GetValue<string>(),level=settings["LogLevel"]!.GetValue<string>();bool auto=settings["AutoStart"]!.GetValue<bool>();
        var deviceSettings=configurationId.Length==0?network:shared with{Coordinator=network.Coordinator,Ddns=network.Ddns};
        var deviceAction=new UiNetworkAction("settings",Settings:deviceSettings,ExpectedRevision:state.DeviceSettingsRevision,ConfirmReplace:true){
            Patch=new(name,level,state.DeviceName,state.LogLevel),
            AutoStart=auto!=state.Desktop?.AutoStart?auto:null,ExpectedAutoStart=auto!=state.Desktop?.AutoStart?state.Desktop?.AutoStart:null
        };
        var networks=configurationId.Length==0?Array.Empty<UiNetworkSettingChange>():new[]{new UiNetworkSettingChange(new("settings",Settings:network,ExpectedRevision:state.SettingsRevision,ConfirmReplace:true),configurationId)};
        Print(await Mutate(new UiControlRequest("save-settings"){NetworkId=configurationId,SettingsBatch=new(deviceAction,networks)}));return;
    }
    if(args[0]=="network"&&args.Length>=2) {
        string verb=args[1];
        if(verb=="list"&&args.Length==2){Print(state.Networks.Select(n=>new{configurationId=n.Id,name=n.Name,networkId=n.Status.NetworkId,role=n.Status.IsOwner?"host":"guest",enabled=n.Status.NetworkEnabled,virtualIp=n.Status.VirtualIp,state=n.Status.State}));return;}
        if(verb=="status"&&args.Length==3){Print(await SelectNetwork(args[2]));return;}
        if(verb is "create" or "join"){
            if(verb=="create"&&args.Length!=2||verb=="join"&&args.Length!=3)throw new ArgumentException("用法：network create 或 network join 入口/配对码/邀请");
            var template=state.DeviceSettings??state.Settings??throw new IOException("设备默认设置尚未就绪");if(template.ConnectionSource!="existing"&&string.IsNullOrWhiteSpace(template.Service))throw new IOException("自主打洞需要 HTTPS 协调入口；无协调时请明确选择只使用已有入口");string value=verb=="join"?args[2]:"";
            string enrollmentAction=verb=="create"?(template.Service.Length==0?"create-direct":"create"):value.Length==6&&value.All(char.IsAsciiDigit)?(template.DirectMode?"join-direct-short":"join"):value.StartsWith("SL6.")?"join-invitation":"join-entry";
            var request=new UiNetworkAction(enrollmentAction,template.Service,template.CertificatePin,enrollmentAction is "join-entry" or "create" or "create-direct"?"":value,Mode:template.PathSelection=="udp-only"?"udp":"faketcp"){Entry=enrollmentAction=="join-entry"?value:""};
            Print(await Mutate(new UiControlRequest("network",Network:request){NetworkId=""}));return;
        }
        bool needsValue=verb is "approve" or "rename" or "remove";
        if(args.Length!=(needsValue?4:3))throw new ArgumentException("请填写明确的网络配置 ID 和所需参数");
        string id=args[2],valueArg=needsValue?args[3]:"";var chosen=await SelectNetwork(id);
        string command=verb switch{"invite"=>"invite","poll"=>"pair-poll","approve"=>"approve","reject"=>"reject","leave"=>"forget-network","withdraw"=>"leave","close"=>"delete-network","remove"=>"revoke","resume"=>"membership-resume","rename"=>"rename-network","remove-config"=>"remove-network",_=>throw new ArgumentException("未知网络操作")};
        if(verb=="approve"&&(chosen.Pairing?.Verification!=valueArg||valueArg.Length==0))throw new IOException("校验码不匹配，请先查询该网络申请并与对端核对");
        int slot=0;if(verb=="remove"&&(!int.TryParse(valueArg,out slot)||slot<1))throw new ArgumentException("请填写成员 Slot");
        var action=new UiNetworkAction(command,ExpectedNetwork:chosen.NetworkId,ConfirmReplace:true,Verification:verb=="approve"?valueArg:"",Candidate:chosen.Pairing?.Candidate??"",PeerSlot:slot,ProposedIp:chosen.Pairing?.ProposedIp??""){Name=verb=="rename"?valueArg:""};
        Print(await Mutate(new UiControlRequest("network",Network:action){NetworkId=id}));return;
    }
    throw new ArgumentException("未知命令，请运行 conwu help");
}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
catch(Exception ex){Console.Error.WriteLine(ex.Message);Environment.ExitCode=1;}
