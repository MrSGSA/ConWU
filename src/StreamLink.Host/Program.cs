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
  remote-admin set <HTTPS来源> 从标准输入设置远程管理密码，重启服务生效
  remote-admin disable        关闭远程管理，重启服务生效
  config show                 导出本机设置，不含成员密钥
  profiles                    列出连接配置及关联网络
  profile show <配置ID>        查看一份连接配置及关联网络
  profile export <配置ID>      导出可编辑连接设置
  profile create <名称> <JSON> 保存新配置，不启动网络
  profile update <ID> <JSON> [--reconnect] 更新配置及全部关联网络
  profile copy <ID> <名称>     复制为独立配置
  profile assign <ID> <网络ID> [--reconnect] 更换网络引用
  profile apply <ID> [--reconnect] 重试应用配置
  profile delete <ID>          删除未关联配置
  config apply <文件.json>    合并并保存设置，不填写的字段保持原值
  coordinator status          查看协调监听、证书与外部 HTTPS 诊断
  coordinator backup <文件>  离线备份协调数据（先关闭协调角色）
  coordinator inspect <文件> 校验备份格式、校验和及成员签名
  coordinator restore <文件> --confirm-rollback
                              离线恢复；显式确认可能回滚审批和撤销
  上述 backup/restore 可加 --data <目录> 迁移旧独立协调数据
  network list                    列出网络操作 ID 和所引用的配置
  network status <网络ID>         查看指定网络状态
  network create <配置ID> [名称]   使用已保存配置创建网络
  network join <16位直连码>       申请加入，批准后自动获取设置
  network join-code <16位直连码>  无需预设配置，批准后自动获取设置
  创建和加入可在末尾加 --ip <虚拟IPv4>，留空自动分配
  network invite <网络ID>         生成 16 位直连码
  network poll|reject|cancel|leave|withdraw|close|resume <网络ID>
  network approve <网络ID> <校验码>
  network rename <网络ID> <名称>  修改本机显示名称
  network remove-config <网络ID>  移除本机网络记录
  network remove <网络ID> <成员Slot>  撤销指定成员
  start|stop|retry <网络ID>       启动、暂停或重试指定连接
  可在命令前使用 --data <已存在的绝对目录> 选择后台数据目录。

使用同一后台用户操作（系统服务通常使用 sudo）。网络管理和本机协调是独立角色。
默认具备独立的协调服务能力；监听与证书可在本机设置的高级部分修改。
首次加入只需主机生成的直连码。旧版 network join <配置ID> <配对码/邀请> 仍供脚本兼容。
""");return;
    }
    if(args is ["remote-admin","set",var publicOrigin]){
        if(!Console.IsInputRedirected)throw new IOException("请将密码从受保护的标准输入传入，不要放在命令参数中");
        var chars=new char[258];int length=0;try{while(length<chars.Length){int n=await Console.In.ReadAsync(chars.AsMemory(length),stop.Token);if(n==0)break;length+=n;}if(length>=chars.Length)throw new IOException("密码输入过长");string password=new string(chars,0,length).TrimEnd('\r','\n');RemoteAdminConfig.Create(publicOrigin,password).Save(ProfileStore.Root);}finally{Array.Clear(chars);}
        Console.WriteLine("远程管理已配置；重启 ConWU 服务后生效。");return;
    }
    if(args is ["remote-admin","disable"]){string path=RemoteAdminConfig.FilePath(ProfileStore.Root);if(File.Exists(path)){if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("远程管理配置不能是链接");File.Delete(path);}Console.WriteLine("远程管理配置已移除；重启 ConWU 服务后生效。");return;}
    if(args[0]=="run") {
        using var worker=new ControlWorker(pairNetworks:true);WebPanel? panel=null,remotePanel=null;
        try {
            if(!args.Contains("--no-web")) {
                panel=await WebPanel.Start(worker.HandleLocalUi,Path.Combine(AppContext.BaseDirectory,"wwwroot"),port:WebPanel.DefaultPort);
                worker.OpenLocalPanel=panel.OpenLink;
            }
            var remoteConfig=RemoteAdminConfig.Load(ProfileStore.Root);
            if(remoteConfig!=null){remotePanel=await WebPanel.StartRemote(worker.HandleLocalUi,Path.Combine(AppContext.BaseDirectory,"wwwroot"),remoteConfig);worker.RemoteManagement=remotePanel.HandleRemoteRequest;}
            await worker.StartAsync(stop.Token);
            Console.WriteLine("ConWU 已启动。使用 conwu web 获取登录链接；使用 conwu status 查看状态。");
            try{await await Task.WhenAny(worker.ExecuteTask!,Task.Delay(Timeout.Infinite,stop.Token));}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        }finally {
            using var shutdown=new CancellationTokenSource(TimeSpan.FromSeconds(65));
            try{await worker.StopAsync(shutdown.Token);}finally{if(remotePanel!=null)await remotePanel.DisposeAsync();if(panel!=null)await panel.DisposeAsync();}
        }
        return;
    }
    if(args[0]=="web") {var result=await UnixControlProtocol.Call(new(OpenPanel:true),stop.Token);if(result.Error.Length>0)throw new IOException(result.Error);Console.WriteLine(result.Panel);return;}
    if(args[0]=="coordinator" && args.Length>=2 && args[1]!="status") {
        Print(CoordinationMaintenance.Execute(args[1..],Path.Combine(ProfileStore.Root,"coordination")));return;
    }
    var state=(await Call(new("status"))).Status??throw new IOException("后台状态尚未就绪");
    if(args is ["coordinator","status"]){Print(state.Coordinator??throw new IOException("协调状态尚未就绪"));return;}
    if(args[0]=="status"){Print(state);return;}
    if(args[0] is "start" or "stop" or "retry"){
        if(args.Length!=2)throw new ArgumentException("请明确填写网络配置 ID");
        var selected=await SelectNetwork(args[1]);Print(await Mutate(new UiControlRequest(args[0]){NetworkId=selected.SelectedNetworkId}));return;
    }
    if(args is ["profiles"]){Print(state.Configurations);return;}
    if(args[0]=="profile") {
        var parts=args.ToList();bool reconnect=parts.Remove("--reconnect");args=parts.ToArray();
        string verb=args.Length>1?args[1]:"";
        if(verb=="create"&&args.Length==4){
            var settings=JsonSerializer.Deserialize<UiNetworkSettings>(await File.ReadAllTextAsync(args[3],stop.Token),json)??throw new FormatException("配置内容为空");
            Print(await Mutate(new("configuration",Configuration:new("save",Name:args[2],Settings:settings))));return;
        }
        if(args.Length<3)throw new ArgumentException("用法：profile show/update/copy/delete/apply/assign <配置ID> ...");
        var config=state.Configurations.SingleOrDefault(c=>c.Id==args[2])??throw new IOException("未找到连接配置");
        if(verb=="show"&&args.Length==3){Print(config);return;}
        if(verb=="export"&&args.Length==3){Print(config.Settings);return;}
        UiConfigurationAction action=verb switch{
            "update" when args.Length==4=>new("save",config.Id,config.Name,config.Revision,JsonSerializer.Deserialize<UiNetworkSettings>(await File.ReadAllTextAsync(args[3],stop.Token),json),reconnect),
            "copy" when args.Length==4=>new("copy",config.Id,args[3],config.Revision),
            "delete" when args.Length==3=>new("delete",config.Id,ExpectedRevision:config.Revision),
            "apply" when args.Length==3=>new("apply",config.Id,ExpectedRevision:config.Revision,ConfirmReconnect:reconnect),
            "assign" when args.Length==4=>new("assign",config.Id,ExpectedRevision:config.Revision,ConfirmReconnect:reconnect),
            _=>throw new ArgumentException("配置命令参数无效；修改连接方式时显式添加 --reconnect")
        };
        Print(await Mutate(new UiControlRequest("configuration",Configuration:action){NetworkId=verb=="assign"?args[3]:""}));return;
    }
    if(args[0]=="config") {
        var shared=state.DeviceSettings??throw new IOException("本机设置尚未就绪");
        var settings=new JsonObject{["DeviceName"]=state.DeviceName,["LogLevel"]=state.LogLevel,["AutoStart"]=state.Desktop?.AutoStart??false,["Coordinator"]=JsonSerializer.SerializeToNode(shared.Coordinator,json)};
        if(args is ["config","show"]){Console.WriteLine(settings.ToJsonString(json));return;}
        if(args.Length!=3||args[1]!="apply")throw new ArgumentException("用法：config show 或 config apply 文件.json；连接参数请使用 profile 命令");
        var input=JsonNode.Parse(await File.ReadAllTextAsync(args[2],stop.Token)) as JsonObject??throw new FormatException("设置需要 JSON 对象");
        void Merge(JsonObject into,JsonObject source){foreach(var pair in source){if(!into.ContainsKey(pair.Key))throw new FormatException("未知本机设置字段："+pair.Key);if(pair.Value is JsonObject child&&into[pair.Key] is JsonObject target)Merge(target,child);else into[pair.Key]=pair.Value?.DeepClone();}}
        Merge(settings,input);string name=settings["DeviceName"]!.GetValue<string>(),level=settings["LogLevel"]!.GetValue<string>();bool auto=settings["AutoStart"]!.GetValue<bool>();
        var action=new UiNetworkAction("settings",Settings:shared with{Coordinator=settings["Coordinator"]!.Deserialize<CoordinatorSettings>(json)??throw new FormatException("协调监听设置为空"),Ddns=null},ExpectedRevision:state.DeviceSettingsRevision,ConfirmReplace:true){Patch=new(name,level,state.DeviceName,state.LogLevel),AutoStart=auto!=state.Desktop?.AutoStart?auto:null,ExpectedAutoStart=auto!=state.Desktop?.AutoStart?state.Desktop?.AutoStart:null};
        Print(await Mutate(new UiControlRequest("save-settings"){SettingsBatch=new(action,[])}));return;
    }
    if(args[0]=="network"&&args.Length>=2) {
        string virtualIp="";var networkArgs=args.ToList();int ipAt=networkArgs.IndexOf("--ip");if(ipAt>=0){if(ipAt<2||ipAt+2!=networkArgs.Count)throw new ArgumentException("--ip 需要放在命令末尾并填写虚拟 IPv4");virtualIp=networkArgs[ipAt+1];MeshAddressing.ValidateAddress(virtualIp);networkArgs.RemoveRange(ipAt,2);args=networkArgs.ToArray();}
        string verb=args[1];
        if(verb=="list"&&args.Length==2){Print(state.Networks.Select(n=>new{id=n.Id,profileId=n.ConfigurationId,name=n.Name,networkId=n.Status.NetworkId,role=n.Status.IsOwner?"host":"guest",enabled=n.Status.NetworkEnabled,virtualIp=n.Status.VirtualIp,state=n.Status.State}));return;}
        if(verb=="status"&&args.Length==3){Print(await SelectNetwork(args[2]));return;}
        if((verb is "join" or "join-code")&&args.Length==3){
            var compact=CompactDirectCode.Import(args[2]);
            Print(await Mutate(new UiControlRequest("network",Network:new("join-compact",Code:args[2],Mode:compact.Mode){AutoConfigure=true,RequestedVirtualIp=virtualIp})));return;
        }
        if(verb is "create" or "join"){
            if(args.Length<3||args.Length>4||verb=="join"&&args.Length!=4)throw new ArgumentException("用法：network create <配置ID> [名称] 或 network join <配置ID> <配对码/邀请>");
            var config=state.Configurations.SingleOrDefault(c=>c.Id==args[2])??throw new IOException("请选择已保存的连接配置");var template=config.Settings;
            string value=verb=="join"?args[3]:"";
            if(!template.DirectMode&&string.IsNullOrWhiteSpace(template.Service))throw new IOException("请在配置中填写 HTTPS 协调服务，或选择无协调的直连邀请");
            string enrollmentAction=verb=="create"?(template.DirectMode?"create-direct":"create"):value.Length==6&&value.All(char.IsAsciiDigit)?(template.ConnectionSource=="existing"?"join-direct-short":"join"):value.StartsWith("SL6.")?"join-invitation":"join-entry";
            if(verb=="join"&&template.DirectMode&&template.ConnectionSource!="existing"&&enrollmentAction!="join-invitation")throw new IOException("无协调的自主入口请使用主机生成的直连邀请");
            var request=new UiNetworkAction(enrollmentAction,template.Service,template.CertificatePin,enrollmentAction is "join-entry" or "create" or "create-direct"?"":value,Mode:TransportModes.Mode(template.PathSelection)){LocalEnrollment=verb=="create",RequestedVirtualIp=virtualIp,ConfigurationId=config.Id,Name=verb=="create"&&args.Length==4?args[3]:"",Entry=enrollmentAction=="join-entry"?value:""};
            Print(await Mutate(new UiControlRequest("network",Network:request)));return;
        }
        bool needsValue=verb is "approve" or "rename" or "remove";
        if(args.Length!=(needsValue?4:3))throw new ArgumentException("请填写明确的网络配置 ID 和所需参数");
        string id=args[2],valueArg=needsValue?args[3]:"";var chosen=await SelectNetwork(id);
        string command=verb switch{"invite"=>"invite-compact","pair-code"=>"invite-code","poll"=>"pair-poll","approve"=>"approve","reject"=>"reject","cancel"=>"pair-cancel","leave"=>"forget-network","withdraw"=>"leave","close"=>"delete-network","remove"=>"revoke","resume"=>"membership-resume","rename"=>"rename-network","remove-config"=>"remove-network",_=>throw new ArgumentException("未知网络操作")};
        if(verb=="approve"&&(chosen.Pairing?.Verification!=valueArg||valueArg.Length==0))throw new IOException("校验码不匹配，请先查询该网络申请并与对端核对");
        int slot=0;if(verb=="remove"&&(!int.TryParse(valueArg,out slot)||slot<1))throw new ArgumentException("请填写成员 Slot");
        var action=new UiNetworkAction(command,ExpectedNetwork:chosen.NetworkId,ConfirmReplace:true,Verification:verb=="approve"?valueArg:"",Candidate:chosen.Pairing?.Candidate??"",PeerSlot:slot,ProposedIp:chosen.Pairing?.ProposedIp??""){Name=verb=="rename"?valueArg:""};
        Print(await Mutate(new UiControlRequest("network",Network:action){NetworkId=id}));return;
    }
    throw new ArgumentException("未知命令，请运行 conwu help");
}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
catch(Exception ex){Console.Error.WriteLine(ex.Message);Environment.ExitCode=1;}
