using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

internal sealed partial class PairNetworkWorkspace
{
    const string ConfigurationFile="connection-configurations.protected";
    const int MaximumConfigurations=32;
    readonly ConcurrentDictionary<string,ConnectionConfiguration> configurations=new(StringComparer.Ordinal);
    readonly ConcurrentDictionary<string,string> configurationErrors=new(StringComparer.Ordinal);
    Dictionary<string,DeviceProfile>? validatingConfigurations;

    bool configurationCatalogInitialized;
    void LoadConfigurations()
    {
        var stored=store.ReadPrivate<ConnectionConfiguration[]>(ConfigurationFile);configurationCatalogInitialized=stored!=null;var saved=stored??[];
        if(JsonSerializer.SerializeToUtf8Bytes(saved).Length>262144)throw new IOException("配置库超过 256 KiB，请减少已保存的配置内容");
        if(saved.Length>MaximumConfigurations)throw new IOException("已保存的连接配置超过上限");
        foreach(var item in saved){
            ValidateConfigurationId(item.Id);ValidateName(item.Name);
            if(item.Revision<1||!configurations.TryAdd(item.Id,item with{Settings=ConnectionSettings.Normalize(item.Settings)}))throw new IOException("连接配置版本或身份无效");
        }
    }
    static void ValidateConfigurationId(string id){if(!Guid.TryParseExact(id,"N",out _))throw new FormatException("连接配置 ID 无效");}
    void PersistConfigurations(){var catalog=configurations.Values.OrderBy(c=>c.Id,StringComparer.Ordinal).ToArray();if(JsonSerializer.SerializeToUtf8Bytes(catalog).Length>262144)throw new IOException("配置库超过 256 KiB，请减少已保存的配置内容");store.WritePrivate(ConfigurationFile,catalog);configurationCatalogInitialized=true;}
    static UiNetworkSettings MigrateConfiguration(UiNetworkSettings settings)=>settings with{
        Coordinator=new(),Ddns=null,RequestedVirtualIp="",ExistingEntries=settings.ExistingEntries.Where(e=>!e.Source.StartsWith("conwu-ddns:",StringComparison.OrdinalIgnoreCase))
            .Select(e=>e with{PeerSlot=e.PeerSlot==0?0:ExistingEntry.NetworkOwner}).Distinct().ToArray()
    };
    void EnsureConfiguration(Context context)
    {
        if(context.Info.ConfigurationId.Length>0){if(!configurations.ContainsKey(context.Info.ConfigurationId))throw new IOException("网络引用的连接配置不存在："+context.Info.Name);return;}
        var settings=ConnectionSettings.Normalize(MigrateConfiguration(context.Worker.SingleUiSnapshot().Settings!));
        // Stable migration key makes interrupted migration repeatable. Equal
        // settings never silently establish a shared reference.
        var config=new ConnectionConfiguration(context.Info.Id,context.Info.Name,1,settings);
        configurations.TryAdd(config.Id,config);PersistConfigurations();
        context.Info=context.Info with{ConfigurationId=config.Id,AppliedConfigurationRevision=1};WriteInfo(context);
    }
    void EnsureInitialConfiguration()
    {
        if(configurations.Count>0||configurationCatalogInitialized)return;
        var initial=new ConnectionConfiguration(Guid.NewGuid().ToString("N"),"默认连接",1,ConnectionSettings.Normalize(MigrateConfiguration(device.SingleUiSnapshot().Settings!)));
        configurations[initial.Id]=initial;PersistConfigurations();
    }
    UiConfigurationDto[] ConfigurationSnapshot()=>configurations.Values.OrderBy(c=>c.Name,StringComparer.Ordinal).ThenBy(c=>c.Id,StringComparer.Ordinal)
        .Select(c=>new UiConfigurationDto(c.Id,c.Name,c.Revision,c.Settings,networks.Values.Where(n=>n.Info.ConfigurationId==c.Id).OrderBy(n=>n.Info.Id,StringComparer.Ordinal)
            .Select(n=>new UiConfigurationUse(n.Info.Id,n.Info.Name,n.Worker.SingleUiSnapshot().NetworkEnabled,
                n.Info.AppliedConfigurationRevision==c.Revision?"applied":configurationErrors.ContainsKey(n.Info.Id)?"failed":"pending",configurationErrors.GetValueOrDefault(n.Info.Id)??"")).ToArray())).ToArray();

    UiNetworkSettings EffectiveConfiguration(Context target,ConnectionConfiguration desired,IReadOnlyDictionary<string,DeviceProfile>? proposed=null)
    {
        var prior=target.Worker.ProfileSnapshot();int source=prior.SourcePort;
        var old=configurations.GetValueOrDefault(target.Info.ConfigurationId);
        if(old==null||old.Settings.SourcePort!=desired.Settings.SourcePort)source=desired.Settings.SourcePort;
        var others=(proposed??networks.ToDictionary(p=>p.Key,p=>p.Value.Worker.ProfileSnapshot())).Where(p=>p.Key!=target.Info.Id).Select(p=>p.Value).ToArray();
        while(source==desired.Settings.ListenPort||others.Any(p=>p.ListenPort==source||p.SourcePort==source)){if(source>65533)throw new IOException("没有空闲的源端口，请调整配置");source+=2;}
        return desired.Settings with{SourcePort=source,RequestedVirtualIp=prior.RequestedVirtualIp};
    }
    void PrepareConfigurationAtStartup(Information info,ProfileStore networkStore)
    {
        if(info.ConfigurationId.Length==0)return;
        if(!configurations.TryGetValue(info.ConfigurationId,out var config))throw new IOException("网络引用的连接配置不存在："+info.Name);
        if(info.AppliedConfigurationRevision==config.Revision)return;
        var before=networkStore.Load();var effective=config.Settings with{SourcePort=before.SourcePort};
        int source=config.Settings.SourcePort;
        while(source==config.Settings.ListenPort||networks.Values.Any(n=>n.Worker.ProfileSnapshot() is {} p&&(p.ListenPort==source||p.SourcePort==source))){if(source>65533)throw new IOException("没有空闲的网络源端口");source+=2;}
        effective=effective with{SourcePort=source,RequestedVirtualIp=before.RequestedVirtualIp};
        var updated=ControlWorker.PrepareConnectionSettings(before,effective);
        networkStore.Save(updated);
    }
    async Task<UiControlReply> ApplyConfiguration(Context context,ConnectionConfiguration config,string sid,Guid operationId,bool confirm,CancellationToken token,UiNetworkSettings? effective=null)
    {
        var action=new UiNetworkAction("settings",Settings:effective??EffectiveConfiguration(context,config),ExpectedRevision:context.Worker.SingleUiSnapshot().SettingsRevision,ConfirmReplace:confirm);
        var id=new Guid(SHA256.HashData(operationId.ToByteArray().Concat(System.Text.Encoding.ASCII.GetBytes(context.Info.Id)).ToArray()).AsSpan(0,16));
        var reply=await context.Worker.HandleSingleUi(new("network",OperationId:id,Network:action),sid,token);
        var until=DateTimeOffset.UtcNow.AddSeconds(100);
        while(reply.Operation is {Completed:false}){
            if(DateTimeOffset.UtcNow>until)throw new IOException("网络应用配置仍待确认，请查看该网络状态并重试应用");
            await Task.Delay(40,token);reply=await context.Worker.HandleSingleUi(new("status",OperationId:id),sid,token);
        }
        if(reply.Ok){context.Info=context.Info with{AppliedConfigurationRevision=config.Revision};WriteInfo(context);configurationErrors.TryRemove(context.Info.Id,out _);}
        return reply;
    }
    async Task<UiControlReply> HandleConfiguration(UiControlRequest request,string sid,CancellationToken token)
    {
        var action=request.Configuration??throw new FormatException("连接配置操作为空");
        if(action.Settings?.RequestedVirtualIp is {Length:>0})throw new FormatException("虚拟地址属于单条网络，请在创建或加入时指定，不保存在共用配置中");
        if(action.Id==null||action.Name==null)throw new FormatException("连接配置名称和身份不能为空");
        if(request.Network!=null||request.SettingsBatch!=null||request.Patch!=null)throw new FormatException("连接配置不能混入其他设置操作");
        if(action.Action is not ("save" or "copy" or "delete" or "assign" or "apply"))throw new FormatException("连接配置操作无效");
        bool creationHeld=false,sharedHeld=false,committed=false;var held=new List<Context>();
        try{
            await WaitGate(creating,request.OperationId,token);creationHeld=true;
            // The same ordering as batch settings: network gates, then shared.
            foreach(var context in networks.Values.OrderBy(n=>n.Info.Id,StringComparer.Ordinal)){
                await WaitGate(context.Actions,request.OperationId,token);held.Add(context);
            }
            await WaitGate(sharedSettings,request.OperationId,token);sharedHeld=true;ActiveOperation(request.OperationId);
            ConnectionConfiguration? previous=null;
            if(action.Id.Length>0){ValidateConfigurationId(action.Id);previous=configurations.GetValueOrDefault(action.Id)??throw new IOException("连接配置已被删除");if(previous.Revision!=action.ExpectedRevision)throw new IOException("此配置已被其他窗口修改，草稿保留，请核对后重试");}
            if(action.Action is not "save"&&previous==null)throw new FormatException("请选择一份已保存配置");
            var users=held.Where(n=>networks.ContainsKey(n.Info.Id)&&n.Info.ConfigurationId==action.Id).ToArray();
            if(action.Action=="delete"){
                if(users.Length>0)throw new IOException("配置仍用于："+string.Join("、",users.Select(n=>n.Info.Name))+"；请先更换配置或移除网络");
                configurations.TryRemove(action.Id,out _);try{PersistConfigurations();}catch{configurations[action.Id]=previous!;throw;}
                return ConfigurationReply(request);
            }
            if(action.Action=="copy"||previous==null){
                if(configurations.Count>=MaximumConfigurations)throw new IOException("最多保存 32 份连接配置，请先删除不用的配置");
                ValidateName(action.Name);var incoming=action.Settings??previous?.Settings??throw new FormatException("配置内容为空");if(action.Action!="copy")incoming=incoming with{DirectMode=incoming.ConnectionSource=="existing"||incoming.DirectMode};var item=new ConnectionConfiguration(Guid.NewGuid().ToString("N"),action.Name,1,ConnectionSettings.Normalize(incoming));
                configurations[item.Id]=item;try{PersistConfigurations();}catch{configurations.TryRemove(item.Id,out _);throw;}
                return ConfigurationReply(request,item.Id);
            }
            var desired=previous!;
            if(action.Action=="save"){ValidateName(action.Name);desired=desired with{Name=action.Name,Revision=checked(desired.Revision+1),Settings=ConnectionSettings.Normalize(action.Settings is {} proposed?proposed with{DirectMode=proposed.ConnectionSource=="existing"||proposed.DirectMode}:throw new FormatException("配置内容为空"))};}
            Context? assigned=null;
            if(action.Action=="assign"){
                assigned=held.FirstOrDefault(n=>n.Info.Id==request.NetworkId&&networks.ContainsKey(n.Info.Id))??throw new IOException("请选择仍存在的网络");users=[assigned];
            }
            var prepared=held.Where(n=>networks.ContainsKey(n.Info.Id)).ToDictionary(n=>n.Info.Id,n=>n.Worker.ProfileSnapshot(),StringComparer.Ordinal);
            var effective=new Dictionary<string,UiNetworkSettings>(StringComparer.Ordinal);
            foreach(var context in users){
                var settings=EffectiveConfiguration(context,desired,prepared);effective[context.Info.Id]=settings;
                var current=prepared[context.Info.Id];var candidate=ControlWorker.PrepareConnectionSettings(current,settings);prepared[context.Info.Id]=candidate;
                if(current.Enabled&&ProfileChanges.Impact(current,candidate)==ProfileChangeImpact.RestartNetwork&&!action.ConfirmReconnect)throw new IOException("保存会重连网络："+string.Join("、",users.Select(n=>n.Info.Name))+"；请确认影响后保存");
            }
            validatingConfigurations=prepared;
            try{foreach(var context in users)ValidateNetwork(context.Info.Id,prepared[context.Info.Id]);}finally{validatingConfigurations=null;}
            if(action.Action=="save"){
                configurations[desired.Id]=desired;try{PersistConfigurations();committed=true;}catch{configurations[previous.Id]=previous;throw;}
            }
            if(assigned!=null){var before=assigned.Info;assigned.Info=before with{ConfigurationId=desired.Id,AppliedConfigurationRevision=0};try{WriteInfo(assigned);committed=true;}catch{assigned.Info=before;throw;}}
            var failures=new List<string>();
            // Release every affected old shared listener before any consumer
            // opens the new protocol or port. Runtime ownership is not shared
            // configuration ownership.
            foreach(var context in users){var before=context.Worker.ProfileSnapshot();if(before.Enabled&&ProfileChanges.Impact(before,prepared[context.Info.Id])==ProfileChangeImpact.RestartNetwork)await context.Worker.SuspendForConfiguration(token);}
            validatingConfigurations=prepared;
            foreach(var context in users){
                try{var applied=await ApplyConfiguration(context,desired,sid,request.OperationId,action.ConfirmReconnect,token,effective[context.Info.Id]);if(!applied.Ok)throw new IOException(applied.Error);}
                catch(Exception ex)when(ex is IOException or FormatException or OperationCanceledException){string reason=ex is OperationCanceledException?"应用尚未完成，请重试应用":ex.Message;configurationErrors[context.Info.Id]=reason;failures.Add(context.Info.Name+"："+reason);}
            }
            return failures.Count==0?ConfigurationReply(request,desired.Id):new(false,"配置已保存，部分网络尚未应用："+string.Join("；",failures),Snapshot(request.NetworkId),Operation:new(request.OperationId,"configuration","部分网络尚未应用",true,false,"请查看配置关联状态"));
        }catch(Exception ex)when(committed&&ex is IOException or FormatException or OperationCanceledException){return new(false,"配置已保存，应用尚未完成："+(ex is OperationCanceledException?"请查看关联状态并重试应用":ex.Message),Snapshot(request.NetworkId),Operation:new(request.OperationId,"configuration","应用尚未完成",true,false,"请重试应用"));}
        finally{validatingConfigurations=null;if(sharedHeld)sharedSettings.Release();for(int i=held.Count-1;i>=0;i--)held[i].Actions.Release();if(creationHeld)creating.Release();}
    }
    UiControlReply ConfigurationReply(UiControlRequest request,string id="")=>new(true,"",Snapshot(request.NetworkId),Operation:new(request.OperationId,"configuration","已完成",true,false)){ConfigurationId=id};
}
