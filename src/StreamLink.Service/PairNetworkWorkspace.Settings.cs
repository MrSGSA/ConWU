using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

internal sealed partial class PairNetworkWorkspace
{
    sealed class SettingOperation(string digest,Guid id)
    {
        public string Digest {get;}=digest;
        public TaskCompletionSource<UiControlReply> Completion {get;}=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ControlOperationStatus State=new(id,"settings","保存网络与共享设置",false,false);
    }
    readonly SemaphoreSlim sharedSettings=new(1,1);
    readonly System.Collections.Concurrent.ConcurrentDictionary<Guid,SettingOperation> settingOperations=new();
    async Task<UiControlReply> SaveSettings(Context target,UiControlRequest request,string sid,CancellationToken token)
    {
        Guid id=request.OperationId==Guid.Empty?Guid.NewGuid():request.OperationId;
        string digest=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(request)));
        var operation=new SettingOperation(digest,id);
        if(!settingOperations.TryAdd(id,operation)){
            var prior=settingOperations[id];if(prior.Digest!=digest)throw new IOException("操作ID已被不同设置使用");
            return await prior.Completion.Task;
        }
        operationNetworks[id]=target.Info.Id;
        UiControlReply result;
        bool acquired=false;
        try{
            await WaitGate(sharedSettings,request.OperationId,token);acquired=true;
            var action=request.Network!;var proposed=action.Settings??throw new FormatException("设置为空");
            var beforeDevice=device.ProfileSnapshot();var beforeNetwork=target.Worker.ProfileSnapshot();var defaultStatus=device.SingleUiSnapshot();
            bool sharedChanged=JsonSerializer.Serialize(proposed.Coordinator)!=JsonSerializer.Serialize(beforeDevice.Coordinator)||
                proposed.Ddns!=null&&proposed.Ddns!=beforeDevice.Ddns||action.DdnsToken!=null||action.ClearDdnsToken||action.AutoStart!=null||
                action.Patch?.DeviceName is {} name&&name!=beforeDevice.DeviceName||action.Patch?.LogLevel is {} level&&level!=beforeDevice.LogLevel;
            if(sharedChanged&&action.ExpectedDeviceRevision!=defaultStatus.SettingsRevision)throw new IOException("共享设置已变化或缺少版本信息；草稿保留，请核对后重新保存");
            if(action.ExpectedRevision!=target.Worker.SingleUiSnapshot().SettingsRevision)throw new IOException("此网络设置已改变；请核对后重新保存");
            var localSettings=proposed with{Coordinator=new(),Ddns=beforeDevice.Ddns};
            UiConfigPatch? localPatch=action.Patch?.RequestedVirtualIp is {} ip?new(){RequestedVirtualIp=ip,ExpectedVirtualIp=action.Patch.ExpectedVirtualIp}:null;
            var local=action with{Settings=localSettings,Patch=localPatch,AutoStart=null,ExpectedAutoStart=null,DdnsToken=null,ClearDdnsToken=false};
            bool startupBefore=StartupSettings.Read().AutoStart,restoreStartup=action.AutoStart is {} startup&&startup!=startupBefore;
            store.WritePrivate(PairSettingsTransaction.FileName,new PairSettingsTransaction(target.Info.Id,beforeDevice,beforeNetwork,startupBefore,restoreStartup));
            try{
                result=await target.Worker.HandleSingleUi(request with{NetworkId="",Network=local},sid,token);
                if(!result.Ok)throw new IOException(result.Error);
                if(sharedChanged){
                    UiConfigPatch? commonPatch=action.Patch is {} patch&&(patch.DeviceName!=null||patch.LogLevel!=null)?new(patch.DeviceName,patch.LogLevel,patch.ExpectedDeviceName,patch.ExpectedLogLevel):null;
                    var common=new UiNetworkAction("settings",Settings:defaultStatus.Settings! with{Coordinator=proposed.Coordinator,Ddns=proposed.Ddns??beforeDevice.Ddns},ExpectedRevision:defaultStatus.SettingsRevision,ConfirmReplace:true){
                        Patch=commonPatch,AutoStart=action.AutoStart,ExpectedAutoStart=action.ExpectedAutoStart,DdnsToken=action.DdnsToken,ClearDdnsToken=action.ClearDdnsToken
                    };
                    byte[] input=id.ToByteArray().Concat("device"u8.ToArray()).ToArray();Guid commonId=new(SHA256.HashData(input).AsSpan(0,16));
                    var saved=await device.HandleSingleUi(new("network",OperationId:commonId,Network:common),sid,token);
                    if(!saved.Ok)throw new IOException(saved.Error);
                }
                foreach(var context in networks.Values)context.Worker.RefreshSharedSettings();
                store.DeletePrivate(PairSettingsTransaction.FileName);
            }catch{
                // These restores merge with current membership and runtime state.
                // Keep the journal if rollback fails so restart can finish it.
                await target.Worker.RestoreSettings(beforeNetwork,CancellationToken.None);
                await device.RestoreSettings(beforeDevice,CancellationToken.None);
                if(restoreStartup&&StartupSettings.Read().AutoStart!=startupBefore)StartupSettings.Set(startupBefore);
                foreach(var context in networks.Values)context.Worker.RefreshSharedSettings();
                store.DeletePrivate(PairSettingsTransaction.FileName);throw;
            }
            operation.State=new(id,"settings","已完成",true,false);
            result=new(true,"",Snapshot(target.Info.Id) with{Operation=operation.State},Operation:operation.State);
        }catch(Exception ex){
            string error=ex is OperationCanceledException?"设置保存已取消，原设置保留":ex.Message;
            operation.State=new(id,"settings","未完成",true,false,error);
            result=new(false,error,Snapshot(target.Info.Id) with{Operation=operation.State},Operation:operation.State);
        }finally{if(acquired)sharedSettings.Release();}
        operation.Completion.TrySetResult(result);
        if(settingOperations.Count>64)foreach(var pair in settingOperations.ToArray().Where(p=>p.Value.State.Completed&&p.Key!=id).Take(16))settingOperations.TryRemove(pair.Key,out _);
        return result;
    }
}
