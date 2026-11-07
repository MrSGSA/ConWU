using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

internal sealed partial class PairNetworkWorkspace
{
    async Task<UiControlReply> SaveBatch(UiControlRequest request,string sid,CancellationToken token)
    {
        var batch=request.SettingsBatch??throw new FormatException("批量设置为空");
        if(request.Network!=null||request.Patch!=null||batch.Networks is not {Length:<=16}||batch.Device==null&&batch.Networks.Length==0)throw new FormatException("批量设置参数无效");
        if(batch.Networks.Any(n=>n==null||!Guid.TryParseExact(n.NetworkId,"N",out _)||n.Action?.Action!="settings"||n.Action.Settings==null)||batch.Networks.Select(n=>n.NetworkId).Distinct(StringComparer.Ordinal).Count()!=batch.Networks.Length)throw new FormatException("批量设置的网络目标无效或重复");
        if(batch.Device is {} deviceAction&&(deviceAction.Action!="settings"||deviceAction.Settings==null))throw new FormatException("设备设置操作无效");
        Guid id=request.OperationId==Guid.Empty?Guid.NewGuid():request.OperationId;
        string digest=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(request)));
        var operation=new SettingOperation(digest,id);
        if(!settingOperations.TryAdd(id,operation)){
            var prior=settingOperations[id];if(prior.Digest!=digest)throw new IOException("操作ID已用于另一项设置");return await prior.Completion.Task;
        }
        operationNetworks[id]=request.NetworkId;
        var held=new List<Context>();bool sharedHeld=false,journaled=false;PairBatchSettingsTransaction? transaction=null;
        UiControlReply result;
        try{
            // All batch writers acquire network gates in the same order before
            // the shared gate, matching single-network settings transactions.
            foreach(var change in batch.Networks.OrderBy(n=>n.NetworkId,StringComparer.Ordinal)){
                if(!networks.TryGetValue(change.NetworkId,out var context))throw new IOException("网络配置已被移除："+change.NetworkId);
                await WaitGate(context.Actions,request.OperationId,token);held.Add(context);
                if(!networks.TryGetValue(change.NetworkId,out var current)||current!=context)throw new IOException("网络配置已被移除");
            }
            await WaitGate(sharedSettings,request.OperationId,token);sharedHeld=true;ActiveOperation(request.OperationId);
            var beforeDevice=device.ProfileSnapshot();var deviceStatus=device.SingleUiSnapshot();
            if(batch.Device!=null&&batch.Device.ExpectedRevision!=deviceStatus.SettingsRevision)throw new IOException("设备设置已被其他窗口修改，请核对全部草稿后重试");
            foreach(var change in batch.Networks){
                var context=held.Single(n=>n.Info.Id==change.NetworkId);var action=change.Action;
                if(action.ExpectedRevision!=context.Worker.SingleUiSnapshot().SettingsRevision)throw new IOException("网络“"+context.Info.Name+"”的设置已改变，未保存任何草稿");
                if(action.DdnsToken!=null||action.ClearDdnsToken||action.AutoStart!=null||action.ExpectedAutoStart!=null||action.Patch?.DeviceName!=null||action.Patch?.LogLevel!=null)throw new FormatException("共享设备设置只能在批量 Device 项中保存");
            }
            bool startupBefore=StartupSettings.Read().AutoStart;
            transaction=new(beforeDevice,held.ToDictionary(n=>n.Info.Id,n=>n.Worker.ProfileSnapshot()),startupBefore,batch.Device?.AutoStart is {} startup&&startup!=startupBefore);
            store.WritePrivate(PairBatchSettingsTransaction.FileName,transaction);journaled=true;
            foreach(var change in batch.Networks){
                var context=held.Single(n=>n.Info.Id==change.NetworkId);
                var local=change.Action with{Settings=change.Action.Settings! with{Coordinator=new(),Ddns=beforeDevice.Ddns}};
                Guid subId=new(SHA256.HashData(id.ToByteArray().Concat(System.Text.Encoding.ASCII.GetBytes(change.NetworkId)).ToArray()).AsSpan(0,16));
                var saved=await context.Worker.HandleSingleUi(new("network",OperationId:subId,Network:local),sid,token);if(!saved.Ok)throw new IOException("网络“"+context.Info.Name+"”："+saved.Error);
            }
            if(batch.Device is {} common){
                Guid subId=new(SHA256.HashData(id.ToByteArray().Concat("device-batch"u8.ToArray()).ToArray()).AsSpan(0,16));
                var saved=await device.HandleSingleUi(new("network",OperationId:subId,Network:common),sid,token);if(!saved.Ok)throw new IOException(saved.Error);
            }
            foreach(var context in networks.Values)context.Worker.RefreshSharedSettings();
            store.DeletePrivate(PairBatchSettingsTransaction.FileName);journaled=false;
            operation.State=new(id,"save-settings","全部设置已保存",true,false);
            result=new(true,"",Snapshot(request.NetworkId) with{Operation=operation.State},Operation:operation.State);
        }catch(Exception ex){
            string error=ex is OperationCanceledException?"批量保存已取消":ex.Message;
            if(journaled&&transaction!=null){
                try{
                    foreach(var context in held)await context.Worker.RestoreSettings(transaction.Networks[context.Info.Id],CancellationToken.None);
                    await device.RestoreSettings(transaction.Device,CancellationToken.None);
                    if(transaction.RestoreStartup&&StartupSettings.Read().AutoStart!=transaction.AutoStartBefore)StartupSettings.Set(transaction.AutoStartBefore);
                    foreach(var context in networks.Values)context.Worker.RefreshSharedSettings();
                    store.DeletePrivate(PairBatchSettingsTransaction.FileName);error+="；此次全部草稿均未保存";
                }catch(Exception rollback){error+="；恢复尚未完成，事务记录已保留，请保留日志并重启后台："+rollback.GetType().Name;}
            }
            operation.State=new(id,"save-settings","未完成",true,false,error);
            result=new(false,error,Snapshot(request.NetworkId) with{Operation=operation.State},Operation:operation.State);
        }finally{
            if(sharedHeld)sharedSettings.Release();for(int index=held.Count-1;index>=0;index--)held[index].Actions.Release();
        }
        operation.Completion.TrySetResult(result);
        if(settingOperations.Count>64)foreach(var pair in settingOperations.ToArray().Where(p=>p.Value.State.Completed&&p.Key!=id).Take(16))settingOperations.TryRemove(pair.Key,out _);
        return result;
    }
}
