using StreamLink.Core;

namespace StreamLink.Service;

internal sealed record PairBatchSettingsTransaction(DeviceProfile Device,Dictionary<string,DeviceProfile> Networks,bool AutoStartBefore,bool RestoreStartup=false)
{
    internal const string FileName="settings-batch-transaction.protected";
    internal static void Recover(ProfileStore store)
    {
        var pending=store.ReadPrivate<PairBatchSettingsTransaction>(FileName);if(pending==null)return;
        if(pending.Networks is not {Count:<=16})throw new IOException("批量设置恢复记录无效");
        foreach(var pair in pending.Networks){
            if(!Guid.TryParseExact(pair.Key,"N",out _))throw new IOException("批量设置恢复的网络身份无效");
            var target=new ProfileStore(Path.Combine(store.DirectoryPath,"networks",pair.Key),store);
            target.Save(PairSettingsTransaction.SettingsOnly(target.Load(),pair.Value));
        }
        store.Save(PairSettingsTransaction.SettingsOnly(store.Load(),pending.Device));
        if(pending.RestoreStartup&&StartupSettings.Read().AutoStart!=pending.AutoStartBefore)StartupSettings.Set(pending.AutoStartBefore);
        store.DeletePrivate(FileName);
    }
}
