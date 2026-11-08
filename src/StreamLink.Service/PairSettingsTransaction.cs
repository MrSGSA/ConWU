using StreamLink.Core;

namespace StreamLink.Service;

// A crash before Commit rolls back settings only. Membership high-water marks
// and independently completed approvals must never be restored from this file.
internal sealed record PairSettingsTransaction(string ConfigurationId,DeviceProfile Device,DeviceProfile Network,bool? AutoStartBefore=null,bool RestoreStartup=false)
{
    internal const string FileName="settings-transaction.protected";
    internal static DeviceProfile SettingsOnly(DeviceProfile current,DeviceProfile before)
    {
        var restored=ProfileChanges.Copy(before);
        restored.Mesh=current.Mesh;restored.Pair=current.Pair;restored.Enabled=current.Enabled;
        restored.PendingMembership=current.PendingMembership;restored.RejoinCredential=current.RejoinCredential;restored.RejoinHistory=current.RejoinHistory;
        restored.NetworkCreatedHere=current.NetworkCreatedHere;restored.NetworkEstablishedAt=current.NetworkEstablishedAt;
        restored.JoinedEntryNetwork=current.JoinedEntryNetwork;restored.JoinedEntrySources=current.JoinedEntrySources;
        restored.AutoConfigureJoin=current.AutoConfigureJoin;restored.ReceivedNetworkSettings=current.ReceivedNetworkSettings;
        restored.PkarrSeed=current.PkarrSeed;restored.PkarrSequence=current.PkarrSequence;
        restored.LastStun=current.LastStun;restored.LastEntry=current.LastEntry;
        restored.ExistingEntries=ControlWorker.RuntimeEntries(restored);return restored;
    }
    internal static void Recover(ProfileStore store)
    {
        var pending=store.ReadPrivate<PairSettingsTransaction>(FileName);if(pending==null)return;
        if(!Guid.TryParseExact(pending.ConfigurationId,"N",out _))throw new IOException("设置恢复记录的网络身份无效");
        var target=new ProfileStore(Path.Combine(store.DirectoryPath,"networks",pending.ConfigurationId),store);
        target.Save(SettingsOnly(target.Load(),pending.Network));
        store.Save(SettingsOnly(store.Load(),pending.Device));
        if(pending.RestoreStartup&&pending.AutoStartBefore is {} startup&&StartupSettings.Read().AutoStart!=startup)StartupSettings.Set(startup);
        store.DeletePrivate(FileName);
    }
}
