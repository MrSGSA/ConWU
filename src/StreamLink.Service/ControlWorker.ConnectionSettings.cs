using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    internal async Task SuspendForConfiguration(CancellationToken token)
    {
        await requests.WaitAsync(token);try{await End(token);}finally{requests.Release();}
    }
    internal static DeviceProfile PrepareConnectionSettings(DeviceProfile before,UiNetworkSettings settings)
    {
        settings=ConnectionSettings.Normalize(settings);
        var previous=PublicSettings(before);
        if(before.Mesh is {} mesh&&(settings.DirectMode!=mesh.Pair.Direct||!mesh.Pair.Direct&&(settings.Service!=previous.Service||settings.CertificatePin!=previous.CertificatePin)))
            throw new IOException("当前网络的协调身份不能直接替换，请先退出该网络再用新配置配对；其他网络和设置保留");
        var updated=ProfileChanges.Copy(before);
        ConnectionSettings.Apply(updated,settings);
        updated.Coordinator=before.Coordinator;
        updated.Ddns=new();updated.CloudflareDdnsToken="";
        if(updated.Mesh!=null){
            updated.DirectMode=updated.Mesh.Pair.Direct;
            updated.SavedPeerEntryNetwork=updated.Mesh.Pair.Network;
            updated.ExistingEntries=RuntimeEntries(updated);
        }
        updated.Validate();updated.RequireFixedTransport();return updated;
    }
}
