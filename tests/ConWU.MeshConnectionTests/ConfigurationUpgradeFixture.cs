using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    // Only used after the isolated MSI service is stopped. No adapter, listener
    // or public coordination request is started by this fixture.
    static void SeedConfigurationUpgrade(string instance)
    {
        WindowsInstance.ConfigureValidation(instance);var store=new ProfileStore();
        using var ownership=new FileStream(Path.Combine(store.DirectoryPath,"runtime.lock"),FileMode.Open,FileAccess.ReadWrite,FileShare.None);
        var root=store.Load();if(root.Mesh!=null||root.NodeSigningPrivate.Length==0)throw new IOException("需要已初始化且没有旧单网络的隔离实例");
        root.DeviceName="MSI 设置检查";root.LogLevel="warn";store.Save(root);
        string configurationId=Guid.NewGuid().ToString("N"),networkId=Guid.NewGuid().ToString("N");
        var settings=ConnectionSettings.Normalize(new(){ConnectionSource="existing",DirectMode=true,ListenPort=46180,SourcePort=46191,ExistingEntries=[new(0,"https://entry.example.com/current#streamlink1")],EntryRefreshSeconds=120});
        var catalog=store.ReadPrivate<ConnectionConfiguration[]>("connection-configurations.protected")??[];
        store.WritePrivate("connection-configurations.protected",catalog.Append(new ConnectionConfiguration(configurationId,"升级保留配置",1,settings)).ToArray());
        var profile=ProfileChanges.Copy(root);ConnectionSettings.Apply(profile,settings);profile.Coordinator=new();profile.Enabled=false;profile.AdapterScope=networkId;
        profile.Mesh=MeshIdentity.Create("","","faketcp",direct:true,pairwise:true,deviceId:root.Device);profile.NetworkCreatedHere=true;profile.NetworkEstablishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var child=new ProfileStore(Path.Combine(store.DirectoryPath,"networks",networkId),store);child.Save(profile);
        File.WriteAllBytes(Path.Combine(child.DirectoryPath,"network-info.json"),JsonSerializer.SerializeToUtf8Bytes(new{Id=networkId,Name="保留网络",Removed=false,PendingEnrollment=false,ConfigurationId=configurationId,AppliedConfigurationRevision=1L}));
        Console.WriteLine("PASS 已写入停止状态的隔离升级配置；未启动网卡或业务连接");
    }
}
