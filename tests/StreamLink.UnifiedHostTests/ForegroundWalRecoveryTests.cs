using StreamLink.Core;
using StreamLink.Service;

static class ForegroundWalRecoveryTests
{
    public static void Run()
    {
        if(!OperatingSystem.IsLinux()||StartupSettings.Read().ServiceRegistered)throw new IOException("测试需要没有注册服务的隔离 Linux 命名空间");
        string root=Path.Combine(Path.GetTempPath(),"conwu-wal-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",root);
        var device=new ProfileStore(root);var original=new DeviceProfile{DeviceName="before",AutoStart=true};device.Save(original);
        string id=Guid.NewGuid().ToString("N");var network=new ProfileStore(Path.Combine(root,"networks",id),device);var networkBefore=new DeviceProfile{DeviceName="before",EntryRefreshSeconds=60};network.Save(networkBefore);
        device.WritePrivate(PairSettingsTransaction.FileName,new PairSettingsTransaction(id,original,networkBefore,false,false));
        var modified=ProfileChanges.Copy(original);modified.DeviceName="changed";device.Save(modified);var networkModified=ProfileChanges.Copy(networkBefore);networkModified.EntryRefreshSeconds=90;network.Save(networkModified);
        using(var worker=new ControlWorker(device,enableWorkspace:true)){}
        if(device.Load().DeviceName!="before"||network.Load().EntryRefreshSeconds!=60||File.Exists(Path.Combine(root,PairSettingsTransaction.FileName)))throw new Exception("单网事务未恢复");
        var beforeBatch=device.Load();var beforeNetwork=network.Load();device.WritePrivate(PairBatchSettingsTransaction.FileName,new PairBatchSettingsTransaction(beforeBatch,new(){{id,beforeNetwork}},false,false));
        modified=ProfileChanges.Copy(beforeBatch);modified.DeviceName="batch-changed";device.Save(modified);networkModified=ProfileChanges.Copy(beforeNetwork);networkModified.EntryRefreshSeconds=120;network.Save(networkModified);
        using(var worker=new ControlWorker(device,enableWorkspace:true)){}
        if(device.Load().DeviceName!="before"||network.Load().EntryRefreshSeconds!=60||File.Exists(Path.Combine(root,PairBatchSettingsTransaction.FileName)))throw new Exception("批量事务未恢复");
        Console.WriteLine("PASS foreground single/batch WAL crash recovery without a registered service");
    }
}
