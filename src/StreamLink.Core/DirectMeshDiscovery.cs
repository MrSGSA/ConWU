namespace StreamLink.Core;

// Serverless discovery uses the same authenticated metadata replication as
// coordinated networks. It still requires an invitation with an initial table.
public sealed class DirectMeshDiscovery : IMeshDiscovery
{
    IMeshDiscovery? backup;
    Func<bool>? readBackup;
    Action<string>? log;
    long registeredRevision,nextWarning,nextBackupRead;
    public MeshPeerSynchronization Synchronization { get; }
    public DirectMeshDiscovery(MeshProfile profile)
    {
        profile.Validate();
        if (!profile.Pair.Direct || profile.Directory == null) throw new IOException("直连网络缺少签名成员表");
        Synchronization = new(profile);
    }
    public void Attach(MeshRouter router) => Synchronization.Attach(router);
    public void Tick(long now) => Synchronization.Tick(now);
    public void UseCoordinatorBackup(IMeshDiscovery discovery,Func<bool> shouldRead,Action<string> logger)
    {
        if(backup!=null)throw new InvalidOperationException("备用协调已配置");
        backup=discovery;readBackup=shouldRead;log=logger;
    }
    async Task<bool> TryBackup(Func<Task> action,CancellationToken token)
    {
        try{await action();return true;}
        catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or HttpRequestException or OperationCanceledException or System.Security.Cryptography.CryptographicException){
            long now=Environment.TickCount64;if(now>=Interlocked.Read(ref nextWarning)){Interlocked.Exchange(ref nextWarning,now+30000);log?.Invoke("备用协调暂不可用，已有直连继续运行："+ex.GetType().Name);}return false;
        }
    }
    public async Task SaveDirectory(MeshDirectory directory, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); Synchronization.SetDirectory(directory);
        if(backup!=null&&await TryBackup(()=>backup.SaveDirectory(directory,token),token))Interlocked.Exchange(ref registeredRevision,directory.Revision);
    }
    public async Task Publish(MeshAnnouncement announcement, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); Synchronization.Publish(announcement);
        if(backup==null)return;
        var directory=Synchronization.Read()?.Directory;
        if(directory!=null&&Interlocked.Read(ref registeredRevision)<directory.Revision){
            if(!await TryBackup(()=>backup.SaveDirectory(directory,token),token))return;
            Interlocked.Exchange(ref registeredRevision,directory.Revision);
        }
        await TryBackup(()=>backup.Publish(announcement,token),token);
    }
    public async Task<MeshSnapshot?> Read(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();var local=Synchronization.Read();
        long now=Environment.TickCount64;
        if(backup==null||readBackup?.Invoke()!=true||now<Interlocked.Read(ref nextBackupRead))return local;
        Interlocked.Exchange(ref nextBackupRead,now+10000);
        MeshSnapshot? found=null;
        if(await TryBackup(async()=>found=await backup.Read(token),token)&&found!=null)return found;
        return local;
    }
    public static byte[][] DirectoryFrames(MeshDirectory directory) => MeshPeerSynchronization.DirectoryFrames(directory);
    public void Dispose(){backup?.Dispose();Synchronization.Dispose();}
}
