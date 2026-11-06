namespace StreamLink.Core;

// Serverless discovery uses the same authenticated metadata replication as
// coordinated networks. It still requires an invitation with an initial table.
public sealed class DirectMeshDiscovery : IMeshDiscovery
{
    public MeshPeerSynchronization Synchronization { get; }
    public DirectMeshDiscovery(MeshProfile profile)
    {
        profile.Validate();
        if (!profile.Pair.Direct || profile.Directory == null) throw new IOException("直连网络缺少签名成员表");
        Synchronization = new(profile);
    }
    public void Attach(MeshRouter router) => Synchronization.Attach(router);
    public void Tick(long now) => Synchronization.Tick(now);
    public Task SaveDirectory(MeshDirectory directory, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); Synchronization.SetDirectory(directory); return Task.CompletedTask;
    }
    public Task Publish(MeshAnnouncement announcement, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); Synchronization.Publish(announcement); return Task.CompletedTask;
    }
    public Task<MeshSnapshot?> Read(CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); return Task.FromResult(Synchronization.Read());
    }
    public static byte[][] DirectoryFrames(MeshDirectory directory) => MeshPeerSynchronization.DirectoryFrames(directory);
    public void Dispose() => Synchronization.Dispose();
}
