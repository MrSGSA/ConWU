using StreamLink.Core;

namespace StreamLink.Service;

internal static class PersonalPacketAdapters
{
    public static Task Preflight(DeviceProfile profile,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if(profile.AdapterBackend!=PacketAdapterBackend.OfficialWintun)
            throw new IOException("AQ-1 使用官方 Wintun；自研驱动已退出产品范围，请迁移配置后连接");
        return Task.CompletedTask;
    }

    public static Task<IPacketAdapter> Open(DeviceProfile profile,CancellationToken token) => Open(profile, _ => { }, token);

    public static async Task<IPacketAdapter> Open(DeviceProfile profile,Action<string> trace,CancellationToken token)
    {
        await Preflight(profile,token);
        var mesh=profile.Mesh??throw new IOException("虚拟网卡需要 Mesh 网络");
        return await Task.Factory.StartNew<IPacketAdapter>(() => {
            // Official PnP APIs are synchronous. Keep their waits off the
            // packet/control thread pool and join their rollback on cancel.
            var official = new NativeAdapter(Path.Combine(AppContext.BaseDirectory,"components"),mesh.Pair.Network,mesh.Self.Slot,trace,token);
            try { token.ThrowIfCancellationRequested(); PacketAdapterProviders.RequireProduction(official.Descriptor); return official; }
            catch { official.Dispose(); throw; }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }
}
