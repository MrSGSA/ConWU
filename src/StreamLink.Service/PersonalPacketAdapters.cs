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

    public static async Task<IPacketAdapter> Open(DeviceProfile profile,CancellationToken token)
    {
        await Preflight(profile,token);
        var mesh=profile.Mesh??throw new IOException("虚拟网卡需要 Mesh 网络");
        var official=await Task.Run(()=>new NativeAdapter(Path.Combine(AppContext.BaseDirectory,"components"),mesh.Pair.Network,mesh.Self.Slot),token);
        PacketAdapterProviders.RequireProduction(official.Descriptor);
        return official;
    }
}
