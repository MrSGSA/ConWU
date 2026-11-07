using StreamLink.Core;

namespace StreamLink.Service;

internal static class PersonalPacketAdapters
{
    public static Task Preflight(DeviceProfile profile,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if(OperatingSystem.IsLinux()){
            if(profile.AdapterBackend!=PacketAdapterBackend.LinuxTun)throw new IOException("Linux 需要内核 TUN 后端");
            if(!File.Exists("/dev/net/tun"))throw new IOException("参与网络需要 /dev/net/tun；仅提供协调服务不需要 TUN");
            return Task.Run(()=>{
                foreach(var command in new[]{"ip","nft","iptables"}){
                    token.ThrowIfCancellationRequested();
                    try{LinuxPlatform.Run(command,command=="ip"?"-Version":"--version");}
                    catch(Exception ex)when(ex is IOException or System.ComponentModel.Win32Exception){throw new IOException("参与网络需要 Linux 网络工具 "+command+"；请安装 iproute2、nftables 和 iptables",ex);}
                }
            },token);
        }
        if(profile.AdapterBackend!=PacketAdapterBackend.OfficialWintun)
            throw new IOException("AQ-1 使用官方 Wintun；自研驱动已退出产品范围，请迁移配置后连接");
        return Task.CompletedTask;
    }

    public static Task<IPacketAdapter> Open(DeviceProfile profile,CancellationToken token) => Open(profile, _ => { }, token);

    public static async Task<IPacketAdapter> Open(DeviceProfile profile,Action<string> trace,CancellationToken token)
    {
        await Preflight(profile,token);
        var mesh=profile.Mesh??throw new IOException("虚拟网卡需要 Mesh 网络");
        if(OperatingSystem.IsLinux())return await Task.Run<IPacketAdapter>(()=>new LinuxTunAdapter(mesh.LocalIp,token),token);
        return await Task.Factory.StartNew<IPacketAdapter>(() => {
            // Official PnP APIs are synchronous. Keep their waits off the
            // packet/control thread pool and join their rollback on cancel.
            var official = new NativeAdapter(Path.Combine(AppContext.BaseDirectory,"components"),mesh.Pair.Network,mesh.Self.Slot,trace,token,mesh.LocalIp,ownerNetwork:profile.AdapterScope.Length>0?profile.AdapterScope:profile.Device);
            try { token.ThrowIfCancellationRequested(); PacketAdapterProviders.RequireProduction(official.Descriptor); return official; }
            catch { official.Dispose(); throw; }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }
}
