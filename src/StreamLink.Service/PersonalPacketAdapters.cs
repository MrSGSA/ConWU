using StreamLink.Core;
using StreamLink.ResearchAdapters;

namespace StreamLink.Service;

internal static class PersonalPacketAdapters
{
    static string Package => Path.Combine(AppContext.BaseDirectory, "components", "self-tun");
    static string Approvals => Path.Combine(ProfileStore.Root, "tun-admission");

    public static async Task Preflight(DeviceProfile profile,CancellationToken token)
    {
        if(profile.AdapterBackend==PacketAdapterBackend.OfficialWintun)return;
        if(!PersonalFeature.Enabled)throw new IOException("标准产品仍只准入官方 Wintun；自研 TUN 需个人功能包");
        _=await PersonalTunAdmission.Inspect(Package,Approvals,token);
    }

    public static async Task<IPacketAdapter> Open(DeviceProfile profile,CancellationToken token)
    {
        var mesh=profile.Mesh??throw new IOException("虚拟网卡工厂需要 Mesh 网络");
        token.ThrowIfCancellationRequested();
        if(profile.AdapterBackend==PacketAdapterBackend.OfficialWintun) {
            var official=await Task.Run(()=>new NativeAdapter(Path.Combine(AppContext.BaseDirectory,"components"),mesh.Pair.Network,mesh.Self.Slot),token);
            PacketAdapterProviders.RequireProduction(official.Descriptor);
            return official;
        }
        var admission=await PersonalTunAdmission.Inspect(Package,Approvals,token);
        token.ThrowIfCancellationRequested();
        return new ResearchTunAdapter(admission,mesh.LocalIp);
    }
}
