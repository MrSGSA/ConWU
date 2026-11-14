namespace StreamLink.Core;

public sealed record PacketAdapterDescriptor(string Provider,int Abi,int MaximumPacket,bool Ipv4,bool CancelRead,bool Experimental);
public sealed record PacketAdapterStatistics(long ReadPackets,long ReadBytes,long WrittenPackets,long WrittenBytes,long RingFull,long Truncated,long ReadWaits,bool Stopping);
public static class PacketAdapterProviders
{
    public const string OfficialWintun="official-wintun",NativeExperimental="streamlink-tun-experimental";
    public const string LinuxTun="linux-tun";
    public static void RequireProduction(PacketAdapterDescriptor descriptor)
    {
        if(descriptor.Provider!=(OperatingSystem.IsLinux()?LinuxTun:OfficialWintun)||descriptor.Abi!=2||descriptor.MaximumPacket!=MeshLink.Mtu||!descriptor.Ipv4||!descriptor.CancelRead||descriptor.Experimental)
            throw new IOException("虚拟网卡provider/ABI未通过默认发布许可");
    }
}
