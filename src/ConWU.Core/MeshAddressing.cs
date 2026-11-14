using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

public static class MeshAddressing
{
    public static void ValidateAddress(string address)
    {
        if(!IPAddress.TryParse(address,out var ip)||ip.AddressFamily!=AddressFamily.InterNetwork||ip.ToString()!=address)throw new FormatException("虚拟 IP 应为完整 IPv4 地址");
        var b=ip.GetAddressBytes();
        if(!(b[0]==10 || b[0]==172&&b[1] is >=16 and <=31 || b[0]==192&&b[1]==168) || b[3] is 0 or 255)
            throw new FormatException("虚拟 IP 需为私有 IPv4 地址，末段为 1–254；使用 /24 网段");
    }
    public static string Prefix(string address)=>address[..address.LastIndexOf('.')];
    public static string Address(string network,MeshMember member)=>member.VirtualIp??MeshIdentity.Address(network,member.Slot);
    public static string Next(MeshProfile profile,string requested="")
    {
        var directory=profile.Directory??throw new IOException("成员目录尚未就绪");
        string prefix=Prefix(profile.LocalIp);
        var used=new HashSet<string>(directory.ReservedAddresses??Enumerable.Range(1,directory.NextSlot-1).Select(i=>MeshIdentity.Address(profile.Pair.Network,i)));
        foreach(var member in directory.Members)used.Add(Address(profile.Pair.Network,member));
        if(requested.Length>0){ValidateAddress(requested);if(Prefix(requested)!=prefix)throw new FormatException("指定 IP 必须位于当前网络的 "+prefix+".0/24 网段");if(used.Contains(requested))throw new FormatException("此 IP 已分配或保留给历史设备");return requested;}
        return Enumerable.Range(1,254).Select(i=>prefix+"."+i).FirstOrDefault(ip=>!used.Contains(ip))??throw new IOException("网络地址已用尽，请创建新网络");
    }
}
