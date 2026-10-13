using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace StreamLink.Core;

public sealed record OverlayAddressPrefix(string Interface,IPAddress Address,int PrefixLength);
public sealed record OverlayRoutePrefix(string Interface,IPAddress Address,int PrefixLength);
public sealed record OverlayConflict(string Severity,string Reason,string Interface,string Prefix);
public static class OverlayRouteConflicts
{
    [DllImport("iphlpapi.dll")]static extern uint GetIpForwardTable2(ushort family,out IntPtr table);
    [DllImport("iphlpapi.dll")]static extern void FreeMibTable(IntPtr table);
    static uint Value(IPAddress address)=>BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
    static uint Mask(int bits)=>bits==0?0:uint.MaxValue<<(32-bits);
    static bool Overlap(IPAddress a,int abits,IPAddress b,int bbits)=>(Value(a)&Mask(Math.Min(abits,bbits)))==(Value(b)&Mask(Math.Min(abits,bbits)));
    public static OverlayConflict[] Evaluate(IPAddress overlay,IEnumerable<OverlayAddressPrefix> addresses,IEnumerable<OverlayRoutePrefix> routes,IReadOnlySet<string>? verifiedOwnedInterfaces=null)
    {
        if(overlay.AddressFamily!=AddressFamily.InterNetwork)throw new ArgumentException("Overlay is IPv4 /24");
        var result=new List<OverlayConflict>();
        foreach(var a in addresses){
            if(a.Address.AddressFamily!=AddressFamily.InterNetwork||a.PrefixLength is<0 or>32||verifiedOwnedInterfaces?.Contains(a.Interface)==true)continue;
            if(Overlap(overlay,24,a.Address,a.PrefixLength))result.Add(new(Overlap(overlay,24,a.Address,32)?"Block":"Warning","LocalAddressPrefixOverlap",a.Interface,$"{a.Address}/{a.PrefixLength}"));
        }
        foreach(var r in routes){
            if(r.Address.AddressFamily!=AddressFamily.InterNetwork||r.PrefixLength is<1 or>32||verifiedOwnedInterfaces?.Contains(r.Interface)==true)continue;
            if(Overlap(overlay,24,r.Address,r.PrefixLength))result.Add(new(r.PrefixLength>=24?"Block":"Warning",r.PrefixLength<=1?"VpnDefaultCoverage":"RoutePrefixOverlap",r.Interface,$"{r.Address}/{r.PrefixLength}"));
        }
        return result.Distinct().ToArray();
    }
    public static OverlayConflict[] Inspect(IPAddress overlay)
    {
        var addresses=NetworkInterface.GetAllNetworkInterfaces().SelectMany(n=>n.GetIPProperties().UnicastAddresses.Select(a=>new OverlayAddressPrefix(n.Id,a.Address,a.PrefixLength))).ToArray();
        var routes=new List<OverlayRoutePrefix>();
        if(OperatingSystem.IsWindows()){
            uint error=GetIpForwardTable2(2,out IntPtr table);if(error!=0)throw new IOException("无法核实虚拟网段路由："+error);
            try{
                int count=Marshal.ReadInt32(table);if(count is<0 or>65536)throw new IOException("路由表大小异常");
                byte[] row=new byte[104];
                for(int i=0;i<count;i++){
                    Marshal.Copy(IntPtr.Add(table,8+i*104),row,0,row.Length);
                    if(BinaryPrimitives.ReadUInt16LittleEndian(row.AsSpan(12))!=2)continue;
                    routes.Add(new("WindowsInterface:"+BinaryPrimitives.ReadUInt64LittleEndian(row).ToString("X16"),new IPAddress(row.AsSpan(16,4)),row[40]));
                }
            }finally{FreeMibTable(table);}
        }
        return Evaluate(overlay,addresses,routes);
    }
}
