using System.ComponentModel;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace StreamLink.Core;

internal sealed record WindowsInterfaceIdentity(Guid Guid,string Name,string Description,OperationalStatus OperationalStatus,ulong Luid);

// Basic IP Helper identities, without GetAdaptersAddresses and all IP/DNS
// properties. During PnP changes the latter can block for many seconds per call.
[SupportedOSPlatform("windows")]
internal static class WindowsInterfaceInventory
{
    // Windows SDK MIB_IF_ROW2, x64 ABI. Only its fixed identity prefix is read;
    // the full row stride also includes the link state and traffic counters.
    const int RowBytes=1352,TableOffset=8;
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    struct Prefix
    {
        public ulong Luid;
        public uint Index;
        public Guid Guid;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)]public string Name;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)]public string Description;
    }
    [DllImport("iphlpapi.dll")]static extern uint GetIfTable2(out IntPtr table);
    [DllImport("iphlpapi.dll")]static extern void FreeMibTable(IntPtr table);

    internal static WindowsInterfaceIdentity[] Read(CancellationToken token=default)
    {
        token.ThrowIfCancellationRequested();
        if(IntPtr.Size!=8||Marshal.SizeOf<Prefix>()!=1056||Marshal.OffsetOf<Prefix>(nameof(Prefix.Name)).ToInt32()!=28||Marshal.OffsetOf<Prefix>(nameof(Prefix.Description)).ToInt32()!=542)
            throw new IOException("网络接口身份查询 ABI 不匹配");
        uint error=GetIfTable2(out var table);
        if(error!=0)throw new Win32Exception((int)error,"读取网络接口身份失败");
        try{
            token.ThrowIfCancellationRequested();
            if(table==IntPtr.Zero)throw new IOException("网络接口身份表为空");
            int count=Marshal.ReadInt32(table);
            if(count is <0 or >65536)throw new IOException("网络接口身份表大小异常");
            var result=new WindowsInterfaceIdentity[count];
            for(int i=0;i<count;i++){
                var pointer=IntPtr.Add(table,checked(TableOffset+i*RowBytes));
                var row=Marshal.PtrToStructure<Prefix>(pointer);
                // SDK IF_OPER_STATUS at offset 1156 has the same 1..7 values.
                result[i]=new(row.Guid,row.Name??"",row.Description??"",(OperationalStatus)Marshal.ReadInt32(pointer,1156),row.Luid);
            }
            return result;
        }finally{if(table!=IntPtr.Zero)FreeMibTable(table);}
    }
}
