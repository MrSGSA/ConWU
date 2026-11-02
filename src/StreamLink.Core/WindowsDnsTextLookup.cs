using System.Runtime.InteropServices;

namespace StreamLink.Core;

internal sealed class DnsTextLookupException(string message):IOException(message);

internal static class WindowsDnsTextLookup
{
    // Use the Windows resolver, including its cache, interface selection and
    // configured DNS policy. Raw UDP bypasses those policies and can query the
    // wrong adapter on a machine with Ethernet, Wi-Fi and virtual interfaces.
    static readonly SemaphoreSlim workers=new(2,2);
    [DllImport("dnsapi.dll",EntryPoint="DnsQuery_W",CharSet=CharSet.Unicode)]
    static extern int DnsQuery(string name,ushort type,uint options,IntPtr extra,out IntPtr records,IntPtr reserved);
    [DllImport("dnsapi.dll")]static extern void DnsRecordListFree(IntPtr records,int kind);
    public static async Task<string[]> Query(string host,CancellationToken token)
    {
        await workers.WaitAsync(token);
        // The OS call is synchronous. A canceled caller stops waiting, while
        // the slot and record ownership remain held until that OS call exits.
        var work=Task.Run(()=>{try{return Read(host);}finally{workers.Release();}});
        return await work.WaitAsync(token);
    }
    static string[] Read(string host)
    {
        int status=DnsQuery(host,16,0,IntPtr.Zero,out var records,IntPtr.Zero);
        try{
            if(status!=0)throw new DnsTextLookupException(status is 9003 or 9501?"域名没有可用的 TXT 记录":"系统 DNS 的 TXT 查询失败（代码 "+status+"）");
            var values=new List<string>();int count=0,data=IntPtr.Size==8?32:24;
            for(var record=records;record!=IntPtr.Zero;record=Marshal.ReadIntPtr(record)){
                if(++count>64)throw new DnsTextLookupException("TXT 响应记录过多");
                if((ushort)Marshal.ReadInt16(record,IntPtr.Size*2)!=16)continue;
                int strings=Marshal.ReadInt32(record,data);if(strings is <1 or >64)throw new DnsTextLookupException("TXT 分段数量无效");
                var text=new System.Text.StringBuilder();
                for(int i=0;i<strings;i++){
                    var value=Marshal.PtrToStringUni(Marshal.ReadIntPtr(record,data+IntPtr.Size+i*IntPtr.Size))??"";
                    if(text.Length+value.Length>ExistingEntryResolver.MaximumBody)throw new DnsTextLookupException("TXT 内容超过 8 KiB");
                    text.Append(value);
                }
                values.Add(text.ToString());
            }
            if(values.Count==0)throw new DnsTextLookupException("域名没有可用的 TXT 记录");
            return values.ToArray();
        }finally{if(records!=IntPtr.Zero)DnsRecordListFree(records,1);}
    }
}
