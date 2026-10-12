using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace StreamLink.Core;

// Exact helper tuple, SNIFF | RECV_ONLY | NO_INSTALL. No send/imported injection
// function exists here; observation cannot steal helper packets or install a
// driver. Only header counters are retained, never STUN/credential payloads.
[SupportedOSPlatform("windows")]
internal sealed class WinDivertHelperObserver : IDisposable
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet=CharSet.Ansi, SetLastError=true)] delegate IntPtr Open(string filter, int layer, short priority, ulong flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError=true)] delegate bool Recv(IntPtr h, byte[] packet, uint capacity, out uint size, byte[] address);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate bool Close(IntPtr h);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate bool Shutdown(IntPtr h, int how);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError=true)] delegate bool SetParam(IntPtr h, int p, ulong v);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr h);
    readonly IntPtr library, handle;
    readonly Close close;
    readonly Shutdown shutdown;
    readonly Task reader;
    int stopping;
    internal static string FilterFor(IPEndPoint local, IPEndPoint remote)
    {
        if(local.AddressFamily!=remote.AddressFamily || local.Port==0 || remote.Port==0 || local.Address.Equals(IPAddress.Any) || local.Address.Equals(IPAddress.IPv6Any) || local.Equals(remote))
            throw new ArgumentException("An explicit helper tuple is required");
        string ip=local.AddressFamily==AddressFamily.InterNetworkV6?"ipv6":"ip";
        // Both directions are identified by addresses, including same-machine
        // traffic which WinDivert reports as outbound in both directions.
        return $"{ip} and tcp and (({ip}.SrcAddr == {local.Address} and tcp.SrcPort == {local.Port} and {ip}.DstAddr == {remote.Address} and tcp.DstPort == {remote.Port}) or ({ip}.SrcAddr == {remote.Address} and tcp.SrcPort == {remote.Port} and {ip}.DstAddr == {local.Address} and tcp.DstPort == {local.Port}))";
    }
    internal WinDivertHelperObserver(string dll, IPEndPoint local, IPEndPoint remote, TcpHelperLedger.Handle counters)
    {
        string filter=FilterFor(local,remote);
        library=LoadLibraryExW(Path.GetFullPath(dll),IntPtr.Zero,0x1100);
        if(library==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastPInvokeError());
        T Api<T>(string name)where T:Delegate=>Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library,name));
        try {
            close=Api<Close>("WinDivertClose");shutdown=Api<Shutdown>("WinDivertShutdown");var recv=Api<Recv>("WinDivertRecv");
            handle=Api<Open>("WinDivertOpen")(filter,0,30000,1|4|16);
            if(handle==new IntPtr(-1))throw new Win32Exception(Marshal.GetLastPInvokeError());
            var set=Api<SetParam>("WinDivertSetParam");
            if(!set(handle,0,256)||!set(handle,1,100)||!set(handle,2,256*1024))throw new IOException("Helper observation queue could not be bounded");
            counters.Observation("WindowsNetworkLayer:ExactHelperTuple:SniffOnly:HeaderCounters");
            reader=Task.Run(()=>{
                byte[] packet=new byte[65535],address=new byte[80];
                while(recv(handle,packet,(uint)packet.Length,out uint n,address)){
                    if(TryHeader(packet.AsSpan(0,(int)n),local,remote,out bool outbound,out byte flags,out int payload))
                        counters.Packet(outbound,(int)n,flags,payload);
                }
                int error=Marshal.GetLastPInvokeError();
                if(Volatile.Read(ref stopping)==0)counters.Observation("Failed:Win32:"+error);
            });
        }catch{if(handle!=IntPtr.Zero&&handle!=new IntPtr(-1))close?.Invoke(handle);FreeLibrary(library);throw;}
    }
    internal static bool TryHeader(ReadOnlySpan<byte> p,IPEndPoint local,IPEndPoint remote,out bool outbound,out byte flags,out int payload)
    {
        outbound=false;flags=0;payload=0;
        int ip;IPAddress source,destination;
        if(p.Length>=40&&(p[0]>>4)==4){
            ip=(p[0]&15)*4;
            if(ip<20||ip+20>p.Length||p[9]!=6||BinaryPrimitives.ReadUInt16BigEndian(p[2..])!=p.Length||(BinaryPrimitives.ReadUInt16BigEndian(p[6..])&0x3fff)!=0)return false;
            source=new(p.Slice(12,4));destination=new(p.Slice(16,4));
        }else if(p.Length>=60&&(p[0]>>4)==6){
            // Extension/fragmented headers remain explicitly outside this
            // observer's evidence; ordinary helper TCP has no extension chain.
            ip=40;if(p[6]!=6||40+BinaryPrimitives.ReadUInt16BigEndian(p[4..])!=p.Length)return false;
            source=new(p.Slice(8,16));destination=new(p.Slice(24,16));
        }else return false;
        int tcp=(p[ip+12]>>4)*4;
        if(tcp<20||ip+tcp>p.Length)return false;
        int sp=BinaryPrimitives.ReadUInt16BigEndian(p[ip..]),dp=BinaryPrimitives.ReadUInt16BigEndian(p[(ip+2)..]);
        outbound=source.Equals(local.Address)&&sp==local.Port&&destination.Equals(remote.Address)&&dp==remote.Port;
        if(!outbound&&!(source.Equals(remote.Address)&&sp==remote.Port&&destination.Equals(local.Address)&&dp==local.Port))return false;
        flags=p[ip+13];payload=p.Length-ip-tcp;return true;
    }
    public void Dispose()
    {
        if(Interlocked.Exchange(ref stopping,1)!=0)return;
        shutdown(handle,3);
        try{reader.GetAwaiter().GetResult();}finally{close(handle);FreeLibrary(library);}
    }
}
