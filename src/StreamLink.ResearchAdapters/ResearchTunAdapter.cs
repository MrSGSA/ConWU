using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using StreamLink.Core;

namespace StreamLink.ResearchAdapters;

// Deliberately a separate research assembly: the product does not reference it.
// A signed/approved adapter must already exist; this class cannot install one.
public sealed class ResearchTunAdapter:IPacketAdapter
{
    [StructLayout(LayoutKind.Sequential)]struct Info{public uint Size,Abi,Mtu,Queue;public ulong Luid;public uint IfIndex,Flags;}
    [StructLayout(LayoutKind.Sequential)]struct Stats{public uint Size,Abi;public ulong Offered,Queued,Dropped,Reads,Writes,Malformed,Cancelled;public uint Pending,Peak,PendingReads,Reserved;}
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]delegate uint Abi();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,SetLastError=true)]delegate ulong Open(uint index);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,SetLastError=true)]delegate bool GetInfo(ulong handle,out Info info);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,SetLastError=true)]delegate bool GetStats(ulong handle,out Stats stats);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,SetLastError=true)]delegate int ReadPacket(ulong handle,byte[] packet,uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,SetLastError=true)]delegate bool WritePacket(ulong handle,byte[] packet,uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,SetLastError=true)]delegate bool Configure(ulong handle,byte[] ip);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,SetLastError=true)]delegate bool HandleCall(ulong handle);
    readonly ReaderWriterLockSlim lifetime=new(LockRecursionPolicy.SupportsRecursion);
    readonly IntPtr library;
    readonly ulong handle;
    readonly ReadPacket read;
    readonly WritePacket write;
    readonly GetStats stats;
    readonly HandleCall stop,close;
    long readBytes,writtenBytes;
    int stopped,disposed;
    PacketAdapterStatistics lastStats=new(0,0,0,0,0,0,0,false);
    public ulong InterfaceLuid{get;}
    public PacketAdapterDescriptor Descriptor=>new(PacketAdapterProviders.NativeExperimental,2,MeshLink.Mtu,true,true,true);
    public ResearchTunAdapter(string dll,uint interfaceIndex,string virtualIp,bool explicitlyApprovedResearchRun)
    {
        if(!explicitlyApprovedResearchRun)throw new IOException("自研TUN仅允许明确批准的隔离研究；默认产品继续使用官方Wintun");
        if(!WindowsHost.IsAdmin)throw new IOException("研究适配器需要管理员权限");
        if(interfaceIndex==0)throw new ArgumentOutOfRangeException(nameof(interfaceIndex));
        var ip=IPAddress.Parse(virtualIp);if(ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork)throw new IOException("研究TUN仅支持IPv4");
        byte[] prefix=ip.GetAddressBytes();prefix[3]=0;if(OverlayRouteConflicts.Inspect(new IPAddress(prefix)).Any(c=>c.Severity=="Block"))throw new IOException("研究网段冲突，拒绝修改既有地址或路由");
        library=NativeLibrary.Load(Path.GetFullPath(dll));
        try{
            T Api<T>(string name)where T:Delegate=>Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library,name));
            if(Api<Abi>("SLT_UserAbi")()!=1)throw new IOException("研究用户API版本不匹配");
            close=Api<HandleCall>("SLT_Close");stop=Api<HandleCall>("SLT_Stop");read=Api<ReadPacket>("SLT_Read");write=Api<WritePacket>("SLT_Write");stats=Api<GetStats>("SLT_Stats");
            handle=Api<Open>("SLT_Open")(interfaceIndex);if(handle==0)throw new Win32Exception(Marshal.GetLastPInvokeError());
            if(!Api<GetInfo>("SLT_Info")(handle,out var info)||info.Size!=32||info.Abi!=1||info.Mtu!=MeshLink.Mtu||info.IfIndex!=interfaceIndex||info.Luid==0)throw new IOException("研究驱动ABI不匹配");
            InterfaceLuid=info.Luid;if(!Api<Configure>("SLT_ConfigureIpv4")(handle,ip.GetAddressBytes()))throw new Win32Exception(Marshal.GetLastPInvokeError());
        }catch{if(handle!=0)close?.Invoke(handle);NativeLibrary.Free(library);throw;}
    }
    public int Read(byte[] buffer)=>Read(buffer,CancellationToken.None);
    public int Read(byte[] buffer,CancellationToken token)
    {
        if(buffer.Length<MeshLink.Mtu)throw new ArgumentException("研究网卡读取缓冲不足");token.ThrowIfCancellationRequested();
        lifetime.EnterReadLock();try{ObjectDisposedException.ThrowIf(disposed!=0,this);using var cancel=token.Register(Stop);int n=read(handle,buffer,(uint)buffer.Length);if(n<0){token.ThrowIfCancellationRequested();throw new Win32Exception(Marshal.GetLastPInvokeError());}Interlocked.Add(ref readBytes,n);return n;}finally{lifetime.ExitReadLock();}
    }
    public bool Write(byte[] packet){if(!MeshPackets.Valid(packet))return false;lifetime.EnterReadLock();try{ObjectDisposedException.ThrowIf(disposed!=0,this);bool sent=write(handle,packet,(uint)packet.Length);if(sent)Interlocked.Add(ref writtenBytes,packet.Length);return sent;}finally{lifetime.ExitReadLock();}}
    public PacketAdapterStatistics Statistics{get{lifetime.EnterReadLock();try{ObjectDisposedException.ThrowIf(disposed!=0,this);if(stopped!=0)return lastStats with{Stopping=true};if(!stats(handle,out var s)||s.Size!=80||s.Abi!=1)throw new IOException("研究驱动统计无效");return lastStats=new((long)s.Reads,Interlocked.Read(ref readBytes),(long)s.Writes,Interlocked.Read(ref writtenBytes),(long)s.Dropped,(long)s.Malformed,0,false);}finally{lifetime.ExitReadLock();}}}
    public void Stop(){lifetime.EnterReadLock();try{if(disposed==0&&Interlocked.Exchange(ref stopped,1)==0)stop(handle);}finally{lifetime.ExitReadLock();}}
    public void Dispose(){if(Volatile.Read(ref disposed)!=0)return;Stop();if(!lifetime.TryEnterWriteLock(5000))throw new IOException("研究TUN I/O退出超时，保留DLL与资源，不能伪报关闭");try{if(Interlocked.Exchange(ref disposed,1)==0){close(handle);NativeLibrary.Free(library);}}finally{lifetime.ExitWriteLock();}}
}
