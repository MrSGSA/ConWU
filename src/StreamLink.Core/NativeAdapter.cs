using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace StreamLink.Core;

public interface IPacketAdapter : IDisposable
{
    int Read(byte[] buffer);
    bool Write(byte[] packet);
    PacketAdapterDescriptor Descriptor=>new("unidentified-fixture",0,MeshLink.Mtu,true,false,true);
    PacketAdapterStatistics Statistics=>new(0,0,0,0,0,0,0,false);
    int Read(byte[] buffer,CancellationToken token){token.ThrowIfCancellationRequested();int length=Read(buffer);token.ThrowIfCancellationRequested();return length;}
    void Stop(){}
}

[SupportedOSPlatform("windows")]
public sealed class NativeAdapter : IPacketAdapter
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)] delegate uint Open(string dll, string name, ref Guid guid, byte[] ip, out IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void Close(IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint ReadPacket(IntPtr adapter, byte[] packet, uint capacity, out uint length);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint WritePacket(IntPtr adapter, byte[] packet, uint length);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint Abi();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void StopPacket(IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint ReadStats(IntPtr adapter,[Out] ulong[] counters);
    readonly IntPtr library;
    IntPtr adapter;
    readonly Close close;
    readonly ReadPacket read;
    readonly WritePacket write;
    readonly StopPacket stop;
    readonly ReadStats stats;
    readonly ReaderWriterLockSlim io=new();
    internal Action<string>? LifecycleTrace { get; set; }
    int stopping;
    public PacketAdapterDescriptor Descriptor=>new(PacketAdapterProviders.OfficialWintun,2,MeshLink.Mtu,true,true,false);
    public IReadOnlyList<OverlayConflict> RouteWarnings { get; }
    public PacketAdapterStatistics Statistics{get{io.EnterReadLock();try{ObjectDisposedException.ThrowIf(disposed,this);var c=new ulong[7];uint error=stats(adapter,c);if(error!=0)throw new Win32Exception((int)error);return new((long)c[0],(long)c[1],(long)c[2],(long)c[3],(long)c[4],(long)c[5],(long)c[6],Volatile.Read(ref stopping)!=0);}finally{io.ExitReadLock();}}}
    bool disposed;
    public NativeAdapter(string components, string network, int slot)
    {
        if (!WindowsHost.IsAdmin) throw new IOException("创建虚拟网卡需要管理员权限");
        string prefix = MeshIdentity.Prefix(network) + ".";
        var conflicts=OverlayRouteConflicts.Inspect(IPAddress.Parse(prefix+"0"));
        RouteWarnings=Array.AsReadOnly(conflicts.Where(c=>c.Severity=="Warning").ToArray());
        if(conflicts.Any(c=>c.Severity=="Block"))throw new IOException($"虚拟网段 {prefix}0/24 与现有地址/路由冲突，请新建网络；不会单机改网段或删除其他路由");
        string driver = Path.GetFullPath(Path.Combine(components, "wintun.dll"));
        if (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(driver))) != "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE") throw new IOException("Wintun 组件校验失败");
        library = NativeLibrary.Load(Path.GetFullPath(Path.Combine(components, "streamlink-tun.dll")));
        try {
            T Load<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
            close = Load<Close>("sltun_close"); read = Load<ReadPacket>("sltun_read"); write = Load<WritePacket>("sltun_write");
            if(Load<Abi>("sltun_abi")()!=2)throw new IOException("网卡适配ABI不匹配");
            stop=Load<StopPacket>("sltun_stop");stats=Load<ReadStats>("sltun_stats");
            PacketAdapterProviders.RequireProduction(Descriptor);
            var guid = new Guid(SHA256.HashData(Encoding.ASCII.GetBytes($"streamlink-wintun-v4/{network}/{slot}")).AsSpan(0, 16));
            uint error = Load<Open>("sltun_open")(driver, $"StreamLink-{network[..8]}-{slot}", ref guid, IPAddress.Parse(MeshIdentity.Address(network, slot)).GetAddressBytes(), out adapter);
            if (error != 0) throw new Win32Exception((int)error, "原生虚拟网卡创建失败");
        } catch { if(adapter!=IntPtr.Zero){close!(adapter);adapter=IntPtr.Zero;}NativeLibrary.Free(library); throw; }
    }
    public int Read(byte[] buffer)
    {
        io.EnterReadLock();try{
        ObjectDisposedException.ThrowIf(disposed, this);
        if(Volatile.Read(ref stopping)!=0)return 0;
        uint error = read(adapter, buffer, (uint)buffer.Length, out uint count);
        if (error is 259 or 122 or 995) return 0;
        if (error != 0) throw new Win32Exception((int)error, "虚拟网卡读取失败");
        return (int)count;
        }finally{io.ExitReadLock();}
    }
    public bool Write(byte[] packet)
    {
        io.EnterReadLock();try{
        ObjectDisposedException.ThrowIf(disposed, this);
        if(Volatile.Read(ref stopping)!=0)return false;
        uint error = write(adapter, packet, (uint)packet.Length);
        if (error is 111 or 995) return false; // Bounded rings/stop do not build latency.
        if (error != 0) throw new Win32Exception((int)error, "虚拟网卡写入失败");
        return true;
        }finally{io.ExitReadLock();}
    }
    public int Read(byte[] buffer,CancellationToken token){using var cancel=token.Register(Stop);token.ThrowIfCancellationRequested();int length=Read(buffer);token.ThrowIfCancellationRequested();return length;}
    public void Stop(){io.EnterReadLock();try{if(!disposed&&Interlocked.Exchange(ref stopping,1)==0)stop(adapter);}finally{io.ExitReadLock();}}
    // The caller joins both packet pumps before closing the native session.
    public void Dispose() {
        // Signal BEFORE waiting for in-flight native reads. Delegate calls hold
        // a shared guard so stats/write/cancellation cannot race a freed pointer
        // or a library unload, even when a caller violates normal pump ordering.
        LifecycleTrace?.Invoke("stop-begin");Stop();LifecycleTrace?.Invoke("stop-complete");io.EnterWriteLock();try{
            if(disposed)return;LifecycleTrace?.Invoke("exclusive-acquired");disposed=true;close(adapter);LifecycleTrace?.Invoke("native-close-complete");adapter=IntPtr.Zero;
            // The guarded native handle closes here; OS/PnP disappearance is
            // recorded separately. Do not block all statistics/cancel callers
            // behind unbounded interface enumeration or alter foreign drivers.
            NativeLibrary.Free(library);LifecycleTrace?.Invoke("library-free-complete");
        }finally{io.ExitWriteLock();}
        // Do not dispose the guard: late calls must deterministically observe
        // the adapter's disposed state rather than touch a closed native handle.
    }
}
