using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

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
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint ReadLuid(IntPtr adapter,out ulong luid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void NativeCloseTrace(uint phase);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void TracedClose(IntPtr adapter,NativeCloseTrace trace);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)] delegate uint TracedOpen(string dll,string name,ref Guid guid,byte[] ip,out IntPtr adapter,NativeCloseTrace trace);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)] delegate uint CancellableOpen(string dll,string name,ref Guid guid,byte[] ip,out IntPtr adapter,NativeCloseTrace trace,SafeWaitHandle cancel);
    // Native create and close cannot overlap in this process. The owner still
    // joins all I/O before close; a new runner cannot overtake its cleanup.
    static readonly SemaphoreSlim lifecycle = new(1, 1);
    // Keep the verified official module loaded for this process. PnP create /
    // close and DLL teardown must not repeatedly race network-class setup.
    // The OS releases these modules at process exit; no adapter/session is kept.
    static readonly Dictionary<string,IntPtr> officialModules=new(StringComparer.OrdinalIgnoreCase);
    static void PinOfficialModule(string path)
    {
        lock(officialModules){
            if(officialModules.ContainsKey(path))return;
            if(officialModules.Count>=16)throw new IOException("本进程加载的 Wintun 组件路径过多，请重新启动应用");
            officialModules.Add(path,NativeLibrary.Load(path,typeof(NativeAdapter).Assembly,DllImportSearchPath.UseDllDirectoryForDependencies|DllImportSearchPath.System32));
        }
    }
    readonly TracedClose? tracedClose;
    readonly IntPtr library;
    readonly FileStream identityLease;
    readonly FileStream? meshIdentityLease;
    readonly WintunIdentity ownershipScope;
    IntPtr adapter;
    readonly Close close;
    readonly ReadPacket read;
    readonly WritePacket write;
    readonly StopPacket stop;
    readonly ReadStats stats;
    readonly ReaderWriterLockSlim io=new();
    internal Action<string>? LifecycleTrace { get; set; }
    string lastTraced = "";
    int stopping;
    public PacketAdapterDescriptor Descriptor=>new(PacketAdapterProviders.OfficialWintun,2,MeshLink.Mtu,true,true,false);
    public IReadOnlyList<OverlayConflict> RouteWarnings { get; }
    public ulong? InterfaceLuid {get;}
    public PacketAdapterStatistics Statistics{get{io.EnterReadLock();try{ObjectDisposedException.ThrowIf(disposed,this);var c=new ulong[7];uint error=stats(adapter,c);if(error!=0)throw new Win32Exception((int)error);return new((long)c[0],(long)c[1],(long)c[2],(long)c[3],(long)c[4],(long)c[5],(long)c[6],Volatile.Read(ref stopping)!=0);}finally{io.ExitReadLock();}}}
    bool disposed;
    public NativeAdapter(string components, string network, int slot, Action<string>? lifecycleTrace=null, CancellationToken cancellationToken=default, string? virtualIp=null,string? ownerNetwork=null)
    {
        LifecycleTrace=lifecycleTrace;
        cancellationToken.ThrowIfCancellationRequested();
        if (!WindowsHost.IsAdmin) throw new IOException("创建虚拟网卡需要管理员权限");
        var scope = WintunIdentity.For(ownerNetwork??network, ownerNetwork==null?slot:1);
        ownershipScope=scope;
        identityLease = scope.Acquire();
        try {
        var legacyIdentity=WintunIdentity.For(network,slot);
        if(legacyIdentity.Guid!=scope.Guid)meshIdentityLease=legacyIdentity.Acquire();
        var preparation=WintunAdapterJournal.Prepare(scope,cancellationToken,Trace,ownerNetwork==null?null:new(network,slot));
        var identity=preparation.Identity;var guid=identity.Guid;string name=identity.Name;
        Trace("lifecycle-wait"); lifecycle.Wait(cancellationToken);
        try {
        cancellationToken.ThrowIfCancellationRequested();
        string address=virtualIp??MeshIdentity.Address(network,slot);
        MeshAddressing.ValidateAddress(address);
        string prefix = MeshAddressing.Prefix(address) + ".";
        var conflicts=OverlayRouteConflicts.Inspect(IPAddress.Parse(prefix+"0"),preparation.VerifiedOrphans);
        RouteWarnings=Array.AsReadOnly(conflicts.Where(c=>c.Severity=="Warning").ToArray());
        if(conflicts.Any(c=>c.Severity=="Block"))throw new IOException($"虚拟网段 {prefix}0/24 与现有地址/路由冲突，请新建网络；不会单机改网段或删除其他路由");
        string driver = Path.GetFullPath(Path.Combine(components, "wintun.dll"));
        if (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(driver))) != "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE") throw new IOException("Wintun 组件校验失败");
        PinOfficialModule(driver);
        library = NativeLibrary.Load(Path.GetFullPath(Path.Combine(components, "conwu-tun.dll")));
        try {
            T Load<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
            if(NativeLibrary.TryGetExport(library,"sltun_close_with_trace",out var diagnosticClose))tracedClose=Marshal.GetDelegateForFunctionPointer<TracedClose>(diagnosticClose);
            close = Load<Close>("sltun_close"); read = Load<ReadPacket>("sltun_read"); write = Load<WritePacket>("sltun_write");
            if(Load<Abi>("sltun_abi")()!=2)throw new IOException("网卡适配ABI不匹配");
            stop=Load<StopPacket>("sltun_stop");stats=Load<ReadStats>("sltun_stats");
            PacketAdapterProviders.RequireProduction(Descriptor);
            string openStage="bridge-open";uint error;
            NativeCloseTrace callback=phase=>{if(phase>=100)openStage=OpenStage(phase);Trace(phase>=100?openStage:"open-rollback/"+CloseStage(phase));};
            byte[] ip = IPAddress.Parse(address).GetAddressBytes();
            cancellationToken.ThrowIfCancellationRequested();
            for(int attempt=0;;attempt++){
                if(NativeLibrary.TryGetExport(library,"sltun_open_cancellable",out var cancellableOpen))
                    error=Marshal.GetDelegateForFunctionPointer<CancellableOpen>(cancellableOpen)(driver,name,ref guid,ip,out adapter,callback,cancellationToken.WaitHandle.SafeWaitHandle);
                else if(NativeLibrary.TryGetExport(library,"sltun_open_with_trace",out var diagnosticOpen))
                    error=Marshal.GetDelegateForFunctionPointer<TracedOpen>(diagnosticOpen)(driver,name,ref guid,ip,out adapter,callback);
                else error=Load<Open>("sltun_open")(driver,name,ref guid,ip,out adapter);
                GC.KeepAlive(callback);cancellationToken.ThrowIfCancellationRequested();
                if(error!=4319||adapter!=IntPtr.Zero||attempt>=1)break;
                // The synchronous official create has finished its rollback.
                // Never adopt its failed GUID or overlap a pending PnP call.
                // One bounded fresh-generation retry handles class setup lag.
                Trace("adapter-class-setup-retry");
                WintunAdapterJournal.MarkClosed(scope,failedCreate:true);
                if(cancellationToken.WaitHandle.WaitOne(1000))cancellationToken.ThrowIfCancellationRequested();
                preparation=WintunAdapterJournal.Prepare(scope,cancellationToken,Trace,ownerNetwork==null?null:new(network,slot));
                guid=preparation.Identity.Guid;name=preparation.Identity.Name;
            }
            // An older ABI-2 bridge may finish after cancellation. The catch
            // below closes that late result before this task may complete.
            cancellationToken.ThrowIfCancellationRequested();
            if (error != 0) throw new Win32Exception((int)error,(error switch {
                4319 => "Windows 未完成 Wintun 网卡准备（4319）；请检查系统网络设备状态。",
                183 => "相同网卡身份仍存在；未接管或删除，请等待旧实例完成退出。",
                _ => "原生虚拟网卡创建失败。"
            }) + "阶段=" + openStage);
            if(NativeLibrary.TryGetExport(library,"sltun_luid",out var identityExport)) {
                error=Marshal.GetDelegateForFunctionPointer<ReadLuid>(identityExport)(adapter,out var luid);
                if(error!=0||luid==0)throw new IOException("网卡实际 LUID 身份无效");InterfaceLuid=luid;
            }
        } catch { if(adapter!=IntPtr.Zero){close!(adapter);adapter=IntPtr.Zero;}NativeLibrary.Free(library); throw; }
        } finally { lifecycle.Release(); }
        } catch { meshIdentityLease?.Dispose();identityLease.Dispose(); throw; }
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
    void Trace(string stage){if(Interlocked.Exchange(ref lastTraced,stage)==stage)return;try{LifecycleTrace?.Invoke(stage);}catch{/* diagnostics cannot break native resource cleanup */}}
    static string OpenStage(uint phase)=>phase switch{
        101=>"wintun-load-begin",102=>"wintun-load-complete",103=>"adapter-create-begin",104=>"adapter-create-complete",
        105=>"ipv4-interface-get-begin",106=>"ipv4-interface-get-complete",107=>"ipv4-interface-set-begin",108=>"ipv4-interface-set-complete",
        109=>"ipv4-address-create-begin",110=>"ipv4-address-create-complete",111=>"session-start-begin",112=>"session-start-complete",
        113=>"read-event-get-begin",114=>"read-event-get-complete",115=>"adapter-open-complete",
        117=>"adapter-create-retry-1",118=>"adapter-create-retry-2",119=>"identity-vacant-wait",120=>"identity-vacant",
        122=>"ipv4-interface-wait",123=>"adapter-create-retry-budget-exhausted",_=>"unknown-open-phase"};
    static string CloseStage(uint phase)=>phase switch{
        1=>"native-stop-handle-close-begin",2=>"native-stop-handle-close-complete",
        3=>"native-session-end-begin",4=>"native-session-end-complete",
        5=>"native-adapter-close-begin",6=>"native-adapter-close-complete",
        7=>"wintun-library-free-begin",8=>"wintun-library-free-complete",_=>"unknown-native-close-phase"};
    void TraceNative(uint phase)=>Trace(CloseStage(phase));
    // The caller joins both packet pumps before closing the native session.
    public void Dispose() {
        // Signal BEFORE waiting for in-flight native reads. Delegate calls hold
        // a shared guard so stats/write/cancellation cannot race a freed pointer
        // or a library unload, even when a caller violates normal pump ordering.
        Trace("stop-begin");Stop();Trace("stop-complete");Trace("exclusive-wait");io.EnterWriteLock();try{
            if(disposed)return;Trace("exclusive-acquired");disposed=true;Trace("native-close-begin");
            lifecycle.Wait();
            try {
                if(LifecycleTrace!=null&&tracedClose!=null){NativeCloseTrace callback=TraceNative;tracedClose(adapter,callback);GC.KeepAlive(callback);}
                else {if(LifecycleTrace!=null)Trace("native-close-phase-trace-unavailable");close(adapter);}
            } finally { lifecycle.Release(); }
            Trace("native-close-complete");adapter=IntPtr.Zero;
            // The guarded native handle closes here; OS/PnP disappearance is
            // recorded separately. Do not block all statistics/cancel callers
            // behind unbounded interface enumeration or alter foreign drivers.
            Trace("bridge-library-free-begin");NativeLibrary.Free(library);Trace("library-free-complete");
            try{WintunAdapterJournal.MarkClosed(ownershipScope);}
            finally{meshIdentityLease?.Dispose();identityLease.Dispose();}
        }finally{io.ExitWriteLock();}
        // Do not dispose the guard: late calls must deterministically observe
        // the adapter's disposed state rather than touch a closed native handle.
    }
}
