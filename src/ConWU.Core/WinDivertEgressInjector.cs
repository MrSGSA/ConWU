using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace StreamLink.Core;

// Injection only: capture and narrowly scoped RST suppression remain owned by
// the unchanged authorized legacy child. Never installs an additional driver.
[SupportedOSPlatform("windows")]
internal sealed class WinDivertEgressInjector:IDisposable
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,CharSet=CharSet.Ansi,SetLastError=true)]delegate IntPtr Open(string filter,int layer,short priority,ulong flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,SetLastError=true)]delegate bool Send(IntPtr handle,byte[] data,uint length,out uint sent,byte[] address);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]delegate bool Close(IntPtr handle);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr LoadLibraryExW(string path,IntPtr file,uint flags);
    readonly IntPtr library,handle;
    readonly Send send;
    readonly Close close;
    int disposed;
    internal WinDivertEgressInjector(string dll)
    {
        library=LoadLibraryExW(Path.GetFullPath(dll),IntPtr.Zero,0x1100);if(library==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastPInvokeError());
        try{
            T Api<T>(string name)where T:Delegate=>Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library,name));
            send=Api<Send>("WinDivertSend");close=Api<Close>("WinDivertClose");
            handle=Api<Open>("WinDivertOpen")("false",0,100,24); // SEND_ONLY | NO_INSTALL
            if(handle==new IntPtr(-1))throw new Win32Exception(Marshal.GetLastPInvokeError());
        }catch{NativeLibrary.Free(library);throw;}
    }
    internal bool Inject(ReadOnlySpan<byte> packet)
    {
        if(disposed!=0||!TcpPacketValidation.Checksums(packet))return false;
        var address=new byte[80];BinaryPrimitives.WriteUInt32LittleEndian(address.AsSpan(8),(1u<<17)|(1u<<21)|(1u<<22));
        byte[] data=packet.ToArray();return send(handle,data,(uint)data.Length,out var count,address)&&count==data.Length;
    }
    public void Dispose(){if(Interlocked.Exchange(ref disposed,1)!=0)return;close(handle);NativeLibrary.Free(library);}
}
