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
}

[SupportedOSPlatform("windows")]
public sealed class NativeAdapter : IPacketAdapter
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)] delegate uint Open(string dll, string name, ref Guid guid, byte[] ip, out IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void Close(IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint ReadPacket(IntPtr adapter, byte[] packet, uint capacity, out uint length);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate uint WritePacket(IntPtr adapter, byte[] packet, uint length);
    readonly IntPtr library;
    IntPtr adapter;
    readonly Close close;
    readonly ReadPacket read;
    readonly WritePacket write;
    bool disposed;
    public NativeAdapter(string components, string network, int slot)
    {
        if (!WindowsHost.IsAdmin) throw new IOException("创建虚拟网卡需要管理员权限");
        string prefix = MeshIdentity.Prefix(network) + ".";
        if (NetworkInterface.GetAllNetworkInterfaces().SelectMany(n => n.GetIPProperties().UnicastAddresses).Any(a => a.Address.ToString().StartsWith(prefix, StringComparison.Ordinal))) throw new IOException($"虚拟网段 {prefix}0/24 已被占用，请使用另一网络");
        string driver = Path.GetFullPath(Path.Combine(components, "wintun.dll"));
        if (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(driver))) != "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE") throw new IOException("Wintun 组件校验失败");
        library = NativeLibrary.Load(Path.GetFullPath(Path.Combine(components, "streamlink-tun.dll")));
        try {
            T Load<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
            close = Load<Close>("sltun_close"); read = Load<ReadPacket>("sltun_read"); write = Load<WritePacket>("sltun_write");
            var guid = new Guid(SHA256.HashData(Encoding.ASCII.GetBytes($"streamlink-wintun-v4/{network}/{slot}")).AsSpan(0, 16));
            uint error = Load<Open>("sltun_open")(driver, $"StreamLink-{network[..8]}-{slot}", ref guid, IPAddress.Parse(MeshIdentity.Address(network, slot)).GetAddressBytes(), out adapter);
            if (error != 0) throw new Win32Exception((int)error, "原生虚拟网卡创建失败");
        } catch { NativeLibrary.Free(library); throw; }
    }
    public int Read(byte[] buffer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        uint error = read(adapter, buffer, (uint)buffer.Length, out uint count);
        if (error is 259 or 122) return 0;
        if (error != 0) throw new Win32Exception((int)error, "虚拟网卡读取失败");
        return (int)count;
    }
    public bool Write(byte[] packet)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        uint error = write(adapter, packet, (uint)packet.Length);
        if (error == 111) return false; // Bounded rings drop instead of building latency.
        if (error != 0) throw new Win32Exception((int)error, "虚拟网卡写入失败");
        return true;
    }
    // The caller joins both packet pumps before closing the native session.
    public void Dispose() { if (disposed) return; disposed = true; close(adapter); adapter = IntPtr.Zero; NativeLibrary.Free(library); }
}
