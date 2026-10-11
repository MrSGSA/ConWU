using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace StreamLink.Core;

[SupportedOSPlatform("windows")]
public sealed class WinDivertEndpointIo : IEndpointPacketIo
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)] delegate IntPtr Open(string filter, int layer, short priority, ulong flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = true)] delegate bool Recv(IntPtr h, byte[] p, uint capacity, out uint length, byte[] address);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = true)] delegate bool Send(IntPtr h, byte[] p, uint length, out uint sent, byte[] address);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = true)] delegate bool SetParam(IntPtr h, int param, ulong value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate bool ShutdownApi(IntPtr h, int how);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate bool Close(IntPtr h);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate bool Checksums(byte[] p, uint length, byte[] address, ulong flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr h);
    readonly IntPtr library, handle;
    readonly Recv recv;
    readonly Send send;
    readonly ShutdownApi shutdown;
    readonly Close close;
    readonly Checksums checksums;
    readonly byte[] receiveBuffer = new byte[65535], receiveAddress = new byte[80];
    int stopped, disposed;
    public string Filter { get; }
    public static string FilterFor(IPEndPoint local, IPEndPoint helper)
    {
        if (local.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || local.Port == 0 || IPAddress.IsLoopback(local.Address) || local.Address.Equals(IPAddress.Any) ||
            helper.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || helper.Port == 0 || helper.Address.Equals(IPAddress.Any) || local.Equals(helper))
            throw new ArgumentException("A held physical IPv4 source endpoint is required");
        // WinDivert permits negation of a test, not !(compound expression).
        // De Morgan form excludes exactly the helper tuple in both directions.
        return $"!loopback and ip and tcp and ((inbound and ip.DstAddr == {local.Address} and tcp.DstPort == {local.Port} and (ip.SrcAddr != {helper.Address} or tcp.SrcPort != {helper.Port})) or (outbound and ip.SrcAddr == {local.Address} and tcp.SrcPort == {local.Port} and (ip.DstAddr != {helper.Address} or tcp.DstPort != {helper.Port})))";
    }
    public WinDivertEndpointIo(string dll, IPEndPoint local, IPEndPoint helper)
    {
        Filter = FilterFor(local, helper);
        library = LoadLibraryExW(Path.GetFullPath(dll), IntPtr.Zero, 0x1100); // DLL_LOAD_DIR | SYSTEM32
        if (library == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastPInvokeError());
        T Api<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
        try {
            recv = Api<Recv>("WinDivertRecv"); send = Api<Send>("WinDivertSend"); shutdown = Api<ShutdownApi>("WinDivertShutdown"); close = Api<Close>("WinDivertClose"); checksums = Api<Checksums>("WinDivertHelperCalcChecksums");
            handle = Api<Open>("WinDivertOpen")(Filter, 0, 100, 16); // NETWORK, sole owner, NO_INSTALL
            if (handle == new IntPtr(-1)) { int error = Marshal.GetLastPInvokeError(); throw new Win32Exception(error, $"Endpoint capture open failed: Win32 {error}: {new Win32Exception(error).Message}"); }
            var set = Api<SetParam>("WinDivertSetParam");
            if (!set(handle, 0, 4096) || !set(handle, 1, 100) || !set(handle, 2, 4 * 1024 * 1024)) throw new IOException("Cannot set bounded capture queue");
        } catch { if (handle != IntPtr.Zero && handle != new IntPtr(-1)) close?.Invoke(handle); FreeLibrary(library); throw; }
    }
    public ValueTask<EndpointPacket> Receive(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        byte[] packet = receiveBuffer, address = receiveAddress;
        if (!recv(handle, packet, (uint)packet.Length, out uint length, address)) throw new IOException("Capture receive stopped: " + Marshal.GetLastPInvokeError());
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(address.AsSpan(8));
        bool outbound = (flags & (1u << 17)) != 0;
        // Same normalization as native backend; only checksums, no seq/payload changes.
        if ((flags & ((1u << 21) | (1u << 22))) != ((1u << 21) | (1u << 22)) && !checksums(packet, length, address, 0))
            throw new IOException("Capture checksum normalization failed");
        return ValueTask.FromResult(new EndpointPacket(packet.AsSpan(0, checked((int)length)).ToArray(), outbound, (byte[])address.Clone()));
    }
    public bool Inject(ReadOnlySpan<byte> packet)
    {
        byte[] address = new byte[80]; BinaryPrimitives.WriteUInt32LittleEndian(address.AsSpan(8), (1u << 17) | (1u << 21) | (1u << 22));
        byte[] data = packet.ToArray();
        return checksums(data, (uint)data.Length, address, 0) && send(handle, data, (uint)data.Length, out uint sent, address) && sent == data.Length;
    }
    public bool Reinject(EndpointPacket packet) => packet.PlatformAddress is { Length: 80 } address && send(handle, packet.Bytes, (uint)packet.Bytes.Length, out uint sent, address) && sent == packet.Bytes.Length;
    public void Shutdown() { if (Interlocked.Exchange(ref stopped, 1) == 0) shutdown(handle, 3); }
    public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) != 0) return; Shutdown(); if (!close(handle)) throw new IOException("Capture handle closure failed"); FreeLibrary(library); }
}
