using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using StreamLink.Core;

static class CaptureFilterTests
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)] delegate bool Compile(string filter, int layer, IntPtr output, uint length, out IntPtr error, out uint position);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)] delegate bool Evaluate(string filter, byte[] packet, uint length, byte[] address);
    public static void Run(string dll, Action<bool, string> check)
    {
        var library = NativeLibrary.Load(Path.GetFullPath(dll));
        try {
            var compile = Marshal.GetDelegateForFunctionPointer<Compile>(NativeLibrary.GetExport(library, "WinDivertHelperCompileFilter"));
            var evaluate = Marshal.GetDelegateForFunctionPointer<Evaluate>(NativeLibrary.GetExport(library, "WinDivertHelperEvalFilter"));
            var local = IPEndPoint.Parse("192.0.2.1:40001"); var helper = IPEndPoint.Parse("192.0.2.2:3478");
            string filter = WinDivertEndpointIo.FilterFor(local, helper);
            check(compile(filter, 0, IntPtr.Zero, 0, out var error, out var at), "official WinDivert compiler accepts source-owner filter without loading driver: " + Marshal.PtrToStringAnsi(error) + " at " + at);
            bool Matches(IPEndPoint from, IPEndPoint to, bool outbound, bool loopback = false) {
                byte[] p = new byte[40]; p[0] = 0x45; p[3] = 40; p[9] = 6; p[32] = 0x50; p[33] = 0x10;
                from.Address.GetAddressBytes().CopyTo(p, 12); to.Address.GetAddressBytes().CopyTo(p, 16);
                BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), (ushort)from.Port); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), (ushort)to.Port);
                byte[] address = new byte[80]; BinaryPrimitives.WriteUInt32LittleEndian(address.AsSpan(8), (outbound ? 1u << 17 : 0) | (loopback ? 1u << 18 : 0));
                return evaluate(filter, p, (uint)p.Length, address);
            }
            check(!Matches(local, helper, true) && !Matches(helper, local, false), "actual filter evaluator excludes both helper directions");
            var sameIp = new IPEndPoint(helper.Address, 3479); var samePort = IPEndPoint.Parse("192.0.2.3:3478");
            check(Matches(local, sameIp, true) && Matches(sameIp, local, false) && Matches(local, samePort, true) && Matches(samePort, local, false),
                "helper exception is exact tuple, not whole helper address or port");
            check(!Matches(new(local.Address, 40002), sameIp, true) && !Matches(sameIp, new(local.Address, 40002), false) && !Matches(local, sameIp, true, true),
                "filter cannot capture other source ports or loopback");
        } finally { NativeLibrary.Free(library); }
    }
}
