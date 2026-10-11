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
            foreach (bool v6 in new[] { false, true }) {
            var local = IPEndPoint.Parse(v6 ? "[2001:db8::1]:40001" : "192.0.2.1:40001"); var helper = IPEndPoint.Parse(v6 ? "[2001:db8::2]:3478" : "192.0.2.2:3478");
            string filter = WinDivertEndpointIo.FilterFor(local, helper);
            check(compile(filter, 0, IntPtr.Zero, 0, out var error, out var at), "official WinDivert compiler accepts source-owner filter without loading driver: " + Marshal.PtrToStringAnsi(error) + " at " + at);
            byte[] Packet(IPEndPoint from, IPEndPoint to) {
                int ip = v6 ? 40 : 20; byte[] p = new byte[ip + 20];
                if (v6) { p[0] = 0x60; p[5] = 20; p[6] = 6; p[7] = 64; }
                else { p[0] = 0x45; p[3] = 40; p[9] = 6; }
                p[ip + 12] = 0x50; p[ip + 13] = 0x10;
                from.Address.GetAddressBytes().CopyTo(p, v6 ? 8 : 12); to.Address.GetAddressBytes().CopyTo(p, v6 ? 24 : 16);
                BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(ip), (ushort)from.Port); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(ip + 2), (ushort)to.Port);
                return p;
            }
            bool Matches(IPEndPoint from, IPEndPoint to, bool outbound, bool loopback = false) {
                byte[] p = Packet(from, to);
                byte[] address = new byte[80]; BinaryPrimitives.WriteUInt32LittleEndian(address.AsSpan(8), (outbound ? 1u << 17 : 0) | (loopback ? 1u << 18 : 0) | (v6 ? 1u << 20 : 0));
                return evaluate(filter, p, (uint)p.Length, address);
            }
            check(!Matches(local, helper, true) && !Matches(helper, local, false), "actual filter evaluator excludes both helper directions");
            var sameIp = new IPEndPoint(helper.Address, 3479); var samePort = IPEndPoint.Parse(v6 ? "[2001:db8::3]:3478" : "192.0.2.3:3478");
            check(Matches(local, sameIp, true) && Matches(sameIp, local, false) && Matches(local, samePort, true) && Matches(samePort, local, false),
                "helper exception is exact tuple, not whole helper address or port");
            check(!Matches(new(local.Address, 40002), sameIp, true) && !Matches(sameIp, new(local.Address, 40002), false) && !Matches(local, sameIp, true, true),
                "filter cannot capture other source ports or loopback");
            if (v6) {
                var p = Packet(local, samePort);
                check(TcpCaptureOwner.Tuple(p, out var source, out var target, true) && source.Equals(local) && target.Equals(samePort), "IPv6 broker parser matches complete authorized source and destination");
                foreach (byte next in new byte[] { 0, 43, 44, 60 }) { var changed = p.ToArray(); changed[6] = next; check(!TcpCaptureOwner.Tuple(changed, out _, out _, true), "IPv6 broker rejects extension/fragment header " + next); }
                var truncated = p[..^1]; var oversized = p.Concat(new byte[1]).ToArray(); var badTcp = p.ToArray(); badTcp[52] = 0xf0;
                check(!TcpCaptureOwner.Tuple(truncated, out _, out _, true) && !TcpCaptureOwner.Tuple(oversized, out _, out _, true) && !TcpCaptureOwner.Tuple(badTcp, out _, out _, true), "IPv6 broker rejects inconsistent IP/TCP lengths before worker dispatch");
            }
            }
        } finally { NativeLibrary.Free(library); }
    }
}
