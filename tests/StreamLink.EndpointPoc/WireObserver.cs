using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;

namespace StreamLink.EndpointPoc;

// Observer at the RECEIVING Windows IP layer before the owned divert. This
// proves arrival at the far Windows stack, not a physical tap or NIC offload view.
sealed class WireObserver : IDisposable
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
    delegate IntPtr Open(string filter, int layer, short priority, ulong flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = true)]
    delegate bool Recv(IntPtr handle, byte[] packet, uint capacity, out uint length, byte[] address);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate bool Close(IntPtr handle);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate bool Shutdown(IntPtr handle, int how);
    readonly IntPtr library, handle;
    readonly Recv recv;
    readonly Close close;
    readonly Shutdown shutdown;
    readonly Task reader;
    readonly List<WireEvent> events = [];
    bool disposed;
    int error;
    public sealed record WireEvent(long Tick, int Length, byte Flags, uint Sequence, uint Ack, int Payload);
    public WireObserver(string dll, IPEndPoint local, IPEndPoint remote)
    {
        library = NativeLibrary.Load(Path.GetFullPath(dll));
        T Api<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
        try {
            var open = Api<Open>("WinDivertOpen"); recv = Api<Recv>("WinDivertRecv"); close = Api<Close>("WinDivertClose"); shutdown = Api<Shutdown>("WinDivertShutdown");
            string filter = $"inbound and !loopback and ip and tcp and ip.DstAddr == {local.Address} and tcp.DstPort == {local.Port} and ip.SrcAddr == {remote.Address} and tcp.SrcPort == {remote.Port}";
            handle = open(filter, 0, 200, 1 | 16); // SNIFF + NO_INSTALL; never diverts
            if (handle == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError(), "Wire observer requires the already installed driver");
            reader = Task.Run(() => {
                byte[] packet = new byte[65535], address = new byte[80];
                while (recv(handle, packet, (uint)packet.Length, out uint n, address)) {
                    int ip = (packet[0] & 15) * 4; if (n < ip + 20) continue;
                    int tcp = (packet[ip + 12] >> 4) * 4;
                    var row = new WireEvent(Environment.TickCount64, (int)n, packet[ip + 13], BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(ip + 4)),
                        BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(ip + 8)), (int)n - ip - tcp);
                    lock (events) { if (events.Count < 20000) events.Add(row); else error = -2; }
                }
                int e = Marshal.GetLastPInvokeError(); if (!disposed && e != 232) error = e;
            });
        } catch { NativeLibrary.Free(library); throw; }
    }
    public object Snapshot(long armed, long revoked)
    {
        lock (events) {
            var window = events.Where(e => e.Tick >= armed && e.Tick < revoked).ToArray();
            return new { point = "receiving-host NETWORK inbound SNIFF priority 200, over specified test interface", error,
                observed = window.Length, rst = window.Count(e => (e.Flags & 4) != 0), synAck = window.Count(e => (e.Flags & 18) == 18),
                armedTick = armed, revokedTick = revoked, rows = window };
        }
    }
    public void Dispose()
    {
        if (disposed) return; disposed = true; shutdown(handle, 3); reader.GetAwaiter().GetResult(); close(handle); NativeLibrary.Free(library);
    }
}
