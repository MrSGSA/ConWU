using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using StreamLink.Core;

namespace StreamLink.Discovery;

// One read-only raw TCP socket. No libpcap dependency and no server replies.
// Classic BPF admits only a header-only IPv4 SYN to the configured
// addresses/ports. Kernel TCP is unaffected (it may send a normal RST).
public sealed class LinuxSynCapture : IAsyncDisposable
{
    readonly Socket socket;
    readonly TcpSynObserver observer;
    readonly CancellationTokenSource stop = new();
    readonly Task pump;
    public long ReceivedPackets => Interlocked.Read(ref received);
    long received;
    [StructLayout(LayoutKind.Sequential)] struct Filter { public ushort Code; public byte Yes, No; public uint K; }
    [StructLayout(LayoutKind.Sequential)] struct Program { public ushort Length; public IntPtr Instructions; }
    [DllImport("libc", SetLastError = true)] static extern int setsockopt(int fd, int level, int name, ref Program program, uint size);
    [DllImport("libc", SetLastError = true)] static extern int setsockopt(int fd, int level, int name, ref int value, uint size);
    public LinuxSynCapture(TcpSynObserver observer, TcpObserverPoint[] points)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("SYN 观察器需要 Linux CAP_NET_RAW");
        TcpObserverProtocol.ValidatePoints(points); this.observer = observer;
        socket = new(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
        try {
            socket.ReceiveBufferSize = 65536;
            Attach(points.Select(p => TcpObserverProtocol.Endpoint(p.Endpoint)).ToArray());
            observer.SetAvailable(true); pump = Receive();
        } catch { socket.Dispose(); throw; }
    }
    void Attach(IPEndPoint[] targets)
    {
        var code = new List<Filter>(); var reject = new List<int>(); var accept = new List<int>();
        void Emit(ushort op, uint k, byte yes = 0, byte no = 0) => code.Add(new() { Code = op, K = k, Yes = yes, No = no });
        void Equal(uint k) { reject.Add(code.Count); Emit(0x15, k); }
        Emit(0x30, 0); Emit(0x54, 0xf0); Equal(0x40);
        Emit(0x30, 9); Equal(6);
        Emit(0x28, 6); Emit(0x54, 0x3fff); Equal(0); // no fragments
        Emit(0xb1, 0); // X = IPv4 header length
        Emit(0x50, 13); Equal(2); // bare SYN, no ACK/RST/data
        Emit(0x50, 12); Emit(0x54, 15); Equal(0); // no reserved/NS bits
        Emit(0x50, 12); Emit(0x74, 4); Emit(0x64, 2); Emit(0x0c, 0); Emit(0x07, 0); // X = IP + TCP header sizes
        Emit(0x28, 2); reject.Add(code.Count); Emit(0x1d, 0); // total length == X, no payload
        Emit(0xb1, 0); // Restore IP length for port lookup. Options may be rewritten by a middlebox.
        foreach (var ep in targets) {
            Emit(0x20, 16); Emit(0x15, BinaryPrimitives.ReadUInt32BigEndian(ep.Address.GetAddressBytes()), no: 2);
            Emit(0x48, 2); accept.Add(code.Count); Emit(0x15, (uint)ep.Port);
        }
        int drop = code.Count; Emit(0x06, 0); int keep = code.Count; Emit(0x06, 120); // max IPv4+TCP headers, never payload
        foreach (int i in reject) { var f = code[i]; f.No = checked((byte)(drop - i - 1)); code[i] = f; }
        foreach (int i in accept) { var f = code[i]; f.Yes = checked((byte)(keep - i - 1)); code[i] = f; }
        var pin = GCHandle.Alloc(code.ToArray(), GCHandleType.Pinned);
        try {
            var program = new Program { Length = checked((ushort)code.Count), Instructions = pin.AddrOfPinnedObject() };
            if (setsockopt(socket.Handle.ToInt32(), 1, 26, ref program, (uint)Marshal.SizeOf<Program>()) != 0) throw new SocketException(Marshal.GetLastPInvokeError());
            int one = 1; if (setsockopt(socket.Handle.ToInt32(), 1, 44, ref one, 4) != 0) throw new SocketException(Marshal.GetLastPInvokeError());
        } finally { pin.Free(); }
    }
    async Task Receive()
    {
        byte[] header = new byte[120];
        try {
            while (true) {
                int count = await socket.ReceiveAsync(header, SocketFlags.None, stop.Token);
                Interlocked.Increment(ref received); observer.Observe(header.AsSpan(0, count));
            }
        } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (SocketException) { } // Disable observation; normal coordination continues.
        finally { observer.SetAvailable(false); }
    }
    public async ValueTask DisposeAsync() { stop.Cancel(); await pump; socket.Dispose(); stop.Dispose(); }
}
