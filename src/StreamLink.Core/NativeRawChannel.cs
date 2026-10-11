using System.Buffers.Binary;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace StreamLink.Core;

// An ACL-restricted, PID-checked local pipe. It carries raw datagrams only
// between the authorized protocol worker and its one source capture owner.
[SupportedOSPlatform("windows")]
internal sealed class NativeRawChannel : IAsyncDisposable
{
    readonly NamedPipeServerStream pipe;
    readonly TcpCaptureOwner.Session session;
    readonly CancellationTokenSource stop = new();
    Task running = Task.CompletedTask;
    public event Action? Faulted;
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
    public NativeRawChannel(string controlName, TcpCaptureOwner.Session session)
    {
        this.session = session;
        pipe = new("StreamLink.Raw." + controlName[18..], PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance, 131072, 131072);
    }
    public void Start(int processId, byte[] identity) => running = Run(processId, (byte[])identity.Clone());
    async Task Run(int processId, byte[] identity)
    {
        Task? input = null, output = null;
        try {
            using var ready = CancellationTokenSource.CreateLinkedTokenSource(stop.Token); ready.CancelAfter(20000);
            await pipe.WaitForConnectionAsync(ready.Token);
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint pid) || pid != processId) throw new IOException("Raw pipe is not the authorized worker");
            byte[] hello = new byte[96]; await pipe.ReadExactlyAsync(hello, ready.Token);
            if (!hello.AsSpan().SequenceEqual(identity)) throw new IOException("Raw pipe attachment mismatch");
            await session.CaptureReady.WaitAsync(ready.Token); await pipe.WriteAsync(identity, ready.Token);
            input = Input(); output = Output();
            await await Task.WhenAny(input, output);
            if (!stop.IsCancellationRequested) throw new IOException("Raw packet pipe ended");
        } catch (Exception) when (stop.IsCancellationRequested) { }
        catch { session.Revoke(); Faulted?.Invoke(); }
        finally {
            stop.Cancel(); pipe.Dispose();
            if (input != null) try { await input; } catch { }
            if (output != null) try { await output; } catch { }
        }
    }
    async Task Input()
    {
        byte[] length = new byte[4];
        while (true) {
            await pipe.ReadExactlyAsync(length, stop.Token); int size = BinaryPrimitives.ReadInt32LittleEndian(length);
            if (size is < 40 or > 65535) throw new IOException("Raw packet frame exceeds bounds");
            byte[] packet = new byte[size]; await pipe.ReadExactlyAsync(packet, stop.Token);
            session.Send(packet); // revalidates source and authorized tuple, including after Revoke
        }
    }
    async Task Output()
    {
        while (true) {
            byte[] packet = await session.Receive(stop.Token), frame = new byte[4 + packet.Length];
            BinaryPrimitives.WriteInt32LittleEndian(frame, packet.Length); packet.CopyTo(frame, 4);
            await pipe.WriteAsync(frame, stop.Token);
        }
    }
    public async ValueTask DisposeAsync() { stop.Cancel(); pipe.Dispose(); await running; stop.Dispose(); }
}
