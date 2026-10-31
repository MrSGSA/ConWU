using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;

static partial class TcpTests
{
    static int Port() { using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp); s.Bind(new IPEndPoint(IPAddress.Loopback, 0)); return ((IPEndPoint)s.LocalEndPoint!).Port; }
    public static async Task Run()
    {
        await SelectionOwnership();
        await using (var first = new StunServer())
        await using (var spare = new StunServer()) {
            int port = Port(); var clock = Stopwatch.StartNew();
            var (binding, result) = await TcpBinding.Connect(port, IPAddress.Loopback, _ => { }, CancellationToken.None, [first.Address, spare.Address]);
            using (binding) {
                Program.Check(result.Server == first.Address && result.Local.Port == port && result.Public.Port == port, "TCP STUN retains the actual fixed source port");
                var again = await binding.Pulse(CancellationToken.None);
                Program.Check(first.Accepted == 1 && first.Requests == 2 && again.Public.Equals(result.Public), "keepalive uses the winning persistent TCP connection");
                Program.Check(spare.Accepted == 0 && clock.ElapsedMilliseconds < 1500, "healthy preferred server avoids fallback traffic and delay");
            }
        }
        await using (var slow = new StunServer { Silent = true })
        await using (var fast = new StunServer()) {
            int port = Port(); var clock = Stopwatch.StartNew();
            var (binding, result) = await TcpBinding.Connect(port, IPAddress.Loopback, _ => { }, CancellationToken.None, [slow.Address, fast.Address]);
            using (binding) {
                Program.Check(result.Server == fast.Address && clock.ElapsedMilliseconds < 2500, "slow preferred STUN does not impose its four-second timeout");
                Program.Check(fast.SourcePorts.Contains(port) && fast.SourcePorts.Any(p => p != port) && result.Public.Port == port, "ephemeral screening result is discarded; final mapping is queried again");
                await binding.Pulse(CancellationToken.None);
                Program.Check(fast.SourcePorts.Count(p => p == port) == 1, "fallback keepalive retains the verified fixed-port socket");
            }
            await Program.Until(() => slow.Active == 0 && fast.Active == 0, "screening and losing fixed-port sockets are closed", 1500);
            Console.WriteLine($"TCP fallback and cleanup: {clock.ElapsedMilliseconds} ms");
        }
        await using (var malformed = new StunServer { WrongTransaction = true })
        await using (var valid = new StunServer()) {
            var (binding, result) = await TcpBinding.Connect(Port(), IPAddress.Loopback, _ => { }, CancellationToken.None, [malformed.Address, valid.Address]);
            using (binding) Program.Check(result.Server == valid.Address, "wrong STUN transaction cannot become the published mapping");
        }
        await using (var silent = new StunServer { Silent = true })
        using (var cancel = new CancellationTokenSource(150)) {
            int port = Port(); bool canceled = false; var clock = Stopwatch.StartNew();
            try { await TcpBinding.Connect(port, IPAddress.Loopback, _ => { }, cancel.Token, [silent.Address]); }
            catch (OperationCanceledException) { canceled = true; }
            Program.Check(canceled && clock.ElapsedMilliseconds < 1500, "caller cancellation promptly ends a blocked STUN round");
            using var rebound = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
            rebound.Bind(new IPEndPoint(IPAddress.Loopback, port)); Program.Check(true, "canceled fixed port can be bound again");
        }
        // Every ephemeral screen succeeds but every actual mapping query stalls.
        // This forces multiple serial fixed-port retries against one round budget.
        int actual = Port(); var servers = Enumerable.Range(0, 5).Select(_ => new StunServer { SilentPort = actual }).ToArray();
        try {
            var clock = Stopwatch.StartNew(); bool failed = false;
            try { var result = await TcpBinding.Connect(actual, IPAddress.Loopback, _ => { }, CancellationToken.None, servers.Select(s => s.Address)); result.Binding.Dispose(); }
            catch (IOException) { failed = true; }
            Program.Check(failed && clock.ElapsedMilliseconds is >= 11000 and < 14500, "entire TCP selection round is bounded to twelve seconds");
            await Program.Until(() => servers.All(s => s.Active == 0), "budget exhaustion cleans all probe sockets", 1500);
        } finally { foreach (var s in servers) await s.DisposeAsync(); }
        await Ownership();
    }

    sealed class StunServer : IAsyncDisposable
    {
        readonly TcpListener listener = new(IPAddress.Loopback, 0);
        readonly CancellationTokenSource stop = new();
        readonly Task accepting;
        readonly ConcurrentBag<Task> handlers = [];
        public ConcurrentBag<int> SourcePorts = [];
        public int Accepted, Active, Requests, Eof, Resets;
        public bool Silent, WrongTransaction;
        public Task? BeforeReply;
        public int SilentPort;
        public string Address => listener.LocalEndpoint.ToString()!;
        public StunServer() { listener.Start(); accepting = Accept(); }
        async Task Accept()
        {
            while (!stop.IsCancellationRequested) {
                var client = await listener.AcceptTcpClientAsync(stop.Token); Interlocked.Increment(ref Accepted);
                handlers.Add(Handle(client));
            }
        }
        async Task Handle(TcpClient client)
        {
            Interlocked.Increment(ref Active);
            try {
                using (client) {
                    var remote = (IPEndPoint)client.Client.RemoteEndPoint!; SourcePorts.Add(remote.Port); var stream = client.GetStream(); byte[] req = new byte[20];
                    while (!stop.IsCancellationRequested) {
                        await stream.ReadExactlyAsync(req, stop.Token); Interlocked.Increment(ref Requests);
                        if (Silent || SilentPort == remote.Port) continue;
                        if (BeforeReply != null) await BeforeReply.WaitAsync(stop.Token);
                        byte[] result = new byte[32]; req.CopyTo(result, 0); result[0] = 1; result[1] = 1; result[3] = 12;
                        if (WrongTransaction) result[8] ^= 0x10;
                        result[21] = 0x20; result[23] = 8; result[25] = 1;
                        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(26), (ushort)(remote.Port ^ 0x2112));
                        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(28), BinaryPrimitives.ReadUInt32BigEndian(remote.Address.GetAddressBytes()) ^ 0x2112a442);
                        await stream.WriteAsync(result, stop.Token);
                    }
                }
            } catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException) {
                if (ex is EndOfStreamException) Interlocked.Increment(ref Eof);
                if (ex is SocketException { SocketErrorCode: SocketError.ConnectionReset } || ex.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset }) Interlocked.Increment(ref Resets);
            }
            finally { Interlocked.Decrement(ref Active); }
        }
        public async ValueTask DisposeAsync()
        {
            stop.Cancel(); listener.Stop(); try { await accepting; } catch (Exception ex) when (ex is OperationCanceledException or SocketException) { }
            await Task.WhenAll(handlers); stop.Dispose();
        }
    }
}
