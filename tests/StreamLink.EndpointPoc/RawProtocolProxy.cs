using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace StreamLink.EndpointPoc;

// Carries raw frames ONLY between this test's loopback native sockets. Bounded
// header metadata and deterministic handshake fault injection, never WAN relay.
sealed class RawProtocolProxy : IAsyncDisposable
{
    readonly UdpClient client = new(new IPEndPoint(IPAddress.Loopback, 0));
    readonly UdpClient server = new(new IPEndPoint(IPAddress.Loopback, 0));
    readonly CancellationTokenSource stop = new();
    readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly Task cPump, sPump;
    readonly object gate = new();
    readonly List<Header> headers = [];
    readonly byte dropFlags;
    readonly bool dropClient;
    bool dropped;
    public int ClientPort => ((IPEndPoint)client.Client.LocalEndPoint!).Port;
    public int ServerPort => ((IPEndPoint)server.Client.LocalEndPoint!).Port;
    // Hold initial delivery until both test sockets exist, so the requested
    // crossed-handshake fault actually occurs instead of a fixture ICMP loss.
    public void Begin() => ready.TrySetResult();
    public sealed record Header(bool Client, byte Flags, uint Seq, uint Ack, int Payload, bool Dropped, long Tick);
    public RawProtocolProxy(int clientWire, int serverWire, byte dropFlags = 0, bool dropClient = true)
    {
        this.dropFlags = dropFlags; this.dropClient = dropClient;
        cPump = Pump(client, server, clientWire, serverWire, true); sPump = Pump(server, client, serverWire, clientWire, false);
    }
    async Task Pump(UdpClient input, UdpClient output, int expected, int destination, bool fromClient)
    {
        try {
            while (true) {
                UdpReceiveResult message;
                try { message = await input.ReceiveAsync(stop.Token); }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset) { continue; }
                await ready.Task.WaitAsync(stop.Token);
                byte[] p = message.Buffer;
                if (!IPAddress.IsLoopback(message.RemoteEndPoint.Address) || message.RemoteEndPoint.Port != expected || p.Length < 40 || p[9] != 6) continue;
                int ip = (p[0] & 15) * 4, tcp = (p[ip+12] >> 4) * 4;
                byte flags = p[ip+13]; int payload = p.Length - ip - tcp; bool lose;
                lock (gate) {
                    lose = !dropped && dropFlags != 0 && dropFlags == flags && payload == 0 && fromClient == dropClient;
                    if (lose) dropped = true;
                    if (headers.Count < 512) headers.Add(new(fromClient, flags, BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(ip+4)), BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(ip+8)), payload, lose, Environment.TickCount64));
                }
                if (!lose) await output.SendAsync(p, new IPEndPoint(IPAddress.Loopback, destination), stop.Token);
            }
        } catch (OperationCanceledException) { }
    }
    public Header[] Snapshot() { lock (gate) return headers.ToArray(); }
    public async ValueTask DisposeAsync() { stop.Cancel(); await Task.WhenAll(cPump, sPump); client.Dispose(); server.Dispose(); stop.Dispose(); }
}
