using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using StreamLink.Core;

// The real udp2raw protocol/event loops with raw packet I/O replaced by a
// loopback wire. Never shipped and never presented as a QoS/WinDivert test.
[SupportedOSPlatform("windows")]
sealed class RawLoopback : IAsyncDisposable
{
    readonly ChildJob job = new();
    readonly UdpClient wire = new(new IPEndPoint(IPAddress.Loopback, 0));
    readonly CancellationTokenSource stop = new();
    readonly Dictionary<int, IPEndPoint> routes = [];
    readonly HashSet<int> allocated = [];
    readonly string root = Path.Combine(Path.GetTempPath(), "streamlink-raw-mesh-" + Guid.NewGuid().ToString("N"));
    readonly Dictionary<(int, int), IPEndPoint> clients = [];
    readonly Task pump;
    long receivedPackets,receivedBytes,forwardedPackets,forwardedBytes,unroutedPackets;
    public object Counters=>new{receiveBufferBytes=wire.Client.ReceiveBufferSize,receivedPackets=Interlocked.Read(ref receivedPackets),receivedBytes=Interlocked.Read(ref receivedBytes),
        forwardedPackets=Interlocked.Read(ref forwardedPackets),forwardedBytes=Interlocked.Read(ref forwardedBytes),unroutedPackets=Interlocked.Read(ref unroutedPackets),kernelDrops="NotMeasured"};
    public bool SawHttp { get; private set; }
    int Port() => NativeTestPorts.Take(allocated);
    public RawLoopback(string executable, MeshProfile profile, params IPEndPoint[] applications)
    {
        Directory.CreateDirectory(root);
        try {
            int[] listeners = applications.Select(_ => Port()).ToArray();
            var ticket = new Invitation(1, profile.Pair.Network, profile.Pair.Secret, "127.0.0.1:1", "faketcp", "test.ustc.edu.cn", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());
            void Start(string name, string mode, string local, string remote, int rawPort) {
                string file = Path.Combine(root, name + ".conf");
                File.WriteAllText(file, $"{mode}\n-l {local}\n-r {remote}\n-k {(profile.Pair.DirectBootstrap?DirectPairWire.CarriageKey:ticket.RawKey)}\n--raw-mode faketcp\n--fake-http test.ustc.edu.cn\n--seq-mode 3\n--fix-gro\n--hb-mode 0\n--log-level 2\n");
                job.Start(Path.GetFullPath(executable), ["--conf-file", file], Path.Combine(root, name + ".log"), new Dictionary<string, string> { ["STREAMLINK_TEST_BIND"] = rawPort.ToString(), ["STREAMLINK_TEST_PEER"] = ((IPEndPoint)wire.Client.LocalEndPoint!).Port.ToString() }, [ticket.RawKey]);
            }
            for (int slot = 0; slot < applications.Length; slot++) {
                int serverWire = Port(); routes[listeners[slot]] = new(IPAddress.Loopback, serverWire);
                Start("server-" + slot, "-s", "127.0.0.1:" + listeners[slot], applications[slot].ToString(), serverWire);
                for (int other = 0; other < slot; other++) {
                    int appPort = Port(); clients[(slot + 1, other + 1)] = new(IPAddress.Loopback, appPort);
                    Start($"client-{slot}-{other}", "-c", "127.0.0.1:" + appPort, "127.0.0.1:" + listeners[other], Port());
                }
            }
            pump = Pump();
        } catch { job.Dispose(); wire.Dispose(); stop.Dispose(); throw; }
    }
    public IPEndPoint? Client(int from, int to) => clients.GetValueOrDefault((from, to));
    async Task Pump()
    {
        while (!stop.IsCancellationRequested) {
            UdpReceiveResult data;
            try { data = await wire.ReceiveAsync(stop.Token); } catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset) { continue; }
            Interlocked.Increment(ref receivedPackets);Interlocked.Add(ref receivedBytes,data.Buffer.Length);
            byte[] p = data.Buffer; if (p.Length < 40 || p[0] >> 4 != 4 || p[9] != 6) continue;
            int ip = (p[0] & 15) * 4; if (ip < 20 || ip + 20 > p.Length) continue;
            int source = BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(ip)), destination = BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(ip + 2));
            routes[source] = data.RemoteEndPoint;
            if (p.AsSpan().IndexOf("Host: test.ustc.edu.cn\r\n"u8) >= 0) SawHttp = true;
            if (routes.TryGetValue(destination, out var target)) {
                int sent=await wire.SendAsync(p, target, stop.Token);Interlocked.Increment(ref forwardedPackets);Interlocked.Add(ref forwardedBytes,sent);
            } else Interlocked.Increment(ref unroutedPackets);
        }
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel(); try { await pump; } catch (OperationCanceledException) { }
        finally { job.Dispose(); wire.Dispose(); stop.Dispose(); foreach (var file in Directory.EnumerateFiles(root, "*.conf")) File.Delete(file); }
    }
}
