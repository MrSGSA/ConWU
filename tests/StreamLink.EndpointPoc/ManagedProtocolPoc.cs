using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.EndpointPoc;

static class ManagedProtocolPoc
{
    static int Port()
    {
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        s.Bind(new IPEndPoint(IPAddress.Loopback, 0)); return ((IPEndPoint)s.LocalEndPoint!).Port;
    }
    public static async Task<int> Run(string binary, string output, bool simultaneousOpen = false, bool matrix = false)
    {
        int rounds = matrix ? 180 : 30;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(matrix ? 450 : 110));
        string directory = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(output))!, Path.GetFileNameWithoutExtension(output) + "-logs");
        Directory.CreateDirectory(directory);
        var rows = new List<object>(); int checks = 0;
        void Check(bool ok, string why) { if (!ok) throw new Exception(why); checks++; }
        // One real UDP echo worker; native test backend carries serialized raw
        // IPv4/TCP frames over loopback. No WinDivert or physical NIC involved.
        using var echo = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var echoTask = Task.Run(async () => {
            try { while (!deadline.IsCancellationRequested) { var p = await echo.ReceiveAsync(deadline.Token); await echo.SendAsync(p.Buffer, p.RemoteEndPoint, deadline.Token); } }
            catch (OperationCanceledException) { }
        });
        try {
            for (int round = 1; round <= rounds; round++) {
                var watch = Stopwatch.StartNew();
                await using var reflector = new Reflector(); Guid generation = Guid.NewGuid();
                using var clientLease = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, deadline.Token);
                using var serverLease = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, deadline.Token);
                using var cAttempt = clientLease.AcquireAttempt(generation);
                using var sAttempt = serverLease.AcquireAttempt(generation);
                await cAttempt.Observe(deadline.Token); await sAttempt.Observe(deadline.Token);
                int cWire = Port(), sWire = Port(), appPort = Port();
                int mechanism = matrix ? (round - 1) / 30 : 0;
                byte lossFlags = mechanism switch { 1 => 2, 2 => 18, 3 => 16, _ => 0 };
                await using var proxy = new RawProtocolProxy(cWire, sWire, lossFlags, round % 2 == 0);
                string key = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
                string[] Common() => ["-k", key, "--raw-mode", "faketcp", "--seq-mode", "3", "--fake-http", "test.ustc.edu.cn", "--log-level", "4"];
                var sArgs = new[] { "-s", "-l", serverLease.Local.ToString(), "-r", echo.Client.LocalEndPoint!.ToString()! }.Concat(Common());
                var cArgs = new[] { "-c", "-l", $"127.0.0.1:{appPort}", "-r", serverLease.Local.ToString() }.Concat(Common());
                Dictionary<string, string> Env(int local, int remote) => new() { ["STREAMLINK_TEST_BIND"] = local.ToString(), ["STREAMLINK_TEST_PEER"] = remote.ToString() };
                async Task<NativeAttachment> Server() => await NativeAttachment.Launch(serverLease, generation, binary, sArgs, clientLease.Local, true,
                    Path.Combine(directory, $"{round}-server.log"), deadline.Token, Env(sWire, proxy.ServerPort), [key], simultaneousOpen);
                async Task<NativeAttachment> Client() => await NativeAttachment.Launch(clientLease, generation, binary, cArgs, serverLease.Local, false,
                    Path.Combine(directory, $"{round}-client.log"), deadline.Token, Env(cWire, proxy.ClientPort), [key], simultaneousOpen);
                await using var firstChild = mechanism == 5 ? await Client() : await Server();
                if (mechanism is 4 or 5) await Task.Delay(500, deadline.Token);
                await using var secondChild = mechanism == 5 ? await Server() : await Client();
                var s = mechanism == 5 ? secondChild : firstChild;
                var c = mechanism == 5 ? firstChild : secondChild;
                proxy.Begin();
                Check(c.Armed && c.Started && s.Armed && s.Started, "Both native control sessions armed and started");
                Check(c.AttachId != s.AttachId, "Each attachment has independent identity");
                bool refused = false; try { using var forbidden = clientLease.AcquireNativeAttachment(generation); } catch (InvalidOperationException) { refused = true; }
                Check(refused, "Second capture owner denied on same lease");
                using var app = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                var destination = new IPEndPoint(IPAddress.Loopback, appPort);
                byte[] payload = System.Security.Cryptography.RandomNumberGenerator.GetBytes(1200);
                using var handshake = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token); handshake.CancelAfter(8000);
                bool received = false;
                while (!received && !handshake.IsCancellationRequested) {
                    await app.SendAsync(payload, destination, handshake.Token);
                    using var window = CancellationTokenSource.CreateLinkedTokenSource(handshake.Token); window.CancelAfter(100);
                    try { var p = await app.ReceiveAsync(window.Token); received = p.Buffer.AsSpan().SequenceEqual(payload); }
                    catch (OperationCanceledException) when (!handshake.IsCancellationRequested) { }
                }
                Check(received, "Existing encrypted HTTP/bare profile exchanges actual data over test raw I/O");
                var wire = proxy.Snapshot();
                if (simultaneousOpen) {
                    Check(wire.Any(p => p.Client && p.Flags == 2) && wire.Any(p => !p.Client && p.Flags == 2), "Both native roles actually send bare SYN");
                    if (lossFlags != 0) Check(wire.Any(p => p.Dropped), "Requested handshake loss was actually injected");
                    foreach (bool role in new[] { false, true }) {
                        var h = wire.Where(p => p.Client == role).ToArray();
                        var http = h.First(p => p.Payload == 180 && p.Flags == 24);
                        var bare = h.First(p => p.Tick >= http.Tick && p.Payload == 48);
                        Check(http.Seq == bare.Seq && http.Ack == bare.Ack, "SO preserves legacy HTTP/bare sequence overlap in both roles");
                    }
                }
                using var cPath = cAttempt.RetainPath(generation);
                cAttempt.Dispose(); sAttempt.Dispose(); clientLease.Dispose(); serverLease.Dispose();
                var query = await cPath.Observe(deadline.Token);
                Check(query.Local.Equals(clientLease.Local) && reflector.Accepted == 2, "Helper remains on original connection during raw traffic");
                cPath.Dispose(); Check(!clientLease.Closed && !serverLease.Closed, "Native references outlive attempt and path references");
                Guid cId = c.AttachId; Guid sId = s.AttachId;
                // Final round covers abrupt native crash; other rounds use revoke.
                if (round == rounds) {
                    using var child = Process.GetProcessById(c.ProcessId); child.Kill(); await child.WaitForExitAsync(deadline.Token);
                    for (int i = 0; i < 100 && !clientLease.Closed; i++) await Task.Delay(5, deadline.Token);
                    Check(clientLease.Closed, "Observed child exit releases attachment without waiting for link timeout");
                }
                await c.DisposeAsync(); await s.DisposeAsync();
                Check(clientLease.Closed && serverLease.Closed, "Revoke/exit releases the final ownership references");
                rows.Add(new { round, clientLease = clientLease.Id, serverLease = serverLease.Id, clientAttach = cId, serverAttach = sId,
                    mechanism, actualClient = clientLease.Local.ToString(), actualServer = serverLease.Local.ToString(), elapsedMs = watch.ElapsedMilliseconds, wire });
                if (matrix && round % 30 == 0) Console.WriteLine($"SO native protocol mechanism {mechanism}: 30/30 passed (loopback test backend)");
            }
        } catch (Exception ex) {
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { scope = "native loopback protocol matrix", status = "Fail", completed = rows.Count, failure = ex.Message, rows }, new JsonSerializerOptions { WriteIndented = true }));
            throw;
        } finally { deadline.Cancel(); await echoTask; }
        await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new {
            scope = "Real C#/native child IPC and serialized C++ raw protocol over loopback-only test backend",
            rounds = rows.Count, checks, simultaneousOpen, nativeControlAttached = true, noSecondBind = true, driverLoaded = false,
            wireRstVerified = false, windowsLanVerified = false, wanVerified = false, rows
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"PASS managed native protocol {rows.Count} rounds / {checks} checks. NOT WinDivert/LAN/WAN."); return 0;
    }
}
