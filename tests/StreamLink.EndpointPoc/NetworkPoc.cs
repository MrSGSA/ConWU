using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.EndpointPoc;

sealed record NetworkPocConfig(string LocalIp, string PeerIp, int SourcePort, int PeerPort,
    int ReflectorPort, int PeerReflectorPort, bool Server, string Binary, string Key, string Output, int DurationSeconds = 45,
    int SilenceReflectorAfterSeconds = 0);

static class NetworkPoc
{
    public static async Task<int> Run(string path)
    {
        var config = JsonSerializer.Deserialize<NetworkPocConfig>(await File.ReadAllTextAsync(path))!;
        if (config.DurationSeconds is < 10 or > 120 || config.SourcePort == config.ReflectorPort) throw new ArgumentException("Invalid isolated test parameters");
        var local = new IPEndPoint(IPAddress.Parse(config.LocalIp), config.SourcePort);
        var peer = new IPEndPoint(IPAddress.Parse(config.PeerIp), config.PeerPort);
        if (IPAddress.IsLoopback(local.Address) || IPAddress.IsLoopback(peer.Address)) throw new ArgumentException("Two independent Windows stacks required");
        string output = Path.GetFullPath(config.Output); Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(config.DurationSeconds + 30));
        await using var reflector = new Reflector(new(local.Address, config.ReflectorPort));
        Guid generation = Guid.NewGuid(); TcpEndpointLease? lease = null;
        // Retry the initial helper connection on the test endpoint only; before
        // ownership is established there is no raw/candidate resource to transfer.
        while (lease == null) {
            try { lease = await TcpEndpointLease.Open(local, new(peer.Address, config.PeerReflectorPort), generation, deadline.Token); }
            catch (SocketException) { await Task.Delay(500, deadline.Token); }
        }
        using (lease) using (var attempt = lease.AcquireAttempt(generation))
        using (var observer = new WireObserver(Path.Combine(Path.GetDirectoryName(config.Binary)!, "WinDivert.dll"), local, peer)) {
            var initial = await attempt.Observe(deadline.Token);
            using var app = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var appEndpoint = (IPEndPoint)app.Client.LocalEndPoint!;
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            int rx = 0, tx = 0, queryCount = 0;
            string helperFailure = "";
            Task echo = config.Server ? Task.Run(async () => {
                try { while (true) { var packet = await app.ReceiveAsync(cancellation.Token); Interlocked.Increment(ref rx); await app.SendAsync(packet.Buffer, packet.RemoteEndPoint, cancellation.Token); Interlocked.Increment(ref tx); } }
                catch (OperationCanceledException) { }
            }) : Task.CompletedTask;
            int appPort = config.Server ? appEndpoint.Port : FreeUdpPort();
            string[] args = [config.Server ? "-s" : "-c", "-l", config.Server ? local.ToString() : $"127.0.0.1:{appPort}",
                "-r", config.Server ? appEndpoint.ToString() : peer.ToString(), "-k", config.Key, "--raw-mode", "faketcp", "--seq-mode", "3", "--fake-http", "test.ustc.edu.cn", "--log-level", "4"];
            long armed = Environment.TickCount64;
            await using var attachment = await NativeAttachment.Launch(lease, generation, config.Binary, args, peer, config.Server,
                Path.ChangeExtension(output, ".native.log"), deadline.Token, secrets: [config.Key]);
            Guid attachId = attachment.AttachId;
            long started = Environment.TickCount64, first = 0;
            string failure = "";
            int rxAtHelperFailure = -1;
            try {
                while (Environment.TickCount64 - started < config.DurationSeconds * 1000L && !attachment.Exited) {
                    if (config.SilenceReflectorAfterSeconds > 0 && Environment.TickCount64 - started >= config.SilenceReflectorAfterSeconds * 1000L)
                        reflector.Silent = true;
                    if (lease.QueryUsable) {
                        try {
                            var result = await attempt.Observe(deadline.Token); queryCount++;
                            if (!result.Local.Equals(initial.Local) || !result.Public.Equals(initial.Public)) throw new IOException("Helper endpoint changed");
                        } catch (Exception ex) when (ex is IOException || (ex is OperationCanceledException && !deadline.IsCancellationRequested)) {
                            helperFailure = ex.GetType().Name; rxAtHelperFailure = rx;
                        }
                    }
                    if (!config.Server) {
                        byte[] data = new byte[1200]; Random.Shared.NextBytes(data);
                        await app.SendAsync(data, new IPEndPoint(IPAddress.Loopback, appPort), deadline.Token); tx++;
                        using var window = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token); window.CancelAfter(500);
                        try { var received = await app.ReceiveAsync(window.Token); if (received.Buffer.AsSpan().SequenceEqual(data)) { rx++; if (first == 0) first = Environment.TickCount64; } }
                        catch (OperationCanceledException) when (!deadline.IsCancellationRequested) { }
                    }
                    await Task.Delay(200, deadline.Token);
                }
            } catch (Exception ex) { failure = ex.GetType().Name + ": " + ex.Message; }
            long revoke = Environment.TickCount64; var wire = observer.Snapshot(armed, revoke);
            await attachment.DisposeAsync(); cancellation.Cancel(); await echo;
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { scope = "Two real Windows stacks; inspect addresses to distinguish overlay test interface from physical/public path",
                leaseId = lease.Id, generation, attachId, source = local.ToString(), peer = peer.ToString(), reflected = initial.Public.ToString(),
                nativeBackend = "windivert", tx, rx, helperQueries = queryCount, firstReplyMs = first == 0 ? (long?)null : first - started,
                elapsedMs = revoke - started, failure, helperFailure, receivedAfterHelperFailure = rxAtHelperFailure < 0 ? 0 : rx - rxAtHelperFailure,
                wire, natClassified = false, multiPeerTested = false }, new JsonSerializerOptions { WriteIndented = true }));
            return failure.Length == 0 && rx > 0 && queryCount > 0 ? 0 : 2;
        }
    }
    static int FreeUdpPort() { using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); return ((IPEndPoint)socket.Client.LocalEndPoint!).Port; }
}
