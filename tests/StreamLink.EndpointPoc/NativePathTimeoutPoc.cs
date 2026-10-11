using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.EndpointPoc;

// Actual managed child and C++ protocol, blackholed only at its loopback test
// carriage. This distinguishes caller cancellation from a no-peer deadline.
static class NativePathTimeoutPoc
{
    public static async Task<int> Run(string binary, string output)
    {
        int checks = 0; var rows = new List<object>();
        void Check(bool value, string why) { if (!value) throw new Exception(why); checks++; }
        string root = Path.Combine(Path.GetDirectoryName(output)!, Path.GetFileNameWithoutExtension(output) + "-logs");
        Directory.CreateDirectory(root);
        using var limit = new CancellationTokenSource(30000);
        try {
            foreach (bool callerCancel in new[] { true, false }) {
                await using var reflector = new Reflector(); var generation = Guid.NewGuid();
                using var local = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, limit.Token);
                using var peer = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, limit.Token);
                using var sink = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                using var drainStop = CancellationTokenSource.CreateLinkedTokenSource(limit.Token);
                int syns = 0;
                var drain = Task.Run(async () => {
                    try { while (true) { var p = (await sink.ReceiveAsync(drainStop.Token)).Buffer;
                        if (p.Length >= 40 && p[9] == 6 && p.Length > (p[0] & 15) * 4 + 13 && (p[(p[0] & 15) * 4 + 13] & 2) != 0) Interlocked.Increment(ref syns);
                    } } catch (OperationCanceledException) when (drainStop.IsCancellationRequested) { }
                });
                var context = new TraversalAttemptContext("timeout-local", "a", Guid.NewGuid(), "b", Guid.NewGuid(), Guid.NewGuid(),
                    Guid.NewGuid(), 1, Guid.NewGuid(), 1, TraversalProfile.FakeTcpHttpSo, true, true, Guid.NewGuid());
                byte[] key = RandomNumberGenerator.GetBytes(32);
                NativeDatagramPath? path = null; NativePathDiagnostics? diagnostic = null; string reason = "";
                long elapsedMs = 0;
                try {
                    path = await NativeDatagramPath.Prepare(binary, root, local, generation, context, peer.Local, key, limit.Token, new(),
                        new Dictionary<string, string> { ["STREAMLINK_TEST_BIND"] = "0", ["STREAMLINK_TEST_PEER"] = ((IPEndPoint)sink.Client.LocalEndPoint!).Port.ToString(), ["STREAMLINK_TEST_HELLO"] = Guid.NewGuid().ToString("N") });
                    Check(path.Armed && !path.Started, "prepared before start");
                    using var call = CancellationTokenSource.CreateLinkedTokenSource(limit.Token);
                    if (callerCancel) call.CancelAfter(150);
                    var timer = Stopwatch.StartNew(); bool expected = false;
                    try { await path.StartAndQualify(call.Token); }
                    catch (OperationCanceledException) when (callerCancel && call.IsCancellationRequested) { expected = true; reason = "caller-cancelled"; }
                    catch (NativePathVerificationException ex) when (!callerCancel) { diagnostic = ex.Diagnostic; reason = ex.Reason; expected = true; }
                    elapsedMs = timer.ElapsedMilliseconds;
                    Check(expected && path.Failed, "negative path cannot qualify");
                    if (callerCancel) Check(elapsedMs < 2000, "caller cancellation is not relabelled as a NAT/handshake timeout");
                    else {
                        Check(elapsedMs is >= 7500 and < 10000 && !call.IsCancellationRequested, "one bounded eight-second round, no outer retry reset");
                        Check(diagnostic is { CaptureArmed: true, StartAcknowledged: true, AuthenticatedProbeReceives: 0, PayloadQualified: false } &&
                            diagnostic.AttemptId == context.AttemptId && diagnostic.LeaseId == local.Id && diagnostic.AttachId == path.AttachId,
                            "no-peer evidence names the actual resource without claiming a completed outer handshake");
                        Check(syns > 0 && diagnostic!.BridgeProbeAttempts > 0, "real test-carriage SYNs and distinct local bridge attempts were exercised");
                    }
                } finally {
                    CryptographicOperations.ZeroMemory(key); if (path != null) await path.DisposeAsync();
                    drainStop.Cancel(); await drain;
                }
                Check(local.ReferenceCount == 1 && local.QueryUsable, "failed attachment releases only its own reference");
                using (var query = local.AcquireAttempt(generation)) Check((await query.Observe(limit.Token)).Public.Equals(local.Local), "helper remains queryable after native cancellation");
                local.Dispose(); peer.Dispose(); Check(local.Closed && peer.Closed && path?.Closed == true, "all final resources close");
                rows.Add(new { callerCancel, reason, elapsedMs, syns, diagnostic });
            }
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows,
                scope = "Actual native test backend and owned Windows TCP helper, loopback only; no WinDivert or WAN classification" }, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"PASS {checks} native cancellation/deadline diagnostics checks"); return 0;
        } catch (Exception ex) { await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() })); throw; }
    }
}
