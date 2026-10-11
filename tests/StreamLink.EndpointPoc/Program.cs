using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.EndpointPoc;
using StreamLink.Core;

if (args is ["--managed", var binary, "--output", var reportPath])
    return await ManagedProtocolPoc.Run(Path.GetFullPath(binary), Path.GetFullPath(reportPath));
if (args is ["--network", var networkConfig]) return await NetworkPoc.Run(networkConfig);
if (args is ["--reject-attach", var nativeBinary, "--output", var negativeOutput]) return await AttachRejectionPoc.Run(Path.GetFullPath(nativeBinary), Path.GetFullPath(negativeOutput));
if (args is ["--so-protocol", var soBinary, "--output", var soOutput]) return await ManagedProtocolPoc.Run(Path.GetFullPath(soBinary), Path.GetFullPath(soOutput), true);
if (args is ["--so-matrix", var matrixBinary, "--output", var matrixOutput]) return await ManagedProtocolPoc.Run(Path.GetFullPath(matrixBinary), Path.GetFullPath(matrixOutput), true, true);

// A separate process attempts a conflicting bind with SO_REUSEADDR. This is
// deliberately loopback-only and targets only a socket owned by this test run.
if (args is ["--contend", var address, var port]) {
    var endpoint = new IPEndPoint(IPAddress.Parse(address), int.Parse(port));
    if (!IPAddress.IsLoopback(endpoint.Address)) throw new ArgumentException("Contention probe is loopback only");
    using var rival = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = false };
    rival.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
    try { rival.Bind(endpoint); Console.WriteLine("unexpected-bind-success"); return 2; }
    catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied) { Console.WriteLine(ex.SocketErrorCode); return 0; }
}
if (args.Length != 2 || args[0] != "--output") throw new ArgumentException("--output results.json (local lifecycle tests only)");
if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows endpoint ownership experiment");
int checks = 0;
void Check(bool value, string reason) { if (!value) throw new Exception(reason); checks++; }
void Rejected(Action action, string reason) { bool rejected = false; try { action(); } catch (InvalidOperationException) { rejected = true; } Check(rejected, reason); }
var rows = new List<object>();
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(55));
for (int round = 1; round <= 30; round++) {
    await using var reflector = new Reflector();
    Guid generation = Guid.NewGuid(); var clock = Stopwatch.StartNew();
    using var owner = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, deadline.Token);
    using var attempt = owner.AcquireAttempt(generation);
    var initial = await attempt.Observe(deadline.Token);
    Check(initial.Local.Equals(initial.Public), "Loopback reflection matches the live source endpoint");
    var executable = Environment.ProcessPath!;
    var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
    if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) start.ArgumentList.Add(Environment.GetCommandLineArgs()[0]);
    start.ArgumentList.Add("--contend");
    start.ArgumentList.Add(owner.Local.Address.ToString()); start.ArgumentList.Add(owner.Local.Port.ToString());
    using (var rival = Process.Start(start)!) {
        try { await rival.WaitForExitAsync(deadline.Token); }
        finally { if (!rival.HasExited) { rival.Kill(true); await rival.WaitForExitAsync(); } }
        Check(rival.ExitCode == 0, "Second process cannot steal the exclusive endpoint: " + await rival.StandardError.ReadToEndAsync());
    }
    Rejected(() => attempt.RetainPath(Guid.NewGuid()), "Wrong-generation reference rejected");
    using var active = attempt.RetainPath(generation);
    attempt.Dispose(); attempt.Dispose(); owner.Dispose(); owner.Dispose();
    Rejected(() => owner.AcquireAttempt(generation), "Retired owner cannot start another attempt");
    Rejected(() => attempt.RetainPath(generation), "Canceled attempt cannot create another path");
    var observations = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => active.Observe(deadline.Token)));
    Check(observations.All(x => x.Local.Equals(initial.Local) && x.Public.Equals(initial.Public)), "Retained path keeps the same live reflection flow");
    Check(reflector.Accepted == 1 && reflector.Requests == 4 && !owner.Closed, "Attempt cleanup does not reconnect or close the winning resource");
    active.Dispose(); Check(owner.Closed, "Last path reference releases the resource");
    while (reflector.Active != 0) await Task.Delay(10, deadline.Token);
    rows.Add(new { round, leaseId = owner.Id, generation, sourcePort = owner.Local.Port, acceptedConnections = reflector.Accepted, transactions = reflector.Requests, elapsedMs = clock.ElapsedMilliseconds });
}
// Queued I/O itself holds a reference; caller cancellation after a partial TCP
// transaction invalidates the flow rather than reusing ambiguous stream state.
await using (var reflector = new Reflector { Silent = true }) {
    Guid generation = Guid.NewGuid();
    using var owner = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, deadline.Token);
    using var attempt = owner.AcquireAttempt(generation);
    using var canceled = new CancellationTokenSource(150);
    Task observing = attempt.Observe(canceled.Token);
    attempt.Dispose(); owner.Dispose(); Check(!owner.Closed, "Pending I/O retains ownership until completion");
    bool didCancel = false; try { await observing; } catch (OperationCanceledException) { didCancel = true; }
    Check(didCancel && owner.Closed, "Canceled final I/O closes retired owner");
}
await using (var reflector = new Reflector { Silent = true }) {
    Guid generation = Guid.NewGuid();
    using var owner = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, deadline.Token);
    using var attempt = owner.AcquireAttempt(generation);
    using var canceled = new CancellationTokenSource(150);
    try { await attempt.Observe(canceled.Token); } catch (OperationCanceledException) { }
    Rejected(() => owner.AcquireAttempt(generation), "Failed partial transaction cannot produce a new candidate");
    Rejected(() => attempt.RetainPath(generation), "Failed stream cannot be retained as a path");
}
string output = Path.GetFullPath(args[1]); Directory.CreateDirectory(Path.GetDirectoryName(output)!);
var report = new { scope = "Windows loopback kernel-TCP resource lifecycle only; NOT WinDivert/FakeTCP coexistence or NAT success", rounds = rows.Count, checks,
    nativeRawAttached = false, captureOwnershipTested = false, rstLeakageTested = false, natClassified = false, publicNetworkUsed = false, rows };
await File.WriteAllTextAsync(output, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"PASS {rows.Count} loopback lifecycle rounds, {checks} checks; no driver or WAN. Report: {output}");
return 0;
