using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.EndpointPoc;
using StreamLink.Core;

if (args is ["--tcp-prflx", var reflexiveBinary, "--rounds", var reflexiveRounds, "--output", var reflexiveOutput])
    return await TcpPeerReflexivePoc.Run(Path.GetFullPath(reflexiveBinary), int.Parse(reflexiveRounds), Path.GetFullPath(reflexiveOutput));

if (args is ["--port-window", var windowBinary, "--rounds", var windowRounds, "--output", var windowOutput])
    return await NativePortWindowPoc.Run(Path.GetFullPath(windowBinary), int.Parse(windowRounds), Path.GetFullPath(windowOutput));
if (args is ["--port-window-wide", var wideBinary, "--output", var wideOutput])
    return await NativePortWindowPoc.Run(Path.GetFullPath(wideBinary), 1, Path.GetFullPath(wideOutput), wide: true);

if (args is ["--managed", var binary, "--output", var reportPath])
    return await ManagedProtocolPoc.Run(Path.GetFullPath(binary), Path.GetFullPath(reportPath));
if (args is ["--network", var networkConfig]) return await NetworkPoc.Run(networkConfig);
if (args is ["--reject-attach", var nativeBinary, "--output", var negativeOutput]) return await AttachRejectionPoc.Run(Path.GetFullPath(nativeBinary), Path.GetFullPath(negativeOutput));
if (args is ["--so-protocol", var soBinary, "--output", var soOutput]) return await ManagedProtocolPoc.Run(Path.GetFullPath(soBinary), Path.GetFullPath(soOutput), true);
if (args is ["--so-matrix", var matrixBinary, "--output", var matrixOutput]) return await ManagedProtocolPoc.Run(Path.GetFullPath(matrixBinary), Path.GetFullPath(matrixOutput), true, true);
if (args is ["--prepared-so", var preparedBinary, "--output", var preparedOutput]) return await ManagedProtocolPoc.Run(Path.GetFullPath(preparedBinary), Path.GetFullPath(preparedOutput), true, prepared: true);
if (args is ["--native-router", var routerBinary, "--output", var routerOutput]) return await NativeRouterPoc.Run(Path.GetFullPath(routerBinary), Path.GetFullPath(routerOutput));
if (args is ["--path-timeout", var timeoutBinary, "--output", var timeoutOutput]) return await NativePathTimeoutPoc.Run(Path.GetFullPath(timeoutBinary), Path.GetFullPath(timeoutOutput));
if (args is ["--capture-broker", var brokerBinary, "--rounds", var brokerRounds, "--output", var brokerOutput]) return await CaptureBrokerPoc.Run(Path.GetFullPath(brokerBinary), int.Parse(brokerRounds), Path.GetFullPath(brokerOutput));
if (args is ["--capture-broker-ipv6", var broker6Binary, "--rounds", var broker6Rounds, "--output", var broker6Output]) return await CaptureBrokerPoc.Run(Path.GetFullPath(broker6Binary), int.Parse(broker6Rounds), Path.GetFullPath(broker6Output), ipv6: true);
if (args is ["--broker-load", var budgetBinary, "--mbps", var budgetMbps, "--seconds", var budgetSeconds, "--rounds", var budgetRounds, "--output", var budgetOutput, "--wire-budget"])
    return await BrokerLoadPoc.Run(Path.GetFullPath(budgetBinary), int.Parse(budgetMbps), int.Parse(budgetSeconds), int.Parse(budgetRounds), Path.GetFullPath(budgetOutput), true);
if (args is ["--broker-load", var deliveryBinary, "--mbps", var deliveryMbps, "--seconds", var deliverySeconds, "--rounds", var deliveryRounds, "--output", var deliveryOutput, "--delivery-feedback"])
    return await BrokerLoadPoc.Run(Path.GetFullPath(deliveryBinary), int.Parse(deliveryMbps), int.Parse(deliverySeconds), int.Parse(deliveryRounds), Path.GetFullPath(deliveryOutput), true, feedback: true);
if (args is ["--broker-load", var pacedBinary, "--mbps", var pacedMbps, "--seconds", var pacedSeconds, "--rounds", var pacedRounds, "--output", var pacedOutput, "--egress-mbps", var egressMbps])
    return await BrokerLoadPoc.Run(Path.GetFullPath(pacedBinary), int.Parse(pacedMbps), int.Parse(pacedSeconds), int.Parse(pacedRounds), Path.GetFullPath(pacedOutput), true, int.Parse(egressMbps));
if (args is ["--broker-load", var loadBinary, "--mbps", var loadMbps, "--seconds", var loadSeconds, "--rounds", var loadRounds, "--output", var loadOutput])
    return await BrokerLoadPoc.Run(Path.GetFullPath(loadBinary), int.Parse(loadMbps), int.Parse(loadSeconds), int.Parse(loadRounds), Path.GetFullPath(loadOutput));
if (args is ["--prepare-router-network", var configs]) { NativeRouterNetwork.Prepare(Path.GetFullPath(configs)); return 0; }
if (args is ["--router-network", var config]) return await NativeRouterNetwork.Run(Path.GetFullPath(config));

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
await using (var reflector = new Reflector()) {
    var held = new List<TcpEndpointLease>(); var kept = new List<TcpEndpointLease.Reference>(); Guid generation = Guid.NewGuid();
    try {
        for (int i = 0; i < TraversalLimits.TcpResources; i++) {
            var owner = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, deadline.Token);
            held.Add(owner); kept.Add(owner.AcquireAttempt(generation)); owner.Dispose();
        }
        bool full = false;
        try { using var ninth = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, deadline.Token); }
        catch (IOException) { full = true; }
        Check(full && held.All(p => !p.Closed), "All eight retained TCP endpoints count toward the machine quota after owner retirement");
        kept[0].Dispose(); Check(held[0].Closed, "Last reference releases exactly one TCP quota entry");
        using var replacement = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, deadline.Token);
        Check(!replacement.Closed, "New endpoint can use the released machine slot");
    } finally { foreach (var p in kept) p.Dispose(); foreach (var p in held) p.Dispose(); }
}
var report = new { scope = "Windows loopback kernel-TCP resource lifecycle only; NOT WinDivert/FakeTCP coexistence or NAT success", rounds = rows.Count, checks,
    nativeRawAttached = false, captureOwnershipTested = false, rstLeakageTested = false, natClassified = false, publicNetworkUsed = false, rows };
await File.WriteAllTextAsync(output, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"PASS {rows.Count} loopback lifecycle rounds, {checks} checks; no driver or WAN. Report: {output}");
return 0;
