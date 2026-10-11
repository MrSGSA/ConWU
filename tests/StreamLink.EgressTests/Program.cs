using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.Core;

bool correctnessOnly = args.Length == 2 && args[1] == "--correctness-only";
if (args.Length != 1 && !correctnessOnly) throw new ArgumentException("output.json [--correctness-only]");
string output = Path.GetFullPath(args[0]);
int checks = 0; var rows = new List<object>(); var throughputGates = new List<bool>();
void Check(bool ok, string why) { if (!ok) throw new Exception(why); checks++; Console.WriteLine("PASS " + why); }
using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2)); var token = deadline.Token;
try {
    Check(new DeviceProfile().ManagedEgressMbps == 0, "default pacing remains off");
    foreach (int invalid in new[] { -1, 10001 }) { bool rejected = false; try { new DeviceProfile { ManagedEgressMbps = invalid }.Validate(); } catch (FormatException) { rejected = true; } Check(rejected, "invalid rate rejected " + invalid); }
    await Lifetime();
    await UdpIo();
    await Churn();
    if (!correctnessOnly) foreach (int members in new[] { 1, 7 }) await Saturation(members);
    await Priority();
    if (!correctnessOnly) Check(throughputGates.All(x => x), "all saturation cases meet the 98% local throughput target");
    File.WriteAllText(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows, performanceGate = correctnessOnly ? "NotRun" : "Pass", scope = "real Windows waitable timer and IPv4/IPv6 UDP loopback; synthetic concurrent peers, not real eight Windows or WAN" }, new JsonSerializerOptions { WriteIndented = true }));
} catch (Exception ex) { File.WriteAllText(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, error = ex.ToString() }, new JsonSerializerOptions { WriteIndented = true })); throw; }

async Task Lifetime()
{
    using var pacer = new EgressPacer(10); using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
    int sent = 0; var flow = pacer.Register("peer", (_, _) => { entered.Set(); release.Wait(token); Interlocked.Increment(ref sent); return true; });
    flow.TrySend(new byte[1000], 1028); entered.Wait(token);
    var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    flow.TrySend(new byte[1000], 1028, completion: completion);
    var close = Task.Run(flow.Dispose); await Task.Delay(40, token);
    Check(!close.IsCompleted && sent == 0, "flow close joins in-flight I/O before underlying resource may close");
    release.Set(); await close.WaitAsync(token);
    bool dropped = false; try { await completion.Task; } catch (IOException) { dropped = true; }
    Check(dropped && sent == 1 && pacer.Snapshot().QueuedBytes == 0, "queued datagram cancelled without replay/retransmission after flow close");
    Check(!flow.TrySend(new byte[40], 40), "retired flow cannot enqueue after cancellation");
    using var independent = pacer.Register("other", (_, _) => true);
    var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); independent.TrySend(new byte[40], 40, completion: done); await done.Task.WaitAsync(token);
    Check(pacer.Snapshot().SentBytes == 1068, "peer cancellation preserves unrelated sender and exact outer byte count");
}

async Task UdpIo()
{
    using var pacer = new EgressPacer(50);
    foreach (var ip in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback }) {
        using var receiver = new TraversalSocket(new(ip, 0)); var underlying = new TraversalSocket(new(ip, 0)); var id = underlying.Id; var local = underlying.Local;
        using var sender = new PacedTraversalSocket(underlying, pacer, ip.ToString());
        var before = pacer.Snapshot().SentBytes; byte[] data = new byte[1344]; "SLM4"u8.CopyTo(data); data[4] = 4;
        await sender.Send(data, receiver.Local, token); var received = await receiver.Receive(token);
        while (pacer.Snapshot().SentBytes == before) await Task.Delay(1, token);
        Check(received.Data.SequenceEqual(data) && received.Source.Equals(local) && sender.Id == id && sender.Local.Equals(local) && sender.DontFragment, ip + ": paced business uses the same real socket/resource/port and bytes");
        Check(pacer.Snapshot().SentBytes - before == (ip.AddressFamily == AddressFamily.InterNetwork ? 1372 : 1392), ip + ": actual UDP outer header charged once");
        await receiver.Send(new byte[96], local, token); var reply = await sender.Receive(token); Check(reply.Data.Length == 96, ip + ": unique socket receive remains usable");
    }
    using var failing = new PacedTraversalSocket(new TooLarge(), pacer, "mtu"); bool rejected = false;
    try { await failing.Send(new byte[1344], new(IPAddress.Loopback, 99), token); } catch (SocketException ex) when (ex.SocketErrorCode == SocketError.MessageSize) { rejected = true; }
    Check(rejected, "PMTU MessageSize from actual send is propagated through queued control completion");
}

async Task Churn()
{
    using var pacer = new EgressPacer(50);
    for (int i = 0; i < 150; i++) {
        using var f = pacer.Register("retired-" + i, (_, _) => true); var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.TrySend(new byte[40], 40, completion: done); await done.Task.WaitAsync(token);
    }
    Check(pacer.Snapshot().SentBytes == 6000 && pacer.Snapshot().Peers.Length <= 64 && pacer.Snapshot().Failure == "", "member churn reclaims bounded peer records without corrupting scheduler cursor");
    var live = Enumerable.Range(0, 64).Select(i => pacer.Register("live-" + i, (_, _) => true)).ToArray(); bool rejected = false;
    try { using var extra = pacer.Register("excess", (_, _) => true); } catch (IOException) { rejected = true; }
    Check(rejected, "flow quota remains global across all members and path generations");
    foreach (var f in live) f.Dispose();
}

async Task Saturation(int peers)
{
    using var pacer = new EgressPacer(50); var sent = new ConcurrentQueue<(long At, int Peer, int Size)>();
    var sizes = Enumerable.Range(0, peers).Select(i => i % 2 == 0 ? 1466 : 300).ToArray(); var packets = sizes.Select(n => new byte[n]).ToArray();
    using var start = new ManualResetEventSlim(); bool finishing = false;
    var flows = new EgressPacer.Flow[peers];
    for (int i = 0; i < peers; i++) { int slot = i; flows[i] = pacer.Register("peer-" + i, (p, _) => {
        start.Wait(token); sent.Enqueue((Stopwatch.GetTimestamp(), slot, p.Length));
        if (!Volatile.Read(ref finishing)) flows[slot].TrySend(packets[slot], sizes[slot]); return true;
    }); }
    // Replenishment from each successful callback gives a permanently backlogged
    // controlled sink; a coarse producer timer cannot masquerade as a slow pacer.
    for (int i = 0; i < peers; i++) for (int n = 0; n < 160000 / peers / sizes[i]; n++) flows[i].TrySend(packets[i], sizes[i]);
    var cpu0 = Process.GetCurrentProcess().TotalProcessorTime; var clock = Stopwatch.StartNew();
    start.Set(); await Task.Delay(3000, token); Volatile.Write(ref finishing, true);
    var elapsed = clock.Elapsed.TotalSeconds; foreach (var f in flows) f.Dispose();
    var snapshot = pacer.Snapshot(); var events = sent.ToArray();
    // Sliding-envelope check uses actual send timestamps, not token internals.
    int begin = 0; long window = 0; bool bounded = true;
    for (int end = 0; end < events.Length; end++) { window += events[end].Size; while (Stopwatch.GetElapsedTime(events[begin].At, events[end].At).TotalMilliseconds > 10) window -= events[begin++].Size;
        if (window > 6144 + Stopwatch.GetElapsedTime(events[begin].At, events[end].At).TotalSeconds * 6250000 + 1466) bounded = false; }
    var perPeer = snapshot.Peers.Select(p => p.SentBytes).ToArray(); double mbps = snapshot.SentBytes * 8 / elapsed / 1e6;
    rows.Add(new { peers, mbps, elapsed, cpuSeconds = (Process.GetCurrentProcess().TotalProcessorTime - cpu0).TotalSeconds, snapshot });
    Check(snapshot.Failure == "" && snapshot.PeakQueuedBytes <= 125000 && snapshot.QueueLimitBytes == 125000 && snapshot.QueuedBytes == 0, peers + " peers: bounded 20ms/1MiB shared queue and cleanup");
    Check(bounded && mbps <= 50.2, peers + " peers: actual output respects one whole-device rate/burst envelope");
    throughputGates.Add(mbps >= 49);
    if (peers > 1) Check(perPeer.Min() > 0 && perPeer.Max() / (double)perPeer.Min() < 1.25, "seven peers with different packet lengths receive comparable byte shares");
    Check(snapshot.OverflowDrops > 0 && events.Sum(e => (long)e.Size) == snapshot.SentBytes, "overload is counted and never turns into business retransmission");
}

async Task Priority()
{
    using var pacer = new EgressPacer(10); long data = 0, control = 0;
    using var payload = pacer.Register("same-peer", (p, _) => { Interlocked.Add(ref data, p.Length); return true; });
    using var signals = pacer.Register("same-peer", (p, _) => { Interlocked.Add(ref control, p.Length); return true; });
    var clock = Stopwatch.StartNew();
    while (clock.ElapsedMilliseconds < 350) {
        for (int n = 0; n < 20; n++) { payload.TrySend(new byte[1466], 1466); signals.TrySend(new byte[100], 100, priority: true); }
        await Task.Delay(1, token);
    }
    Check(data > control && control > 0 && pacer.Snapshot().PriorityPackets * 100 <= 3072 + 8192 * clock.Elapsed.TotalSeconds + 100, "control priority has a separate small allowance and cannot starve data or bypass total rate");
    rows.Add(new { priority = pacer.Snapshot(), data, control });
}

sealed class TooLarge : ITraversalSocket
{
    public Guid Id { get; } = Guid.NewGuid(); public IPEndPoint Local => new(IPAddress.Loopback, 40001); public bool DontFragment => true;
    public ValueTask Send(ReadOnlyMemory<byte> p, IPEndPoint r, CancellationToken t) => ValueTask.FromException(new SocketException((int)SocketError.MessageSize));
    public ValueTask<TraversalDatagram> Receive(CancellationToken t) => throw new NotSupportedException(); public void Dispose() { }
}
