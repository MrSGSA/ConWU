using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

static partial class Program
{
    static TraversalAttemptContext ProbabilityContext() => new("fixture-network", "left", Guid.NewGuid(), "right", Guid.NewGuid(),
        Guid.NewGuid(), Guid.NewGuid(), 1, Guid.NewGuid(), 1, TraversalProfile.UdpDirect, true, true, Guid.NewGuid());
    static TraversalAttemptContext ReverseProbability(TraversalAttemptContext c) => c with { LocalNodeId = c.RemoteNodeId, LocalBootId = c.RemoteBootId,
        RemoteNodeId = c.LocalNodeId, RemoteBootId = c.LocalBootId, LocalCandidateId = c.RemoteCandidateId, RemoteCandidateId = c.LocalCandidateId,
        LocalCandidateVersion = c.RemoteCandidateVersion, RemoteCandidateVersion = c.LocalCandidateVersion, ProtocolClient = !c.ProtocolClient, Nominator = !c.Nominator };
    sealed class ProbeInterceptSocket(ITraversalSocket socket) : ITraversalSocket
    {
        public bool FailReceive, HoldSelection;
        public readonly TaskCompletionSource<byte[]> Selection = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Guid Id => socket.Id;
        public IPEndPoint Local => socket.Local;
        public bool DontFragment => socket.DontFragment;
        public ValueTask Send(ReadOnlyMemory<byte> data, IPEndPoint remote, CancellationToken token) {
            if (data.Span.StartsWith("SLG3"u8) && data.Span[4] == 5) { Selection.TrySetResult(data.ToArray()); if (Volatile.Read(ref HoldSelection)) return ValueTask.CompletedTask; }
            return socket.Send(data, remote, token);
        }
        public ValueTask<TraversalDatagram> Receive(CancellationToken token) => FailReceive ? ValueTask.FromException<TraversalDatagram>(new IOException("fixture receiver failure")) : socket.Receive(token);
        public void Dispose() => socket.Dispose();
    }
    static async Task ProbabilityBoundaries(string output)
    {
        var rows = new List<object>();
        try {
            var context = ProbabilityContext(); byte[] key = Key();
            var resources = new TraversalResources(); var held = Enumerable.Range(0, 8).Select(_ => resources.Acquire()).ToList();
            using (resources.BeginUdpExploration()) for (int i = 0; i < 3; i++) held.Add(resources.Acquire());
            var sockets = new List<NatLab.Port>(); var lab = new NatLab();
            await using (var hard = new UdpProbabilityPreparation(resources, ReverseProbability(context), Guid.NewGuid(), key, false,
                IPAddress.Parse("192.0.2.1"), IPEndPoint.Parse("192.0.2.1:40111"), [], 32, i => {
                    var socket = lab.Add("192.0.2.2", "apdm", "apdf", 51000 + i * 101, localPort: 43000 + i); sockets.Add(socket); return socket;
                })) Check(hard.SocketIds.Length == 29 && resources.Usage().OpenUdpResources == 40,
                    "requested N=32 falls to actual 29 when eleven Active/retiring references already occupy the same ledger");
            Check(resources.Usage().OpenUdpResources == 11 && sockets.All(s => s.Disposed), "disposing unstarted exploration preserves pre-existing resource owners");
            foreach (var item in held) item.Dispose();
            sockets.Clear(); bool openFailed = false;
            try {
                await using var failed = new UdpProbabilityPreparation(resources, ReverseProbability(context), Guid.NewGuid(), key, false,
                    IPAddress.Parse("192.0.2.1"), IPEndPoint.Parse("192.0.2.1:40111"), [], 4, i => {
                        if (i == 2) throw new IOException("fixture bind failure");
                        var socket = lab.Add("192.0.2.2", "apdm", "apdf", 51000 + i * 101, localPort: 44000 + i); sockets.Add(socket); return socket;
                    });
            } catch (IOException) { openFailed = true; }
            Check(openFailed && resources.Usage().OpenUdpResources == 0 && sockets.All(s => s.Disposed), "partial creation failure closes all receivers and releases socket/expansion ownership");
            using (resources.BeginUdpExploration()) Check(true, "failed preparation permits another exclusive exploration owner");
            await using (var dead = new UdpProbabilityPreparation(resources, ReverseProbability(context), Guid.NewGuid(), key, false,
                IPAddress.Parse("192.0.2.1"), IPEndPoint.Parse("192.0.2.1:40111"), [], 1,
                _ => new ProbeInterceptSocket(new TraversalSocket(new(IPAddress.Loopback, 0))) { FailReceive = true }))
                Check(!dead.Armed, "a group with no functioning receive pump cannot announce Ready");
            await using (var pending = new UdpProbabilityPreparation(resources, ReverseProbability(context), Guid.NewGuid(), key, false,
                IPAddress.Parse("192.0.2.1"), IPEndPoint.Parse("192.0.2.1:40111"), [], 2,
                i => new TraversalSocket(new(IPAddress.Loopback, 0)))) {
                using var silent = new TraversalSocket(new(IPAddress.Loopback, 0));
                var observing = pending.Observe(silent.Local, None); bool competing = false;
                try { _ = pending.Activate(None); } catch (IOException) { competing = true; }
                var cleanup = Stopwatch.StartNew(); await pending.DisposeAsync();
                bool stopped = false; try { await observing; } catch (OperationCanceledException) { stopped = true; }
                Check(competing && stopped && cleanup.ElapsedMilliseconds < 1000 && resources.Usage().OpenUdpResources == 0,
                    "dispose joins and cancels live STUN observations before releasing the group, and activation cannot race them");
            }
            using (var expired = new UdpProbeGroup(resources, false, IPAddress.Parse("192.0.2.1"), IPEndPoint.Parse("192.0.2.1:40111"), [])) {
                expired.Register(Guid.NewGuid()); expired.Begin(); long started = expired.Started;
                await Task.Delay(60); expired.Begin();
                Check(expired.Started == started && expired.Remaining.TotalMilliseconds < UdpProbeGroup.DurationMs - 40,
                    "observation and activation share a non-renewing monotonic round deadline");
            }
            var completion = new TraversalControlRound(new TraversalResources(8, 1000, 600), 512, 256 * 1024);
            for (int i = 0; i < 488; i++) if (!completion.TrySend(96, false)) throw new Exception("premature search limit");
            Check(!completion.TrySend(96, false), "all sources together reserve the last 24 packets for authenticated completion");
            for (int i = 0; i < 24; i++) if (!completion.TrySend(96, true)) throw new Exception("completion budget unavailable");
            Check(completion.Packets == 512 && !completion.TrySend(96, true), "512 packet hard limit includes search and completion with no per-source refill");
            var byteRound = new TraversalControlRound(new TraversalResources(8, 10000, 600), 512, 256 * 1024);
            for (int i = 0; i < 16; i++) {
                while (!byteRound.TrySend(16384, true)) await Task.Delay(25);
            }
            Check(byteRound.Bytes == 256 * 1024 && !byteRound.TrySend(1, true), "256 KiB round ceiling remains below the global byte-rate limiter and cannot refill");
            var reserved = new TraversalResources(8, 100000, 1); bool sawReserved = false;
            for (int i = 0; i < 30 && !sawReserved; i++) {
                _ = reserved.TrySend(96); await Task.Delay(1);
                sawReserved = !reserved.TrySend(96) && reserved.TryControlSend(96, true);
            }
            Check(sawReserved, "completion can consume aggregate capacity reserved from ordinary search");
            var capped = new TraversalResources(8, 0, 1);
            Check(capped.TryControlSend(96, true) && !capped.TryControlSend(96, true), "completion still obeys the aggregate machine bucket and does not get a second rate budget");

            // All networks below are separate deterministic fixtures. Their
            // known target mappings authorize only these isolated test inputs.
            foreach (string fault in new[] { "first-receiver-fails", "cancel", "selection-authentication", "wrong-member-key", "pmtu-too-small", "unstable-easy-mapping" }) {
                var clock = Stopwatch.StartNew(); var model = new NatLab(); var aBudget = new TraversalResources(); var bBudget = new TraversalResources();
                var c = ProbabilityContext(); var reverse = ReverseProbability(c); byte[] shared = Key();
                var aPort = model.Add("192.0.2.1", fault == "unstable-easy-mapping" ? "apdm" : "eim", "apdf", 40111, maximumPayload: fault == "pmtu-too-small" ? 1200 : 1472);
                var wrapped = new ProbeInterceptSocket(aPort) { HoldSelection = fault == "selection-authentication" };
                var bPorts = new List<NatLab.Port>();
                int count = fault == "first-receiver-fails" ? 4 : 2;
                var easyGeneration = Guid.NewGuid(); var hardGeneration = Guid.NewGuid();
                using var deadline = new CancellationTokenSource(16000);
                await using var easy = new UdpProbabilityPreparation(aBudget, c, easyGeneration, shared, true,
                    IPAddress.Parse("192.0.2.2"), null, Enumerable.Range(0, count).Select(i => 51000 + i * 101).ToArray(), 1, _ => wrapped);
                await using var hard = new UdpProbabilityPreparation(bBudget, reverse, hardGeneration, fault == "wrong-member-key" ? Key() : shared, false,
                    IPAddress.Parse("192.0.2.1"), IPEndPoint.Parse("192.0.2.1:40111"), [], count, i => {
                        var port = model.Add("192.0.2.2", "apdm", "apdf", 51000 + i * 101, localPort: 45000 + i); bPorts.Add(port);
                        return new ProbeInterceptSocket(port) { FailReceive = fault == "first-receiver-fails" && i == 0 };
                    });
                using var cancel = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                if (fault == "unstable-easy-mapping") await easy.Observe(NatLab.Reflectors[0], cancel.Token);
                var left = easy.Activate(cancel.Token); var right = hard.Activate(cancel.Token);
                if (fault == "cancel") { await Task.Delay(5); cancel.Cancel(); }
                if (fault == "selection-authentication") {
                    byte[] valid = await wrapped.Selection.Task.WaitAsync(deadline.Token);
                    byte[] scoped = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, PathNomination.ContextDigest(c), "streamlink-udp-exploration-v1"u8.ToArray());
                    byte[] macKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, scoped, 32, c.AttemptId.ToByteArray(), "streamlink-udp-check-v2"u8.ToArray());
                    CryptographicOperations.ZeroMemory(scoped);
                    foreach (int offset in new[] { 7, 8, 24, 40, valid.Length - 1 }) {
                        byte[] corrupted = valid.ToArray(); corrupted[offset] ^= 0x40;
                        if (offset != valid.Length - 1) HMACSHA256.HashData(macKey, corrupted.AsSpan(0, corrupted.Length - 32), corrupted.AsSpan(corrupted.Length - 32));
                        foreach (var port in bPorts) port.Incoming.Writer.TryWrite(new(corrupted, IPEndPoint.Parse("192.0.2.1:40111")));
                    }
                    foreach (var port in bPorts) port.Incoming.Writer.TryWrite(new(valid, IPEndPoint.Parse("192.0.2.99:40111")));
                    await Task.Delay(250, deadline.Token);
                    Check(!left.IsCompleted && !right.IsCompleted, "wrong role/attempt/destination token/source token/MAC and unauthorized source cannot commit a preliminary path");
                    CryptographicOperations.ZeroMemory(macKey); Volatile.Write(ref wrapped.HoldSelection, false);
                }
                bool succeeded = false, canceled = false;
                IMeshDatagramPath[] paths = [];
                try { paths = await Task.WhenAll(left, right); succeeded = true; }
                catch (OperationCanceledException) when (fault == "cancel") { canceled = true; }
                catch (IOException) when (fault is "wrong-member-key" or "pmtu-too-small" or "unstable-easy-mapping") { }
                Check(fault is "first-receiver-fails" or "selection-authentication" ? succeeded : fault == "cancel" ? canceled : !succeeded,
                    $"exploration handles {fault} without promoting an unverified pair");
                if (fault == "first-receiver-fails") Check(paths[1].Identity.LeaseId != bPorts[0].Id, "failed receiver leaves the fair drive rotation so surviving sources can win");
                rows.Add(new { fault, elapsedMs = clock.Elapsed.TotalMilliseconds, easy = easy.Statistics, hard = hard.Statistics });
                foreach (var path in paths) await path.DisposeAsync();
                await easy.DisposeAsync(); await hard.DisposeAsync();
                Check(aBudget.Usage().OpenUdpResources == 0 && bBudget.Usage().OpenUdpResources == 0 && bPorts.All(p => p.Disposed) && aPort.Disposed,
                    "success, failure and cancellation all release their exact resource references");
                Check(aBudget.Enhancements.Usage() is { Active: 0, Waiting: 0 } && bBudget.Enhancements.Usage() is { Active: 0, Waiting: 0 },
                    "ending actual exploration releases cross-protocol high-cost admission on both machines");
                bool cooled = false;
                try { using var next = aBudget.Enhancements.TryEnter(new(c.NetworkId, c.LocalNodeId, c.RemoteNodeId, easyGeneration), TraversalEnhancementKind.UdpExploration); }
                catch (IOException ex) { cooled = ex.Message.StartsWith("EnhancementCoolingDown"); }
                Check(cooled == (fault is "wrong-member-key" or "pmtu-too-small" or "unstable-easy-mapping"),
                    "only an actually failed peer exploration starts cooldown; success and cancellation permit another round");
                CryptographicOperations.ZeroMemory(shared);
            }
            CryptographicOperations.ZeroMemory(key);
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows, scope = "internal mechanism boundary tests; model I/O, no public scanning, driver or installed configuration changes" }, new JsonSerializerOptions { WriteIndented = true }));
        } catch (Exception ex) {
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, rows, failure = ex.ToString() }, new JsonSerializerOptions { WriteIndented = true })); throw;
        }
    }
}
