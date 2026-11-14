using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

static partial class Program
{
    static async Task Probability(string output, int rounds)
    {
        var rows = new List<object>();
        try {
            var ledger = new TraversalResources(); var held = Enumerable.Range(0, 8).Select(_ => ledger.Acquire()).ToArray();
            using (ledger.BeginUdpExploration()) {
                var extra = Enumerable.Range(0, 32).Select(_ => ledger.Acquire()).ToArray();
                bool refused = false; try { using var excess = ledger.Acquire(); } catch (IOException) { refused = true; }
                Check(refused && ledger.Usage().OpenUdpResources == 40, "experimental expansion includes eight already-held resources in the same forty-slot ledger");
                bool second = false; try { using var duplicate = ledger.BeginUdpExploration(); } catch (IOException) { second = true; }
                Check(second, "a second high-cost UDP owner cannot open another independent pool");
                foreach (var item in extra) item.Dispose();
            }
            bool normalFull = false; try { using var extra = ledger.Acquire(); } catch (IOException) { normalFull = true; }
            Check(normalFull, "ending explicit expansion restores the default eight-resource ceiling");
            foreach (var item in held) item.Dispose();

            foreach (string environment in new[] { "model-eim-apdf-vs-apdm-apdf", "real-loopback" }) {
                for (int run = 1; run <= rounds; run++) {
                    var a = MeshIdentity.Create("https://example.com/", "", "udp");
                    var b = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a))); b.Directory = a.Directory;
                    var aa = new RoutedAdapter(); var ab = new RoutedAdapter();
                    await using var ra = new MeshRouter(a, aa, selection: new(AllowUdpFallback: true));
                    await using var rb = new MeshRouter(b, ab, selection: new(AllowUdpFallback: true));
                    var context = new TraversalAttemptContext(a.Pair.Network, a.Self.Device, ra.BootId, b.Self.Device, rb.BootId,
                        Guid.NewGuid(), Guid.NewGuid(), 1, Guid.NewGuid(), 1, TraversalProfile.UdpDirect, run % 2 == 1, true, Guid.NewGuid());
                    var reverse = context with { LocalNodeId = context.RemoteNodeId, LocalBootId = context.RemoteBootId,
                        RemoteNodeId = context.LocalNodeId, RemoteBootId = context.LocalBootId, LocalCandidateId = context.RemoteCandidateId,
                        RemoteCandidateId = context.LocalCandidateId, ProtocolClient = !context.ProtocolClient, Nominator = false };
                    byte[] shared = MeshIdentity.SharedKey(a, b.Self);
                    var leftBudget = new TraversalResources(); var rightBudget = new TraversalResources();
                    var hardSockets = new List<ITraversalSocket>();
                    var hardModel = new List<NatLab.Port>();
                    NatLab? lab = null;
                    await using var reflector = new Reflector(IPAddress.Loopback);
                    IPEndPoint observedAt; ITraversalSocket stableSocket;
                    using var reservation = leftBudget.Acquire(); // quota BEFORE opening the retained test source
                    if (environment == "real-loopback") { stableSocket = new TraversalSocket(new(IPAddress.Loopback, 0)); observedAt = reflector.Endpoint; }
                    else { lab = new NatLab(); stableSocket = lab.Add("192.0.2.1", "eim", "apdf", 40111); observedAt = NatLab.Reflectors[0]; }
                    IPEndPoint stablePublic = lab == null ? stableSocket.Local : new(IPAddress.Parse("192.0.2.1"), 40111);
                    int wanted = lab == null ? 4 : 8;
                    using var deadline = new CancellationTokenSource(18000);
                    await using var hard = new UdpProbabilityPreparation(rightBudget, reverse, Guid.NewGuid(), shared, false,
                        stablePublic.Address, stablePublic, [], wanted, i => {
                            ITraversalSocket s;
                            if (lab == null) s = new TraversalSocket(new(IPAddress.Loopback, 0));
                            else { var modeled = lab.Add("192.0.2.2", "apdm", "apdf", 51000 + i * 101, localPort: 43000 + i); hardModel.Add(modeled); s = modeled; }
                            s = new SelectionFaultSocket(s, run == 1); hardSockets.Add(s); return s;
                        });
                    var hardObserved = await hard.Observe(observedAt, deadline.Token);
                    int[] ports = lab == null ? hardSockets.Select(s => s.Local.Port).ToArray() : hardModel.Select(s => s.NextPort).ToArray();
                    await using var easy = new UdpProbabilityPreparation(leftBudget, context, Guid.NewGuid(), shared, true,
                        lab == null ? IPAddress.Loopback : IPAddress.Parse("192.0.2.2"), null, ports, 1, _ => stableSocket);
                    reservation.Dispose(); // transfer removes the extra conservative reservation, no close/rebind
                    var easyObserved = await easy.Observe(observedAt, deadline.Token);
                    CryptographicOperations.ZeroMemory(shared);
                    var clock = Stopwatch.StartNew();
                    var paths = await Task.WhenAll(easy.Activate(deadline.Token), hard.Activate(deadline.Token));
                    var left = paths[0]; var right = paths[1];
                    Check(left.Identity.LeaseId == easyObserved.Single().SocketId && hardObserved.Any(o => o.SocketId == right.Identity.LeaseId),
                        "exploration STUN and winning data retain the actual owned socket identities");
                    Check(left.Identity.ActualRemote.Address.Equals(lab == null ? IPAddress.Loopback : IPAddress.Parse("192.0.2.2")) &&
                        right.Identity.ActualRemote.Equals(stablePublic), "both endpoints adopt the authenticated stable-to-hard pair");
                    if (lab != null) Check(hardModel.Single(p => p.Id == right.Identity.LeaseId).Bindings[stablePublic.ToString()].External.Equals(left.Identity.ActualRemote),
                        "strict NAT model confirms the selected hard source is exactly the easy peer's actual remote mapping");
                    Check(rightBudget.Usage().OpenUdpResources == 1, "unselected source resources close before data-path transfer");
                    var roundA = ((ITraversalControlledPath)left).ControlRound; var roundB = ((ITraversalControlledPath)right).ControlRound;
                    ra.RegisterPath(2, left, context, 1, easy.RemainingAttemptTime, 1);
                    rb.RegisterPath(1, right, reverse, 1, hard.RemainingAttemptTime, 1);
                    await easy.DisposeAsync(); await hard.DisposeAsync();
                    async Task Until(Func<bool> condition) { while (!condition()) { deadline.Token.ThrowIfCancellationRequested(); await Task.Delay(10, deadline.Token); } }
                    await Until(() => ra.Paths(2).Any(p => p.Stage == NominationStage.Selected) && rb.Paths(1).Any(p => p.Stage == NominationStage.Selected));
                    aa.Outgoing.Add(InnerPacket(a.LocalIp, b.LocalIp)); ab.Outgoing.Add(InnerPacket(b.LocalIp, a.LocalIp));
                    await Until(() => aa.Incoming.Count == 1 && ab.Incoming.Count == 1);
                    Check(aa.Incoming.Single().Length == 1280 && ab.Incoming.Single().Length == 1280,
                        "real MeshRouter/MeshLink nomination and full inner IP continue after exploration owner disposal");
                    Check(roundA.Packets <= 512 && roundB.Packets <= 512 && roundA.Bytes <= 256 * 1024 && roundB.Bytes <= 256 * 1024,
                        "all sources, PMTU, selection and subsequent nomination share one bounded round per endpoint");
                    int lost = hardSockets.Cast<SelectionFaultSocket>().Sum(s => s.Dropped);
                    if (run == 1) Check(lost >= 1, "winning source survives actual selection-ACK suppression and retry");
                    rows.Add(new { environment, run, wanted, establishedMs = clock.Elapsed.TotalMilliseconds, selectionAcksDropped = lost,
                        easy = easy.Statistics, hard = hard.Statistics, actualHardMappingsInModel = lab == null ? (int?)null : hardModel.Count(p => p.Bindings.ContainsKey(stablePublic.ToString())),
                        winningEasyResource = left.Identity.LeaseId, winningHardResource = right.Identity.LeaseId });
                    await ra.DisposeAsync(); await rb.DisposeAsync();
                    Check(leftBudget.Usage().OpenUdpResources == 0 && rightBudget.Usage().OpenUdpResources == 0, "last winning path release returns every socket quota");
                }
            }
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, rows,
                scope = "internal exploration mechanism and real Router; memory IP adapters; stability/target ports are known fixture inputs, not production qualification or public NAT coverage" }, new JsonSerializerOptions { WriteIndented = true }));
        } catch (Exception ex) {
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Fail", checks, failure = ex.ToString(), rows }, new JsonSerializerOptions { WriteIndented = true })); throw;
        }
    }
    sealed class SelectionFaultSocket(ITraversalSocket socket, bool dropAck) : ITraversalSocket
    {
        public int Dropped;
        public Guid Id => socket.Id;
        public IPEndPoint Local => socket.Local;
        public bool DontFragment => socket.DontFragment;
        public ValueTask Send(ReadOnlyMemory<byte> data, IPEndPoint remote, CancellationToken token) {
            if (dropAck && data.Span.StartsWith("SLG3"u8) && data.Span[4] == 6 && Interlocked.CompareExchange(ref Dropped, 1, 0) == 0) return ValueTask.CompletedTask;
            return socket.Send(data, remote, token);
        }
        public ValueTask<TraversalDatagram> Receive(CancellationToken token) => socket.Receive(token);
        public void Dispose() => socket.Dispose();
    }
}
