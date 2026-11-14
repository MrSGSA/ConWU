using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

// Uses the complete product MeshRouter, shared listener and authenticating
// stream transport. Only the packet adapter and workload are synthetic.
static class FormalFlowBench
{
    static void Output(object value) => Console.WriteLine(JsonSerializer.Serialize(value));
    public static async Task Run()
    {
        var config = JsonDocument.Parse((await Console.In.ReadLineAsync())!); var c = config.RootElement;
        bool host = c.GetProperty("host").GetBoolean(), lanes = c.GetProperty("lanes").GetBoolean();
        string mode = c.GetProperty("mode").GetString()!;
        if (!TransportModes.Stream(mode)) throw new ArgumentException("stream modes only");
        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var certificate = StreamCertificates.CreateServer(signing, DateTimeOffset.UtcNow.AddDays(1));
        var mesh = host ? MeshIdentity.Create("", "", mode, direct: true, pairwise: true) : c.GetProperty("mesh").Deserialize<MeshProfile>()!;
        if (host && mode == "https") mesh.Pair = mesh.Pair with { TransportKeyPin = StreamMeshTransport.CertificatePin(certificate) };
        MeshProfile? guest = host ? MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(mesh))) : null;
        string peer = host ? guest!.LocalIp : MeshAddressing.Address(mesh.Pair.Network, mesh.Directory!.Members.Single(m => m.Slot != mesh.Self.Slot));
        var adapter = new Adapter(host, mesh.LocalIp, peer); await using var router = new MeshRouter(mesh, adapter);
        string folder = Path.Combine(Path.GetTempPath(), "conwu-formal-flow-" + Guid.NewGuid().ToString("N"));
        using var shared = new SharedMeshReceiver(folder); IMeshTransport? server = null; StreamMeshTransport? client = null;
        try {
            if (host) server = shared.Acquire(new(folder, mesh, router.LocalEndpoint, true, c.GetProperty("port").GetInt32(), null, "off") { StreamFlowLanes = lanes, RetireEndpoint = router.FailLegacyIngress },
                r => new StreamMeshTransport(r.Mesh, r.Target, true, r.Port, () => certificate, flowLanes: r.StreamFlowLanes, flowPolicy: r.StreamFlowPolicy), _ => false, p => PairNetworkFrame.Authenticated(mesh, p.Span), _ => 0);
            else { client = new(mesh, IPEndPoint.Parse(c.GetProperty("target").GetString()!), false, 0, flowLanes: lanes); router.SetCandidate(mesh.IntroducerSlot, client.ClientEndpoint, "host", ""); }
            Output(new { eventName = "ready", mesh = guest }); Task? sending = null;
            while (await Console.In.ReadLineAsync() is { } line) {
                using var command = JsonDocument.Parse(line); var cmd = command.RootElement; string action = cmd.GetProperty("action").GetString()!;
                if (action == "stop") break;
                if (action == "reset") { adapter.Reset(); Output(new { eventName = "reset", peer = router.Status().Single() }); }
                else if (action == "start") { int rate = cmd.GetProperty("mbps").GetInt32(), seconds = cmd.GetProperty("seconds").GetInt32(); if (rate is < 1 or > 45 || seconds is < 2 or > 30) throw new ArgumentException(); sending = Task.Run(() => adapter.Send(rate, seconds)); Output(new { eventName = "started" }); }
                else if (action == "finish") { if (sending != null) await sending; Output(new { eventName = "finished", stats = adapter.Snapshot(), peer = router.Status().Single(), io = client?.Io }); }
            }
            if (sending != null) await sending;
        } finally { if (client != null) await client.DisposeAsync(); server?.Dispose(); shared.Dispose(); if (Directory.Exists(folder) && !Directory.EnumerateFileSystemEntries(folder).Any()) Directory.Delete(folder); }
    }
    sealed class Adapter(bool host, string local, string peer) : IPacketAdapter
    {
        readonly BlockingCollection<byte[]> output = new(512);
        readonly object gate = new(); readonly List<double> controls = [], audio = [];
        readonly Dictionary<int, long> expected = []; long videoBytes, packets, reordered, gaps, offered, rejected;
        long start;
        public int Read(byte[] buffer) { if (!output.TryTake(out var packet, 20)) return 0; packet.CopyTo(buffer, 0); return packet.Length; }
        public bool Write(byte[] packet)
        {
            int flow = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(20));
            if (host && flow == 47999) {
                byte[] reply = StreamFlowChecks.Packet(local, peer, flow, packet.Length, BinaryPrimitives.ReadInt32BigEndian(packet.AsSpan(28)));
                packet.AsSpan(32).CopyTo(reply.AsSpan(32)); Offer(reply); return true;
            }
            lock (gate) {
                int sequence = BinaryPrimitives.ReadInt32BigEndian(packet.AsSpan(28));
                long previous = expected.GetValueOrDefault(flow); if (sequence <= previous) reordered++; else if (sequence > previous + 1) gaps += sequence - previous - 1;
                expected[flow] = Math.Max(previous, sequence); packets++;
                double ms = Stopwatch.GetElapsedTime(BinaryPrimitives.ReadInt64BigEndian(packet.AsSpan(32))).TotalMilliseconds;
                if (flow == 47998) videoBytes += packet.Length; else if (flow == 47999) controls.Add(ms); else if (flow == 48000) audio.Add(ms);
            }
            return true;
        }
        void Offer(byte[] packet) { Interlocked.Increment(ref offered); if (!output.TryAdd(packet)) Interlocked.Increment(ref rejected); }
        public void Reset() { lock (gate) { controls.Clear(); audio.Clear(); expected.Clear(); videoBytes = packets = reordered = gaps = offered = rejected = 0; start = Stopwatch.GetTimestamp(); } }
        public async Task Send(int mbps, int seconds)
        {
            long began = Stopwatch.GetTimestamp(); int video = 0, sounds = 0, probes = 0, frame = 0;
            while (Stopwatch.GetElapsedTime(began).TotalSeconds < seconds) {
                double elapsed = Stopwatch.GetElapsedTime(began).TotalSeconds;
                if (host) {
                    if (elapsed * 60 >= frame) { frame++; int target = (int)(Math.Min(frame / 60d, seconds) * mbps * 1e6 / (1200 * 8)); while (video < target) Make(47998, 1200, ++video); }
                    while (sounds < elapsed * 200) Make(48000, 180, ++sounds);
                } else while (probes < elapsed * 120) Make(47999, 96, ++probes);
                await Task.Delay(1);
            }
            void Make(int flow, int length, int seq) { byte[] packet = StreamFlowChecks.Packet(local, peer, flow, length, seq); RandomNumberGenerator.Fill(packet.AsSpan(40)); BinaryPrimitives.WriteInt64BigEndian(packet.AsSpan(32), Stopwatch.GetTimestamp()); Offer(packet); }
        }
        public object Snapshot()
        {
            lock (gate) {
                double Percentile(List<double> values, double p) { var ordered = values.Order().ToArray(); return ordered.Length == 0 ? 0 : ordered[Math.Min(ordered.Length - 1, (int)Math.Ceiling(ordered.Length * p) - 1)]; }
                return new { videoBytes, packets, reordered, gaps, offered, rejected, controlCount = controls.Count, controlP95 = Percentile(controls, .95), controlP99 = Percentile(controls, .99), audioP99 = Percentile(audio, .99), elapsed = Stopwatch.GetElapsedTime(start).TotalSeconds };
            }
        }
        public void Dispose() => output.CompleteAdding();
    }
}
