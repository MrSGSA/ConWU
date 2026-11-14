using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

// Full local router path, including shared ingress and the selected TCP/TLS
// transport. All identities and sockets belong to this bounded measurement.
static class RouterBench
{
    sealed class Adapter : IPacketAdapter
    {
        readonly BlockingCollection<byte[]> outgoing = new(256);
        readonly List<double> latency = [];
        long expectedSequence;
        public long Received, Invalid, Gaps;
        public bool Offer(byte[] packet) => outgoing.TryAdd(packet);
        public int Read(byte[] buffer)
        {
            if (!outgoing.TryTake(out var packet, 30)) return 0;
            packet.CopyTo(buffer, 0);
            return packet.Length;
        }
        public bool Write(byte[] packet)
        {
            if (packet.Length != MeshLink.Mtu || packet.AsSpan(44).IndexOfAnyExcept((byte)0x6d) >= 0) {
                Interlocked.Increment(ref Invalid);
                return false;
            }
            long sequence = BinaryPrimitives.ReadInt64LittleEndian(packet.AsSpan(28));
            if (sequence != expectedSequence + 1) Interlocked.Increment(ref Gaps);
            expectedSequence = sequence;
            long stamp = BinaryPrimitives.ReadInt64LittleEndian(packet.AsSpan(36));
            lock (latency) latency.Add(Stopwatch.GetElapsedTime(stamp).TotalMilliseconds);
            Interlocked.Increment(ref Received);
            return true;
        }
        public double Percentile(double fraction)
        {
            lock (latency) {
                latency.Sort();
                return latency.Count == 0 ? 0 : latency[Math.Min(latency.Count - 1, (int)Math.Ceiling(latency.Count * fraction) - 1)];
            }
        }
        public void Dispose() => outgoing.CompleteAdding();
    }

    public static async Task Run(string mode, int mbps, int seconds, string report,string direction="guest-to-host")
    {
        if (!TransportModes.Stream(mode) || mbps is < 1 or > 50 || seconds is < 2 or > 60 || direction is not ("guest-to-host" or "host-to-guest"))
            throw new ArgumentException("Router trial bounds invalid");
        string folder = Path.Combine(Path.GetTempPath(), "conwu-router-bench-" + Guid.NewGuid().ToString("N"));
        try { await Measure(mode, mbps, seconds, report, folder,direction); }
        finally {
            if (Directory.Exists(folder) && !Directory.EnumerateFileSystemEntries(folder).Any()) Directory.Delete(folder);
        }
    }
    static async Task Measure(string mode, int mbps, int seconds, string report, string folder,string direction)
    {
        var host = MeshIdentity.Create("", "", mode, direct: true, pairwise: true);
        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = StreamCertificates.CreateServer(signing, DateTimeOffset.UtcNow.AddDays(1));
        if (mode == "https") host.Pair = host.Pair with { TransportKeyPin = StreamMeshTransport.CertificatePin(certificate) };
        var guest = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(host)));
        using var hostAdapter = new Adapter();
        using var guestAdapter = new Adapter();
        await using var hostRouter = new MeshRouter(host, hostAdapter);
        await using var guestRouter = new MeshRouter(guest, guestAdapter);
        using var shared = new SharedMeshReceiver(folder);
        int port = FreePort();
        using var lease = shared.Acquire(new(folder, host, hostRouter.LocalEndpoint, true, port, null, "off"),
            request => new StreamMeshTransport(request.Mesh, request.Target, true, port, () => certificate),
            _ => false, packet => PairNetworkFrame.Authenticated(host, packet.Span), _ => 0);
        await using var client = new StreamMeshTransport(guest, new(IPAddress.Loopback, port), false, 0);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(seconds + 20));
        guestRouter.SetCandidate(host.Self.Slot, client.ClientEndpoint, "Host", "");
        while (!hostRouter.HasHealthyPath(guest.Self.Slot) || !guestRouter.HasHealthyPath(host.Self.Slot))
            await Task.Delay(20, deadline.Token);

        bool hostSending=direction=="host-to-guest";
        var sender=hostSending?hostAdapter:guestAdapter;
        var receiver=hostSending?guestAdapter:hostAdapter;
        byte[] template = Packet(hostSending?host.LocalIp:guest.LocalIp,hostSending?guest.LocalIp:host.LocalIp);
        long offered = 0, sourceRejected = 0;
        var process = Process.GetCurrentProcess();
        var cpu = process.TotalProcessorTime;
        long allocatedAt = GC.GetTotalAllocatedBytes(true);
        long began = Stopwatch.GetTimestamp(), creditedAt = began;
        double credit = 0, packetsPerSecond = mbps * 1_000_000d / 8 / MeshLink.Mtu;
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(10));
        while (Stopwatch.GetElapsedTime(began).TotalSeconds < seconds && await timer.WaitForNextTickAsync(deadline.Token)) {
            long now = Stopwatch.GetTimestamp();
            credit = Math.Min(credit + packetsPerSecond * Stopwatch.GetElapsedTime(creditedAt, now).TotalSeconds, packetsPerSecond * .05);
            creditedAt = now;
            int count = (int)credit;
            credit -= count;
            for (int index = 0; index < count; index++) {
                if (Stopwatch.GetElapsedTime(began).TotalSeconds >= seconds) break;
                byte[] packet = template.ToArray();
                BinaryPrimitives.WriteInt64LittleEndian(packet.AsSpan(28), offered + 1);
                BinaryPrimitives.WriteInt64LittleEndian(packet.AsSpan(36), Stopwatch.GetTimestamp());
                if (sender.Offer(packet)) offered++;
                else sourceRejected++;
            }
        }
        long ended = Stopwatch.GetTimestamp();
        long drain = Stopwatch.GetTimestamp();
        while (Interlocked.Read(ref receiver.Received) < offered && Stopwatch.GetElapsedTime(drain).TotalSeconds < 4)
            await Task.Delay(10, deadline.Token);
        double deliverySeconds = Stopwatch.GetElapsedTime(began).TotalSeconds;
        var peer = (hostSending?hostRouter:guestRouter).Status().Single();
        bool healthy = hostRouter.HasHealthyPath(guest.Self.Slot) && guestRouter.HasHealthyPath(host.Self.Slot);
        long received = Interlocked.Read(ref receiver.Received);
        double deliveredMbps = received * MeshLink.Mtu * 8 / deliverySeconds / 1_000_000;
        bool passed = offered > 0 && received == offered && receiver.Invalid == 0 && receiver.Gaps == 0 && healthy;
        var result = new {
            status = passed ? "Pass" : "Fail", mode,direction, targetMbps = mbps, targetAchieved = deliveredMbps >= mbps * .95,
            offered, received, sourceRejected, invalid = receiver.Invalid, gaps = receiver.Gaps,
            sendingSeconds = Stopwatch.GetElapsedTime(began, ended).TotalSeconds, deliverySeconds,
            payloadMbps = deliveredMbps, p95Ms = receiver.Percentile(.95), p99Ms = receiver.Percentile(.99),
            cpuMs = (process.TotalProcessorTime - cpu).TotalMilliseconds,
            allocatedBytes = GC.GetTotalAllocatedBytes(true) - allocatedAt,
            workingSet = process.WorkingSet64, directHealthy = healthy, routerDrops = peer.DroppedPackets,
            latencyKind = "source adapter queue to peer adapter write",
            scope = "Production MeshRouter, pair-network framing, SharedMeshReceiver and real TCP/TLS; memory adapters and loopback"
        };
        string path = Path.GetFullPath(report);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine(JsonSerializer.Serialize(result));
        if (!passed) Environment.ExitCode = 1;
    }

    static byte[] Packet(string source, string target)
    {
        byte[] packet = new byte[MeshLink.Mtu];
        packet[0] = 0x45; packet[8] = 64; packet[9] = 17;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
        IPAddress.Parse(source).GetAddressBytes().CopyTo(packet, 12);
        IPAddress.Parse(target).GetAddressBytes().CopyTo(packet, 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), 45123);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), 45124);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24), (ushort)(packet.Length - 20));
        packet.AsSpan(44).Fill(0x6d);
        uint sum = 0;
        for (int offset = 0; offset < 20; offset += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset));
        while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), (ushort)~sum);
        return packet;
    }
    static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
