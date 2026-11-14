using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;

namespace StreamLink.Core;

public sealed record LegacyControlStats(long Requests, long AdmittedPackets, long AdmittedBytes,
    long BudgetDenied, long WindowDenied, long Expired, int TupleRecords, int Pending);

// Only scheduled compatibility-native controls. Successful injection remains
// a separate native observation; a consumed permit is never reported as NIC
// delivery. Ordinary business datagrams do not enter this controller.
internal sealed class LegacyControlGovernor(TraversalResources machine)
{
    internal static LegacyControlGovernor Shared { get; } = new(TraversalResources.Shared);
    readonly object gate = new();
    readonly Dictionary<(Guid Resource, string Tuple), Window> windows = [];
    readonly LinkedList<Waiter> waiting = [];
    long requests, admitted, bytes, budgetDenied, windowDenied, expired;
    sealed class Window { public long At, Seen; public int Packets, Bytes; public ulong Capture; }
    sealed class Waiter { public required Guid Resource; public required LegacyControlRequest Request; public bool BudgetWait; }
    internal LegacyControlStats Snapshot() { lock (gate) return new(requests, admitted, bytes, budgetDenied, windowDenied, expired, windows.Count, waiting.Count); }
    internal async ValueTask<byte> Admit(Guid resource, LegacyControlRequest request, CancellationToken token)
    {
        var waiter = new Waiter { Resource = resource, Request = request };
        lock (gate) {
            requests++;
            if (waiting.Count >= 32) { budgetDenied++; return 1; }
            waiting.AddLast(waiter);
        }
        try {
            while (true) {
                token.ThrowIfCancellationRequested();
                lock (gate) {
                    long now = Environment.TickCount64;
                    if (now - request.QueuedAt > 250 || request.QueuedAt > now + 10) { expired++; if (waiter.BudgetWait) budgetDenied++; return 3; }
                    // FIFO includes waiting age. One busy native process
                    // cannot repeatedly acquire fresh credit ahead of waiters.
                    if (waiting.First?.Value == waiter) {
                        if (!WindowEligible(resource, request, now, out var window)) { windowDenied++; return 2; }
                        bool allowed = request.Kind == NativeWireKind.Maintenance
                            ? machine.TrySend(request.Bytes, maintenance: true)
                            : machine.TryControlSend(request.Bytes, completion: request.Kind == NativeWireKind.Completion);
                        if (allowed) {
                            if (request.Kind is NativeWireKind.Handshake or NativeWireKind.Completion) { window.Packets++; window.Bytes += request.Bytes; }
                            admitted++; bytes += request.Bytes; return 0;
                        }
                        // Keep the oldest waiter at the head until it obtains
                        // credit or expires. Rotating on every failed polling
                        // tick made fairness depend on thread wakeup order.
                        waiter.BudgetWait = true;
                    }
                }
                await Task.Delay(2, token);
            }
        } finally { lock (gate) { waiting.Remove(waiter); } }
    }
    bool WindowEligible(Guid resource, LegacyControlRequest request, long now, out Window window)
    {
        var key = (resource, request.Tuple);
        if (!windows.TryGetValue(key, out window!)) {
            foreach (var old in windows.Where(p => now - p.Value.Seen > 30000).Select(p => p.Key).ToArray()) windows.Remove(old);
            if (windows.Count >= 128) return false;
            windows[key] = window = new() { At = now, Capture = request.Capture };
        }
        if (request.Capture < window.Capture) return false;
        if (request.Capture != window.Capture || now - window.At >= 8000 && request.Kind == NativeWireKind.Handshake) {
            // This is an explicitly named local compatibility budget window,
            // not a claim that the native/inner handshake has been nominated.
            window.At = now; window.Capture = request.Capture; window.Packets = window.Bytes = 0;
        }
        window.Seen = now;
        if (request.Kind is NativeWireKind.Maintenance) return true;
        int reserve = request.Kind == NativeWireKind.Completion ? 0 : TraversalLimits.CompletionReserve;
        return now - window.At < 8000 && window.Packets < TraversalLimits.RoundPackets - reserve &&
            request.Bytes <= TraversalLimits.RoundBytes - window.Bytes;
    }
    internal void Retire(Guid resource) { lock (gate) foreach (var key in windows.Keys.Where(k => k.Resource == resource).ToArray()) windows.Remove(key); }
}

internal sealed record LegacyControlRequest(ulong Sequence, ulong Capture, NativeWireKind Kind, int Bytes,
    IPAddress Source, ushort SourcePort, IPAddress Target, ushort TargetPort, byte Protocol, byte Flags, bool Secure, long QueuedAt)
{
    internal string Tuple => $"{Protocol}/{Source}:{SourcePort}/{Target}:{TargetPort}";
    internal static LegacyControlRequest Decode(ReadOnlySpan<byte> data, byte expectedProtocol, int serverPort)
    {
        if (data.Length != 56 || data[16] is not (0 or 1 or 3) || data[17] != expectedProtocol || data[19] > 1 ||
            !data.Slice(46, 2).SequenceEqual(new byte[2])) throw new IOException("Legacy control metadata rejected");
        ulong sequence = BinaryPrimitives.ReadUInt64LittleEndian(data), capture = BinaryPrimitives.ReadUInt64LittleEndian(data[8..]);
        int bytes = BinaryPrimitives.ReadInt32LittleEndian(data[20..]);
        ushort sourcePort = BinaryPrimitives.ReadUInt16BigEndian(data[32..]), targetPort = BinaryPrimitives.ReadUInt16BigEndian(data[34..]);
        ushort headers = BinaryPrimitives.ReadUInt16LittleEndian(data[44..]);
        if (sequence == 0 || capture == 0 || bytes is < 28 or > 6144 || sourcePort == 0 || targetPort == 0 ||
            serverPort != 0 && sourcePort != serverPort || headers > bytes ||
            expectedProtocol == 6 && (headers is < 40 or > 120 || bytes < 40) || expectedProtocol == 17 && headers is < 28 or > 68)
            throw new IOException("Legacy control tuple/header rejected");
        var source = new IPAddress(data.Slice(24, 4)); var target = new IPAddress(data.Slice(28, 4));
        if (source.Equals(IPAddress.Any) || target.Equals(IPAddress.Any) || source.GetAddressBytes()[0] >= 224 || target.GetAddressBytes()[0] >= 224)
            throw new IOException("Legacy control address rejected");
        return new(sequence, capture, (NativeWireKind)data[16], bytes, source, sourcePort, target, targetPort, data[17], data[18], data[19] != 0,
            BinaryPrimitives.ReadInt64LittleEndian(data[48..]));
    }
}
