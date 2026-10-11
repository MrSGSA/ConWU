using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace StreamLink.Core;

// One optional multicast receiver per process/listening port. Windows cannot
// bind an IPv4 multicast address (WSAEADDRNOTAVAIL); bind ANY with reuse, join
// only owned interfaces, and verify destination + arrival interface + gateway.
// No outgoing datagrams, mapping requests or business data pass this socket.
internal static class PortControlMulticast
{
    internal static readonly IPAddress Group = IPAddress.Parse("224.0.0.1");
    static readonly object poolGate = new();
    static readonly Dictionary<int, Hub> hubs = [];
    internal static bool Matches(PortControlRoute route, int ownedInterface, IPEndPoint source, IPAddress destination, int arrivalInterface)
        => destination.Equals(Group) && ownedInterface > 0 && arrivalInterface == ownedInterface && route.Gateway.Equals(source);

    public static Subscription Subscribe(PortControlRoute route, TraversalResources resources, Action<ReadOnlyMemory<byte>> callback)
    {
        int index;
        try { index = route.NotificationInterface(); }
        catch (NetworkInformationException) { return new("InterfaceUnavailable"); }
        if (index <= 0) return new("InterfaceUnavailable");
        lock (poolGate) {
            if (hubs.TryGetValue(route.NotificationPort, out var hub) && !ReferenceEquals(hub.Resources, resources)) return new("LedgerMismatch");
            if (hub == null) {
                hub = new(route.NotificationPort, resources);
                hubs.Add(route.NotificationPort, hub);
            }
            return hub.Add(route, index, callback);
        }
    }

    internal sealed class Subscription : IDisposable
    {
        readonly Hub? hub;
        readonly string unavailable;
        int disposed;
        internal readonly Guid Id = Guid.NewGuid();
        internal readonly PortControlRoute? Route;
        internal readonly int Interface;
        internal readonly Action<ReadOnlyMemory<byte>>? Callback;
        internal string JoinFailure = "";
        internal Subscription(string reason) { unavailable = reason; }
        internal Subscription(Hub hub, PortControlRoute route, int index, Action<ReadOnlyMemory<byte>> callback)
        { this.hub = hub; Route = route; Interface = index; Callback = callback; unavailable = ""; }
        public string Reason => Volatile.Read(ref disposed) != 0 ? "Closed" : JoinFailure.Length != 0 ? JoinFailure : hub?.Reason ?? unavailable;
        public string Mode => Reason.Length == 0 ? "UnicastAndMulticast" : "UnicastOnly";
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0 || hub == null) return;
            lock (poolGate) {
                if (!hub.Remove(this)) return;
                hubs.Remove(hub.Port); hub.Dispose();
            }
        }
    }

    internal sealed class Hub(int port, TraversalResources resources) : IDisposable
    {
        public readonly int Port = port;
        public readonly TraversalResources Resources = resources;
        readonly object gate = new();
        readonly Dictionary<Guid, Subscription> subscribers = [];
        readonly HashSet<int> memberships = [];
        TraversalResources.OptionalSocket? quota;
        Socket? socket;
        CancellationTokenSource? stop;
        Task receiver = Task.CompletedTask;
        string reason = "SocketBudgetUnavailable";
        bool started;
        public string Reason => Volatile.Read(ref reason);

        public Subscription Add(PortControlRoute route, int index, Action<ReadOnlyMemory<byte>> callback)
        {
            lock (gate) {
                if (subscribers.Count >= 32) return new("SubscriberLimit");
                var entry = new Subscription(this, route, index, callback); subscribers.Add(entry.Id, entry);
                if (!started) {
                    started = true;
                    try { quota = Resources.TryOpenOptional(Open); }
                    catch (SocketException ex) { reason = "SocketUnavailable:" + ex.SocketErrorCode; }
                    catch (PlatformNotSupportedException) { reason = "PlatformUnsupported"; }
                } else if (socket != null && Reason.Length == 0) Join(entry);
                return entry;
            }
        }
        IDisposable Open()
        {
            var opened = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try {
                opened.ExclusiveAddressUse = false;
                opened.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                opened.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
                opened.ReceiveBufferSize = 64 * 1024;
                opened.Bind(new IPEndPoint(OperatingSystem.IsWindows() ? IPAddress.Any : Group, Port));
                socket = opened;
                foreach (var entry in subscribers.Values) Join(entry);
                if (memberships.Count == 0) throw new SocketException((int)SocketError.AddressNotAvailable);
                stop = new(); reason = ""; receiver = Receive(opened, stop.Token);
                return new ReceiverOwner(this);
            } catch { socket = null; memberships.Clear(); opened.Dispose(); throw; }
        }
        void Join(Subscription entry)
        {
            if (memberships.Contains(entry.Interface)) return;
            try {
                socket!.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(Group, entry.Interface));
                memberships.Add(entry.Interface);
            } catch (SocketException ex) { entry.JoinFailure = "MembershipUnavailable:" + ex.SocketErrorCode; }
        }
        public bool Remove(Subscription entry)
        {
            lock (gate) {
                subscribers.Remove(entry.Id);
                if (socket != null && memberships.Contains(entry.Interface) && !subscribers.Values.Any(s => s.Interface == entry.Interface && s.JoinFailure.Length == 0)) {
                    try { socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.DropMembership, new MulticastOption(Group, entry.Interface)); }
                    catch (SocketException) { /* interface may already have disappeared */ }
                    memberships.Remove(entry.Interface);
                }
                return subscribers.Count == 0;
            }
        }
        async Task Receive(Socket source, CancellationToken token)
        {
            byte[] packet = new byte[1101]; long window = Stopwatch.GetTimestamp(); int messages = 0;
            try {
                while (true) {
                    SocketReceiveMessageFromResult received;
                    try { received = await source.ReceiveMessageFromAsync(packet, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), token); }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.MessageSize) { continue; }
                    if (received.ReceivedBytes > 1100 || (received.SocketFlags & (SocketFlags.Truncated | SocketFlags.ControlDataTruncated)) != 0 ||
                        !received.PacketInformation.Address.Equals(Group)) continue;
                    // Multicast carries only restart/address hints, never MAP.
                    var bytes = packet.AsMemory(0, received.ReceivedBytes);
                    if (PortControlProtocol.PcpAnnounceEpoch(bytes.Span) == null && PortControlProtocol.ParsePmp(bytes.Span, [0, 0], null) is not { Error: 0, External: not null }) continue;
                    Subscription[] targets;
                    lock (gate) targets = subscribers.Values.Where(s => s.JoinFailure.Length == 0 && Matches(s.Route!, s.Interface,
                        (IPEndPoint)received.RemoteEndPoint, received.PacketInformation.Address, received.PacketInformation.Interface)).ToArray();
                    if (targets.Length == 0) continue;
                    long now = Stopwatch.GetTimestamp();
                    if (Stopwatch.GetElapsedTime(window, now).TotalSeconds >= 1) { window = now; messages = 0; }
                    if (++messages > 64) continue;
                    foreach (var entry in targets) entry.Callback!(bytes);
                }
            } catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            catch (Exception ex) { Volatile.Write(ref reason, "ReceiverFailed:" + ex.GetType().Name); }
        }
        void CloseReceiver()
        {
            Socket? closing; Task joining; CancellationTokenSource? cancel;
            lock (gate) {
                Volatile.Write(ref reason, "ResourcePreempted"); closing = socket; socket = null;
                cancel = stop; stop = null; joining = receiver; memberships.Clear();
            }
            cancel?.Cancel(); joining.GetAwaiter().GetResult(); closing?.Dispose(); cancel?.Dispose();
        }
        public void Dispose() => quota?.Dispose();
        sealed class ReceiverOwner(Hub owner) : IDisposable { public void Dispose() => owner.CloseReceiver(); }
    }
}
