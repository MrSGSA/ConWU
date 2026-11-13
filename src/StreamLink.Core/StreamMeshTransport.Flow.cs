using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;

namespace StreamLink.Core;

public sealed partial class StreamMeshTransport
{
    // The framing and HTTP upgrade remain unchanged. Control records are
    // ordinary bounded datagrams; an older receiver simply ignores them.
    sealed class StreamFlowWire(StreamMeshTransport owner, TcpClient tcp, Stream stream, WebSocket? web, bool batch) : IDisposable
    {
        readonly byte[] readBuffer = new byte[MaximumBatchBytes + 1];
        readonly byte[] writeBuffer = new byte[MaximumBatchBytes];
        readonly Queue<byte[]> incoming = new();
        int buffered;
        public async Task<byte[]> Read(CancellationToken token)
        {
            while (incoming.Count == 0) {
                if (web != null) {
                    int length = 0, maximum = batch ? MaximumBatchBytes : MaximumDatagram;
                    ValueWebSocketReceiveResult part;
                    do {
                        if (length > maximum) throw new IOException("HTTPS 消息过大");
                        part = await web.ReceiveAsync(readBuffer.AsMemory(length, maximum + 1 - length), token);
                        Interlocked.Increment(ref owner.networkReads);
                        if (part.MessageType == WebSocketMessageType.Close) throw new EndOfStreamException();
                        if (part.MessageType != WebSocketMessageType.Binary) throw new IOException("HTTPS 只接收二进制数据");
                        length += part.Count;
                    } while (!part.EndOfMessage);
                    if (length < 1 || length > maximum) throw new IOException("HTTPS 数据报长度无效");
                    if (!batch) incoming.Enqueue(readBuffer.AsSpan(0, length).ToArray());
                    else if (Parse(length, true) != length) throw new IOException("HTTPS 批量数据帧无效");
                } else {
                    int count = await stream.ReadAsync(readBuffer.AsMemory(buffered, MaximumBatchBytes - buffered), token);
                    Interlocked.Increment(ref owner.networkReads);
                    if (count == 0) throw new EndOfStreamException();
                    buffered += count;
                    int consumed = Parse(buffered, false);
                    buffered -= consumed; readBuffer.AsSpan(consumed, buffered).CopyTo(readBuffer);
                }
            }
            Interlocked.Increment(ref owner.receivedDatagrams);
            return incoming.Dequeue();
        }
        int Parse(int length, bool complete)
        {
            int offset = 0, count = 0;
            while (length - offset >= 2) {
                int size = BinaryPrimitives.ReadUInt16BigEndian(readBuffer.AsSpan(offset, 2));
                if (size is < 1 or > MaximumDatagram) throw new IOException("TCP 数据帧长度无效");
                if (size > length - offset - 2) break;
                if (complete && ++count > MaximumBatchDatagrams) throw new IOException("HTTPS 批量数据帧数量无效");
                incoming.Enqueue(readBuffer.AsSpan(offset + 2, size).ToArray()); offset += size + 2;
            }
            return offset;
        }
        public async Task Write(IReadOnlyList<byte[]> packets, CancellationToken token)
        {
            int used = 0;
            foreach (byte[] packet in packets) {
                BinaryPrimitives.WriteUInt16BigEndian(writeBuffer.AsSpan(used, 2), (ushort)packet.Length);
                packet.CopyTo(writeBuffer, used + 2); used += packet.Length + 2;
            }
            if (web != null) await web.SendAsync(batch ? writeBuffer.AsMemory(0, used) : writeBuffer.AsMemory(2, used - 2), WebSocketMessageType.Binary, true, token);
            else await stream.WriteAsync(writeBuffer.AsMemory(0, used), token);
            Interlocked.Increment(ref owner.networkWrites); Interlocked.Add(ref owner.sentDatagrams, packets.Count);
        }
        public int BatchSize => batch ? MaximumBatchDatagrams : 1;
        public void Dispose() => tcp.Dispose();
    }

    async Task RunStream(StreamFlowWire wire, Socket? udp, IPEndPoint? fixedReceiver, (IPEndPoint Target, string Pin)? remote,
        bool bootstrap, StreamFlowSession? group, int lane, Action? authenticated, CancellationToken token)
    {
        if (group != null) {
            await wire.Write([group.Control(5, lane)], token);
            byte[] answer = await wire.Read(token).WaitAsync(TimeSpan.FromSeconds(6), token);
            if (!group.Valid(answer, 6, lane)) throw new IOException("分流连接身份确认失败");
            await group.RunLane(lane, wire, token); return;
        }
        byte[]? first = null;
        if (remote == null) {
            first = await wire.Read(token).WaitAsync(TimeSpan.FromSeconds(8), token);
            if (StreamFlowSession.IsControl(first) && first[5] == 5) {
                var id = new Guid(first.AsSpan(28, 16));
                if (!flowGroups.TryGetValue(id, out var session) || !session.CurrentPolicy() || !session.Attach(lane = first[6], first)) throw new IOException("拒绝未绑定的分流连接");
                authenticated?.Invoke();
                await wire.Write([session.Control(6, lane)], token);
                await session.RunLane(lane, wire, token); return;
            }
        }
        using var accepted = remote == null ? LocalSocket() : null;
        using var main = new StreamFlowSession(this, wire, udp ?? accepted!, fixedReceiver, remote, bootstrap, authenticated, token);
        flowSessions.TryAdd(main, 0);
        try { await main.Run(first); } finally { flowSessions.TryRemove(main, out _); }
    }

    async Task ConnectLane(StreamFlowSession group, int lane, (IPEndPoint Target, string Pin) remote, CancellationToken token)
    {
        using var tcp = new TcpClient(remote.Target.AddressFamily) { NoDelay = true };
        var id = Guid.NewGuid(); clients[id] = tcp;
        try {
            using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(token)) {
                deadline.CancelAfter(6000); await tcp.ConnectAsync(remote.Target.Address, remote.Target.Port, deadline.Token);
            }
            // Every TLS connection independently validates the approved pin.
            await Bridge(tcp, local!, null, null, remote, false, group, lane);
        } finally { clients.TryRemove(id, out _); }
    }

    sealed class StreamFlowSession : StreamFlowRoutes.ISession, IDisposable
    {
        const int QueueBudget = 256 * 1024, ControlReserve = 24 * 1024, BulkLimit = 176 * 1024;
        const int ControlSize = 100;
        readonly object gate = new();
        readonly StreamMeshTransport owner;
        readonly StreamFlowWire primary;
        readonly Socket udp;
        readonly IPEndPoint endpoint;
        readonly IPEndPoint? fixedReceiver;
        IPEndPoint? receiver;
        readonly (IPEndPoint Target, string Pin)? remote;
        readonly Action? authenticated;
        readonly CancellationTokenSource stop;
        readonly Queue<byte[]>[] queued = [new(), new(), new(), new()];
        readonly Queue<byte[]>[] held = [new(), new(), new(), new()];
        readonly SemaphoreSlim[] signals = [new(0), new(0), new(0), new(0)];
        readonly StreamFlowWire?[] wires = new StreamFlowWire?[4];
        readonly bool[] claimed = new bool[4], suspended = new bool[4], fallback = new bool[4];
        readonly long[] suspendedAt = new long[4];
        readonly int[] laneBytes = new int[4];
        readonly List<Task> laneTasks = [];
        byte[]? key;
        byte[] clientNonce = new byte[16], serverNonce = new byte[16];
        long timestamp, lastRead = Environment.TickCount64, rejected, receiveRejected;
        long confirmationDeadline, fenceDeadline;
        int bytes, stage;
        bool negotiated, active, holding, fenceSent, verified, disposed;
        public string Network { get; private set; } = "";
        public int LocalSlot { get; private set; }
        public int RemoteSlot { get; private set; }
        public IPEndPoint Endpoint => endpoint;
        int ClientSlot => remote == null ? RemoteSlot : LocalSlot;
        int ServerSlot => remote == null ? LocalSlot : RemoteSlot;
        Guid GroupId => new(clientNonce);
        public CancellationToken Token => stop.Token;
        public bool Negotiated { get { lock (gate) return negotiated && !disposed; } }
        public StreamFlowStatus Status { get { lock (gate) { int count=1+Enumerable.Range(2,2).Count(i=>wires[i]!=null&&!suspended[i]);return new(negotiated&&!disposed,count,rejected){SplitActive=active&&!disposed&&count>1,ReceiveRejectedPackets=receiveRejected}; } } }

        public StreamFlowSession(StreamMeshTransport owner, StreamFlowWire wire, Socket udp, IPEndPoint? fixedReceiver,
            (IPEndPoint Target, string Pin)? remote, bool bootstrap, Action? authenticated, CancellationToken token)
        {
            this.owner = owner; primary = wire; this.udp = udp; this.fixedReceiver = fixedReceiver; receiver = fixedReceiver;
            this.remote = remote; this.authenticated = authenticated;
            endpoint = (IPEndPoint)udp.LocalEndPoint!; stop = CancellationTokenSource.CreateLinkedTokenSource(token);
            if (remote != null && !bootstrap && owner.mesh.Directory?.Pairwise == true) {
                int peer = owner.mesh.IntroducerSlot;
                if (peer != owner.mesh.Self.Slot && SetIdentity(owner.mesh, peer)) {
                    BindIdentity();
                    if (owner.flowLanes) {
                        RandomNumberGenerator.Fill(clientNonce); timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                        stage = 1; EnqueueControl(Control(1));
                    }
                }
            }
        }

        bool SetIdentity(MeshProfile profile, int peer)
        {
            if (profile.Directory?.Pairwise != true || profile.Pair.Mode != owner.mesh.Pair.Mode || profile.Self.Slot == peer) return false;
            var member = profile.Directory.Members.FirstOrDefault(m => m.Slot == peer); if (member == null) return false;
            if (Network.Length > 0) return Network == profile.Pair.Network && RemoteSlot == peer && LocalSlot == profile.Self.Slot;
            byte[] shared = MeshIdentity.SharedKey(profile, member);
            try { key = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, info: Encoding.ASCII.GetBytes($"conwu-stream-flow-v1/{profile.Pair.Network}/{owner.mesh.Pair.Mode}/{Math.Min(peer, profile.Self.Slot)}/{Math.Max(peer, profile.Self.Slot)}")); }
            finally { CryptographicOperations.ZeroMemory(shared); }
            Network = profile.Pair.Network; LocalSlot = profile.Self.Slot; RemoteSlot = peer;
            return true;
        }
        void BindIdentity() { if (verified) return; StreamFlowRoutes.Register(endpoint, this); verified = true; authenticated?.Invoke(); }
        void Inspect(ReadOnlySpan<byte> frame)
        {
            if (verified || !PairNetworkFrame.IsFrame(frame) || frame.Length < PairNetworkFrame.HeaderSize + MeshLink.Overhead) return;
            var policy = owner.flowPolicy(PairNetworkFrame.Network(frame));
            if (policy != null && PairNetworkFrame.Authenticated(policy.Mesh, frame))
                lock(gate)if(!disposed&&SetIdentity(policy.Mesh,frame[25]))BindIdentity();
        }

        public static bool IsControl(ReadOnlySpan<byte> frame) => frame.Length == ControlSize && frame[..4].SequenceEqual("CWF1"u8) && frame[4] == 1;
        public byte[] Control(int kind, int lane = 0)
        {
            lock (gate) {
                byte[] frame = new byte[ControlSize]; "CWF1"u8.CopyTo(frame); frame[4] = 1; frame[5] = (byte)kind; frame[6] = (byte)lane;
                frame[7] = owner.https ? (byte)2 : (byte)1; Convert.FromHexString(Network).CopyTo(frame, 8);
                frame[24] = (byte)ClientSlot; frame[25] = (byte)ServerSlot; frame[26] = remote == null ? (byte)1 : (byte)0;
                clientNonce.CopyTo(frame, 28); serverNonce.CopyTo(frame, 44); BinaryPrimitives.WriteInt64BigEndian(frame.AsSpan(60), timestamp);
                HMACSHA256.HashData(key!, frame.AsSpan(0, 68), frame.AsSpan(68)); return frame;
            }
        }
        public bool Valid(ReadOnlySpan<byte> frame, int kind, int lane = 0)
        {
            lock (gate) {
                if (disposed || key == null || !IsControl(frame) || frame[5] != kind || frame[6] != lane || frame[7] != (owner.https ? 2 : 1) ||
                    !frame.Slice(8, 16).SequenceEqual(Convert.FromHexString(Network)) || frame[24] != ClientSlot || frame[25] != ServerSlot ||
                    frame[26] != (remote == null ? 0 : 1) || frame[27] != 0 || !frame.Slice(28, 16).SequenceEqual(clientNonce) ||
                    !frame.Slice(44, 16).SequenceEqual(serverNonce) || BinaryPrimitives.ReadInt64BigEndian(frame[60..]) != timestamp) return false;
                Span<byte> mac = stackalloc byte[32]; HMACSHA256.HashData(key, frame[..68], mac);
                bool valid = CryptographicOperations.FixedTimeEquals(mac, frame[68..]);
                if(valid)Interlocked.Exchange(ref lastRead,Environment.TickCount64);
                return valid;
            }
        }
        bool Offer(byte[] frame, StreamFlowPolicy? policy)
        {
            if (remote != null || stage != 0 || frame[5] != 1 || frame[6] != 0 || frame.AsSpan(44, 16).IndexOfAnyExcept((byte)0) >= 0) return false;
            long issued = BinaryPrimitives.ReadInt64BigEndian(frame.AsSpan(60));
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (issued < now - 30 || issued > now + 30) return false;
            if (policy is not { Enabled: true } || frame[25] != policy.Mesh.Self.Slot || !SetIdentity(policy.Mesh, frame[24])) return false;
            clientNonce = frame.AsSpan(28, 16).ToArray(); timestamp = issued;
            if (!Valid(frame, 1) || owner.flowGroups.Count >= 16 || !owner.flowGroups.TryAdd(GroupId, this)) return false;
            BindIdentity();
            RandomNumberGenerator.Fill(serverNonce); stage = 2; confirmationDeadline=Environment.TickCount64+8000;EnqueueControl(Control(2)); return true;
        }

        bool HandleControl(byte[] frame)
        {
            if (!IsControl(frame)) return false;
            // Never acquire the shared listener guard while holding a session
            // guard: route retirement can concurrently enter the mesh router.
            var policy = frame[5] == 1 && remote == null ? owner.flowPolicy(Convert.ToHexString(frame.AsSpan(8, 16)).ToLowerInvariant()) : null;
            lock (gate) {
                if (disposed) return true;
                if (frame[5] == 1) { Offer(frame, policy); return true; }
                if (remote != null && stage == 1 && frame[5] == 2) {
                    // The challenge supplies the server's fresh group nonce.
                    serverNonce = frame.AsSpan(44, 16).ToArray();
                    if (Valid(frame, 2)) { stage = 3; confirmationDeadline=Environment.TickCount64+8000;EnqueueControl(Control(3)); }
                    else Array.Clear(serverNonce);
                    return true;
                }
                if (remote == null && stage == 2 && Valid(frame, 3)) { negotiated = true; stage = 4; EnqueueControl(Control(4)); return true; }
                if (remote != null && stage == 3 && Valid(frame, 4)) {
                    negotiated = true; stage = 4;
                    laneTasks.Add(OpenLanes()); return true;
                }
                if (!negotiated) return true;
                if (Valid(frame, 7)) {
                    if (!fenceSent && Ready()) BeginFence();
                    EnqueueControl(Control(8)); return true;
                }
                if (fenceSent && Valid(frame, 8)) {
                    active = true; holding = false; FlushHeld(); return true;
                }
                int lane = frame[6];
                if (lane is 2 or 3 && Valid(frame, 9, lane)) {
                    Suspend(lane); EnqueueControl(Control(10, lane)); ResumeFallback(lane); return true;
                }
                if (lane is 2 or 3 && suspended[lane] && Valid(frame, 10, lane)) { ResumeFallback(lane); return true; }
                return true;
            }
        }
        bool Ready() => wires[2] != null && wires[3] != null && !suspended[2] && !suspended[3];
        void BeginFence()
        {
            // The marker is FIFO behind the old primary traffic. New business
            // waits until the peer has delivered everything before the marker.
            holding = fenceSent = true; fenceDeadline=Environment.TickCount64+8000;EnqueueControl(Control(7));
        }
        public bool Attach(int lane, byte[] frame)
        {
            lock (gate) {
                if (!negotiated || lane is not (2 or 3) || claimed[lane] || !Valid(frame, 5, lane)) return false;
                claimed[lane] = true; return true;
            }
        }
        public bool CurrentPolicy()
        {
            var policy = owner.flowPolicy(Network);
            if (policy is not { Enabled: true } || policy.Mesh.Self.Slot != LocalSlot) return false;
            var member = policy.Mesh.Directory?.Members.FirstOrDefault(m => m.Slot == RemoteSlot); if (member == null) return false;
            byte[] shared = MeshIdentity.SharedKey(policy.Mesh, member);
            byte[] current = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, info: Encoding.ASCII.GetBytes($"conwu-stream-flow-v1/{Network}/{owner.mesh.Pair.Mode}/{Math.Min(LocalSlot, RemoteSlot)}/{Math.Max(LocalSlot, RemoteSlot)}"));
            try { lock (gate) return !disposed && key != null && CryptographicOperations.FixedTimeEquals(current, key); }
            finally { CryptographicOperations.ZeroMemory(shared); CryptographicOperations.ZeroMemory(current); }
        }
        async Task OpenLanes()
        {
            var opening = new[] { Open(2), Open(3) };
            lock (gate) laneTasks.AddRange(opening);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stop.Token); deadline.CancelAfter(8000);
            try {
                while (!deadline.IsCancellationRequested) {
                    lock (gate) { if (Ready()) { if (!fenceSent) BeginFence(); return; } if(suspended[2]||suspended[3])return; }
                    await Task.Delay(20, deadline.Token);
                }
            } catch (OperationCanceledException) { }
            finally {
                // A failed auxiliary never takes down the healthy primary.
                lock (gate) if (!active && !fenceSent) { foreach (int i in new[] { 2, 3 }) { suspended[i] = true; fallback[i] = true; wires[i]?.Dispose(); } }
            }
            async Task Open(int lane) {
                try { await owner.ConnectLane(this, lane, remote!.Value, stop.Token); }
                catch (Exception ex) when (ex is TimeoutException or IOException or System.Security.Authentication.AuthenticationException or SocketException or OperationCanceledException or WebSocketException or ObjectDisposedException) { FailLane(lane); }
            }
        }

        public async Task RunLane(int lane, StreamFlowWire wire, CancellationToken outer)
        {
            lock (gate) {
                if (disposed || suspended[lane] || wires[lane] != null) throw new IOException("分流通道已关闭或重复");
                wires[lane] = wire;
            }
            using var token = CancellationTokenSource.CreateLinkedTokenSource(stop.Token, outer);
            var tasks = new[] { Write(lane, wire, token.Token), Read(wire, lane, token.Token) };
            try { await await Task.WhenAny(tasks); }
            finally {
                token.Cancel(); wire.Dispose(); FailLane(lane);
                try { await Task.WhenAll(tasks); } catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or WebSocketException or ObjectDisposedException) { }
            }
        }
        void FailLane(int lane)
        {
            lock (gate) {
                if (disposed || stop.IsCancellationRequested || fallback[lane] || suspended[lane]) return;
                Suspend(lane);
                if (negotiated) EnqueueControl(Control(9, lane)); else ResumeFallback(lane);
            }
        }
        void Suspend(int lane)
        {
            if (suspended[lane]) return;
            suspended[lane] = true; suspendedAt[lane]=Environment.TickCount64;wires[lane]?.Dispose(); wires[lane] = null;
            while (queued[lane].TryDequeue(out var frame)) { signals[lane].Wait(0); held[lane].Enqueue(frame); }
        }
        void ResumeFallback(int lane)
        {
            fallback[lane] = true;
            while (held[lane].TryDequeue(out var frame)) Queue(0, frame);
        }
        void FlushHeld()
        {
            for (int lane = 1; lane <= 3; lane++)
                while (held[lane].TryDequeue(out var frame)) Queue(lane == 1 || fallback[lane] ? 0 : lane, frame);
        }
        void Queue(int wire, byte[] packet) { queued[wire].Enqueue(packet); signals[wire].Release(); }
        void EnqueueControl(byte[] packet)
        {
            if (disposed || bytes + packet.Length > QueueBudget) return;
            bytes += packet.Length; laneBytes[0] += packet.Length; Queue(0, packet);
        }
        static int PacketLane(ReadOnlySpan<byte> packet)
        {
            if (PairNetworkFrame.IsFrame(packet) && packet.Length >= 20 + MeshLink.Overhead && packet.Slice(20, 4).SequenceEqual("SLM4"u8) && packet[24] == 4 && packet[27] is >= 1 and <= 3) return packet[27];
            return 0;
        }
        public bool TrySend(ReadOnlySpan<byte> packet, IPEndPoint? sender = null)
        {
            lock (gate) {
                if (disposed || packet.Length is < 1 or > MaximumDatagram) return false;
                if (fixedReceiver == null && sender != null) {
                    receiver ??= sender;
                    if (!sender.Equals(receiver)) return false;
                }
                return EnqueuePacket(packet.ToArray());
            }
        }
        bool EnqueuePacket(byte[] packet)
        {
            int lane = PacketLane(packet);
            // Original lane-zero business remains bulk, not control.
            bool business = lane != 0 || PairNetworkFrame.IsFrame(packet) && packet.Length > 24 && packet[24] == 4;
            int budget = business ? QueueBudget - ControlReserve : QueueBudget;
            if (bytes + packet.Length > budget || business && lane == 3 && laneBytes[3] + packet.Length > BulkLimit) { rejected++; return false; }
            bytes += packet.Length; laneBytes[lane] += packet.Length;
            if (lane != 0 && (holding || suspended[lane] && !fallback[lane])) held[lane].Enqueue(packet);
            else Queue(active && lane >= 2 && !fallback[lane] ? lane : 0, packet);
            return true;
        }
        public bool SendPacket(ReadOnlySpan<byte> packet, MeshLink link, IPEndPoint sender, out byte[]? encoded)
        {
            lock (gate) {
                encoded = disposed ? null : negotiated ? link.StreamData(packet, StreamFlowClassifier.Lane(packet)) : link.Data(packet);
                if (encoded == null) return false;
                if (fixedReceiver == null) { receiver ??= sender; if (!sender.Equals(receiver)) return false; }
                return EnqueuePacket(PairNetworkFrame.Wrap(Network, encoded));
            }
        }
        async Task Write(int lane, StreamFlowWire wire, CancellationToken token)
        {
            while (!token.IsCancellationRequested) {
                await signals[lane].WaitAsync(token);
                var batch = new List<byte[]>(wire.BatchSize); int size = 0;
                lock (gate) {
                    if (!queued[lane].TryDequeue(out var first)) continue;
                    Add(first);
                    while (batch.Count < wire.BatchSize && queued[lane].TryPeek(out var next) && size + next.Length + 2 <= MaximumBatchBytes && signals[lane].Wait(0)) { queued[lane].Dequeue(); Add(next); }
                }
                await wire.Write(batch, token);
                void Add(byte[] packet) { batch.Add(packet); size += packet.Length + 2; bytes -= packet.Length; laneBytes[PacketLane(packet)] -= packet.Length; }
            }
        }
        async Task Read(StreamFlowWire wire, int lane, CancellationToken token)
        {
            while (!token.IsCancellationRequested) {
                byte[] packet = await wire.Read(token);
                if (lane == 0 && HandleControl(packet)) continue;
                if (verified && (!PairNetworkFrame.IsFrame(packet) || PairNetworkFrame.Network(packet) != Network)) continue;
                if (lane == 0) Inspect(packet);
                Interlocked.Exchange(ref lastRead, Environment.TickCount64);
                Deliver(packet,lane);
            }
        }
        void Deliver(byte[] packet,int lane)
        {
            // Retire/ACK and local delivery share this guard. A nonblocking
            // send completes before an auxiliary can be retired; an old read
            // cannot slip past its retirement ACK and overtake fallback data.
            lock(gate){
                if(disposed||lane!=0&&(suspended[lane]||PacketLane(packet)!=lane)||receiver==null)return;
                try { if(udp.SendTo(packet,SocketFlags.None,receiver)!=packet.Length)receiveRejected++; }
                catch(SocketException ex)when(ex.SocketErrorCode is SocketError.WouldBlock or SocketError.NoBufferSpaceAvailable or SocketError.TimedOut or SocketError.ConnectionReset or SocketError.ConnectionRefused){receiveRejected++;}
            }
        }
        async Task FromLocal()
        {
            byte[] buffer = new byte[MaximumDatagram + 1]; EndPoint any = new IPEndPoint(IPAddress.Loopback, 0);
            while (!stop.IsCancellationRequested) {
                var incoming = await udp.ReceiveFromAsync(buffer, SocketFlags.None, any, stop.Token);
                if (incoming.ReceivedBytes is < 1 or > MaximumDatagram || incoming.RemoteEndPoint is not IPEndPoint sender || !IPAddress.IsLoopback(sender.Address) || fixedReceiver != null && !sender.Equals(fixedReceiver)) continue;
                receiver ??= sender;
                if (sender.Equals(receiver)) TrySend(buffer.AsSpan(0, incoming.ReceivedBytes));
            }
        }
        async Task Watch()
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
            while (await timer.WaitForNextTickAsync(stop.Token)) {
                long now=Environment.TickCount64;
                if (now - Interlocked.Read(ref lastRead) > 20000) throw new IOException("TCP 对端长时间未回应");
                lock(gate) {
                    if((stage is 2 or 3)&&now>confirmationDeadline||holding&&now>fenceDeadline||Enumerable.Range(2,2).Any(i=>suspended[i]&&!fallback[i]&&now-suspendedAt[i]>8000))
                        throw new IOException("TCP 分流控制确认超时，重新建立连接");
                }
            }
        }
        public async Task Run(byte[]? first)
        {
            owner.RouteOpened?.Invoke(endpoint);
            if (first != null) {
                if (!HandleControl(first)) { Inspect(first); Deliver(first,0); }
            }
            var pumps = new[] { FromLocal(), Write(0, primary, stop.Token), Read(primary, 0, stop.Token), Watch() };
            try { await await Task.WhenAny(pumps); }
            finally {
                Dispose();
                try { await Task.WhenAll(pumps); } catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or WebSocketException or ObjectDisposedException) { }
                Task[] pending; lock (gate) pending = laneTasks.ToArray();
                try { await Task.WhenAll(pending); } catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or WebSocketException or ObjectDisposedException) { }
                stop.Dispose(); foreach (var signal in signals) signal.Dispose();
            }
        }
        public void Dispose()
        {
            lock (gate) {
                if (disposed) return; disposed = true; stop.Cancel(); primary.Dispose();
                foreach (var wire in wires) wire?.Dispose();
                if (owner.flowGroups.TryGetValue(GroupId, out var value) && ReferenceEquals(value, this)) owner.flowGroups.TryRemove(GroupId, out _);
                StreamFlowRoutes.Unregister(this); if (key != null) CryptographicOperations.ZeroMemory(key);
                foreach (var queue in queued.Concat(held)) queue.Clear();
            }
            owner.RouteClosed?.Invoke(endpoint);
        }
    }
}
