using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

static class StreamMappingRecoveryChecks
{
    internal sealed class Reflector : IAsyncDisposable
    {
        readonly TcpListener listener = new(IPAddress.Loopback, 0);
        readonly CancellationTokenSource stop = new();
        readonly ConcurrentBag<Task> peers = [];
        readonly Task accepting;
        public readonly ConcurrentBag<int> SourcePorts = [];
        public readonly TaskCompletionSource Withheld = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Requests, Mode, ExternalPort, Active;
        public string Address => listener.LocalEndpoint.ToString()!;

        public Reflector(int externalPort)
        {
            ExternalPort = externalPort;
            listener.Start();
            accepting = Accept();
        }
        async Task Accept()
        {
            try {
                while (true) {
                    var client = await listener.AcceptTcpClientAsync(stop.Token);
                    SourcePorts.Add(((IPEndPoint)client.Client.RemoteEndPoint!).Port);
                    peers.Add(Serve(client));
                }
            } catch (Exception error) when (stop.IsCancellationRequested && error is OperationCanceledException or SocketException or ObjectDisposedException) { }
        }
        async Task Serve(TcpClient client)
        {
            Interlocked.Increment(ref Active);
            try {using (client) {
                var stream = client.GetStream();
                try {
                    while (true) {
                        byte[] request = new byte[20];
                        await stream.ReadExactlyAsync(request, stop.Token);
                        Interlocked.Increment(ref Requests);
                        switch (Volatile.Read(ref Mode)) {
                            case 1: return;
                            case 2:
                                Withheld.TrySetResult();
                                // Withhold the reply but observe a losing
                                // client's close instead of retaining it until
                                // the whole fixture is stopped.
                                await stream.ReadExactlyAsync(new byte[1], stop.Token);
                                return;
                        }
                        byte[] response = new byte[32];
                        request.CopyTo(response, 0);
                        response[0] = 1; response[1] = 1; response[3] = 12;
                        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(20), 0x20);
                        response[23] = 8; response[25] = 1;
                        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(26), (ushort)(Volatile.Read(ref ExternalPort) ^ 0x2112));
                        byte[] address = [203, 0, 113, 20];
                        for (int index = 0; index < address.Length; index++) response[28 + index] = (byte)(address[index] ^ request[4 + index]);
                        if (Volatile.Read(ref Mode) == 3 || Volatile.Read(ref Mode) == 4 && Volatile.Read(ref Requests) >= 2) response[8] ^= 1;
                        await stream.WriteAsync(response, stop.Token);
                    }
                } catch (Exception error) when (error is IOException or SocketException or OperationCanceledException) { }
            }}finally{Interlocked.Decrement(ref Active);}
        }
        public async ValueTask DisposeAsync()
        {
            stop.Cancel();
            listener.Stop();
            await accepting;
            await Task.WhenAll(peers);
            stop.Dispose();
        }
    }

    public static async Task Run(Action<bool, string> check)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        var token = deadline.Token;
        await using var first = new Reflector(48000);
        await using var backup = new Reflector(48001);
        using var sink = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var application = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int port = FreePort();
        var profile = MeshIdentity.Create("", "", "tcp", direct: true);
        await using var listener = new StreamMeshTransport(profile, (IPEndPoint)sink.Client.LocalEndPoint!, true, port);
        await using var client = new StreamMeshTransport(profile, new(IPAddress.Loopback, port), false, 0);

        async Task<bool> RoundTrip()
        {
            byte[] data = RandomNumberGenerator.GetBytes(1280);
            await application.SendAsync(data, client.ClientEndpoint!, token);
            var incoming = await sink.ReceiveAsync(token);
            await sink.SendAsync(incoming.Buffer, incoming.RemoteEndPoint, token);
            return (await application.ReceiveAsync(token)).Buffer.SequenceEqual(data);
        }

        await using (var mapping = await StreamMapping.Create(port, _ => { }, token,
            [first.Address, backup.Address], false, new(false, TimeSpan.FromMilliseconds(75)))) {
            var maintaining = mapping.Maintain(token);
            var replaced = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
            bool validAtChange = false;
            mapping.Changed += endpoint => { validAtChange = mapping.IsValid; replaced.TrySetResult(endpoint); };
            check(await RoundTrip(), "TCP business traffic is established before reflector recovery");
            Volatile.Write(ref first.Mode, 1);
            await Until(() => !mapping.IsValid, token);
            check(!maintaining.IsCompleted && !listener.Exited && await RoundTrip(),
                "a closed TCP STUN flow invalidates its candidate while the mapping owner, listener and existing connection continue");
            var endpoint = await replaced.Task.WaitAsync(TimeSpan.FromSeconds(9), token);
            check(endpoint.Port == 48001 && mapping.IsValid && validAtChange && ((StreamMapping)mapping).StunServer == backup.Address,
                "TCP reflection recovers automatically through a configured backup and publishes a validated replacement candidate");
            check(first.SourcePorts.Concat(backup.SourcePorts).All(source => source == port),
                "reflector recovery retains the receiver's exact local source port");
            int failedRequests = Volatile.Read(ref first.Requests), backupRequests = Volatile.Read(ref backup.Requests);
            await Until(() => Volatile.Read(ref backup.Requests) >= backupRequests + 2, token);
            check(Volatile.Read(ref first.Requests) == failedRequests && await RoundTrip(),
                "healthy TCP STUN maintenance keeps its selected server and the existing business connection");
            Volatile.Write(ref backup.Mode, 2);
            await backup.Withheld.Task.WaitAsync(TimeSpan.FromSeconds(2), token);
            await mapping.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2), token);
            try { await maintaining; } catch (OperationCanceledException) { }
            check(!mapping.IsValid && !listener.Exited && await RoundTrip(),
                "disposal cancels a blocked reflection read promptly and preserves the separate TCP listener and connection");
            ((IMappingRefresh)mapping).RequestRefresh();
            bool refused = false;
            try { _ = mapping.Maintain(token); } catch (ObjectDisposedException) { refused = true; }
            check(refused, "a disposed TCP mapping refuses new maintenance and safely ignores refresh hints");
        }

        Volatile.Write(ref first.Mode, 0);
        await using (var mapping = await StreamMapping.Create(port, _ => { }, token, [first.Address], false,
            new(false, TimeSpan.FromMinutes(10)))) {
            var maintaining = mapping.Maintain(token);
            Volatile.Write(ref first.Mode, 3);
            ((IMappingRefresh)mapping).RequestRefresh();
            await Until(() => !mapping.IsValid, token);
            check(!maintaining.IsCompleted, "a STUN transaction mismatch withdraws only its candidate and schedules recovery");
            Volatile.Write(ref first.Mode, 0);
            Volatile.Write(ref first.ExternalPort, 48002);
            ((IMappingRefresh)mapping).RequestRefresh();
            await Until(() => mapping.IsValid, token);
            check(mapping.PublicEndpoint.Port == 48002 && ((StreamMapping)mapping).StunServer == first.Address,
                "a refresh hint promptly retries a sole configured STUN server without requiring another discovery host");
        }
        await RunnerPublication(check, token);
    }

    sealed class RecoverableMapping : IMapping
    {
        readonly TaskCompletionSource maintenance = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public volatile bool Valid = true;
        public bool IsValid => Valid;
        public IPAddress LocalAddress { get; init; } = IPAddress.Loopback;
        public IPEndPoint PublicEndpoint { get; set; } = new(IPAddress.Parse("203.0.113.20"), 48000);
        public event Action<IPEndPoint>? Changed { add { } remove { } }
        public Task Maintain(CancellationToken token) => maintenance.Task.WaitAsync(token);
        public void Fail() { Valid = false; maintenance.TrySetException(new IOException("source address changed")); }
        public ValueTask DisposeAsync() { Valid = false; maintenance.TrySetCanceled(); return ValueTask.CompletedTask; }
    }
    sealed class Receiver : IMeshTransport
    {
        public IPEndPoint? ClientEndpoint => null;
        public bool Exited { get; private set; }
        public void Dispose() => Exited = true;
    }
    static async Task RunnerPublication(Action<bool, string> check, CancellationToken token)
    {
        var mesh = MeshIdentity.Create("", "", "tcp", direct: true);
        var profile = new DeviceProfile { Mesh = mesh, ListenPort = 48110, SourcePort = 48111 };
        profile.SelectTransport("tcp-only");
        var mapping = new RecoverableMapping();
        var replacement = new RecoverableMapping { LocalAddress = IPAddress.Parse("127.0.0.2") };
        var receiver = new Receiver();
        int probes = 0, adapters = 0, listeners = 0;
        string folder = Path.Combine(Path.GetTempPath(), "conwu-stream-publication-" + Guid.NewGuid().ToString("N"));
        Task<IPacketAdapter> OpenAdapter()
        {
            Interlocked.Increment(ref adapters);
            return Task.FromResult<IPacketAdapter>(new MemoryAdapter());
        }
        var services = new MeshRuntimeServices(m => new DirectMeshDiscovery(m), _ => OpenAdapter(), (_, _, _) => {
            return Task.FromResult<IMapping>(Interlocked.Increment(ref probes) == 1 ? mapping : replacement);
        }, _ => {
            Interlocked.Increment(ref listeners);
            return receiver;
        }, (_, _, stop) => Task.Delay(Timeout.Infinite, stop), (_, _, _) => { }, (_, _) => { }, folder) {
            NetworkWake = () => new MeshNetworkWake(false),
            ProfileAdapter = (_, _, _) => OpenAdapter()
        };
        var runner = new MeshRunner(profile, _ => { }, _ => { }, _ => { }, _ => { }, services);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var running = runner.Run(cancellation.Token);
        try {
            await Until(() => runner.PreparedInvitationEntries.Length == 1, token);
            mapping.Valid = false;
            await Until(() => runner.PreparedInvitationEntries.Length == 0, token);
            check(runner.EntryPreparation.Endpoint.Length == 0 && !receiver.Exited && probes == 1 && adapters == 1 && listeners == 1,
                "the production runner withdraws a temporarily invalid invitation candidate while retaining its mapping, receiver and adapter");
            mapping.PublicEndpoint = new(IPAddress.Parse("203.0.113.20"), 48002);
            mapping.Valid = true;
            await Until(() => runner.PreparedInvitationEntries.FirstOrDefault()?.Source == mapping.PublicEndpoint.ToString(), token);
            check(runner.EntryPreparation.Endpoint == mapping.PublicEndpoint.ToString() && !receiver.Exited && probes == 1 && adapters == 1 && listeners == 1,
                "the production runner republishes the recovered invitation and UI candidate through the same retained resources");
            mapping.Fail();
            await Until(() => probes == 2 && runner.PreparedInvitationEntries.FirstOrDefault()?.Source == replacement.PublicEndpoint.ToString(), token);
            check(!receiver.Exited && adapters == 1 && listeners == 1,
                "a changed STUN source address preserves the wildcard TCP receiver and its existing accepted connections during mapping replacement");
        } finally {
            cancellation.Cancel();
            try { await running; } catch (OperationCanceledException) { }
            if (Directory.Exists(folder)) {
                foreach (string child in Directory.EnumerateDirectories(folder)) Directory.Delete(child);
                Directory.Delete(folder);
            }
        }
    }

    static async Task Until(Func<bool> ready, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));
        while (!ready()) await Task.Delay(10, deadline.Token);
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
