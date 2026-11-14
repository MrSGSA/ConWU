using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using StreamLink.Core;
using StreamLink.EndpointPoc;

static class TcpMappingMaintenanceTests
{
    internal static async Task Run(Action<bool, string> check)
    {
        void Check(bool ok, string why) { check(ok, why); Console.WriteLine("PASS " + why); }
        var clock = new Clock(); var policy = new TcpHelperRecovery(clock);
        string[] names = ["first:3478", "second:3478"];
        policy.Failed(names[0]);
        Check(policy.Candidates(names, names[0]).SequenceEqual([names[1]]), "failed helper is excluded while another configured reflector is available");
        Check(policy.Candidates([names[0]], names[0]).SequenceEqual([names[0]]), "single-server configuration has no invented fallback");
        clock.Ms = 300001;
        Check(policy.Candidates(names, names[0]).SequenceEqual(names), "failed reflector becomes eligible after the bounded five-minute cooldown");
        Check(TcpMapping.HelperFailure(new EndOfStreamException()) == "RemoteClosed" &&
            TcpMapping.HelperFailure(new IOException("unused", new SocketException(10054))) == "Socket:ConnectionReset",
            "helper log distinguishes remote close/reset from a query deadline without payload or credentials");
        Check(TcpMapping.LocalSourcePresent(IPAddress.Loopback) && !TcpMapping.LocalSourcePresent(IPAddress.Parse("192.0.2.254")),
            "helper recovery distinguishes a present Windows source address from a removed one");

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(110)); var token = timeout.Token;
        async Task Until(Func<bool> ready, int milliseconds = 4000) {
            var elapsed = Stopwatch.StartNew();
            while (!ready()) { if (elapsed.ElapsedMilliseconds > milliseconds) throw new TimeoutException("mapping recovery did not reach expected state"); await Task.Delay(20, token); }
        }
        await using var shortLived = new Reflector { CloseAfterResponses = 1 };
        await using var stable = new Reflector();
        string first = shortLived.Endpoint.ToString(), second = stable.Endpoint.ToString();
        using var free = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        free.Bind(new IPEndPoint(IPAddress.Loopback, 0)); int port = ((IPEndPoint)free.LocalEndPoint!).Port; free.Dispose();
        var (binding, observed) = await TcpBinding.Connect(port, IPAddress.Loopback, _ => { }, token, [first]);
        var rule = new RouterMapping(port, port == 40000 ? 40001 : 40000, "127.0.0.1", "TCP", "StreamLink-fixture");
        await using var gateway = new Gateway(rule);
        var logs = new ConcurrentQueue<string>();
        await using var mapping = new TcpMapping(new(gateway.Service), rule, binding, observed, logs.Enqueue, [first, second]);
        var maintaining = mapping.Maintain(token); mapping.RequestRefresh();
        await Until(() => mapping.HelperObservation == null);
        Check(!mapping.IsValid && gateway.Deletes == 0 && !maintaining.IsCompleted,
            "lost outer observation withdraws the candidate while preserving the owned UPnP rule and maintenance");
        await Until(() => mapping.HelperResource.Server == second && mapping.IsValid, 14000);
        var held = mapping.HelperResource;
        Check(shortLived.Accepted == 1 && stable.Accepted == 1 && gateway.Deletes == 0,
            "actual failed helper selects another configured server on the same fixed source port");
        // Cross both the old one-minute symptom and a genuine UPnP renewal.
        await Until(() => gateway.Adds == 1 && stable.Requests >= 6, 67000);
        Check(mapping.HelperResource.LeaseId == held.LeaseId && stable.Accepted == 1 &&
            mapping.HelperResource.Local == held.Local && mapping.IsValid && gateway.Deletes == 0,
            "sixty-second UPnP renewal and repeated STUN pulses preserve the same healthy helper identity and source");
        Console.WriteLine("PROGRESS stable helper crossed a real 60-second lease renewal");
        await shortLived.DisposeAsync(); await stable.DisposeAsync(); mapping.RequestRefresh();
        await Until(() => mapping.HelperObservation == null);
        await Until(() => logs.Count(l => l.StartsWith("STUN 辅助观察暂不可用")) >= 3, 20000);
        Check(!maintaining.IsCompleted && !mapping.IsValid && gateway.Deletes == 0,
            "failed reconnection to every configured server does not remove the owned rule or stop mapping maintenance");
        await mapping.DisposeAsync();
        Check(gateway.Deletes == 1 && mapping.HelperResource.Closed,
            "explicit mapping stop still removes exactly its own rule and releases the final helper");
    }
    sealed class Clock : TimeProvider
    {
        public long Ms;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Ms;
    }
    sealed class Gateway(RouterMapping rule) : IAsyncDisposable
    {
        readonly TcpListener listener = new(IPAddress.Loopback, 0);
        readonly CancellationTokenSource stop = new();
        Task? running; public int Adds, Deletes;
        public RouterService Service {
            get {
                listener.Start(); running ??= Serve();
                return new(new Uri($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/control"),
                    "urn:schemas-upnp-org:service:WANIPConnection:1", IPAddress.Loopback);
            }
        }
        async Task Serve()
        {
            try {
                while (true) {
                    using var socket = await listener.AcceptTcpClientAsync(stop.Token);
                    using var stream = socket.GetStream(); using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                    await reader.ReadLineAsync(stop.Token); string action = ""; int length = 0;
                    while (await reader.ReadLineAsync(stop.Token) is { Length: > 0 } line) {
                        if (line.StartsWith("SOAPAction:", StringComparison.OrdinalIgnoreCase)) action = line;
                        if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)) length = int.Parse(line[15..]);
                    }
                    char[] body = new char[length];
                    if (await reader.ReadBlockAsync(body.AsMemory(), stop.Token) != length) throw new EndOfStreamException();
                    string xml;
                    if (action.Contains("GetSpecificPortMappingEntry")) xml = $"<root><NewInternalPort>{rule.InternalPort}</NewInternalPort><NewInternalClient>{rule.InternalClient}</NewInternalClient><NewPortMappingDescription>{rule.Description}</NewPortMappingDescription></root>";
                    else if (action.Contains("AddPortMapping")) { Interlocked.Increment(ref Adds); xml = "<root/>"; }
                    else if (action.Contains("DeletePortMapping")) { Interlocked.Increment(ref Deletes); xml = "<root/>"; }
                    else throw new IOException("unexpected fixture action");
                    byte[] response = Encoding.UTF8.GetBytes(xml);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), stop.Token);
                    await stream.WriteAsync(response, stop.Token);
                }
            } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); if (running != null) await running; stop.Dispose(); }
    }
}
