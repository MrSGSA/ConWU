using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Collections.Concurrent;
using StreamLink.Core;

int checks = 0;
void Check(bool ok, string message) { if (!ok) throw new Exception(message); checks++; }
string Descriptor(string control = "/control") => $"<root><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>{control}</controlURL></service></serviceList></device></root>";

// All discovery and description traffic stays on loopback. Multicast notice
// tests use an isolated port, loopback interface and TTL=0; no live gateway,
// adapter, driver, profile or firewall mutation takes place.
await using (var gateway = new Gateway())
{
    gateway.Documents["/good.xml"] = Descriptor();
    gateway.Locations = ["/good.xml"];
    var clock = Stopwatch.StartNew();
    await using var scan = Upnp.DiscoverServices(IPAddress.Loopback, gateway.SearchAddress, TimeSpan.FromSeconds(30), CancellationToken.None).GetAsyncEnumerator();
    Check(await scan.MoveNextAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(3)), "Valid gateway was held until search window ended");
    Check(scan.Current.ControlUrl.AbsolutePath == "/control", "Wrong control service returned");
    Console.WriteLine($"First usable gateway received in {clock.Elapsed.TotalMilliseconds:F0} ms; simulated SSDP window is 30000 ms.");
    await scan.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
    Check(clock.Elapsed < TimeSpan.FromSeconds(5), "Early-stop cleanup waited for the remaining search window");
}

await using (var gateway = new Gateway())
{
    gateway.Documents["/bad.xml"] = "not XML";
    gateway.Documents["/foreign.xml"] = Descriptor("http://127.0.0.2/control");
    gateway.Documents["/good.xml"] = Descriptor("/good-control");
    gateway.Locations = ["http://127.0.0.2/never.xml", "/bad.xml", "/foreign.xml", "/good.xml", "/good.xml"];
    var found = new List<RouterService>();
    await foreach (var service in Upnp.DiscoverServices(IPAddress.Loopback, gateway.SearchAddress, TimeSpan.FromMilliseconds(300), CancellationToken.None)) found.Add(service);
    Check(found.Count == 1 && found[0].ControlUrl.AbsolutePath == "/good-control", "Malformed/foreign descriptors blocked fallback or duplicate service was yielded");
    Check(gateway.Hits.GetValueOrDefault("/good.xml") == 1, "Duplicate SSDP location was fetched again");
    Check(!gateway.Hits.ContainsKey("/never.xml"), "Foreign SSDP location accepted");
}

await using (var gateway = new Gateway())
{
    gateway.Documents["/one.xml"] = Descriptor("/one");
    gateway.Documents["/two.xml"] = Descriptor("/two");
    gateway.Locations = ["/one.xml", "/two.xml"];
    await using var scan = Upnp.DiscoverServices(IPAddress.Loopback, gateway.SearchAddress, TimeSpan.FromMilliseconds(250), CancellationToken.None).GetAsyncEnumerator();
    Check(await scan.MoveNextAsync(), "First candidate absent");
    // A mapping attempt can fail after SSDP expires. Responses arriving during
    // that attempt must remain available to try the next gateway.
    await Task.Delay(350);
    Check(await scan.MoveNextAsync() && scan.Current.ControlUrl.AbsolutePath == "/two", "Slow first mapping attempt lost the second candidate");
    Check(!await scan.MoveNextAsync(), "Discovery did not finish after exhausting responses");
}

await using (var gateway = new Gateway())
using (var stop = new CancellationTokenSource(100))
{
    gateway.Locations = [];
    await using var scan = Upnp.DiscoverServices(IPAddress.Loopback, gateway.SearchAddress, TimeSpan.FromSeconds(30), stop.Token).GetAsyncEnumerator();
    bool canceled = false;
    try { await scan.MoveNextAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2)); } catch (OperationCanceledException) { canceled = true; }
    Check(canceled, "Discovery swallowed caller cancellation");
}
if (args.Length == 1)
{
    string executable = Path.GetFullPath(args[0]);
    string folder = Path.Combine(Path.GetTempPath(), "streamlink-config-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(folder);
    try
    {
        var ticket = Invitation.Create("203.0.113.1:1234", "faketcp", "test.ustc.edu.cn");
        foreach (bool host in new[] { true, false })
        {
            int slot = host ? 1 : 2;
            string config = NetworkConfiguration.Create(ticket, Guid.NewGuid().ToString("N"), slot, $"10.231.199.{slot}", host, 42780);
            string path = Path.Combine(folder, host ? "host.toml" : "guest.toml"); await File.WriteAllTextAsync(path, config);
            var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string name in info.Environment.Keys.Where(k => k.StartsWith("ET_", StringComparison.Ordinal)).ToArray()) info.Environment.Remove(name);
            foreach (string arg in new[] { "--check-config", "--config-file", path, "--disable-env-parsing" }) info.ArgumentList.Add(arg);
            using var child = Process.Start(info)!;
            try
            {
                Task<string> stdout = child.StandardOutput.ReadToEndAsync(), stderr = child.StandardError.ReadToEndAsync();
                await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); await Task.WhenAll(stdout, stderr);
                Check(child.ExitCode == 0, "Bundled EasyTier rejected generated configuration");
            }
            finally { if (!child.HasExited) child.Kill(); }
        }
        Check(NetworkConfiguration.AdapterName(ticket, 1) != NetworkConfiguration.AdapterName(ticket, 2), "Slot adapter identities collide");
        // Files contain only newly generated test credentials; delete exact paths.
    }
    finally { foreach (string file in new[] { "host.toml", "guest.toml" }) File.Delete(Path.Combine(folder, file)); Directory.Delete(folder); }
}
await PortControlTests.Run(Check);
Console.WriteLine($"PASS {checks}: streaming UPnP discovery and bounded PCP/NAT-PMP wire protocols, ownership, renewal, epoch, cancellation, product TCP mapping. Loopback only; no live router/adapter changes.");

sealed class Gateway : IAsyncDisposable
{
    readonly CancellationTokenSource stop = new();
    readonly UdpClient search = new(new IPEndPoint(IPAddress.Loopback, 0));
    readonly TcpListener http = new(IPAddress.Loopback, 0);
    readonly Task searchTask, httpTask;
    public ConcurrentDictionary<string, string> Documents { get; } = new();
    public ConcurrentDictionary<string, int> Hits { get; } = new();
    public string[] Locations { get; set; } = [];
    public IPEndPoint SearchAddress => (IPEndPoint)search.Client.LocalEndPoint!;
    public Gateway() { http.Start(); searchTask = Search(); httpTask = Http(); }
    async Task Search()
    {
        var request = await search.ReceiveAsync(stop.Token);
        foreach (string location in Locations)
        {
            string uri = location.StartsWith('/') ? $"http://127.0.0.1:{((IPEndPoint)http.LocalEndpoint).Port}{location}" : location;
            await search.SendAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nLOCATION: {uri}\r\n\r\n"), request.RemoteEndPoint, stop.Token);
        }
    }
    async Task Http()
    {
        while (!stop.IsCancellationRequested)
        {
            using var client = await http.AcceptTcpClientAsync(stop.Token);
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            string first = await reader.ReadLineAsync(stop.Token) ?? "";
            while (await reader.ReadLineAsync(stop.Token) is { Length: > 0 }) { }
            string path = first.Split(' ')[1]; Hits.AddOrUpdate(path, 1, (_, count) => count + 1);
            byte[] body = Encoding.UTF8.GetBytes(Documents.GetValueOrDefault(path, "invalid"));
            byte[] header = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(header, stop.Token); await stream.WriteAsync(body, stop.Token);
        }
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel();
        try { await Task.WhenAll(searchTask, httpTask); } catch (OperationCanceledException) { }
        search.Dispose(); http.Stop(); stop.Dispose();
    }
}
