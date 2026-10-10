using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Channels;

namespace StreamLink.Core;

public sealed record RouterService(Uri ControlUrl, string ServiceType, IPAddress LocalAddress);
public sealed record RouterMapping(int ExternalPort, int InternalPort, string InternalClient, string Protocol, string Description);

public sealed class Upnp : IDisposable
{
    readonly HttpClient http = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(4), MaxResponseContentBufferSize = 256 * 1024 };
    public RouterService Service { get; }
    public Upnp(RouterService service) => Service = service;

    public static async Task<IReadOnlyList<RouterService>> Discover(IPAddress local, CancellationToken token)
    {
        var services = new List<RouterService>();
        await foreach (var service in DiscoverServices(local, token)) services.Add(service);
        return services;
    }

    public static IAsyncEnumerable<RouterService> DiscoverServices(IPAddress local, CancellationToken token) =>
        DiscoverServices(local, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900), TimeSpan.FromMilliseconds(3500), token);

    internal static async IAsyncEnumerable<RouterService> DiscoverServices(IPAddress local, IPEndPoint searchTarget, TimeSpan searchWindow, [EnumeratorCancellation] CancellationToken token)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(local, 0));
        var request = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n");
        await socket.SendToAsync(request, SocketFlags.None, searchTarget, token);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(searchWindow);
        var locations = Channel.CreateUnbounded<Uri>(new() { SingleWriter = true, SingleReader = true });
        async Task ReceiveLocations()
        {
            var seen = new HashSet<Uri>();
            var buffer = new byte[8192];
            try
            {
                while (!timeout.IsCancellationRequested)
                {
                    var response = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), timeout.Token);
                    foreach (var line in Encoding.ASCII.GetString(buffer, 0, response.ReceivedBytes).Split("\r\n"))
                        if (seen.Count < 32 && line.Length <= 2048 && line.StartsWith("location:", StringComparison.OrdinalIgnoreCase)
                            && Uri.TryCreate(line[9..].Trim(), UriKind.Absolute, out var uri) && uri.UserInfo.Length == 0
                            && (uri.Scheme is "http" or "https") && IPAddress.TryParse(uri.Host, out var ip)
                            && ip.Equals(((IPEndPoint)response.RemoteEndPoint).Address) && seen.Add(uri)) locations.Writer.TryWrite(uri);
                }
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
            catch (Exception ex) { locations.Writer.TryComplete(ex); }
            finally { locations.Writer.TryComplete(); }
        }
        // Receive other gateways while fetching a description or trying a lease.
        // A caller can stop at the first working service without waiting for MX.
        Task receiving = ReceiveLocations();
        using var http = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(4), MaxResponseContentBufferSize = 256 * 1024 };
        try
        {
            await foreach (var location in locations.Reader.ReadAllAsync(token))
            {
                XDocument doc;
                try { doc = XDocument.Parse(await http.GetStringAsync(location, token)); }
                catch (Exception ex) when (!token.IsCancellationRequested && ex is HttpRequestException or System.Xml.XmlException or OperationCanceledException) { continue; }
                foreach (var service in doc.Descendants().Where(x => x.Name.LocalName == "service"))
                {
                    string type = service.Elements().FirstOrDefault(x => x.Name.LocalName == "serviceType")?.Value ?? "";
                    string url = service.Elements().FirstOrDefault(x => x.Name.LocalName == "controlURL")?.Value ?? "";
                    if (!(type.Contains(":WANIPConnection:") || type.Contains(":WANPPPConnection:")) || string.IsNullOrWhiteSpace(url)) continue;
                    if (Uri.TryCreate(location, url, out var control) && control.UserInfo.Length == 0
                        && control.Host == location.Host && (control.Scheme is "http" or "https")) yield return new(control, type, local);
                }
            }
            token.ThrowIfCancellationRequested();
        }
        finally { timeout.Cancel(); await receiving; }
    }

    async Task<XDocument> Call(string action, Dictionary<string, string> args, CancellationToken token)
    {
        XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/";
        XNamespace service = Service.ServiceType;
        var body = new XDocument(new XElement(soap + "Envelope", new XAttribute(XNamespace.Xmlns + "s", soap),
            new XAttribute(soap + "encodingStyle", "http://schemas.xmlsoap.org/soap/encoding/"),
            new XElement(soap + "Body", new XElement(service + action, args.Select(p => new XElement(p.Key, p.Value))))));
        using var request = new HttpRequestMessage(HttpMethod.Post, Service.ControlUrl);
        request.Headers.TryAddWithoutValidation("SOAPAction", $"\"{Service.ServiceType}#{action}\"");
        request.Content = new StringContent(body.ToString(SaveOptions.DisableFormatting), Encoding.UTF8, "text/xml");
        using var response = await http.SendAsync(request, token);
        var xml = XDocument.Parse(await response.Content.ReadAsStringAsync(token));
        string? error = xml.Descendants().FirstOrDefault(e => e.Name.LocalName == "errorCode")?.Value;
        if (error != null) throw new UpnpException(error, action);
        response.EnsureSuccessStatusCode();
        return xml;
    }

    static Dictionary<string, string> Key(int port, string protocol) => new() { ["NewRemoteHost"] = "", ["NewExternalPort"] = port.ToString(), ["NewProtocol"] = protocol };
    public async Task<RouterMapping?> Get(int port, string protocol, CancellationToken token)
    {
        try
        {
            var xml = await Call("GetSpecificPortMappingEntry", Key(port, protocol), token);
            string Value(string name) => xml.Descendants().First(e => e.Name.LocalName == name).Value;
            return new(port, int.Parse(Value("NewInternalPort")), Value("NewInternalClient"), protocol, Value("NewPortMappingDescription"));
        }
        catch (UpnpException ex) when (ex.Code == "714") { return null; }
    }

    public async Task Add(RouterMapping mapping, CancellationToken token)
    {
        var existing = await Get(mapping.ExternalPort, mapping.Protocol, token);
        if (existing != null && existing != mapping) throw new IOException("路由器端口已被其他规则占用，不覆盖原规则");
        var args = Key(mapping.ExternalPort, mapping.Protocol);
        args["NewInternalPort"] = mapping.InternalPort.ToString();
        args["NewInternalClient"] = mapping.InternalClient;
        args["NewEnabled"] = "1";
        args["NewPortMappingDescription"] = mapping.Description;
        args["NewLeaseDuration"] = "180";
        // No permanent-lease fallback: an unattended failure must not leave an unowned rule forever.
        await Call("AddPortMapping", args, token);
    }

    public async Task RemoveOwned(RouterMapping mapping, CancellationToken token)
    {
        var current = await Get(mapping.ExternalPort, mapping.Protocol, token);
        if (current == mapping) await Call("DeletePortMapping", Key(mapping.ExternalPort, mapping.Protocol), token);
    }
    public async Task<string> ExternalAddress(CancellationToken token) => (await Call("GetExternalIPAddress", [], token)).Descendants().First(e => e.Name.LocalName == "NewExternalIPAddress").Value;
    public void Dispose() => http.Dispose();
}
public sealed class UpnpException(string code, string action) : IOException($"路由器 {action} 返回 UPnP 错误 {code}") { public string Code { get; } = code; }
