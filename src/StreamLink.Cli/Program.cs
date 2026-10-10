using System.Net;
using System.Text.Json;
using StreamLink.Core;
using System.Runtime.Versioning;

[assembly: SupportedOSPlatform("windows")]

var options = new JsonSerializerOptions { WriteIndented = true };
using var cancel = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };
try
{
    if(args.Length >= 3 && args[0] == "control") {
        var request = JsonSerializer.Deserialize<ControlRequest>(File.ReadAllText(args[1])) ?? throw new IOException("控制请求为空");
        var reply = await ServiceProtocol.Call(request,cancel.Token);
        await File.WriteAllTextAsync(args[2],JsonSerializer.Serialize(reply,options),cancel.Token);
        Console.WriteLine(reply.Ok ? "Control OK" : "Control failed: " + reply.Error); if(!reply.Ok) Environment.ExitCode=1; return;
    }
    if (args.Length == 0) { Console.WriteLine("StreamLink: probe [源端口] | mapping [源端口] [目标端口] [秒数] | session 配置.json 状态.json [秒数]"); return; }
    if (args[0] == "session")
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        string config = args[1], statePath = Path.GetFullPath(args[2]);
        int seconds = args.Length > 3 ? int.Parse(args[3]) : 600;
        var settings = JsonSerializer.Deserialize<SessionOptions>(File.ReadAllText(config), new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? throw new IOException("配置为空");
        using var ttl = CancellationTokenSource.CreateLinkedTokenSource(cancel.Token); ttl.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(seconds, 20, 7200)));
        await using var session = new StreamSession(Path.Combine(AppContext.BaseDirectory, "components"), Console.WriteLine);
        SessionStatus? status = null; string invite = "";
        object sync = new();
        void Save() { lock(sync) { File.WriteAllText(statePath + ".tmp", JsonSerializer.Serialize(new { invite, status, diagnostics = session.EvidenceDirectory }, options)); File.Move(statePath + ".tmp", statePath, true); } }
        session.InviteChanged += value => { invite = value; Save(); };
        session.StatusChanged += value => { bool changed=status?.State!=value.State; status = value; Save(); if(changed) Console.WriteLine(value.State + " " + value.Detail); };
        File.Delete(statePath + ".stop");
        await session.Start(settings, ttl.Token);
        invite = session.Ticket?.Encode() ?? invite; Save();
        while (!File.Exists(statePath + ".stop")) await Task.Delay(1000, ttl.Token);
        return;
    }
    if (args[0] == "quality")
    {
        string input=File.ReadAllText(args[1]);
        var config=JsonSerializer.Deserialize<SessionOptions>(input,new JsonSerializerOptions {PropertyNameCaseInsensitive=true})!;
        using var state=JsonDocument.Parse(input);
        SessionStatus? status=state.RootElement.TryGetProperty("status",out var statusJson) && statusJson.ValueKind==JsonValueKind.Object ? statusJson.Deserialize<SessionStatus>() : null;
        if(status is {Connected:false}) throw new IOException("会话尚未连接对端");
        string local=status?.LocalIp ?? (config.Host ? "10.129.129.1" : "10.129.129.2");
        string peer=status?.PeerIp ?? (config.Host ? "10.129.129.2" : "10.129.129.1");
        var ticket=Invitation.Decode(config.Invite);
        int mbps=args.Length>2?int.Parse(args[2]):50;
        var result=await Quality.Measure(peer,ticket.Secret,mbps,cancel.Token,local:local);
        string json=JsonSerializer.Serialize(result,options);
        if(args.Length>3) File.WriteAllText(args[3],json);
        Console.WriteLine(json); return;
    }
    if (args[0] == "inspect-mappings")
    {
        var services=await Upnp.Discover(IPAddress.Parse(args[1]),cancel.Token);
        var results=new List<object>();
        foreach(var service in services) {
            using var router=new Upnp(service);
            foreach(var port in args.Skip(2).Select(int.Parse)) foreach(var protocol in new[]{"TCP","UDP"}) {
                var mapping=await router.Get(port,protocol,cancel.Token);
                results.Add(new {port,protocol,mapping});
            }
        }
        Console.WriteLine(JsonSerializer.Serialize(results,options)); return;
    }
    if (args[0] == "probe")
    {
        int port = args.Length > 1 ? int.Parse(args[1]) : 41391;
        var results = new List<object>();
        IPAddress? local = null;
        foreach (bool tcp in new[] { true, false })
        {
            foreach (string server in (tcp ? Stun.TcpServers : Stun.UdpServers).Take(3))
            {
                try
                {
                    var r = await Stun.Query(tcp, server, port, cancel.Token);
                    local ??= r.Local.Address;
                    results.Add(new { protocol = r.Protocol, server, local = r.Local.ToString(), mapped = r.Public.ToString() });
                }
                catch (Exception ex) { results.Add(new { protocol = tcp ? "tcp" : "udp", server, error = ex.Message }); }
            }
        }
        var routers = local == null ? [] : await Upnp.Discover(local, cancel.Token);
        Console.WriteLine(JsonSerializer.Serialize(new { stun = results, routers = routers.Select(s => new { control = s.ControlUrl.AbsoluteUri, service = s.ServiceType, local = s.LocalAddress.ToString() }) }, options));
        return;
    }
    if (args[0] == "mapping")
    {
        int source = args.Length > 1 ? int.Parse(args[1]) : 41391;
        int target = args.Length > 2 ? int.Parse(args[2]) : 41380;
        int seconds = args.Length > 3 ? int.Parse(args[3]) : 120;
        using var ttl = CancellationTokenSource.CreateLinkedTokenSource(cancel.Token);
        ttl.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(seconds, 10, 1800)));
        await using var mapping = await TcpMapping.Create(source, target, Console.Error.WriteLine, ttl.Token);
        void Publish() {
            string json = JsonSerializer.Serialize(new { state = "candidate-unverified", publicEndpoint = mapping.PublicEndpoint.ToString(), localAddress = mapping.LocalAddress.ToString(), sourcePort = source, targetPort = target, router = mapping.RouterAddress }, options);
            Console.WriteLine(json);
            if(args.Length > 4) File.WriteAllText(args[4], json);
        }
        mapping.Changed += _ => Publish();
        Publish();
        await mapping.Maintain(ttl.Token);
        return;
    }
    throw new ArgumentException("未知命令");
}
catch (OperationCanceledException) { }
catch (Exception ex) { Console.Error.WriteLine(ex.Message); Environment.ExitCode = 1; }
