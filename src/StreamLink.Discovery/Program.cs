using StreamLink.Discovery;

if(args.Length>0 && args[0]=="coordinator") {
    try {
        var result=CoordinationMaintenance.Execute(args[1..],Environment.GetEnvironmentVariable("STREAMLINK_DISCOVERY_DATA")??Path.Combine(AppContext.BaseDirectory,"data"));
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(result,new System.Text.Json.JsonSerializerOptions{WriteIndented=true}));
    }catch(Exception ex){Console.Error.WriteLine(ex.Message);Environment.ExitCode=1;}
    return;
}

await using var host = CoordinationHost.Create(new(
    Environment.GetEnvironmentVariable("STREAMLINK_DISCOVERY_DATA") ?? Path.Combine(AppContext.BaseDirectory, "data"),
    TrustCloudflare: Environment.GetEnvironmentVariable("STREAMLINK_TRUST_CLOUDFLARE") == "1",
    TcpObserverPoints: Environment.GetEnvironmentVariable("STREAMLINK_TCP_OBSERVER_POINTS")), args);
await host.Run();
