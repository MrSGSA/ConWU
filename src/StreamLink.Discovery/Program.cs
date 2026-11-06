using StreamLink.Discovery;

await using var host = CoordinationHost.Create(new(
    Environment.GetEnvironmentVariable("STREAMLINK_DISCOVERY_DATA") ?? Path.Combine(AppContext.BaseDirectory, "data"),
    TrustCloudflare: Environment.GetEnvironmentVariable("STREAMLINK_TRUST_CLOUDFLARE") == "1",
    TcpObserverPoints: Environment.GetEnvironmentVariable("STREAMLINK_TCP_OBSERVER_POINTS")), args);
await host.Run();
