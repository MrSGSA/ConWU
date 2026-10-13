using StreamLink.Core;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("StreamLink.ConnectionTests")]

namespace StreamLink.Service;

// Keep scheduling independent of driver/process startup, so it can be exercised
// without creating adapters, mappings, firewall rules or changing a live profile.
internal sealed record RunnerServices(
    Func<Pairing, IDiscoveryClient> OpenDiscovery,
    Func<Action<string>, IStreamSession> NewSession,
    Func<DeviceProfile, Action<string>, CancellationToken, Task<IMapping>> Probe,
    TimeSpan ConnectingPoll,
    TimeSpan ConnectedPoll)
{
    public Func<IMeshNetworkWake> NetworkWake { get; init; } = () => new MeshNetworkWake();
    public static RunnerServices Default { get; } = new(
        pair => new DiscoveryClient(pair),
        log => new StreamSession(Path.Combine(AppContext.BaseDirectory, "components"), log, Path.Combine(ProfileStore.Root, "sessions")),
        async (profile, log, token) => profile.Pair!.Mode == "udp"
            ? await UdpMapping.Create(profile.ListenPort, profile.ListenPort, log, token, profile.UdpStun, profile.Device)
            : await GatewayMapping.CreateTcp(profile.SourcePort, profile.ListenPort, log, token, profile.OrderedTcp(), profile.Device, profile.PortControlMapping),
        // Two peers, PUT + GET: at most 96 regular requests/minute while
        // connecting, leaving headroom under the existing 120/minute limit.
        TimeSpan.FromMilliseconds(2500), TimeSpan.FromSeconds(5));
}
