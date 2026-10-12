using System.Net;
using StreamLink.Core;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("StreamLink.MeshConnectionTests")]
[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("StreamLink.MeshRunnerTraversalTests")]
[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("StreamLink.MeshHarness")]

namespace StreamLink.Service;

internal sealed record MeshTransportRequest(string Folder, MeshProfile Mesh, IPEndPoint Target, bool Server, int Port, IMapping? Mapping, string LogLevel);

// The production runner itself is exercised with loopback transports and an
// in-memory adapter. Tests never touch the installed service or network rules.
internal sealed record MeshRuntimeServices(
    Func<MeshProfile, IMeshDiscovery> Discovery,
    Func<MeshProfile, Task<IPacketAdapter>> Adapter,
    Func<DeviceProfile, Action<string>, CancellationToken, Task<IMapping>> Probe,
    Func<MeshTransportRequest, IMeshTransport> Transport,
    Func<string, Func<IPAddress, string?>, CancellationToken, Task> QualityServer,
    Action<string, string, string> Firewall,
    Action<string, string> Record,
    string SessionRoot)
{
    public Func<IMeshNetworkWake> NetworkWake { get; init; } = () => new MeshNetworkWake();
    public Func<DeviceProfile, string, Action<string>, CancellationToken, Task<IMeshCandidateFactory?>> Candidates { get; init; } =
        (profile, folder, log, token) => MeshCandidateFactory.Create(profile, Path.Combine(AppContext.BaseDirectory, "components", "udp2raw-native.exe"), folder, log, token);
    public static MeshRuntimeServices Default => new(
        mesh => new MeshDiscoveryClient(mesh),
        mesh => Task.Run<IPacketAdapter>(() => new NativeAdapter(Path.Combine(AppContext.BaseDirectory, "components"), mesh.Pair.Network, mesh.Self.Slot)),
        async (profile, log, token) => profile.Mesh!.Pair.Mode == "udp"
            ? await UdpMapping.Create(profile.ListenPort, profile.ListenPort, log, token, profile.UdpStun, profile.Device)
            : await GatewayMapping.CreateTcp(profile.SourcePort, profile.ListenPort, log, token, profile.OrderedTcp(), profile.Device, profile.PortControlMapping),
        r => new MeshTransport(Path.Combine(AppContext.BaseDirectory, "components"), r.Folder, r.Mesh, r.Target, r.Server, r.Port, r.Mapping, r.LogLevel),
        (ip, key, token) => Quality.Serve(ip, key, token),
        (rule, local, remote) => { WindowsHost.RemoveFirewall(rule); if (remote.Length > 0) WindowsHost.AddFirewall(rule, local, remote); },
        Recovery.Record,
        Path.Combine(ProfileStore.Root, "sessions"));
}
