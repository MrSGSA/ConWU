using System.Net;
using StreamLink.Core;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("StreamLink.MeshConnectionTests")]
[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("StreamLink.MeshRunnerTraversalTests")]
[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("StreamLink.MeshHarness")]
[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("StreamLink.UnifiedHostTests")]

namespace StreamLink.Service;

internal sealed record MeshTransportRequest(string Folder, MeshProfile Mesh, IPEndPoint Target, bool Server, int Port, IMapping? Mapping, string LogLevel)
{
    public Action<IPEndPoint>? ReserveEndpoint { get; init; }
    public EgressPacer? Egress {get;init;}
}

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
    // A null override lets the runner own one resolver for its whole lifetime.
    // Recreating it each refresh discards healthy HTTPS connections.
    public Func<ExistingEntry[],string,CancellationToken,Task<EntryResolution[]>>? ResolveEntries {get;init;}
    public Func<MeshProfile,string,string,IMeshDiscovery> CoordinatorBackup {get;init;}=(mesh,service,pin)=>new MeshDiscoveryClient(mesh,service,pin);

    public Func<DeviceProfile,string,Func<IPAddress,string?>,CancellationToken,Task>? QualityWithPolicy {get;init;}
    public Func<DeviceProfile,string,Action<string>,CancellationToken,EgressPacer?,Task<IMeshCandidateFactory?>>? CandidatesWithEgress{get;init;}
    public Func<IMeshNetworkWake> NetworkWake { get; init; } = () => new MeshNetworkWake();
    // Keep the original injected fixture contract; the product uses the same
    // profile-aware factory in service and elevated foreground modes.
    public Func<DeviceProfile,Action<string>,CancellationToken,Task<IPacketAdapter>>? ProfileAdapter {get;init;}
    public Func<DeviceProfile, string, Action<string>, CancellationToken, Task<IMeshCandidateFactory?>> Candidates { get; init; } =
        (profile, folder, log, token) => MeshCandidateFactory.Create(profile, Path.Combine(AppContext.BaseDirectory, "components", "udp2raw-native.exe"), folder, log, token);
    public static MeshRuntimeServices Default => OperatingSystem.IsLinux()?Linux:new(
        mesh => mesh.Pair.Direct ? new DirectMeshDiscovery(mesh) : new MeshDiscoveryClient(mesh),
        mesh => Task.Run<IPacketAdapter>(() => new NativeAdapter(Path.Combine(AppContext.BaseDirectory, "components"), mesh.Pair.Network, mesh.Self.Slot)),
        async (profile, log, token) => profile.TransportMode == "udp"
            ? await UdpMapping.Create(profile.ListenPort, profile.ListenPort, log, token, profile.UdpStun, profile.ResourceScope)
            : await GatewayMapping.CreateTcp(profile.SourcePort, profile.ListenPort, log, token, profile.OrderedTcp(), profile.ResourceScope, profile.PortControlMapping),
        r => new MeshTransport(Path.Combine(AppContext.BaseDirectory, "components"), r.Folder, r.Mesh, r.Target, r.Server, r.Port, r.Mapping, r.LogLevel, r.ReserveEndpoint,r.Egress),
        (ip, key, token) => Quality.Serve(ip, key, token),
        (rule, local, remote) => { WindowsHost.RemoveFirewall(rule); if (remote.Length > 0) WindowsHost.AddFirewall(rule, local, remote); },
        Recovery.Record,
        Path.Combine(ProfileStore.Root, "sessions")) {
            ProfileAdapter=PersonalPacketAdapters.Open,
            QualityWithPolicy=(profile,ip,key,token)=>Quality.Serve(ip,key,token,new(()=>profile.AllowManualQualityRequests)),
            CandidatesWithEgress=(profile,folder,log,token,pacer)=>MeshCandidateFactory.Create(profile,Path.Combine(AppContext.BaseDirectory,"components","udp2raw-native.exe"),folder,log,token,pacer)
        };
    static MeshRuntimeServices Linux => new(
        mesh=>mesh.Pair.Direct?new DirectMeshDiscovery(mesh):new MeshDiscoveryClient(mesh),
        mesh=>Task.Run<IPacketAdapter>(()=>new LinuxTunAdapter(mesh.LocalIp)),
        async (profile,log,token)=>profile.TransportMode=="udp"
            ?await UdpMapping.Create(profile.ListenPort,profile.ListenPort,log,token,profile.UdpStun,profile.ResourceScope)
            :await GatewayMapping.CreateTcp(profile.SourcePort,profile.ListenPort,log,token,profile.OrderedTcp(),profile.ResourceScope,profile.PortControlMapping),
        r=>new LinuxMeshTransport(Path.Combine(AppContext.BaseDirectory,"components"),r.Folder,r.Mesh,r.Target,r.Server,r.Port,r.Mapping,r.LogLevel,r.ReserveEndpoint),
        (ip,key,token)=>Quality.Serve(ip,key,token),
        LinuxFirewall.Update,
        Recovery.Record,
        Path.Combine(ProfileStore.Root,"sessions")) {
            ProfileAdapter=PersonalPacketAdapters.Open,
            Candidates=(profile,folder,log,token)=>MeshCandidateFactory.Create(profile,Path.Combine(AppContext.BaseDirectory,"components","udp2raw-native"),folder,log,token),
            QualityWithPolicy=(profile,ip,key,token)=>Quality.Serve(ip,key,token,new(()=>profile.AllowManualQualityRequests))
        };

}
