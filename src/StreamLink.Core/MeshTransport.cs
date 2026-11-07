using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;

namespace StreamLink.Core;

public interface IMeshTransport : IDisposable
{
    IPEndPoint? ClientEndpoint { get; }
    bool Exited { get; }
    bool ControlsWirePackets => false;
    string FailureReason => Exited ? "TransportExited" : "";
}
// A server multiplexes authenticated peers on the same mapped public port.
// Outbound clients are independent: changing one peer never recreates the TUN.
[SupportedOSPlatform("windows")]
public sealed class MeshTransport : IMeshTransport
{
    readonly ChildJob job = new();
    readonly string configuration;
    readonly LegacyTransportLedger.Handle? accounting;
    readonly LegacyControlChannel? control;
    readonly LegacyEgressChannel? business;
    readonly LegacyRouteEvidence? route;
    int disposed;
    public IPEndPoint? ClientEndpoint { get; }
    public bool Exited => job.AnyExited || control?.Failed == true || business?.Failed==true;
    public bool ControlsWirePackets => true;
    internal string ControlFailure => (control?.Failure??"")+" "+(business?.Snapshot().Failure??"");
    public string FailureReason => control?.Failed==true ? "ControlChannel:"+control.Failure : business?.Failed==true ? "BusinessChannel:"+business.Snapshot().Failure : job.AnyExited ? "NativeProcessExited" : "";
    public MeshTransport(string components, string sessionRoot, MeshProfile profile, IPEndPoint target, bool server, int listenPort, IMapping? mapping, string logLevel)
        : this(components, sessionRoot, profile, target, server, listenPort, mapping, logLevel, null, null) { }
    public MeshTransport(string components, string sessionRoot, MeshProfile profile, IPEndPoint target, bool server, int listenPort, IMapping? mapping, string logLevel,
        Action<IPEndPoint>? reserveEndpoint,EgressPacer? pacer=null)
        : this(components, sessionRoot, profile, target, server, listenPort, mapping, logLevel, null, reserveEndpoint,pacer) { }
    internal MeshTransport(string components, string sessionRoot, MeshProfile profile, IPEndPoint target, bool server, int listenPort, IMapping? mapping,
        string logLevel, Dictionary<string, string>? testEnvironment, Action<IPEndPoint>? reserveEndpoint = null,EgressPacer? pacer=null,Func<ReadOnlyMemory<byte>,bool>? testInject=null,
        Func<IPEndPoint,IPEndPoint,Guid,ulong,EgressRouteWitness>? routeObserver=null)
    {
        Directory.CreateDirectory(sessionRoot);
        configuration = Path.Combine(sessionRoot, "raw-" + Guid.NewGuid().ToString("N") + ".conf");
        try {
            string binary = Path.Combine(components, "udp2raw-native.exe");
            LegacyNativeCapabilities.Require(binary,true);
            string binding;
            if (server) binding = $"{mapping?.LocalAddress ?? IPAddress.Any}:{listenPort}";
            else {
                using var port = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); port.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                ClientEndpoint = (IPEndPoint)port.LocalEndPoint!; binding = ClientEndpoint.ToString();
                reserveEndpoint?.Invoke(ClientEndpoint);
            }
            accounting = LegacyTransportLedger.Shared.Acquire(profile.Pair.Mode, server, server ? binding : "",
                target.ToString(), mapping is TcpMapping tcp ? tcp.HelperResource.LeaseId : Guid.Empty);
            var ticket = new Invitation(1, profile.Pair.Network, profile.Pair.Secret, target.ToString(), profile.Pair.Mode, "test.ustc.edu.cn", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());
            string rawKey=DirectPairWire.CarriageKey;
            string config = $"{(server ? "-s" : "-c")}\n-l {binding}\n-r {target}\n-k {rawKey}\n--raw-mode {profile.Pair.Mode}\n--fix-gro\n--seq-mode 3\n--log-level {(logLevel == "debug" ? 5 : logLevel == "error" ? 2 : 4)}\n";
            if (profile.Pair.Mode == "faketcp") config += "--fake-http test.ustc.edu.cn\n";
            File.WriteAllText(configuration, config);
            var environment = new Dictionary<string, string> { ["STREAMLINK_ALLOW_DRIVER_INSTALL"] = "1" };
            environment["STREAMLINK_DIRECT_RENDEZVOUS"]="1";
            if (testEnvironment != null) foreach (var pair in testEnvironment) {
                if (!pair.Key.StartsWith("STREAMLINK_TEST_", StringComparison.Ordinal)) throw new ArgumentException("Only explicit test backend variables can be injected");
                environment[pair.Key] = pair.Value;
            }
            route=new LegacyRouteEvidence(accounting.ResourceId,pacer!=null,routeObserver??(testInject==null?null:(s,t,g,e)=>new(g,e,s.ToString(),t.ToString(),0,0,"LoopbackFixture","LoopbackFixture","LoopbackFixture","")));
            accounting.Route=route.Snapshot;
            control = new(accounting.ResourceId, profile.Pair.Mode == "faketcp", server ? listenPort : 0,route:route);
            accounting.Control=control.Snapshot;
            if(pacer!=null){
                if(profile.Pair.Mode!="faketcp")throw new NotSupportedException("Experimental compatibility egress currently requires FakeTCP");
                LegacyNativeCapabilities.RequireEgress(binary);
                business=new(control.Authorization,pacer,profile,target,server,listenPort,Path.Combine(components,"WinDivert.dll"),route,testInject);
                environment["STREAMLINK_LEGACY_EGRESS"]=business.Name;
                accounting.Egress=business.Snapshot;
            }
            environment["STREAMLINK_LEGACY_CONTROL"] = control.Name;
            environment["STREAMLINK_LEGACY_AUTH"] = control.Authorization;
            environment["STREAMLINK_LEGACY_PARENT"] = Environment.ProcessId.ToString();
            environment["STREAMLINK_LEGACY_WIRE_ID"]=accounting.ResourceId.ToString("N");
            if (server&&profile.Pair.Mode=="udp")environment["STREAMLINK_UDP_SHARED_BIND"]="1";
            if (server && mapping is UdpMapping udp) environment["STREAMLINK_STUN_ENDPOINT"] = udp.StunEndpoint.ToString();
            var child = job.StartObserved(binary, ["--conf-file", configuration], logLevel == "off" ? null : Path.ChangeExtension(configuration, ".log"), environment,
                [ticket.RawKey, ticket.Secret, control.Authorization],accounting.WireLine);
            control.Start(child.Id);
            business?.Start(child.Id);
            accounting.Started(child);
        } catch { Dispose(); throw; }
    }
    public void Dispose() {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        try { job.Dispose(); }
        finally { try{business?.Dispose();control?.Dispose(); accounting?.Dispose();}finally{route?.Dispose();File.Delete(configuration);} }
    }
}
