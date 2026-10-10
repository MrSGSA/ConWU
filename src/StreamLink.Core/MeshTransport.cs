using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;

namespace StreamLink.Core;

// A server multiplexes authenticated peers on the same mapped public port.
// Outbound clients are independent: changing one peer never recreates the TUN.
[SupportedOSPlatform("windows")]
public sealed class MeshTransport : IDisposable
{
    readonly ChildJob job = new();
    readonly string configuration;
    public IPEndPoint? ClientEndpoint { get; }
    public bool Exited => job.AnyExited;
    public MeshTransport(string components, string sessionRoot, MeshProfile profile, IPEndPoint target, bool server, int listenPort, IMapping? mapping, string logLevel)
    {
        Directory.CreateDirectory(sessionRoot);
        configuration = Path.Combine(sessionRoot, "raw-" + Guid.NewGuid().ToString("N") + ".conf");
        try {
            string binding;
            if (server) binding = $"{mapping?.LocalAddress ?? IPAddress.Any}:{listenPort}";
            else {
                using var port = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); port.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                ClientEndpoint = (IPEndPoint)port.LocalEndPoint!; binding = ClientEndpoint.ToString();
            }
            var ticket = new Invitation(1, profile.Pair.Network, profile.Pair.Secret, target.ToString(), profile.Pair.Mode, "test.ustc.edu.cn", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());
            string config = $"{(server ? "-s" : "-c")}\n-l {binding}\n-r {target}\n-k {ticket.RawKey}\n--raw-mode {profile.Pair.Mode}\n--fix-gro\n--seq-mode 3\n--log-level {(logLevel == "debug" ? 5 : logLevel == "error" ? 2 : 4)}\n";
            if (profile.Pair.Mode == "faketcp") config += "--fake-http test.ustc.edu.cn\n";
            File.WriteAllText(configuration, config);
            var environment = new Dictionary<string, string> { ["STREAMLINK_ALLOW_DRIVER_INSTALL"] = "1" };
            if (server && mapping is UdpMapping udp) { environment["STREAMLINK_UDP_SHARED_BIND"] = "1"; environment["STREAMLINK_STUN_ENDPOINT"] = udp.StunEndpoint.ToString(); }
            job.Start(Path.Combine(components, "udp2raw-native.exe"), ["--conf-file", configuration], logLevel == "off" ? null : Path.ChangeExtension(configuration, ".log"), environment, [ticket.RawKey, ticket.Secret]);
        } catch { Dispose(); throw; }
    }
    public void Dispose() { job.Dispose(); File.Delete(configuration); }
}
