using System.Text.Json;

namespace StreamLink.Core;

// EasyTier is used only for the local virtual adapter and authenticated overlay.
// Keep root settings separate from [flags]; unknown top-level flags are ignored.
internal static class NetworkConfiguration
{
    public static string AdapterName(Invitation ticket, int slot) => $"sl_{ticket.Network}_{slot}";
    public static string Create(Invitation ticket, string instance, int slot, string localIp, bool host, int appPort)
    {
        ticket.Validate();
        if (slot is < 1 or > 2 || appPort is < 1 or > 65535) throw new ArgumentException("组网参数无效");
        static string Q(string value) => JsonSerializer.Serialize(value);
        string endpoint = $"udp://127.0.0.1:{appPort}";
        string config = $"instance_name = {Q("sl-" + instance)}\nhostname = {Q(slot == 1 ? "StreamLink-Host" : "StreamLink-Guest")}\nipv4 = {Q(localIp)}\nlisteners = [{(host ? Q(endpoint) : "")}]\nstun_servers = []\nstun_servers_v6 = []\n[network_identity]\nnetwork_name = {Q("streamlink-" + ticket.Network)}\nnetwork_secret = {Q(ticket.Secret)}\n";
        if (!host) config += $"[[peer]]\nuri = {Q(endpoint)}\n";
        return config + $"[flags]\ndev_name = {Q(AdapterName(ticket, slot))}\nmtu = 1280\nenable_ipv6 = false\ndisable_p2p = true\np2p_only = true\ndisable_udp_hole_punching = true\ndisable_tcp_hole_punching = true\ndisable_upnp = true\nbind_device = false\naccept_dns = false\n";
    }
}
