using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace StreamLink.Core;

public sealed record PortControlRoute(string InterfaceId, IPAddress Local, IPEndPoint Gateway, string Generation)
{
    // Nonstandard ports are only used by isolated tests, never configuration.
    internal int NotificationPort { get; init; } = 5350;
    internal int NotificationInterface()
    {
        var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Id == InterfaceId && n.OperationalStatus == OperationalStatus.Up);
        if (nic == null) return 0;
        var properties = nic.GetIPProperties();
        return properties.UnicastAddresses.Any(a => a.Address.Equals(Local)) ? properties.GetIPv4Properties()?.Index ?? 0 : 0;
    }
    public static PortControlRoute[] Discover(IPAddress source)
    {
        var routes = new List<PortControlRoute>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()) {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType is not (NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211) ||
                nic.Description.Contains("Wintun", StringComparison.OrdinalIgnoreCase) || nic.Description.Contains("EasyTier", StringComparison.OrdinalIgnoreCase) ||
                nic.Description.Contains("StreamLink", StringComparison.OrdinalIgnoreCase) || nic.Name.Contains("StreamLink", StringComparison.OrdinalIgnoreCase)) continue;
            var properties = nic.GetIPProperties();
            var local = properties.UnicastAddresses.FirstOrDefault(a => a.Address.Equals(source));
            if (local == null || source.AddressFamily != AddressFamily.InterNetwork || local.PrefixLength is < 1 or > 32) continue;
            foreach (var gateway in properties.GatewayAddresses.Select(g => g.Address).Where(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any)).Distinct().Take(2)) {
                byte[] a = source.GetAddressBytes(), b = gateway.GetAddressBytes();
                bool onLink = Enumerable.Range(0, local.PrefixLength).All(bit => (a[bit / 8] & (128 >> bit % 8)) == (b[bit / 8] & (128 >> bit % 8)));
                if (!onLink || gateway.Equals(source) || gateway.GetAddressBytes()[0] is 0 or 127 or >= 224) continue;
                string generation = nic.Id + "/" + source + "/" + local.PrefixLength + "/" + gateway;
                routes.Add(new(nic.Id, source, new(gateway, 5351), generation));
            }
        }
        return routes.ToArray();
    }
    public bool StillCurrent() => Discover(Local).Any(r => r.Generation == Generation && r.Gateway.Equals(Gateway));
    public static bool Private(IPAddress address) {
        byte[] b = address.GetAddressBytes(); return b.Length == 4 && (b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168);
    }
    // This is candidate eligibility, not a proof of end-to-end reachability.
    public static bool GlobalV4(IPAddress address) {
        byte[] b = address.GetAddressBytes();
        return b.Length == 4 && !Private(address) && b[0] is not (0 or 127) && b[0] < 224 &&
            !(b[0] == 100 && b[1] is >= 64 and <= 127) && !(b[0] == 169 && b[1] == 254) &&
            !(b[0] == 192 && (b[1] == 0 && b[2] is 0 or 2 || b[1] == 88 && b[2] == 99)) &&
            !(b[0] == 198 && (b[1] is 18 or 19 || b[1] == 51 && b[2] == 100)) && !(b[0] == 203 && b[1] == 0 && b[2] == 113);
    }
}
