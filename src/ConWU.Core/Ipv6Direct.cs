using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace StreamLink.Core;

// Native outer IPv6 only. Inner virtual addressing is unchanged. LAN/link-local
// scopes and transition tunnels require a separate negotiated path contract.
public static class Ipv6Direct
{
    public static bool UnscopedUnicast(IPAddress ip) => ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.ScopeId == 0 &&
        !ip.Equals(IPAddress.IPv6Any) && !ip.IsIPv4MappedToIPv6 && !ip.IsIPv6Multicast && !ip.IsIPv6LinkLocal && !ip.IsIPv6SiteLocal &&
        // Also exclude deprecated IPv4-compatible ::/96, except the local test loopback.
        (ip.Equals(IPAddress.IPv6Loopback) || !ip.GetAddressBytes().AsSpan(0, 12).SequenceEqual(new byte[12]));
    public static bool Global(IPAddress ip)
    {
        if (!UnscopedUnicast(ip)) return false;
        var b = ip.GetAddressBytes();
        if ((b[0] & 0xe0) != 0x20) return false; // conservative native global-unicast policy
        if (b[0] == 0x20 && b[1] == 2) return false; // 6to4
        if (b[0] == 0x20 && b[1] == 1 && b[2] < 2) return false; // IETF protocol assignments, includes Teredo
        if (b[0] == 0x20 && b[1] == 1 && b[2] == 0x0d && b[3] == 0xb8) return false;
        if (b[0] == 0x3f && b[1] == 0xff && (b[2] & 0xf0) == 0) return false;
        return true;
    }
    public static bool Physical(NetworkInterface nic) => nic.OperationalStatus == OperationalStatus.Up &&
        nic.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211 &&
        !new[] { "StreamLink", "Wintun", "EasyTier", "VMware", "Hyper-V", "VirtualBox", "VPN", "Virtual" }
            .Any(word => (nic.Name + " " + nic.Description).Contains(word, StringComparison.OrdinalIgnoreCase));
    static bool Ready(UnicastIPAddressInformation address) => OperatingSystem.IsWindows() &&
        address.DuplicateAddressDetectionState == DuplicateAddressDetectionState.Preferred && address.AddressValidLifetime > 30 && address.AddressPreferredLifetime > 30;
    public static bool SourceReady(IPAddress ip) => Global(ip) && NetworkInterface.GetAllNetworkInterfaces().Any(n => Physical(n) &&
        n.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(ip) && Ready(a)));
    public static bool Available() => OperatingSystem.IsWindows() && Socket.OSSupportsIPv6 && NetworkInterface.GetAllNetworkInterfaces().Any(n => Physical(n) &&
        n.GetIPProperties().UnicastAddresses.Any(a => Global(a.Address) && Ready(a)));
}
