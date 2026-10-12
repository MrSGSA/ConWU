using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace StreamLink.Core;

// Read-only OS route evidence. No packet is sent and no route is changed.
// Lifetime/age/metric counters are deliberately excluded: they do not by
// themselves change the selected source, interface or next hop.
public static class EgressRouteSnapshot
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    static extern uint GetBestRoute2(nint luid, uint index, nint source, byte[] destination, uint options,
        [Out] byte[] route, [Out] byte[] bestSource);

    static byte[] Address(IPAddress ip)
    {
        var bytes = new byte[28];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, (ushort)ip.AddressFamily);
        ip.GetAddressBytes().CopyTo(bytes, ip.AddressFamily == AddressFamily.InterNetwork ? 4 : 8);
        if (ip.AddressFamily == AddressFamily.InterNetworkV6) BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(24), (uint)ip.ScopeId);
        return bytes;
    }
    static IPAddress Decode(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt16LittleEndian(bytes) switch {
        (ushort)AddressFamily.InterNetwork => new(bytes.Slice(4, 4)),
        (ushort)AddressFamily.InterNetworkV6 => new(bytes.Slice(8, 16), BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(24, 4))),
        _ => throw new IOException("RouteSnapshotUnsupportedAddress")
    };
    public static string Capture(IPEndPoint target)
    {
        try {
            IPAddress source; string routeKey;
            if (OperatingSystem.IsWindows()) {
                // SOCKADDR_INET=28, MIB_IPFORWARD_ROW2=104 in the Windows ABI.
                var row = new byte[104]; var best = new byte[28];
                uint error = GetBestRoute2(0, 0, 0, Address(target.Address), 0, row, best);
                if (error != 0) return "Unavailable:" + error;
                source = Decode(best);
                routeKey = BinaryPrimitives.ReadUInt64LittleEndian(row) + "/" +
                    BinaryPrimitives.ReadUInt32LittleEndian(row.AsSpan(8)) + "/" + Decode(row.AsSpan(44, 28));
            } else { source = Stun.LocalAddress(target); routeKey = "SourceSelectionOnly"; }
            var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
                n.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(source)));
            if (nic == null || nic.OperationalStatus != OperationalStatus.Up) return "Unavailable:Interface";
            var local = nic.GetIPProperties().UnicastAddresses.First(a => a.Address.Equals(source));
            string addressState = OperatingSystem.IsWindows() ? local.DuplicateAddressDetectionState.ToString() : "Unknown";
            return nic.Id + "/" + routeKey + "/" + source + "/" + local.PrefixLength + "/" + addressState;
        } catch (Exception ex) when (ex is NetworkInformationException or SocketException or IOException or InvalidOperationException) {
            return "Unavailable:" + ex.GetType().Name;
        }
    }
}
