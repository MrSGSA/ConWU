using System.Security.Cryptography;

namespace StreamLink.Core;

// The link pins a public signing key supplied by the user. DNS is not a
// trust-on-first-use authority, and this locator never grants membership.
public sealed record DdnsEntryLink(string Domain, string Network, string Device, int Slot, string Key)
{
    public const string Scheme = "conwu-ddns://";
    public MeshMember Member => new(Slot, Device, Key, "", "");
    public string RecordName => DdnsAddressRecords.Name(Domain, Network, Device);
    public static string Create(string domain, MeshProfile mesh) => new DdnsEntryLink(domain.ToLowerInvariant(), mesh.Pair.Network,
        mesh.Self.Device, mesh.Self.Slot, mesh.Self.SigningKey).Encode();
    string Encode() => $"{Scheme}{Domain}/{Network}/{Device}/{Slot}?key={Uri.EscapeDataString(Key)}";
    public static DdnsEntryLink Parse(string source) {
        try {
            if (source.Length > 2048 || !Uri.TryCreate(source, UriKind.Absolute, out var uri) || uri.Scheme != "conwu-ddns" ||
                uri.UserInfo.Length != 0 || uri.Port != -1 || uri.Fragment.Length != 0 || !uri.Query.StartsWith("?key=", StringComparison.Ordinal) || uri.Query.Contains('&'))
                throw new FormatException();
            var parts = uri.AbsolutePath.Split('/');
            if (parts.Length != 4 || !int.TryParse(parts[3], out int slot) || slot is < 1 or > 254) throw new FormatException();
            var link = new DdnsEntryLink(uri.Host, parts[1], parts[2], slot, Uri.UnescapeDataString(uri.Query[5..]));
            _ = link.RecordName;
            using var key = ECDsa.Create(); var bytes = Convert.FromBase64String(link.Key);
            key.ImportSubjectPublicKeyInfo(bytes, out int used);
            if (used != bytes.Length || key.KeySize != 256 || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7" ||
                link.Key != Convert.ToBase64String(key.ExportSubjectPublicKeyInfo())) throw new FormatException();
            return link;
        } catch (Exception ex) when (ex is ArgumentException or FormatException or CryptographicException) {
            throw new FormatException("DDNS 入口链接无效，请复制发布设备提供的完整链接");
        }
    }
}
