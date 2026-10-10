using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

public sealed class MeshRevokedException() : IOException("本设备已被移出网络，请重新申请加入");

// A network administrator signs membership; members have independent signing
// and ECDH keys. The six-digit exchange delivers one device credential, never
// the administrator key. Slots are never recycled within a network.
public sealed record MeshMember(int Slot, string Device, string SigningKey, string ExchangeKey, string Signature);
public sealed record MeshDirectory(string Network, string OwnerKey, long Revision, int NextSlot, MeshMember[] Members, string Signature);
public sealed record MeshEnrollment(Pairing Pair, string OwnerKey, MeshMember Member, string SigningPrivate, string ExchangePrivate, long Expires);
public sealed class MeshProfile
{
    public Pairing Pair { get; set; } = null!;
    public string OwnerKey { get; set; } = "";
    public string OwnerPrivate { get; set; } = "";
    public MeshMember Self { get; set; } = null!;
    public string SigningPrivate { get; set; } = "";
    public string ExchangePrivate { get; set; } = "";
    public MeshDirectory? Directory { get; set; }
    public bool IsOwner => OwnerPrivate.Length > 0;
    public string LocalIp => MeshIdentity.Address(Pair.Network, Self.Slot);
    public void Validate()
    {
        Pair.Validate(); MeshIdentity.ValidateMember(Pair.Network, OwnerKey, Self);
        if (MeshIdentity.PublicSigning(SigningPrivate) != Self.SigningKey || MeshIdentity.PublicExchange(ExchangePrivate) != Self.ExchangeKey)
            throw new CryptographicException("设备凭据不匹配");
        if (IsOwner && (MeshIdentity.PublicSigning(OwnerPrivate) != OwnerKey || Self.Slot != 1)) throw new CryptographicException("管理员凭据不匹配");
        if (Directory != null) MeshIdentity.ValidateDirectory(Directory, Pair.Network, OwnerKey);
    }
}

public static class MeshIdentity
{
    public const int MaxMembers = 8;
    static byte[] Data(object value) => JsonSerializer.SerializeToUtf8Bytes(value);
    static byte[] MemberData(string network, MeshMember member) => Data(new { domain = "streamlink-member-v4", network, member.Slot, member.Device, member.SigningKey, member.ExchangeKey });
    static byte[] DirectoryData(MeshDirectory directory) => Data(new { domain = "streamlink-directory-v4", directory.Network, directory.OwnerKey, directory.Revision, directory.NextSlot, directory.Members });
    public static string NetworkId(string ownerKey) => Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(ownerKey)).AsSpan(0, 16)).ToLowerInvariant();
    public static string Prefix(string network)
    {
        if (!Guid.TryParseExact(network, "N", out _)) throw new FormatException("网络身份无效");
        byte[] bytes = Convert.FromHexString(network); return $"10.{160 + bytes[0] % 64}.{1 + bytes[1] % 253}";
    }
    public static string Address(string network, int slot) => slot is >= 1 and <= 254 ? $"{Prefix(network)}.{slot}" : throw new FormatException("成员地址无效");
    public static string PublicSigning(string key) { using var ec = ECDsa.Create(); ec.ImportPkcs8PrivateKey(Convert.FromBase64String(key), out _); return Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo()); }
    public static string PublicExchange(string key) { using var ec = ECDiffieHellman.Create(); ec.ImportPkcs8PrivateKey(Convert.FromBase64String(key), out _); return Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo()); }
    public static string Sign(string key, ReadOnlySpan<byte> data) { using var ec = ECDsa.Create(); ec.ImportPkcs8PrivateKey(Convert.FromBase64String(key), out _); return Convert.ToBase64String(ec.SignData(data, HashAlgorithmName.SHA256)); }
    public static bool Verify(string key, ReadOnlySpan<byte> data, string signature)
    {
        try { using var ec = ECDsa.Create(); byte[] bytes = Convert.FromBase64String(key); ec.ImportSubjectPublicKeyInfo(bytes, out int used); return used == bytes.Length && ec.KeySize == 256 && ec.ExportParameters(false).Curve.Oid.Value == "1.2.840.10045.3.1.7" && ec.VerifyData(data, Convert.FromBase64String(signature), HashAlgorithmName.SHA256); }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException) { return false; }
    }
    static (MeshMember member, string signing, string exchange) NewMember(string network, string owner, int slot)
    {
        using var sign = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var exchange = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var member = new MeshMember(slot, Guid.NewGuid().ToString("N"), Convert.ToBase64String(sign.ExportSubjectPublicKeyInfo()), Convert.ToBase64String(exchange.ExportSubjectPublicKeyInfo()), "");
        return (member with { Signature = Sign(owner, MemberData(network, member)) }, Convert.ToBase64String(sign.ExportPkcs8PrivateKey()), Convert.ToBase64String(exchange.ExportPkcs8PrivateKey()));
    }
    static MeshDirectory SignDirectory(MeshProfile profile, MeshMember[] members, int next) {
        var directory = new MeshDirectory(profile.Pair.Network, profile.OwnerKey, (profile.Directory?.Revision ?? 0) + 1, next, members.OrderBy(m => m.Slot).ToArray(), "");
        return directory with { Signature = Sign(profile.OwnerPrivate, DirectoryData(directory)) };
    }
    public static MeshProfile Create(string service, string pin, string mode)
    {
        using var owner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var profile = new MeshProfile { OwnerKey = Convert.ToBase64String(owner.ExportSubjectPublicKeyInfo()), OwnerPrivate = Convert.ToBase64String(owner.ExportPkcs8PrivateKey()) };
        profile.Pair = Pairing.Create(service, pin, mode) with { Network = NetworkId(profile.OwnerKey) };
        var keys = NewMember(profile.Pair.Network, profile.OwnerPrivate, 1);
        profile.Self = keys.member; profile.SigningPrivate = keys.signing; profile.ExchangePrivate = keys.exchange;
        profile.Directory = SignDirectory(profile, [profile.Self], 2); profile.Validate(); return profile;
    }
    public static MeshEnrollment Issue(MeshProfile owner)
    {
        owner.Validate(); if (!owner.IsOwner || owner.Directory == null) throw new IOException("仅创建者可以邀请成员");
        if (owner.Directory.Members.Length >= MaxMembers || owner.Directory.NextSlot > 254) throw new IOException("本网络的成员额度已用完");
        var keys = NewMember(owner.Pair.Network, owner.OwnerPrivate, owner.Directory.NextSlot);
        owner.Directory = SignDirectory(owner, [.. owner.Directory.Members, keys.member], owner.Directory.NextSlot + 1);
        return new(owner.Pair, owner.OwnerKey, keys.member, keys.signing, keys.exchange, DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds());
    }
    public static void Revoke(MeshProfile owner, int slot)
    {
        owner.Validate(); if (!owner.IsOwner || owner.Directory == null || slot == 1 || !owner.Directory.Members.Any(m => m.Slot == slot)) throw new IOException("无法移除此成员");
        owner.Directory = SignDirectory(owner, owner.Directory.Members.Where(m => m.Slot != slot).ToArray(), owner.Directory.NextSlot);
    }
    public static string Export(MeshEnrollment enrollment) => "SL4." + Convert.ToBase64String(Data(enrollment));
    public static MeshProfile Import(string invitation)
    {
        if (!invitation.StartsWith("SL4.") || invitation.Length > 5500) throw new FormatException("请使用新版多机配对邀请");
        var ticket = JsonSerializer.Deserialize<MeshEnrollment>(Convert.FromBase64String(invitation[4..])) ?? throw new FormatException("邀请为空");
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); if (ticket.Expires <= now || ticket.Expires > now + 600) throw new FormatException("邀请已过期");
        var profile = new MeshProfile { Pair = ticket.Pair, OwnerKey = ticket.OwnerKey, Self = ticket.Member, SigningPrivate = ticket.SigningPrivate, ExchangePrivate = ticket.ExchangePrivate };
        profile.Validate(); return profile;
    }
    public static void ValidateMember(string network, string owner, MeshMember member)
    {
        if (member == null || member.Slot is < 1 or > 254 || !Guid.TryParseExact(member.Device, "N", out _) || NetworkId(owner) != network || !Verify(owner, MemberData(network, member), member.Signature)) throw new CryptographicException("成员签名无效");
        PairKeyExchange.ValidatePublic(member.ExchangeKey, Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(member.ExchangeKey))));
        using var sign = ECDsa.Create(); sign.ImportSubjectPublicKeyInfo(Convert.FromBase64String(member.SigningKey), out _);
        if (sign.KeySize != 256 || sign.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7") throw new CryptographicException("成员曲线无效");
    }
    public static void ValidateDirectory(MeshDirectory directory, string network, string owner, long minimumRevision = 0)
    {
        if (directory.Network != network || directory.OwnerKey != owner || directory.Revision < Math.Max(1, minimumRevision) || directory.NextSlot is < 2 or > 255 || directory.Members is not { Length: >= 1 and <= MaxMembers } || directory.Members.Select(m => m.Slot).Distinct().Count() != directory.Members.Length || directory.Members.Select(m => m.Device).Distinct().Count() != directory.Members.Length || directory.Members.Count(m => m.Slot == 1) != 1 || directory.Members.Any(m => m.Slot >= directory.NextSlot) || !Verify(owner, DirectoryData(directory), directory.Signature)) throw new CryptographicException("成员目录无效或已回退");
        foreach (var member in directory.Members) ValidateMember(network, owner, member);
    }
    public static byte[] SharedKey(MeshProfile local, MeshMember peer)
    {
        ValidateMember(local.Pair.Network, local.OwnerKey, peer);
        using var own = ECDiffieHellman.Create(); own.ImportPkcs8PrivateKey(Convert.FromBase64String(local.ExchangePrivate), out _);
        using var remote = ECDiffieHellman.Create(); remote.ImportSubjectPublicKeyInfo(Convert.FromBase64String(peer.ExchangeKey), out _);
        byte[] secret = own.DeriveKeyFromHash(remote.PublicKey, HashAlgorithmName.SHA256);
        try { return HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32, Encoding.UTF8.GetBytes(local.Pair.Network), "streamlink-mesh-link-v4"u8.ToArray()); }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }
}
