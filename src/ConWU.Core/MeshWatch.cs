using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

// The network bearer alone is insufficient to occupy another member's waiter.
// Every wait is additionally signed by that member, with a short replay window.
public sealed record MeshWatchRequest(int Slot, string Device, Guid BootId, Guid RequestId,
    Guid ServerEpoch, long After, long Expires, string Signature);
public sealed record MeshChange(long Cursor, string Kind, int Slot, int TargetSlot = 0);
public sealed record MeshWatchResponse(Guid ServerEpoch, long Cursor, bool Reset,
    MeshChange[] Changes, MeshSnapshot Snapshot);
public static class MeshWatch
{
    static byte[] Signed(string network, MeshWatchRequest r) => JsonSerializer.SerializeToUtf8Bytes(new {
        domain = "streamlink-mesh-watch-v1", network, r.Slot, r.Device, r.BootId, r.RequestId, r.ServerEpoch, r.After, r.Expires });
    public static MeshWatchRequest Create(MeshProfile profile, Guid boot, Guid epoch, long after)
    {
        var request = new MeshWatchRequest(profile.Self.Slot, profile.Self.Device, boot, Guid.NewGuid(), epoch, after,
            DateTimeOffset.UtcNow.AddSeconds(40).ToUnixTimeSeconds(), "");
        return request with { Signature = MeshIdentity.Sign(profile.SigningPrivate, Signed(profile.Pair.Network, request)) };
    }
    public static bool Validate(string network, MeshMember member, MeshWatchRequest r, long? observedUnixSeconds = null)
    {
        long now = observedUnixSeconds ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return r.Slot == member.Slot && r.Device == member.Device && r.BootId != Guid.Empty && r.RequestId != Guid.Empty &&
            r.After >= 0 && r.Expires > now && r.Expires <= now + 45 && r.Signature is { Length: > 0 and < 256 } &&
            MeshIdentity.Verify(member.SigningKey, Signed(network, r), r.Signature);
    }
}

public interface IMeshChangeDiscovery
{
    bool SupportsLongPolling { get; }
    Task<MeshSnapshot?> WaitForChanges(CancellationToken token);
}
