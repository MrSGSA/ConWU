using System.Buffers.Binary;
using System.Security.Cryptography;

namespace StreamLink.Core;

// Approval is authenticated by the enclosing MeshLink and belongs to this
// comparison and standby context. It does not replace in-path nomination.
internal sealed class PathQualityAgreement
{
    internal const int FrameSize = 112, ApprovalMs = 8000;
    readonly Guid session;
    readonly int target;
    readonly byte[] scope, evidence;
    readonly long began;
    long lastSent, selectionAt;
    int sends;
    public bool LocalApproved { get; private set; }
    public bool PeerApproved { get; private set; }
    public bool LocalHardFailure { get; private set; }
    public bool PeerHardFailure { get; private set; }
    public bool SelectionStarted => selectionAt != 0;
    public PathQualityAgreement(Guid session, int target, byte[] scope, string digest, long now)
    {
        if (session == Guid.Empty || target is < 1 or > 50 || scope.Length != 32) throw new ArgumentException("Invalid quality comparison");
        evidence = Convert.FromHexString(digest);
        if (evidence.Length != 32) throw new ArgumentException("Invalid quality evidence digest");
        this.session = session; this.target = target; this.scope = scope.ToArray(); began = now;
    }
    public static bool IsControl(ReadOnlySpan<byte> p) => p.StartsWith("SQV1"u8);
    public bool Open(long now) => now >= began && now - began <= ApprovalMs;
    public bool Authorized(long now) => LocalApproved && PeerApproved &&
        (SelectionStarted ? now >= selectionAt && now - selectionAt <= ApprovalMs : Open(now));
    public void Approve(long now, bool hardFailure)
    {
        if (!Open(now)) return;
        LocalApproved = true; LocalHardFailure |= hardFailure;
    }
    public bool BeginSelection(long now)
    {
        if (!Authorized(now)) return false;
        if (!SelectionStarted) selectionAt = now;
        return true;
    }
    public bool Receive(ReadOnlySpan<byte> p, long now)
    {
        if (!Open(now) || p.Length != FrameSize || !IsControl(p) || p[4] != 1 || p[5] != 1 || p[6] > 1 || p[7] != 0 ||
            new Guid(p.Slice(8, 16)) != session || !CryptographicOperations.FixedTimeEquals(p.Slice(24, 32), scope) ||
            BinaryPrimitives.ReadInt32BigEndian(p[56..]) != target || p.Slice(60, 4).IndexOfAnyExcept((byte)0) >= 0 ||
            !CryptographicOperations.FixedTimeEquals(p.Slice(64, 32), evidence) || p[96..].IndexOfAnyExcept((byte)0) >= 0) return false;
        PeerApproved = true; PeerHardFailure |= p[6] == 1; return true;
    }
    public byte[]? Tick(long now)
    {
        if (!LocalApproved || !Open(now) || sends >= 17 || sends != 0 && now - lastSent < 500) return null;
        var p = new byte[FrameSize]; "SQV1"u8.CopyTo(p); p[4] = p[5] = 1; p[6] = LocalHardFailure ? (byte)1 : (byte)0;
        session.TryWriteBytes(p.AsSpan(8)); scope.CopyTo(p, 24); BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(56), target); evidence.CopyTo(p, 64);
        lastSent = now; sends++; return p;
    }
}
