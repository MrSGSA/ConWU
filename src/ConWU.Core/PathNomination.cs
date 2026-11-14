using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

public enum NominationStage { Checking, Prepared, Nominating, Confirming, Committing, Selected, Cancelled, Standby }

// Plain control bodies carried ONLY inside an authenticated MeshLink kind 7.
// One instance belongs to one actual receiving path, not its advertised endpoint.
// The router serializes access and performs the switch before transmitting Commit.
public sealed class PathNomination
{
    public const int FrameSize = 80;
    readonly TraversalAttemptContext context;
    readonly Guid path;
    readonly long revision, began;
    readonly TimeProvider time;
    readonly TimeSpan remaining;
    readonly byte[] digest, challenge = RandomNumberGenerator.GetBytes(16);
    byte[]? peerChallenge;
    bool checkedPeer, peerChecked, mtuQualified, everSwitch;
    long lastSent;
    bool sent;
    int cancelSends;
    readonly StandbyNomination? standby;
    NominationStage stage;
    public NominationStage Stage { get => standby?.Stage ?? stage; private set => stage = value; }
    public bool SwitchRequested => Stage is NominationStage.Committing or NominationStage.Selected;
    public bool PeerAdopted => Stage == NominationStage.Selected;
    public bool NeedsResync => standby?.NeedsResync ?? (Stage == NominationStage.Cancelled && everSwitch);
    public bool StandbyConfirmed => standby?.Confirmed == true;
    public long Revision => revision;
    public Guid PathId => path;
    public Guid AttemptId => context.AttemptId;
    public TimeSpan TimeLeft => standby?.TimeLeft ?? (remaining - time.GetElapsedTime(began));
    public PathNomination(TraversalAttemptContext context, Guid path, long revision, TimeSpan remaining,
        bool mtuQualified, TimeProvider? time = null)
    {
        int maximum = context.Profile == TraversalProfile.UdpDirect ? context.UdpExploration ? UdpProbeGroup.DurationMs : TraversalLimits.UdpRoundMs : TraversalLimits.SoRoundMs;
        if (path == Guid.Empty || revision <= 0 || remaining <= TimeSpan.Zero || remaining > TimeSpan.FromMilliseconds(maximum))
            throw new ArgumentException("提名路径、版本或剩余期限无效");
        this.context = context; this.path = path; this.revision = revision; this.remaining = remaining;
        this.time = time ?? TimeProvider.System; began = this.time.GetTimestamp(); this.mtuQualified = mtuQualified;
        digest = ContextDigest(context);
        if (context.Standby) standby = new(context, path, revision, remaining, mtuQualified, this.time);
    }
    public static byte[] ContextDigest(TraversalAttemptContext c)
    {
        if (string.IsNullOrWhiteSpace(c.NetworkId) || c.NetworkId.Length > 128 || string.IsNullOrWhiteSpace(c.LocalNodeId) || c.LocalNodeId.Length > 128 ||
            string.IsNullOrWhiteSpace(c.RemoteNodeId) || c.RemoteNodeId.Length > 128 || c.LocalNodeId == c.RemoteNodeId || c.LocalBootId == Guid.Empty ||
            c.RemoteBootId == Guid.Empty || c.AttemptId == Guid.Empty || c.LocalCandidateId == Guid.Empty || c.RemoteCandidateId == Guid.Empty ||
            c.LocalCandidateVersion <= 0 || c.RemoteCandidateVersion <= 0 || c.ValidationNonce == Guid.Empty || !Enum.IsDefined(c.Profile) ||
            c.UdpExploration && c.Profile != TraversalProfile.UdpDirect || c.Standby &&
                (c.UdpExploration || c.Profile is not (TraversalProfile.FakeTcpHttpSo or TraversalProfile.UdpDirect)))
            throw new ArgumentException("提名上下文不完整");
        object Local() => new { node = c.LocalNodeId, boot = c.LocalBootId, candidate = c.LocalCandidateId, version = c.LocalCandidateVersion, client = c.ProtocolClient, nominator = c.Nominator };
        object Remote() => new { node = c.RemoteNodeId, boot = c.RemoteBootId, candidate = c.RemoteCandidateId, version = c.RemoteCandidateVersion, client = !c.ProtocolClient, nominator = !c.Nominator };
        bool first = string.CompareOrdinal(c.LocalNodeId, c.RemoteNodeId) < 0;
        if (c.Standby) return SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { domain = "streamlink-path-standby-v1", c.NetworkId,
            a = first ? Local() : Remote(), b = first ? Remote() : Local(), c.AttemptId, c.Profile, c.ValidationNonce }));
        // The ordinary digest remains byte-for-byte compatible. Only negotiated
        // exploration has a distinct domain and its extended shared deadline.
        return SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { domain = c.UdpExploration ? "streamlink-path-nomination-udp-exploration-v1" : "streamlink-path-nomination-v1", c.NetworkId,
            a = first ? Local() : Remote(), b = first ? Remote() : Local(), c.AttemptId, c.Profile, c.ValidationNonce }));
    }
    byte[] Frame(byte kind, bool echo = true)
    {
        byte[] frame = new byte[FrameSize]; "SLN1"u8.CopyTo(frame); frame[4] = kind;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(6), FrameSize);
        BinaryPrimitives.WriteInt64BigEndian(frame.AsSpan(8), revision); digest.CopyTo(frame, 16); challenge.CopyTo(frame, 48);
        if (echo && peerChallenge != null) peerChallenge.CopyTo(frame, 64);
        return frame;
    }
    public void QualifyMtu() { if (standby != null) { standby.QualifyMtu(); return; } if (Stage != NominationStage.Cancelled && TimeLeft > TimeSpan.Zero) mtuQualified = true; }
    public void AllowStandbySelection() => (standby ?? throw new InvalidOperationException("Path did not negotiate standby")).AllowSelection();
    public bool SelectStandby() => standby?.Select() == true;
    void Prepare()
    {
        if (Stage == NominationStage.Checking && checkedPeer && peerChecked && mtuQualified) Stage = NominationStage.Prepared;
    }
    public byte[][] Tick()
    {
        if (standby != null) return standby.Tick();
        if (TimeLeft <= TimeSpan.Zero && Stage is not (NominationStage.Selected or NominationStage.Cancelled)) Cancel();
        if (Stage == NominationStage.Cancelled) {
            // Bounded cleanup notices after expiry; must still use global control
            // quota. This does not extend the authentication/nomination window.
            if (cancelSends >= 3 || TimeLeft < TimeSpan.FromSeconds(-1)) return [];
        } else if (TimeLeft <= TimeSpan.Zero) return [];
        if (sent && time.GetElapsedTime(lastSent).TotalMilliseconds < 250) return [];
        sent = true; lastSent = time.GetTimestamp(); Prepare();
        if (Stage == NominationStage.Cancelled) { cancelSends++; return [Frame(7)]; }
        if (Stage == NominationStage.Prepared && context.Nominator) Stage = NominationStage.Nominating;
        return Stage switch {
            NominationStage.Checking or NominationStage.Prepared => [Frame(1, false)],
            NominationStage.Nominating => [Frame(3)],
            NominationStage.Confirming => [Frame(4)],
            NominationStage.Committing => [Frame(5)],
            // Repeat final evidence until deadline. No business retransmission.
            NominationStage.Selected => context.Nominator ? [Frame(5)] : [Frame(6)],
            _ => []
        };
    }
    public void Cancel() { if (standby != null) { standby.Cancel(); return; } if (Stage == NominationStage.Cancelled) return; everSwitch |= SwitchRequested; Stage = NominationStage.Cancelled; sent = false; }
    public byte[][] Receive(Guid actualPath, ReadOnlySpan<byte> message)
    {
        if (standby != null) return standby.Receive(actualPath, message);
        if (actualPath != path || message.Length != FrameSize || !message[..4].SequenceEqual("SLN1"u8) || message[4] is < 1 or > 7 || message[5] != 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(message[6..]) != FrameSize || BinaryPrimitives.ReadInt64BigEndian(message[8..]) != revision ||
            !CryptographicOperations.FixedTimeEquals(message.Slice(16, 32), digest) || message.Slice(48, 16).IndexOfAnyExcept((byte)0) < 0) return [];
        if (Stage == NominationStage.Cancelled) return []; // no late message can revive it
        byte kind = message[4];
        if (TimeLeft <= TimeSpan.Zero && kind != 7) return [];
        if (kind == 7) {
            if (TimeLeft >= TimeSpan.FromSeconds(-2)) Cancel();
            return [];
        }
        var theirs = message.Slice(48, 16);
        if (peerChallenge != null && !theirs.SequenceEqual(peerChallenge)) return [];
        if (kind != 1 && !message.Slice(64, 16).SequenceEqual(challenge)) return [];
        peerChallenge ??= theirs.ToArray();
        if (kind == 1) { peerChecked = true; Prepare(); return [Frame(2)]; }
        if (kind == 2) { checkedPeer = true; Prepare(); return []; }
        Prepare();
        if (Stage == NominationStage.Checking) return [];
        if (kind == 3 && !context.Nominator) {
            if (Stage is NominationStage.Prepared or NominationStage.Confirming) Stage = NominationStage.Confirming;
            return Stage == NominationStage.Confirming ? [Frame(4)] : Stage == NominationStage.Selected ? [Frame(6)] : [];
        }
        if (kind == 4 && context.Nominator && Stage is NominationStage.Nominating or NominationStage.Committing or NominationStage.Selected) {
            if (Stage != NominationStage.Selected) Stage = NominationStage.Committing;
            everSwitch = true; return [Frame(5)];
        }
        if (kind == 5 && !context.Nominator && Stage is NominationStage.Confirming or NominationStage.Selected) {
            Stage = NominationStage.Selected; everSwitch = true; return [Frame(6)];
        }
        if (kind == 6 && context.Nominator && Stage is NominationStage.Committing or NominationStage.Selected) {
            Stage = NominationStage.Selected; return [];
        }
        return [];
    }
}
