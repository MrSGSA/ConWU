using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

// A bounded, authenticated metadata lane shared by coordinated and direct
// networks. Only the original issuer can change membership or an announcement.
// All calls belong to the runner loop; no IO or callbacks occur under its lock.
public sealed class MeshPeerSynchronization : IDisposable
{
    const int Chunk = 1200, Maximum = 49152, Header = 24;
    readonly MeshProfile profile;
    MeshDirectory? directory;
    readonly Dictionary<int, MeshEnvelope> nodes = [];
    readonly Dictionary<int, Assembly> incoming = [];
    readonly Dictionary<int, Outbound> outgoing = [];
    readonly Dictionary<int, long> nextSend = [];
    MeshRouter? router;
    public long Version { get; private set; }
    public long DirectoryRevision => directory?.Revision ?? 0;
    sealed class Assembly(Guid id, int length, long expires)
    {
        public readonly Guid Id = id;
        public readonly byte[] Data = new byte[length];
        public readonly bool[] Seen = new bool[(length + Chunk - 1) / Chunk];
        public readonly long Expires = expires;
        public int Count;
    }
    sealed class Outbound(byte[][] frames, long expires)
    {
        public readonly byte[][] Frames = frames;
        public readonly long Expires = expires;
        public int Index;
    }
    public MeshPeerSynchronization(MeshProfile profile)
    {
        profile.Validate(); this.profile = profile;
        if (profile.Directory is {} known) SetDirectory(known);
    }
    public void Attach(MeshRouter value) => router = value;
    public void SetDirectory(MeshDirectory value)
    {
        MeshIdentity.ValidateDirectory(value, profile.Pair.Network, profile.OwnerKey);
        if (directory != null) {
            if (value.Revision < directory.Revision) return;
            MeshIdentity.ValidateSuccessor(value, directory);
            if (value.Revision == directory.Revision) return;
        }
        directory = value; Version++; nextSend.Clear(); outgoing.Clear();
        foreach (int slot in nodes.Keys.ToArray())
            if (!value.Members.Any(m => m.Slot == slot && m.Device == nodes[slot].Device)) nodes.Remove(slot);
        foreach (int slot in incoming.Keys.ToArray())
            if (!value.Members.Any(m => m.Slot == slot)) incoming.Remove(slot);
    }
    public void Publish(MeshAnnouncement announcement)
    {
        nodes[profile.Self.Slot] = MeshMetadata.Seal(profile, announcement); Version++;
    }
    public MeshSnapshot? Read() => directory == null ? null : new(directory, FreshNodes());
    MeshEnvelope[] FreshNodes()
    {
        var result = new List<MeshEnvelope>();
        if (directory != null) foreach (var member in directory.Members)
            if (nodes.TryGetValue(member.Slot, out var envelope))
                try { MeshMetadata.Open(profile, member, envelope); result.Add(envelope); }
                catch (Exception ex) when (ex is FormatException or CryptographicException or JsonException) { }
        return result.ToArray();
    }
    public void Merge(MeshSnapshot snapshot)
    {
        if (snapshot.Directory == null || snapshot.Nodes is not { Length: <= MeshIdentity.MaxMembers } || snapshot.Nodes.Any(n => n == null))
            throw new FormatException("同步成员无效");
        // Install the signed high-water mark even if individual announcements
        // are invalid. Old snapshots can update only still-authorized members.
        SetDirectory(snapshot.Directory);
        foreach (var envelope in snapshot.Nodes) {
            var member = directory!.Members.FirstOrDefault(m => m.Slot == envelope.Slot);
            if (member == null || !snapshot.Directory.Members.Contains(member) || member.Slot == profile.Self.Slot) continue;
            try { MeshMetadata.Open(profile, member, envelope); }
            catch (Exception ex) when (ex is FormatException or CryptographicException or JsonException) { continue; }
            if (envelope.Revision <= (nodes.GetValueOrDefault(member.Slot)?.Revision ?? 0)) continue;
            nodes[member.Slot] = envelope; Version++;
        }
    }
    public void Tick(long now)
    {
        if (router == null || directory == null) return;
        foreach (int slot in incoming.Where(p => p.Value.Expires < now).Select(p => p.Key).ToArray()) incoming.Remove(slot);
        foreach (var frame in router.DrainSynchronization()) {
            if (!directory.Members.Any(m => m.Slot == frame.Slot)) continue;
            try { Receive(frame, now); }
            catch (Exception ex) when (ex is FormatException or CryptographicException or JsonException or ArgumentException) { incoming.Remove(frame.Slot); }
        }
        foreach (int slot in directory.Members.Where(m => m.Slot != profile.Self.Slot).Select(m => m.Slot)) {
            if (!router.HasHealthyPath(slot)) { outgoing.Remove(slot); nextSend.Remove(slot); continue; }
            if (outgoing.TryGetValue(slot, out var pending) && pending.Expires < now) { outgoing.Remove(slot); pending = null; }
            if (pending == null && now >= nextSend.GetValueOrDefault(slot)) {
                outgoing[slot] = pending = new(Frames(new(directory, FreshNodes())), now + 10000);
                nextSend[slot] = now + 10000;
            }
            if (pending != null && router.SendSynchronization(slot, pending.Frames[pending.Index]) && ++pending.Index == pending.Frames.Length) outgoing.Remove(slot);
        }
    }
    static byte[][] Frames(MeshSnapshot snapshot)
    {
        byte[] data = JsonSerializer.SerializeToUtf8Bytes(snapshot);
        if (data.Length > Maximum) throw new FormatException("成员同步超过大小限制");
        var id = Guid.NewGuid(); int count = (data.Length + Chunk - 1) / Chunk; var result = new byte[count][];
        for (int i = 0; i < count; i++) {
            int size = Math.Min(Chunk, data.Length - i * Chunk); var frame = new byte[Header + size]; id.TryWriteBytes(frame);
            BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(16), data.Length); BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(20), i);
            data.AsSpan(i * Chunk, size).CopyTo(frame.AsSpan(Header)); result[i] = frame;
        }
        return result;
    }
    public static byte[][] DirectoryFrames(MeshDirectory directory) => Frames(new(directory, []));
    void Receive(MeshSyncFrame frame, long now)
    {
        byte[] bytes = frame.Payload;
        if (bytes.Length < Header) return;
        var id = new Guid(bytes.AsSpan(0, 16));
        int length = BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(16)), index = BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(20));
        if (id == Guid.Empty || length is < 1 or > Maximum || index < 0 || index >= (length + Chunk - 1) / Chunk || bytes.Length != Header + Math.Min(Chunk, length - index * Chunk)) return;
        if (!incoming.TryGetValue(frame.Slot, out var assembly) || assembly.Id != id) incoming[frame.Slot] = assembly = new(id, length, now + 10000);
        if (assembly.Data.Length != length || assembly.Seen[index]) return;
        bytes.AsSpan(Header).CopyTo(assembly.Data.AsSpan(index * Chunk)); assembly.Seen[index] = true;
        if (++assembly.Count != assembly.Seen.Length) return;
        incoming.Remove(frame.Slot);
        Merge(JsonSerializer.Deserialize<MeshSnapshot>(assembly.Data) ?? throw new FormatException("同步内容为空"));
    }
    public void Dispose() { incoming.Clear(); outgoing.Clear(); nodes.Clear(); nextSend.Clear(); router = null; }
}
