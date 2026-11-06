using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Discovery;

// Offline only. A snapshot has signed membership records and auth hashes, not
// device private keys, TLS keys, profile settings or ephemeral pairing rooms.
public static class CoordinationBackup
{
    public sealed record Entry(string Name, int Length, string Sha256);
    public sealed record Manifest(int Format, DateTimeOffset CreatedAt, Entry[] Files);
    public sealed record RestoreResult(string PreviousSnapshot, string DataDirectory);
    const int MaximumArchiveBytes = CoordinationStorage.MaximumFileBytes * 2 + 1024 * 1024;

    public static Manifest Inspect(string archive) => Open(archive).Manifest;

    public static Manifest Create(string root, string archive)
    {
        using var lease = CoordinationStorage.Acquire(root);
        return CreateSnapshot(root, archive);
    }

    static Manifest CreateSnapshot(string root, string archive, bool validateMembership = true)
    {
        var files = new Dictionary<string, byte[]>();
        foreach (var name in CoordinationStorage.Files) {
            string path = Path.Combine(root, name);
            CoordinationStorage.CheckPath(path);
            if (Directory.Exists(path)) throw new IOException("协调记录路径被目录占用，请先保留并检查该目录");
            if (File.Exists(path)) { var bytes = CoordinationStorage.Read(path); if (validateMembership) Validate(name, bytes); files.Add(name, bytes); }
        }
        var manifest = new Manifest(1, DateTimeOffset.UtcNow, files.Select(p => new Entry(p.Key, p.Value.Length, Convert.ToHexString(SHA256.HashData(p.Value)))).ToArray());
        CoordinationStorage.CheckPath(archive);
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (OperatingSystem.IsLinux()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        bool created = false;
        try {
            using var output = new FileStream(archive, options); created = true;
            using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true)) {
                using (var target = zip.CreateEntry("manifest.json").Open()) JsonSerializer.Serialize(target, manifest);
                foreach (var pair in files) { using var target = zip.CreateEntry(pair.Key, CompressionLevel.Fastest).Open(); target.Write(pair.Value); }
            }
            output.Flush(true);
        } catch { if (created) File.Delete(archive); throw; }
        return manifest;
    }

    static (Manifest Manifest, Dictionary<string, byte[]> Files) Open(string archive)
    {
        CoordinationStorage.CheckPath(archive);
        using var input = new FileStream(archive, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length > MaximumArchiveBytes) throw new IOException("协调备份超过大小上限");
        using var zip = new ZipArchive(input, ZipArchiveMode.Read);
        if (zip.Entries.Count is < 1 or > 3 || zip.Entries.Select(e => e.FullName).Distinct(StringComparer.Ordinal).Count() != zip.Entries.Count)
            throw new IOException("协调备份文件清单无效");
        var manifestEntry = zip.GetEntry("manifest.json") ?? throw new IOException("缺少协调备份清单");
        var manifest = JsonSerializer.Deserialize<Manifest>(ReadEntry(manifestEntry, 8192)) ?? throw new IOException("协调备份清单为空");
        if (manifest.Format != 1 || manifest.Files == null || manifest.Files.Length > 2 || manifest.Files.Any(e => e == null) ||
            manifest.Files.Select(e => e.Name).Distinct(StringComparer.Ordinal).Count() != manifest.Files.Length || zip.Entries.Count != manifest.Files.Length + 1)
            throw new IOException("不支持此协调备份格式");
        var files = new Dictionary<string, byte[]>();
        foreach (var entry in manifest.Files) {
            if (!CoordinationStorage.Files.Contains(entry.Name, StringComparer.Ordinal) || entry.Length is < 2 or > CoordinationStorage.MaximumFileBytes)
                throw new IOException("协调备份包含未知文件或无效长度");
            var bytes = ReadEntry(zip.GetEntry(entry.Name) ?? throw new IOException("协调备份缺少记录"), entry.Length);
            if (bytes.Length != entry.Length || Convert.ToHexString(SHA256.HashData(bytes)) != entry.Sha256)
                throw new IOException("协调备份校验失败，当前记录未修改");
            Validate(entry.Name, bytes); files.Add(entry.Name, bytes);
        }
        return (manifest, files);
    }

    static byte[] ReadEntry(ZipArchiveEntry entry, int maximum)
    {
        if (entry.Length > maximum || entry.Length < 0) throw new IOException("协调备份解压大小超过上限");
        byte[] bytes = new byte[checked((int)entry.Length)];
        using var stream = entry.Open(); stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new IOException("协调备份解压长度不符");
        return bytes;
    }

    static void Validate(string name, byte[] data)
    {
        if (name == "mesh-networks.json") CoordinationStorage.Decode<MeshRegistry.Registration>(data, MeshRegistry.ValidateStored);
        else CoordinationStorage.Decode<CoordinationHost.Registration>(data, CoordinationHost.ValidateStored);
    }

    public static RestoreResult Restore(string root, string archive, bool confirmRollback)
    {
        if (!confirmRollback) throw new IOException("恢复可能撤销备份之后的审批、移除和解散记录；请停用协调服务，并明确确认权限回滚风险");
        var snapshot = Open(archive); // Fully validate before changing anything.
        using var lease = CoordinationStorage.Acquire(root, allowIncompleteRestore: true);
        string marker = Path.Combine(root, CoordinationStorage.RestoreMarker);
        string previous;
        if (File.Exists(marker)) {
            // Preserve the original recovery point after an interrupted restore.
            using var record = JsonDocument.Parse(CoordinationStorage.Read(marker, 8192));
            previous = record.RootElement.GetProperty("PreviousSnapshot").GetString() ?? throw new IOException("恢复记录不完整");
        } else {
            previous = Path.Combine(Path.GetFullPath(root), "before-restore-" + Guid.NewGuid().ToString("N") + ".slcoord");
            // A damaged current registry must not prevent recovery from a good
            // snapshot. Preserve its original bytes, even if it cannot validate.
            CreateSnapshot(root, previous, validateMembership: false);
            CoordinationStorage.Write(marker, new { PreviousSnapshot = previous, StartedAt = DateTimeOffset.UtcNow });
        }
        // The marker blocks all starts until both files are replaced. A crash
        // never silently starts a registry assembled from two different epochs.
        foreach (string name in CoordinationStorage.Files) {
            string path = Path.Combine(root, name); CoordinationStorage.CheckPath(path);
            if (snapshot.Files.TryGetValue(name, out var data)) CoordinationStorage.WriteBytes(path, data);
            else File.Delete(path);
        }
        File.Delete(marker);
        return new(previous, Path.GetFullPath(root));
    }
}
