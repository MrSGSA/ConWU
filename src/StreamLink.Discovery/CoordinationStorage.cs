using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Discovery;

// One owner for the complete registry, including offline maintenance. Never
// recover an older membership table automatically: that could undo revocation.
public static class CoordinationStorage
{
    public const int MaximumFileBytes = 64 * 1024 * 1024;
    public const int MaximumNetworks = 2048;
    public const string RestoreMarker = "restore-in-progress.json";
    public static readonly string[] Files = ["networks.json", "mesh-networks.json"];

    public static FileStream Acquire(string root, bool allowIncompleteRestore = false)
    {
        root = Path.GetFullPath(root);
        if (OperatingSystem.IsLinux()) LinuxPlatform.PrivateDirectory(root);
        else Directory.CreateDirectory(root);
        CheckPath(root);
        string path = Path.Combine(root, "coordinator.lock"); CheckPath(path);
        var lease = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try {
            string marker = Path.Combine(root, RestoreMarker); CheckPath(marker);
            if (!allowIncompleteRestore && (File.Exists(marker) || Directory.Exists(marker)))
                throw new IOException("上次协调数据恢复未完成，已停止启动以保护成员权限；请检查恢复记录并显式重新恢复备份");
            return lease;
        } catch { lease.Dispose(); throw; }
    }

    public static void CheckPath(string path)
    {
        for (var current = new FileInfo(Path.GetFullPath(path)); current != null; current = current.Directory == null ? null : new FileInfo(current.Directory.FullName)) {
            FileAttributes attributes;
            try { attributes = File.GetAttributes(current.FullName); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("协调数据路径不能经过链接");
        }
    }

    public static byte[] Read(string path, int maximum = MaximumFileBytes)
    {
        CheckPath(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > maximum) throw new CoordinationCapacityException();
        byte[] data = new byte[checked((int)stream.Length)]; stream.ReadExactly(data);
        return data;
    }

    public static Dictionary<string, T> Load<T>(string path, Action<string, T> validate)
    {
        CheckPath(path);
        if (Directory.Exists(path)) throw new IOException("协调记录路径被目录占用；原数据已保留");
        if (!File.Exists(path)) return [];
        return Decode(Read(path), validate);
    }

    public static Dictionary<string, T> Decode<T>(byte[] data, Action<string, T> validate)
    {
        // Enumerating properties explicitly also rejects duplicate network IDs.
        using var document = JsonDocument.Parse(data);
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new IOException("协调成员记录格式无效；原文件已保留");
        Dictionary<string, T> result = [];
        foreach (var property in document.RootElement.EnumerateObject()) {
            if (result.Count >= MaximumNetworks) throw new CoordinationCapacityException();
            var value = property.Value.Deserialize<T>() ?? throw new IOException("协调成员记录为空");
            validate(property.Name, value);
            if (!result.TryAdd(property.Name, value)) throw new IOException("协调成员记录包含重复网络 ID");
        }
        return result;
    }

    public static void Write<T>(string file, T value) => Atomic(file, stream => JsonSerializer.Serialize(stream, value));
    public static void WriteBytes(string file, byte[] data) => Atomic(file, stream => stream.Write(data));
    static void Atomic(string file, Action<Stream> write)
    {
        string temporary = file + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try {
            CheckPath(file);
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (OperatingSystem.IsLinux()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var output = new FileStream(temporary, options)) {
                using var bounded = new BoundedWriteStream(output, MaximumFileBytes);
                write(bounded); output.Flush(true);
            }
            File.Move(temporary, file, true);
        } catch (Exception ex) when (ex is not CoordinationCapacityException && (ex is IOException or UnauthorizedAccessException)) {
            throw new CoordinationWriteException(ex);
        } finally {
            try { if (File.Exists(temporary)) File.Delete(temporary); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* Preserve the primary write failure. */ }
        }
    }

    sealed class BoundedWriteStream(Stream inner, long maximum) : Stream
    {
        long written;
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer) {
            if (buffer.Length > maximum - written) throw new CoordinationCapacityException();
            inner.Write(buffer); written += buffer.Length;
        }
        public override void Flush() => inner.Flush();
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => written;
        public override long Position { get => written; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}

public sealed class CoordinationCapacityException() : IOException("协调存储已达到上限，请由服务管理员检查容量；现有成员记录保持不变");
public sealed class CoordinationWriteException(Exception inner) : IOException("协调记录写入失败，未确认本次变更；请检查存储权限和剩余空间", inner);
