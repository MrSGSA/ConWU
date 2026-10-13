using System.Diagnostics;
using System.Text.Json;

namespace StreamLink.Core;

internal static class LegacyNativeCapabilities
{
    static readonly object gate = new();
    static readonly Dictionary<string, (long Size, DateTime At)> ready = [];
    internal static void Require(string binary)
    {
        var file = new FileInfo(binary);
        lock (gate) {
            if (ready.TryGetValue(file.FullName, out var old) && old.Size == file.Length && old.At == file.LastWriteTimeUtc) return;
            var info = new ProcessStartInfo(file.FullName) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            info.ArgumentList.Add("--native-info");
            using var process = Process.Start(info) ?? throw new IOException("Native capability process could not start");
            var output = process.StandardOutput.ReadToEndAsync(); var errors = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(3000)) { process.Kill(); throw new IOException("Native compatibility capability query timed out"); }
            string json = output.GetAwaiter().GetResult(); errors.GetAwaiter().GetResult();
            if (process.ExitCode != 0 || json.Length > 4096) throw new IOException("Native compatibility capability query rejected");
            using var parsed = JsonDocument.Parse(json);
            if (!parsed.RootElement.TryGetProperty("legacyControl", out var control) || control.ValueKind != JsonValueKind.Number || control.GetInt32() != 1)
                throw new NotSupportedException("Native component does not support authenticated compatibility control; verify the matching software bundle");
            if (ready.Count >= 32) ready.Clear();
            ready[file.FullName] = (file.Length, file.LastWriteTimeUtc);
        }
    }
    internal static void RequireEgress(string binary)
    {
        Require(binary);
        var info=new ProcessStartInfo(binary){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true};info.ArgumentList.Add("--native-info");
        using var process=Process.Start(info)??throw new IOException("Native egress query failed");var output=process.StandardOutput.ReadToEndAsync();
        if(!process.WaitForExit(3000)){process.Kill();throw new IOException("Native egress query timed out");}
        using var parsed=JsonDocument.Parse(output.GetAwaiter().GetResult());
        if(process.ExitCode!=0||!parsed.RootElement.TryGetProperty("legacyEgress",out var cap)||cap.GetInt32()!=1)throw new NotSupportedException("Native compatibility egress capability unavailable");
    }
}
