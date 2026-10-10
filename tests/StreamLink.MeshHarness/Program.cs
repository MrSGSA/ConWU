using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

// Explicit isolated integration harness. It never opens the installed control
// pipe or registers a Windows service. The caller supplies a private profile.
if (args.Length < 1) throw new ArgumentException("Expected prepare or run");
if (args[0] == "prepare") {
    string folder = Path.GetFullPath(args[1]); Directory.CreateDirectory(folder);
    var owner = MeshIdentity.Create(args[2], "", "faketcp"); var guest = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));
    var a = new DeviceProfile { Mesh = owner, DeviceName = "Native-test-Akane", ListenPort = 42780, SourcePort = 42791, Enabled = true };
    var b = new DeviceProfile { Mesh = guest, DeviceName = "Native-test-Thinkbook", ListenPort = 42780, SourcePort = 42791, Enabled = true };
    File.WriteAllText(Path.Combine(folder, "akane.private.json"), JsonSerializer.Serialize(a)); File.WriteAllText(Path.Combine(folder, "thinkbook.private.json"), JsonSerializer.Serialize(b));
    Console.WriteLine(JsonSerializer.Serialize(new { ownerIp = owner.LocalIp, guestIp = guest.LocalIp })); return;
}
if (args[0] != "run" || args.Length < 4) throw new ArgumentException("run private-profile.json seconds result.json [measure-slot]");
string path = Path.GetFullPath(args[1]), output = Path.GetFullPath(args[3]);
string root = Path.Combine(Path.GetDirectoryName(path)!, "profile-" + Path.GetFileNameWithoutExtension(path));
Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT", root);
var store = new ProfileStore(); // Applies local administrator/SYSTEM ACL.
var profile = JsonSerializer.Deserialize<DeviceProfile>(File.ReadAllText(path))!; profile.Validate(); store.Save(profile);
using var timer = new CancellationTokenSource(TimeSpan.FromSeconds(int.Parse(args[2])));
long started = Environment.TickCount64, connectedAt = 0;
SessionStatus? latest = null; QualityResult? quality = null; string failure = "";
var runner = new MeshRunner(profile, line => Console.WriteLine(DateTime.Now.ToString("HH:mm:ss ") + line), status => { latest = status; if (status.Connected && connectedAt == 0) { connectedAt = Environment.TickCount64 - started; Console.WriteLine("Connected in " + connectedAt + " ms"); } }, _ => { });
Task running = runner.Run(timer.Token);
try {
    if (args.Length > 4) {
        while (latest?.Connected != true) { if (running.IsCompleted) await running; await Task.Delay(300, timer.Token); }
        await Task.Delay(3000, timer.Token);
        quality = await runner.Measure(50, int.Parse(args[4]), timer.Token);
        Console.WriteLine(JsonSerializer.Serialize(quality));
    }
    await running;
} catch (OperationCanceledException) when (timer.IsCancellationRequested) { }
catch (Exception ex) { failure = ex.ToString(); Console.Error.WriteLine(failure); Environment.ExitCode = 1; }
finally {
    timer.Cancel(); try { await running; } catch (OperationCanceledException) { } catch (Exception ex) { failure = ex.ToString(); Environment.ExitCode = 1; }
    File.WriteAllText(output, JsonSerializer.Serialize(new { startedAt = DateTimeOffset.Now.AddMilliseconds(-(Environment.TickCount64 - started)), connectedMs = connectedAt, status = latest, quality, error = failure }, new JsonSerializerOptions { WriteIndented = true }));
}
