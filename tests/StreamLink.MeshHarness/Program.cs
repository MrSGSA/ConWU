using System.Text.Json;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

// Explicit isolated integration harness. It never opens the installed control
// pipe or registers a Windows service. The caller supplies a private profile.
if (args.Length < 1) throw new ArgumentException("Expected prepare or run");
if (args[0] == "traversal-verdict-test" && args.Length == 2) { TraversalVerdict.Test(args[1]); return; }
if(args is ["traversal-negative-infrastructure",var negativeRoot]) {
    string negativeFolder=Path.GetFullPath(negativeRoot);if(Directory.Exists(negativeFolder))throw new IOException("Fresh negative evidence root required");Directory.CreateDirectory(negativeFolder);
    var port=new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback,0);port.Start();int number=((System.Net.IPEndPoint)port.LocalEndpoint).Port;port.Stop();
    var identity=MeshIdentity.Create($"https://127.0.0.1:{number}/",new string('A',64),"faketcp");MeshIdentity.Issue(identity);
    var node=new TraversalNode(new(){Mesh=identity,TraversalMode="tcp-udp",Enabled=true},"127.0.0.1","127.0.0.1","tcp","public",44411,44401,44402,2,
        LifetimeSeconds:30,MeasureLoad:false,ExpectedNoDirectPath:true);
    string config=Path.Combine(negativeFolder,"generated.private.json");File.WriteAllText(config,JsonSerializer.Serialize(node));
    try{await TraversalNetwork.Run(["traversal-run",config,Path.Combine(negativeFolder,"result.json")]);}
    finally{File.Delete(config);}
    return;
}
if (args[0].StartsWith("traversal-", StringComparison.Ordinal)) { await TraversalNetwork.Run(args); return; }
if (args[0] == "prepare") {
    string folder = Path.GetFullPath(args[1]); Directory.CreateDirectory(folder);
    var owner = MeshIdentity.Create(args[2], args.Length > 3 ? args[3] : "", "faketcp"); var guest = MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));
    guest.Directory = owner.Directory;
    var a = new DeviceProfile { Mesh = owner, DeviceName = "Native-test-Akane", ListenPort = 42780, SourcePort = 42791, Enabled = true };
    var b = new DeviceProfile { Mesh = guest, DeviceName = "Native-test-Thinkbook", ListenPort = 42780, SourcePort = 42791, Enabled = true };
    File.WriteAllText(Path.Combine(folder, "akane.private.json"), JsonSerializer.Serialize(a)); File.WriteAllText(Path.Combine(folder, "thinkbook.private.json"), JsonSerializer.Serialize(b));
    Console.WriteLine(JsonSerializer.Serialize(new { ownerIp = owner.LocalIp, guestIp = guest.LocalIp })); return;
}
if (args[0] == "measure") {
    if (args.Length != 7) throw new ArgumentException("measure private-profile.json peer-slot mbps seconds result.json timeout-seconds");
    var p = JsonSerializer.Deserialize<DeviceProfile>(File.ReadAllText(Path.GetFullPath(args[1])))!; p.Validate();
    var member = p.Mesh!.Directory!.Members.Single(m => m.Slot == int.Parse(args[2]));
    byte[] key = MeshIdentity.SharedKey(p.Mesh, member);
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(int.Parse(args[6])));
    try {
        var result = await Quality.Measure(MeshIdentity.Address(p.Mesh.Pair.Network, member.Slot), Convert.ToHexString(key), int.Parse(args[3]), deadline.Token, int.Parse(args[4]), p.Mesh.LocalIp);
        string json = JsonSerializer.Serialize(new { measuredAt = DateTimeOffset.Now, receiver = p.DeviceName, senderSlot = member.Slot, result }, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(Path.GetFullPath(args[5]), json); Console.WriteLine(json);
    } finally { CryptographicOperations.ZeroMemory(key); }
    return;
}
if (args[0] != "run" || args.Length < 4) throw new ArgumentException("run private-profile.json seconds result.json [measure-slot]");
string path = Path.GetFullPath(args[1]), output = Path.GetFullPath(args[3]);
string root = Path.Combine(Path.GetDirectoryName(path)!, "profile-" + Path.GetFileNameWithoutExtension(path));
Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT", root);
var store = new ProfileStore(); // Applies local administrator/SYSTEM ACL.
var profile = JsonSerializer.Deserialize<DeviceProfile>(File.ReadAllText(path))!; profile.Validate(); store.Save(profile);
using var timer = new CancellationTokenSource(TimeSpan.FromSeconds(int.Parse(args[2])));
// Exact per-run stop file permits graceful shutdown over SSH without touching
// the installed service. The independent deadline also cleans up after a lost SSH.
Task stopping = Task.Run(async () => {
    while (!timer.IsCancellationRequested) {
        if (File.Exists(output + ".stop")) { timer.Cancel(); break; }
        await Task.Delay(250, timer.Token);
    }
});
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
    try { await stopping; } catch (OperationCanceledException) { }
    File.WriteAllText(output, JsonSerializer.Serialize(new { startedAt = DateTimeOffset.Now.AddMilliseconds(-(Environment.TickCount64 - started)), connectedMs = connectedAt, status = latest, quality, error = failure }, new JsonSerializerOptions { WriteIndented = true }));
}
