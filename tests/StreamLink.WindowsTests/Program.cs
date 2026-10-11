using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using StreamLink;
using StreamLink.Core;
using StreamLink.Service;

static class Program
{
    static int count;
    static void Check(bool value, string reason) { if (!value) throw new Exception(reason); count++; }
    static T Field<T>(object value, string name) => (T)value.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(value)!;
    static async Task Lifecycle()
    {
        string root = Path.Combine(Path.GetTempPath(), "StreamLink-test-" + Guid.NewGuid().ToString("N"));
        Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT", Path.Combine(root, "profile"));
        Pairing saved;
        using (var worker = new ControlWorker()) {
            worker.StartLocal();
            var initial = await worker.Handle(new("status"));
            Check(!initial.Profile!.Enabled, "Fresh foreground backend unexpectedly enabled");
            Check(initial.PathSelectionVersion == 1, "Backend must advertise implemented policy capability independently of release number");
            var legacy = JsonSerializer.Deserialize<ControlReply>("{\"Ok\":true,\"Version\":\"0.4.1\"}")!;
            Check(legacy.PathSelectionVersion == 0, "Old same-version backend must not imply support for new policy fields");
            Check(!(await worker.Handle(new("start"))).Ok, "Unpaired start accepted");
            var reply = await worker.Handle(new("create", Service: "https://example.com/", Mode: "udp"));
            Check(reply.Ok && reply.Profile!.Pair!.Mode == "udp" && !reply.Profile.Enabled, "Create must persist without starting network");
            saved = reply.Profile!.Pair!;
            Check(!Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(ProfileStore.Root, "profile.dpapi"))).Contains(saved.Secret), "Profile secret stored in plaintext");
            var updated = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(reply.Profile))!;
            updated.DeviceName = "Lifecycle test"; updated.LogLevel = "off"; updated.TransportMode = "udp";
            Check((await worker.Handle(new("save", updated))).Ok, "Settings save failed");
            var changed = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(updated))!; changed.Slot = 2;
            Check(!(await worker.Handle(new("save", changed))).Ok, "Settings changed paired identity");
            Check(!(await worker.Handle(new("quality"))).Ok, "Disconnected quality test accepted");
            Check((await worker.Handle(new("stop"))).Ok, "Stop failed");
            bool locked = false; try { using var other = new ControlWorker(); } catch (IOException) { locked = true; }
            Check(locked, "Two backends acquired the same profile");
            await worker.StopLocal();
        }
        using (var worker = new ControlWorker()) {
            var reply = await worker.Handle(new("status"));
            Check(reply.Profile!.Pair == saved && reply.Profile.DeviceName == "Lifecycle test" && !reply.Profile.Enabled, "Persistence/lease release failed");
            reply = await worker.Handle(new("mesh-create", Service: "https://example.com/", Mode: "faketcp"));
            Check(reply.Ok && reply.Profile!.Mesh!.IsOwner && reply.Profile.Pair == null && !reply.Profile.Enabled, "Native creation must persist without changing live network");
            var selected = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(reply.Profile))!;
            selected.TransportMode = "faketcp"; selected.PathSelection = "faketcp-only"; selected.AllowUdpFallback = true;
            var applied = await worker.Handle(new("save", selected));
            Check(applied.Ok && applied.Profile!.Selection().Policy == PathPolicy.FakeTcpOnly && !applied.Profile.Enabled, "Control backend persists policy while leaving an idle network stopped");
            var unsupported = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(selected))!; unsupported.PathSelection = "auto-quality";
            Check(!(await worker.Handle(new("save", unsupported))).Ok && (await worker.Handle(new("status"))).Profile!.PathSelection == "faketcp-only", "Rejected AutoQuality cannot overwrite the valid saved policy");
            var udpNetwork = MeshIdentity.Create("https://example.com/", "", "udp");
            string meshInvite = MeshIdentity.Export(MeshIdentity.Issue(udpNetwork)), pairInvite = Pairing.Create("https://example.com/", "", "udp").Invite();
            byte[] beforeRejected = File.ReadAllBytes(Path.Combine(ProfileStore.Root, "profile.dpapi"));
            foreach (string command in new[] { "create", "join", "mesh-create", "mesh-join" }) {
                var rejected = await worker.Handle(new(command, Invite: command.StartsWith("mesh") ? meshInvite : pairInvite, Service: "https://example.com/", Mode: "udp"));
                Check(!rejected.Ok && rejected.Profile!.Mesh!.Pair.Network == selected.Mesh!.Pair.Network && beforeRejected.SequenceEqual(File.ReadAllBytes(Path.Combine(ProfileStore.Root, "profile.dpapi"))),
                    command + ": incompatible UDP request cannot replace identity or stored configuration before policy validation");
            }
            using (var oldSettings = new SettingsWindow(selected, supportsSelection: false))
                Check(!Field<ComboBox>(oldSettings, "selection").Enabled && !Field<CheckBox>(oldSettings, "udpFallback").Enabled, "UI disables unsupported settings on old backend");
            string backup = Directory.GetFiles(ProfileStore.Root, "profile-before-native-*.dpapi").Single();
            var restored = JsonSerializer.Deserialize<DeviceProfile>(ProtectedData.Unprotect(File.ReadAllBytes(backup), "StreamLink-profile-v2"u8.ToArray(), DataProtectionScope.LocalMachine))!;
            Check(restored.Pair == saved && restored.Mesh == null, "Legacy migration backup cannot restore the original pairing");
            reply = await worker.Handle(new("mesh-invite"));
            var member = MeshIdentity.Import(reply.Invite);
            Check(reply.Ok && member.Self.Slot == 2 && !member.IsOwner && reply.Profile!.Mesh!.Directory!.Members.Length == 2, "Native invitation lost independent member identity");
            Check(!(await worker.Handle(new("mesh-revoke", PeerSlot: 1))).Ok, "Administrator removed itself");
            Check((await worker.Handle(new("mesh-revoke", PeerSlot: 2))).Ok, "Single-member revocation failed");
            var changed = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(reply.Profile))!;
            changed.Mesh!.Self = member.Self;
            Check(!(await worker.Handle(new("save", changed))).Ok, "Settings replaced the native identity");
            reply = await worker.Handle(new("mesh-join", Invite: reply.Invite));
            Check(reply.Ok && !reply.Profile!.Mesh!.IsOwner, "Native member import failed");
            Check(!(await worker.Handle(new("mesh-invite"))).Ok, "Guest issued a new member credential");
            await worker.StopLocal();
        }
        string source = Path.Combine(root, "bundle"), parent = Path.Combine(root, "install"), destination = Path.Combine(parent, "candidate");
        Directory.CreateDirectory(source); File.WriteAllText(Path.Combine(source, "payload.bin"), "synthetic install payload");
        string manifest = Path.Combine(source, "manifest.json");
        void Manifest(string path, string hash) => File.WriteAllText(manifest, JsonSerializer.Serialize(new { version = typeof(MainWindow).Assembly.GetName().Version!.ToString(3) + "-preview", files = new[] { new { path, sha256 = hash } } }));
        string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(source, "payload.bin")))); Manifest("payload.bin", hash);
        var copy = typeof(ServiceInstaller).GetMethod("CopyBundle", BindingFlags.NonPublic | BindingFlags.Static)!;
        void Copy(string from, string to, string list) => copy.Invoke(null, [from, to, parent, list]);
        Copy(source, destination, manifest); Check(File.ReadAllText(Path.Combine(destination, "payload.bin")) == "synthetic install payload", "Bundle copy failed");
        Copy(destination, destination, Path.Combine(destination, "manifest.json")); count++; // idempotent install from installed directory
        Manifest("payload.bin", new string('0', 64)); bool invalid = false;
        try { Copy(source, destination, manifest); } catch (TargetInvocationException e) when (e.InnerException is IOException) { invalid = true; }
        Check(invalid, "Modified bundle accepted");
        Manifest("../outside.bin", hash); invalid = false;
        try { Copy(source, destination, manifest); } catch (TargetInvocationException e) when (e.InnerException is IOException) { invalid = true; }
        Check(invalid, "Manifest traversal accepted");
        string log = Path.Combine(root, "child.log");
        using (var job = new ChildJob()) {
            using var child = job.Start(Path.Combine(Environment.SystemDirectory, "cmd.exe"), ["/c", "echo configuration=SYNTHETIC_TEST_SECRET"], log, secrets: ["SYNTHETIC_TEST_SECRET"]);
            await child.WaitForExitAsync(); await Task.Delay(200);
        }
        Check(File.ReadAllText(log).Contains("[redacted]") && !File.ReadAllText(log).Contains("SYNTHETIC_TEST_SECRET"), "Child logs contain pairing secret");
        // Keep test artifacts in an isolated temporary directory; never touch SCM, drivers, routes or the live profile.
        Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT", null);
    }
    static async Task Feedback()
    {
        using var window = new MainWindow(); // Never Show: no status poll or backend is started.
        var method = typeof(MainWindow).GetMethod("Run", BindingFlags.NonPublic | BindingFlags.Instance)!;
        Task Run(string message, Func<Task<string>> action) => (Task)method.Invoke(window, [message, action])!;
        var pending = new TaskCompletionSource<string>();
        Task first = Run("正在测试忙碌反馈…", () => pending.Task);
        Check(Field<bool>(window, "busy"), "Busy not immediate");
        Check(Field<Label>(window, "notice").Text == "正在测试忙碌反馈…", "Pending feedback missing");
        Check(Field<List<Control>>(window, "actions").All(c => !c.Enabled), "Conflicting buttons still active");
        bool repeated = false;
        await Run("duplicate", () => { repeated = true; return Task.FromResult(""); });
        Check(!repeated, "Repeated action was executed");
        pending.SetResult("操作完成"); await first;
        Check(!Field<bool>(window, "busy") && Field<Label>(window, "notice").Text == "操作完成", "Success feedback not restored");
        Check(Field<List<Control>>(window, "actions").All(c => c.Enabled), "Buttons not restored after success");
        await Run("正在模拟失败…", () => throw new IOException("可重试的测试错误"));
        Check(!Field<bool>(window, "busy") && Field<Label>(window, "notice").Text == "可重试的测试错误", "Failure feedback missing");
        Check(Field<List<Control>>(window, "actions").All(c => c.Enabled), "Buttons not restored after failure");
    }
    [STAThread] static void Main()
    {
        ApplicationConfiguration.Initialize();
        using var host = new Form { ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new(-30000, -30000) };
        host.Shown += async (_, _) => {
            try { await Lifecycle(); await Feedback(); Console.WriteLine($"PASS {count}: isolated foreground lifecycle, DPAPI, mutual exclusion, bundle verification and UI busy/success/failure feedback. No live service/network changed."); }
            catch (Exception e) { Console.Error.WriteLine(e); Environment.ExitCode = 1; }
            finally { host.Close(); }
        };
        Application.Run(host);
    }
}
