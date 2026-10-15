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
            Check(initial.TcpCalibrationVersion == 1 && !initial.Profile.TcpPortCalibration, "Calibration capability is explicit and new profiles remain opted out");
            Check(initial.TcpPredictionVersion == 1 && !initial.Profile.TcpPortPrediction, "Conditional TCP prediction is separately advertised and default off");
            Check(initial.TcpPeerReflexiveVersion == 1 && !initial.Profile.TcpPeerReflexive, "Source learning has independent backend capability and remains default off");
            var legacy = JsonSerializer.Deserialize<ControlReply>("{\"Ok\":true,\"Version\":\"0.4.1\"}")!;
            Check(legacy.PathSelectionVersion == 0, "Old same-version backend must not imply support for new policy fields");
            Check(legacy.TcpCalibrationVersion == 0, "Old backend JSON does not imply support for calibration");
            Check(legacy.TcpPredictionVersion == 0, "Old backend JSON does not imply support for predicted paths");
            Check(legacy.TcpPeerReflexiveVersion == 0, "Old backend JSON does not imply support for source learning");
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
            var calibrationProfile = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(selected))!;
            calibrationProfile.TraversalMode = "tcp"; calibrationProfile.TcpSynObservation = true;
            // Exercise explicit opt-in from an off state in either edition;
            // the personal creation preset independently enables source learning.
            calibrationProfile.TcpPeerReflexive = false;
            calibrationProfile.CapabilityIntents[nameof(DeviceProfile.TcpPeerReflexive)] = false;
            using (var calibrationSettings = new SettingsWindow(calibrationProfile)) {
                var box = Field<CheckBox>(calibrationSettings, "tcpCalibration");
                var predicted = Field<CheckBox>(calibrationSettings, "tcpPrediction");
                Check(!predicted.Enabled && !predicted.Checked, "Prediction requires explicit calibration, not just observer capability");
                Check(box.Enabled && !box.Checked, "Calibration requires both managed TCP and observer; default remains unchecked");
                box.Checked = true; calibrationSettings.Result.Validate();
                Check(calibrationSettings.Result.TcpPortCalibration, "Explicit calibration opt-in is stored in the editable profile");
                Check(predicted.Enabled && !predicted.Checked, "Calibration alone never opts into actual predicted attempts");
                predicted.Checked = true; calibrationSettings.Result.Validate();
                Check(calibrationSettings.Result.TcpPortPrediction, "Explicit prediction opt-in survives profile validation");
                string? screenshot = Environment.GetEnvironmentVariable("STREAMLINK_TEST_SCREENSHOT");
                if (!string.IsNullOrEmpty(screenshot)) {
                    calibrationSettings.StartPosition = FormStartPosition.Manual; calibrationSettings.Location = new(-30000, -30000); calibrationSettings.ShowInTaskbar = false;
                    calibrationSettings.Show(); Application.DoEvents(); using var bitmap = new Bitmap(calibrationSettings.Width, calibrationSettings.Height);
                    calibrationSettings.DrawToBitmap(bitmap, new(0, 0, bitmap.Width, bitmap.Height)); bitmap.Save(screenshot, System.Drawing.Imaging.ImageFormat.Png);
                }
                Field<CheckBox>(calibrationSettings, "tcpObservation").Checked = false;
                Check(!box.Enabled && !box.Checked && !calibrationSettings.Result.TcpPortCalibration, "Disabling the observer removes dependent calibration opt-in");
                Check(!predicted.Enabled && !predicted.Checked && !calibrationSettings.Result.TcpPortPrediction, "Disabling an observation dependency also clears actual prediction opt-in");
                Field<CheckBox>(calibrationSettings, "tcpObservation").Checked = true; box.Checked = true;
                Field<ComboBox>(calibrationSettings, "traversal").SelectedIndex = 0;
                Check(!box.Enabled && !calibrationSettings.Result.TcpPortCalibration, "Returning to compatible mode cannot retain an invisible calibration option");
            }
            using (var oldCalibration = new SettingsWindow(calibrationProfile, supportsCalibration: false))
                Check(!Field<CheckBox>(oldCalibration, "tcpCalibration").Enabled, "New frontend cannot enable calibration on an old backend");
            using (var oldPrediction = new SettingsWindow(calibrationProfile, supportsPrediction: false))
                Check(!Field<CheckBox>(oldPrediction, "tcpPrediction").Enabled, "New frontend cannot enable predicted paths on a backend without capability");
            using (var sourceSettings = new SettingsWindow(calibrationProfile)) {
                var sourceBox = Field<CheckBox>(sourceSettings, "tcpPeerSource");
                Check(sourceBox.Enabled && !sourceBox.Checked, "Source learning UI is available only in explicit TCP mode and starts unchecked");
                sourceBox.Checked = true;
                Check(sourceSettings.Result.TcpPeerReflexive, "Checking the source-learning option updates the actual saved profile");
                Field<ComboBox>(sourceSettings, "traversal").SelectedIndex = 0;
                Check(!sourceBox.Enabled && !sourceBox.Checked && !sourceSettings.Result.TcpPeerReflexive, "Compatible mode removes hidden source-learning opt-in");
            }
            using (var oldSource = new SettingsWindow(calibrationProfile, supportsPeerSource: false))
                Check(!Field<CheckBox>(oldSource, "tcpPeerSource").Enabled, "Old backend cannot be opted into source learning from the new frontend");
            var explorationProfile=JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(selected))!;
            explorationProfile.TraversalMode="tcp-udp";explorationProfile.PathSelection="prefer-faketcp";explorationProfile.AllowUdpFallback=true;
            using(var explorationSettings=new SettingsWindow(explorationProfile)){
                var box=Field<CheckBox>(explorationSettings,"udpExploration");
                Check(box.Enabled&&!box.Checked,"UDP exploration starts unchecked behind explicit fallback permission");
                box.Checked=true;explorationSettings.Result.Validate();
                Check(explorationSettings.Result.UdpExploration,"UDP exploration checkbox updates the actual profile");
                Field<CheckBox>(explorationSettings,"udpFallback").Checked=false;
                Check(!box.Enabled&&!box.Checked&&!explorationSettings.Result.UdpExploration,"removing fallback clears hidden expensive UDP opt-in");
            }
            using(var oldExploration=new SettingsWindow(explorationProfile,supportsUdpExploration:false))
                Check(!Field<CheckBox>(oldExploration,"udpExploration").Enabled,"old backend cannot silently accept UDP source expansion");
            Check((await worker.Handle(new("status"))).UdpExplorationVersion==1,"backend independently advertises UDP expansion IPC version");
            Check(new ControlReply(true,"",null,null,"",[]).UdpExplorationVersion==0,"old IPC reply defaults to no UDP expansion capability");
            var feedbackProfile=JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(selected))!;feedbackProfile.TraversalMode="tcp";
            using(var feedbackSettings=new SettingsWindow(feedbackProfile)){
                var box=Field<CheckBox>(feedbackSettings,"qualityFeedback");Check(box.Enabled&&!box.Checked,"receipt experiment begins unchecked in explicit managed mode");
                box.Checked=true;feedbackSettings.Result.Validate();Check(feedbackSettings.Result.QualityFeedback,"receipt checkbox updates the actual profile opt-in");
                Field<ComboBox>(feedbackSettings,"traversal").SelectedIndex=0;
                Check(!box.Enabled&&!box.Checked&&!feedbackSettings.Result.QualityFeedback,"returning to compatibility clears hidden receipt overhead permission");
                Check(feedbackSettings.Result.CapabilityIntents[nameof(DeviceProfile.QualityFeedback)]==true,"temporary compatibility unavailability preserves enabled user intent");
                Field<ComboBox>(feedbackSettings,"traversal").SelectedIndex=1;
                Check(box.Enabled&&box.Checked&&feedbackSettings.Result.QualityFeedback,"supported mode restores previously chosen intent");
                box.Checked=false;
                Check(feedbackSettings.Result.CapabilityIntents[nameof(DeviceProfile.QualityFeedback)]==false,"explicit user disable is distinct from legacy unspecified default");
            }
            using(var oldFeedback=new SettingsWindow(feedbackProfile,supportsQualityFeedback:false))Check(!Field<CheckBox>(oldFeedback,"qualityFeedback").Enabled,"old backend cannot be opted into receipt traffic from a new frontend");
            Check((await worker.Handle(new("status"))).QualityFeedbackVersion==1,"backend declares its independent receipt IPC capability");
            using(var standbySettings=new SettingsWindow(feedbackProfile)){
                var box=Field<CheckBox>(standbySettings,"standbyPaths");Check(box.Enabled&&!box.Checked,"standby starts off behind explicit managed-mode permission");
                box.Checked=true;standbySettings.Result.Validate();Check(standbySettings.Result.StandbyPaths,"standby checkbox updates actual backend profile opt-in");
                Field<ComboBox>(standbySettings,"traversal").SelectedIndex=0;
                Check(!box.Enabled&&!box.Checked&&!standbySettings.Result.StandbyPaths,"compatibility mode clears hidden standby resource permission");
            }
            using(var oldStandby=new SettingsWindow(feedbackProfile,supportsStandbyPaths:false))Check(!Field<CheckBox>(oldStandby,"standbyPaths").Enabled,"old service cannot be asked to retain unsupported standby resources");
            Check((await worker.Handle(new("status"))).StandbyPathsVersion==1,"backend independently advertises standby IPC version");
            var diagnosticProfile=JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(feedbackProfile))!;
            diagnosticProfile.TraversalMode="tcp";diagnosticProfile.StandbyPaths=true;diagnosticProfile.ManagedEgressMbps=70;
            using(var diagnostics=new SettingsWindow(diagnosticProfile)){
                var box=Field<CheckBox>(diagnostics,"pathDiagnostics");Check(box.Enabled&&!box.Checked,"explicit paced standby can opt into idle-only diagnostic, initially off");
                box.Checked=true;diagnostics.Result.Validate();Check(diagnostics.Result.PathDiagnostics,"diagnostic opt-in updates actual profile with a bounded goal");
                Field<CheckBox>(diagnostics,"standbyPaths").Checked=false;Check(!box.Enabled&&!box.Checked&&!diagnostics.Result.PathDiagnostics,"removing standby permission clears hidden high-rate diagnostic permission");
            }
            using(var oldDiagnostics=new SettingsWindow(diagnosticProfile,supportsDiagnostics:false))Check(!Field<CheckBox>(oldDiagnostics,"pathDiagnostics").Enabled,"old backend cannot enable unsupported diagnostic from new UI");
            Check((await worker.Handle(new("status"))).PathDiagnosticsVersion==1,"backend declares independent diagnostic IPC version");
            using(var qualitySettings=new SettingsWindow(diagnosticProfile)){
                var choice=Field<ComboBox>(qualitySettings,"selection");choice.SelectedIndex=2;
                Check(choice.SelectedIndex==0,"AutoQuality cannot be enabled from UI without explicit diagnostic consent");
                Field<CheckBox>(qualitySettings,"pathDiagnostics").Checked=true;choice.SelectedIndex=2;
                qualitySettings.Result.Validate();Check(qualitySettings.Result.PathSelection=="auto-quality","UI stores explicit automatic quality policy after all prerequisites");
                Field<CheckBox>(qualitySettings,"standbyPaths").Checked=false;
                Check(choice.SelectedIndex==0&&qualitySettings.Result.PathSelection=="prefer-faketcp","removing standby permission restores conservative selection and clears probes");
            }
            using(var oldQuality=new SettingsWindow(diagnosticProfile,supportsAutoQuality:false))Check(Field<ComboBox>(oldQuality,"selection").Items.Count==2,"old backend cannot opt into the new quality selection contract");
            Check((await worker.Handle(new("status"))).AutoQualityVersion==1,"backend independently declares automatic quality selection IPC capability");
            Guid diagnosticId=Guid.NewGuid();
            var fullWindows=Enumerable.Range(0,12).Select(i=>new PathDiagnosticWindow(diagnosticId,i,i<6?1:2,Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),50,
                new(25000,0,5000,25000,35000000,0,4,10,"Completed"),new(diagnosticId,i,25000,25000,32000000,0,0,0,0,0,1,0,1000,"ReportedAtCutoff"),100000)).ToArray();
            var fullStatus=new SessionStatus("connected","10.1.1.1","","faketcp",true,10,"",Peers:Enumerable.Range(2,7).Select(i=>new MeshPeerStatus(i,"10.1.1."+i,"node-"+i,true,10,""){
                Diagnostics=new(diagnosticId,"Done",11,50,"",new(diagnosticId,100000,150000000,0,85000,false),fullWindows)}).ToArray());
            Check(JsonSerializer.SerializeToUtf8Bytes(fullStatus).Length>65536,"seven full diagnostic transcripts would exceed the unchanged IPC envelope");
            var display=(SessionStatus)typeof(ControlWorker).GetMethod("DisplayStatus",System.Reflection.BindingFlags.Static|System.Reflection.BindingFlags.NonPublic)!.Invoke(null,[fullStatus])!;
            await using(var wire=new MemoryStream()){
                var compact=(await worker.Handle(new("status"))) with{Status=display};
                await ServiceProtocol.Write(wire,compact,CancellationToken.None);wire.Position=0;
                var decoded=await ServiceProtocol.Read<ControlReply>(wire,CancellationToken.None);
                Check(decoded.Status!.Peers!.Length==7&&decoded.Status.Peers.All(p=>p.Diagnostics is{Windows.Length:0,State:"Done"}),
                    "actual bounded pipe serialization carries seven diagnostic summaries without enlarging the protocol");
            }
            Check(fullStatus.Peers!.All(p=>p.Diagnostics!.Windows.Length==12),"desktop snapshot cannot discard runner evidence needed for current selection");
            string backup = Directory.GetFiles(ProfileStore.Root, "profile-before-native-*.dpapi").Single();
            var restored = JsonSerializer.Deserialize<DeviceProfile>(ProtectedData.Unprotect(File.ReadAllBytes(backup), "StreamLink-profile-v2"u8.ToArray(), DataProtectionScope.LocalMachine))!;
            Check(restored.Pair == saved && restored.Mesh == null, "Legacy migration backup cannot restore the original pairing");
            reply = await worker.Handle(new("mesh-invite"));
            var member = MeshIdentity.Import(reply.Invite);
            Check(reply.Ok && member.Self.Slot == 2 && !member.IsOwner && reply.Profile!.Mesh!.Directory!.Members.Length == 2, "Native invitation lost independent member identity");
            Check(!(await worker.Handle(new("mesh-revoke", PeerSlot: 1))).Ok, "Administrator removed itself");
            Check((await worker.Handle(new("mesh-revoke", PeerSlot: 2))).Ok, "Single-member revocation failed");
            var revoked=(await worker.Handle(new("status"))).Profile!;
            var rollback=ProfileChanges.Copy(reply.Profile!);bool rollbackRejected=false;
            try{new ProfileStore().Save(rollback);}catch(CryptographicException){rollbackRejected=true;}catch(IOException){rollbackRejected=true;}
            Check(rollbackRejected&&new ProfileStore().Load().Mesh!.Directory!.Revision==revoked.Mesh!.Directory!.Revision,"same-network save cannot lower the persistent revocation revision");
            string[] credentials=[revoked.Mesh.Pair.Secret,revoked.Mesh.OwnerPrivate,revoked.Mesh.SigningPrivate,revoked.Mesh.ExchangePrivate,new Invitation(1,revoked.Mesh.Pair.Network,revoked.Mesh.Pair.Secret,"","faketcp","",0).RawKey];
            typeof(ControlWorker).GetMethod("Log",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(worker,["security log negative: "+string.Join(' ',credentials)+" "+reply.Invite]);
            string logged=(await worker.Handle(new("status"))).Logs.Last();
            Check(credentials.All(c=>!logged.Contains(c))&&!logged.Contains(reply.Invite)&&logged.Contains("隐藏"),"actual worker log redacts raw/shared/member secrets and complete invitations");
            var changed = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(reply.Profile))!;
            changed.Mesh!.Self = member.Self;
            Check(!(await worker.Handle(new("save", changed))).Ok, "Settings replaced the native identity");
            reply = await worker.Handle(new("mesh-join", Invite: reply.Invite));
            Check(reply.Ok && !reply.Profile!.Mesh!.IsOwner, "Native member import failed");
            Check(reply.Profile.Mesh.Directory!.Revision==revoked.Mesh.Directory!.Revision&&!reply.Profile.Mesh.Directory.Members.Any(m=>m.Slot==2),"same-network re-import cannot erase already known member revocation");
            Check(!(await worker.Handle(new("mesh-invite"))).Ok, "Guest issued a new member credential");
            await worker.StopLocal();
        }
        string source = Path.Combine(root, "bundle"), parent = Path.Combine(root, "install"), destination = Path.Combine(parent, "candidate");
        Directory.CreateDirectory(source); File.WriteAllText(Path.Combine(source, "payload.bin"), "synthetic install payload");
        string manifest = Path.Combine(source, "manifest.json");
        string release=(typeof(MainWindow).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false).Cast<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion).Split('+')[0];
        void Manifest(string path, string hash) => File.WriteAllText(manifest, JsonSerializer.Serialize(new { version = release, files = new[] { new { path, sha256 = hash } } }));
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
        foreach (string path in new[] { Path.Combine(source, "payload.bin"), "payload.bin:stream", "payload.bin.", "CON.txt", "sub/../payload.bin", "./payload.bin", "sub//payload.bin" }) {
            Manifest(path, hash); invalid = false;
            try { Copy(source, destination, manifest); } catch (TargetInvocationException e) when (e.InnerException is IOException) { invalid = true; }
            Check(invalid, "Non-canonical/absolute/alias bundle path accepted: " + path);
        }
        File.WriteAllText(manifest, JsonSerializer.Serialize(new { version = typeof(MainWindow).Assembly.GetName().Version!.ToString(3) + "-preview", files = new[] { new { path = "payload.bin", sha256 = hash }, new { path = "PAYLOAD.bin", sha256 = hash } } }));
        invalid = false; try { Copy(source, destination, manifest); } catch (TargetInvocationException e) when (e.InnerException is IOException) { invalid = true; }
        Check(invalid, "Case-insensitive duplicate bundle path accepted");
        Manifest("payload.bin", hash); invalid = false;
        try { Copy(source, Path.Combine(root, "outside"), manifest); } catch (TargetInvocationException e) when (e.InnerException is IOException) { invalid = true; }
        Check(invalid && !Directory.Exists(Path.Combine(root, "outside")), "Unmanaged install destination was mutated");
        invalid=false;try{ServiceInstaller.VerifyBundle(source);}catch(IOException){invalid=true;}Check(invalid,"self-listed hash-only package cannot pass runtime/provenance preflight");
        string[] required=["StreamLink.exe","StreamLink.dll","StreamLink.runtimeconfig.json","StreamLink.deps.json","StreamLink.Service.exe","StreamLink.Service.dll","StreamLink.Service.runtimeconfig.json","StreamLink.Service.deps.json","components/udp2raw-native.exe","components/streamlink-tun.dll","components/wintun.dll","components/WinDivert.dll","components/WinDivert64.sys"];
        if(PersonalFeature.Enabled)required=[..required,"web/StreamLink.Web.exe","web/StreamLink.Web.dll","web/StreamLink.Web.runtimeconfig.json","web/wwwroot/index.html","web/wwwroot/app.js","web/wwwroot/style.css"];
        var pe=new byte[80];pe[0]=(byte)'M';pe[1]=(byte)'Z';pe[60]=64;pe[64]=(byte)'P';pe[65]=(byte)'E';pe[68]=0x64;pe[69]=0x86;
        foreach(string file in required){string path=Path.Combine(source,file);Directory.CreateDirectory(Path.GetDirectoryName(path)!);File.WriteAllBytes(path,pe);}
        void RuntimeManifest(IEnumerable<string> list,string publisher="UnsignedCandidate")=>File.WriteAllText(manifest,JsonSerializer.Serialize(new{schemaVersion=2,version=release,architecture="win-x64",tunAbi=2,meshProtocol=4,personalContract=PersonalFeature.Contract,provenance=new{publisherSignature=publisher},files=list.Select(path=>new{path,sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(source,path))))})}));
        RuntimeManifest(required);Check(ServiceInstaller.VerifyBundle(source)==required.Length,"complete synthetic runtime-header contract passes integrity preflight, without claiming executable/driver validation");
        RuntimeManifest(required.Where(p=>p!="components/wintun.dll"));invalid=false;try{ServiceInstaller.VerifyBundle(source);}catch(IOException){invalid=true;}Check(invalid,"regenerating valid hashes cannot omit mandatory Wintun component");
        RuntimeManifest(required,"VerifiedPublisher");invalid=false;try{ServiceInstaller.VerifyBundle(source);}catch(IOException){invalid=true;}Check(invalid,"self-declared publisher signature is not trusted");RuntimeManifest(required);
        File.WriteAllBytes(manifest, new byte[] { 0xef, 0xbb, 0xbf }.Concat(File.ReadAllBytes(manifest)).ToArray());
        Check(ServiceInstaller.VerifyBundle(source) == required.Length, "UTF-8 BOM from a Windows package writer must remain valid");
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
            try { await Lifecycle(); await InstallationTransaction(); await Feedback(); Console.WriteLine($"PASS {count}: isolated foreground lifecycle, DPAPI, mutual exclusion, bundle verification and UI busy/success/failure feedback. No live service/network changed."); }
            catch (Exception e) { Console.Error.WriteLine(e); Environment.ExitCode = 1; }
            finally { host.Close(); }
        };
        Application.Run(host);
    }
    static async Task InstallationTransaction()
    {
        var calls=new List<string>();
        await ServiceInstallTransaction.Execute(()=>{calls.Add("apply");return Task.CompletedTask;},()=>{calls.Add("auth");return Task.CompletedTask;},()=>{calls.Add("service");return Task.CompletedTask;});
        Check(calls.SequenceEqual(["apply"]),"healthy candidate must not invoke rollback");
        calls.Clear();bool failed=false;
        try{await ServiceInstallTransaction.Execute(()=>throw new IOException("candidate"),()=>{calls.Add("auth");return Task.CompletedTask;},()=>{calls.Add("service");return Task.CompletedTask;});}catch(IOException ex){failed=ex.InnerException?.Message=="candidate";}
        Check(failed&&calls.SequenceEqual(["auth","service"]),"candidate readiness failure restores authorization and prior service independently");
        calls.Clear();int errors=0;
        try{await ServiceInstallTransaction.Execute(()=>throw new IOException("candidate"),()=>{calls.Add("auth");throw new IOException("authorization");},()=>{calls.Add("service");throw new IOException("restore executable");});}catch(IOException ex){errors=(ex.InnerException as AggregateException)?.InnerExceptions.Count??0;}
        Check(errors==3&&calls.SequenceEqual(["auth","service"]),"double rollback failure retains original error and still attempts executable restoration after authorization failure");
    }
}
