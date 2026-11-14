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
            selected.SelectTransport("faketcp-only");
            var applied = await worker.Handle(new("save", selected));
            Check(applied.Ok && applied.Profile!.Selection().Policy == PathPolicy.FakeTcpOnly && !applied.Profile.Enabled, "Control backend persists policy while leaving an idle network stopped");
            var unsupported = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(selected))!; unsupported.PathSelection = "auto-quality";
            Check(!(await worker.Handle(new("save", unsupported))).Ok && (await worker.Handle(new("status"))).Profile!.PathSelection == "faketcp-only", "Rejected AutoQuality cannot overwrite the valid saved policy");
            var udpNetwork = MeshIdentity.Create("https://example.com/", "", "udp");
            string meshInvite = MeshIdentity.Export(MeshIdentity.Issue(udpNetwork)), pairInvite = Pairing.Create("https://example.com/", "", "udp").Invite();
            byte[] beforeRejected = File.ReadAllBytes(Path.Combine(ProfileStore.Root, "profile.dpapi"));
            foreach (string command in new[] { "create", "join", "mesh-create", "mesh-join" }) {
                var rejected = await worker.Handle(new(command, Invite: "invalid-invitation", Service: "https://example.com/", Mode: "invalid-mode"));
                Check(!rejected.Ok && rejected.Profile!.Mesh!.Pair.Network == selected.Mesh!.Pair.Network && beforeRejected.SequenceEqual(File.ReadAllBytes(Path.Combine(ProfileStore.Root, "profile.dpapi"))),
                    command + ": malformed explicit create/join cannot replace identity or stored configuration before validation");
            }
            Check((await worker.Handle(new("status"))).QualityFeedbackVersion==1,"backend declares its independent receipt IPC capability");
            Check((await worker.Handle(new("status"))).AutoQualityVersion==1,"backend declares automatic quality selection IPC capability");
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
            Check(fullStatus.Peers!.All(p=>p.Diagnostics!.Windows.Length==12),"UI snapshot cannot discard runner evidence needed for current selection");
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
            string[] credentials=[revoked.Mesh!.Pair.Secret,revoked.Mesh.OwnerPrivate,revoked.Mesh.SigningPrivate,revoked.Mesh.ExchangePrivate,new Invitation(1,revoked.Mesh.Pair.Network,revoked.Mesh.Pair.Secret,"","faketcp","",0).RawKey];
            int logsBefore=(await worker.Handle(new("status"))).Logs.Length;
            typeof(ControlWorker).GetMethod("Log",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(worker,["security log negative while recording is off"]);
            Check((await worker.Handle(new("status"))).Logs.Length==logsBefore,"off suppresses new in-memory logs as well as file output");
            var logging=ProfileChanges.Copy(revoked);logging.LogLevel="info";
            Check((await worker.Handle(new("save",logging))).Ok,"logging can be explicitly re-enabled for credential-redaction verification");
            typeof(ControlWorker).GetMethod("Log",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(worker,["security log negative: "+string.Join(' ',credentials)+" "+reply.Invite]);
            string logged=(await worker.Handle(new("status"))).Logs.Last();
            Check(credentials.All(c=>!logged.Contains(c))&&!logged.Contains(reply.Invite)&&logged.Contains("隐藏"),"actual worker log redacts raw/shared/member secrets and complete invitations");
            var changed = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(reply.Profile))!;
            changed.Mesh!.Self = member.Self;
            Check(!(await worker.Handle(new("save", changed))).Ok, "Settings replaced the native identity");
            reply = await worker.Handle(new("mesh-join", Invite: reply.Invite));
            Check(reply.Ok && !reply.Profile!.Mesh!.IsOwner, "Native member import failed");
            Check(reply.Profile!.Mesh!.Directory!.Revision==revoked.Mesh!.Directory!.Revision&&!reply.Profile.Mesh.Directory.Members.Any(m=>m.Slot==2),"same-network re-import cannot erase already known member revocation");
            Check(!(await worker.Handle(new("mesh-invite"))).Ok, "Guest issued a new member credential");
            await worker.StopLocal();
        }
        string source = Path.Combine(root, "bundle"), parent = Path.Combine(root, "install"), destination = Path.Combine(parent, "candidate");
        Directory.CreateDirectory(source); File.WriteAllText(Path.Combine(source, "payload.bin"), "synthetic install payload");
        string manifest = Path.Combine(source, "manifest.json");
        string release=(typeof(ServiceInstaller).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false).Cast<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion).Split('+')[0];
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
        File.WriteAllText(manifest, JsonSerializer.Serialize(new { version = typeof(ServiceInstaller).Assembly.GetName().Version!.ToString(3) + "-preview", files = new[] { new { path = "payload.bin", sha256 = hash }, new { path = "PAYLOAD.bin", sha256 = hash } } }));
        invalid = false; try { Copy(source, destination, manifest); } catch (TargetInvocationException e) when (e.InnerException is IOException) { invalid = true; }
        Check(invalid, "Case-insensitive duplicate bundle path accepted");
        Manifest("payload.bin", hash); invalid = false;
        try { Copy(source, Path.Combine(root, "outside"), manifest); } catch (TargetInvocationException e) when (e.InnerException is IOException) { invalid = true; }
        Check(invalid && !Directory.Exists(Path.Combine(root, "outside")), "Unmanaged install destination was mutated");
        invalid=false;try{ServiceInstaller.VerifyBundle(source);}catch(IOException){invalid=true;}Check(invalid,"self-listed hash-only package cannot pass runtime/provenance preflight");
        string[] required=["ConWU.exe","ConWU.dll","ConWU.runtimeconfig.json","ConWU.deps.json","ConWU.Service.exe","ConWU.Service.dll","ConWU.Service.runtimeconfig.json","ConWU.Service.deps.json","components/udp2raw-native.exe","components/conwu-phantun.exe","components/conwu-raw.exe","components/conwu-tun.dll","components/wintun.dll","components/WinDivert.dll","components/WinDivert64.sys"];
        required=[..required,"web/ConWU.Web.exe","web/ConWU.Web.dll","web/ConWU.Web.runtimeconfig.json","web/wwwroot/index.html","web/wwwroot/app.js","web/wwwroot/style.css"];
        var pe=new byte[80];pe[0]=(byte)'M';pe[1]=(byte)'Z';pe[60]=64;pe[64]=(byte)'P';pe[65]=(byte)'E';pe[68]=0x64;pe[69]=0x86;
        foreach(string file in required){string path=Path.Combine(source,file);Directory.CreateDirectory(Path.GetDirectoryName(path)!);File.WriteAllBytes(path,pe);}
        void RuntimeManifest(IEnumerable<string> list,string publisher="UnsignedCandidate")=>File.WriteAllText(manifest,JsonSerializer.Serialize(new{schemaVersion=2,version=release,architecture="win-x64",tunAbi=2,meshProtocol=4,personalContract=PersonalFeature.Contract,provenance=new{publisherSignature=publisher},files=list.Select(path=>new{path,sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(source,path))))})}));
        RuntimeManifest(required.Where(p=>p!="web/ConWU.Web.exe"));invalid=false;try{ServiceInstaller.VerifyBundle(source);}catch(IOException){invalid=true;}Check(invalid,"Web-only product cannot pass preflight with its Web host missing");
        RuntimeManifest(required);Check(ServiceInstaller.VerifyBundle(source)==required.Length,"complete synthetic runtime-header contract passes integrity preflight, without claiming executable/driver validation");
        RuntimeManifest(required.Where(p=>p!="components/conwu-phantun.exe"));invalid=false;try{ServiceInstaller.VerifyBundle(source);}catch(IOException){invalid=true;}Check(invalid,"regenerating valid hashes cannot omit the required Phantun carrier");
        RuntimeManifest(required.Where(p=>p!="components/conwu-raw.exe"));invalid=false;try{ServiceInstaller.VerifyBundle(source);}catch(IOException){invalid=true;}Check(invalid,"regenerating valid hashes cannot omit the optional-protocol implementation from a complete runtime");
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
    [STAThread] static void Main(string[] args)
    {
        if(args is ["--wintun-reopen-owned-node",var ownedComponents,var ownerNetwork,var ownedNetwork,var ownedIp,var ownedEvidence]){
            try{WintunReopenHarness.Node(Path.GetFullPath(ownedComponents),ownedNetwork,ownedIp,Path.GetFullPath(ownedEvidence),ownerNetwork);}catch(Exception ex){Console.Error.WriteLine(ex);Environment.ExitCode=1;}return;
        }
        if(args is ["--wintun-reopen-node",var nodeComponents,var network,var ip,var nodeEvidence]){
            WintunReopenHarness.Node(Path.GetFullPath(nodeComponents),network,ip,nodeEvidence);return;
        }
        if(args is ["--wintun-diagnostic",var diagnosticComponents,var diagnosticEvidence]){
            try{WintunReopenHarness.Run(Path.GetFullPath(diagnosticComponents),diagnosticEvidence,true).GetAwaiter().GetResult();}
            catch(Exception ex){Console.Error.WriteLine(ex);Environment.ExitCode=1;}return;
        }
        if(args is ["--wintun-fresh-identities",var freshComponents,var freshEvidence]){
            try{WintunReopenHarness.Run(Path.GetFullPath(freshComponents),freshEvidence,false,true).GetAwaiter().GetResult();}
            catch(Exception ex){Console.Error.WriteLine(ex);Environment.ExitCode=1;}return;
        }
        if(args is ["--wintun-reopen",var components,var evidence]) {
            try { WintunReopenHarness.Run(Path.GetFullPath(components),evidence).GetAwaiter().GetResult(); }
            catch(Exception ex) { Console.Error.WriteLine(ex); Environment.ExitCode=1; } return;
        }
        if(args is ["--wintun-installer",var instance,var operation,var output]) {
            try { WintunInstallerHarness.Run(instance,operation,output).GetAwaiter().GetResult(); }
            catch(Exception ex) { Console.Error.WriteLine(ex); Environment.ExitCode=1; } return;
        }
        ApplicationConfiguration.Initialize();
        using var host = new Form { ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new(-30000, -30000) };
        host.Shown += async (_, _) => {
            try { await Lifecycle(); await InstallationTransaction(); Console.WriteLine($"PASS {count}: isolated foreground lifecycle, DPAPI, mutual exclusion, bundle verification and installation recovery. No live service/network changed."); }
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
