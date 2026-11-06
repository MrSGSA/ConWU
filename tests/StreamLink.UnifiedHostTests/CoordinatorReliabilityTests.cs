using System.Net;
using System.Net.Http.Json;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Discovery;

static class CoordinatorReliabilityTests
{
    public static async Task Run(Action<bool, string> check)
    {
        void Reject(Action action, string name) {
            try { action(); }
            catch (Exception ex) when (ex is IOException or ArgumentException or FormatException or CryptographicException or JsonException) { check(true, name); return; }
            throw new Exception("accepted: " + name);
        }
        string root = Path.Combine(Path.GetTempPath(), "streamlink-coordination-reliability-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var token = deadline.Token;
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        string pem = Path.Combine(root, "certificate.pem"), secret = Path.Combine(root, "key.pem");
        File.WriteAllText(pem, cert.ExportCertificatePem()); File.WriteAllText(secret, key.ExportPkcs8PrivateKeyPem());
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(secret, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        string pin = Convert.ToHexString(SHA256.HashData(cert.RawData));
        var options = new CoordinationHostOptions(Path.Combine(root, "source"), "https://127.0.0.1:0", pem, secret);
        var mesh = MeshIdentity.Create("https://coord.example.test/", "", "faketcp"); MeshGovernance.Enable(mesh);
        var genesis = mesh.Directory!;
        string archive = Path.Combine(root, "membership.slcoord"), previousInstance;
        try {
            await using (var host = CoordinationHost.Create(options)) {
                await host.Start(token); previousInstance = host.InstanceId;
                string address = host.Addresses.Single() + "/";
                var diagnosis = await MeshCoordinatorPreflight.Probe(address, pin, host.InstanceId, token);
                check(diagnosis.Reachable && diagnosis.Code == "reachable", "external HTTPS probe confirms the running instance and fresh challenge: " + diagnosis.Code + " / " + diagnosis.Detail);
                check((await MeshCoordinatorPreflight.Probe(address, pin, new string('0', 32), token)).Code == "origin-mismatch", "a healthy but wrong Tunnel origin is rejected");
                check((await MeshCoordinatorPreflight.Probe(address + "missing/", pin, null, token)).Code == "http-404", "wrong proxy path reports the HTTP status");
                check((await MeshCoordinatorPreflight.Probe(address, new string('0', 64), host.InstanceId, token)).Code == "tls", "certificate pin failures are distinguished from DNS and HTTP errors");
                using (var cancelled = new CancellationTokenSource()) {
                    cancelled.Cancel(); bool cancelledCorrectly = false;
                    try { await MeshCoordinatorPreflight.Probe(address, pin, host.InstanceId, cancelled.Token); }
                    catch (OperationCanceledException) { cancelledCorrectly = true; }
                    check(cancelledCorrectly, "caller cancellation is not reported as an HTTPS outage");
                }
                Reject(() => CoordinationBackup.Create(options.DataDirectory, archive), "online coordination data cannot be backed up unsafely");
                using var handler = new HttpClientHandler { UseProxy = false, ServerCertificateCustomValidationCallback = (_, c, _, _) => c != null && Convert.ToHexString(SHA256.HashData(c.RawData)) == pin };
                using var http = new HttpClient(handler) { BaseAddress = new(address), Timeout = TimeSpan.FromSeconds(5) };
                async Task<HttpStatusCode> Put(string path, object value, string auth) {
                    using var message = new HttpRequestMessage(HttpMethod.Put, path) { Content = JsonContent.Create(value) };
                    message.Headers.Authorization = new("Bearer", auth);
                    using var response = await http.SendAsync(message, token); return response.StatusCode;
                }
                string oldFile = Path.Combine(options.DataDirectory, "networks.json"), network = Guid.NewGuid().ToString("N");
                var envelope = new Envelope(Guid.NewGuid().ToString("N"), 1, new string('A', 40));
                Directory.CreateDirectory(oldFile); // Inject a real atomic-replace failure.
                check(await Put("v1/" + network + "/1", envelope, new string('A', 64)) == HttpStatusCode.ServiceUnavailable, "legacy write failure returns an explicit service error");
                Directory.Delete(oldFile);
                check(await Put("v1/" + network + "/1", envelope, new string('B', 64)) == HttpStatusCode.NoContent, "failed legacy creation leaves no phantom auth or occupied slot");

                string meshFile = Path.Combine(options.DataDirectory, "mesh-networks.json"), path = "v4/mesh/" + mesh.Pair.Network + "/membership";
                Directory.CreateDirectory(meshFile);
                check(await Put(path, new MeshMembershipRequest("", genesis), new string('C', 64)) == HttpStatusCode.ServiceUnavailable, "membership persistence failure is reported before confirmation");
                Directory.Delete(meshFile);
                check(await Put(path, new MeshMembershipRequest("", genesis), mesh.Pair.Auth) == HttpStatusCode.OK, "failed membership commit rolls back memory and can be retried");
                var issued = MeshIdentity.Issue(mesh);
                var addition = new MeshMembershipRequest(MeshGovernance.Head(genesis), mesh.Directory!);
                check(await Put(path, addition, mesh.Pair.Auth) == HttpStatusCode.OK, "signed member addition is durably confirmed");
                byte[] committed = File.ReadAllBytes(meshFile);
                check(await Put(path, addition, mesh.Pair.Auth) == HttpStatusCode.OK && committed.SequenceEqual(File.ReadAllBytes(meshFile)), "lost approval reply can be retried without a duplicate member or write");
                string head = MeshGovernance.Head(mesh.Directory!); MeshIdentity.Revoke(mesh, issued.Member.Slot);
                check(await Put(path, new MeshMembershipRequest(head, mesh.Directory!), mesh.Pair.Auth) == HttpStatusCode.OK, "revocation is persisted before backup");
            }
            var manifest = CoordinationBackup.Create(options.DataDirectory, archive);
            check(manifest.Files.Length == 2 && CoordinationBackup.Inspect(archive).Format == 1, "offline snapshot includes both registry generations and validates signatures");
            Reject(() => CoordinationBackup.Create(options.DataDirectory, archive), "backup refuses to overwrite an existing recovery point");
            check(CoordinationBackup.Inspect(archive).Files.Length == 2, "refused overwrite leaves the previous snapshot intact");
            string damaged = Path.Combine(root, "damaged.slcoord"); File.Copy(archive, damaged);
            using (var zip = ZipFile.Open(damaged, ZipArchiveMode.Update)) {
                zip.GetEntry("networks.json")!.Delete();
                using var replacement = new StreamWriter(zip.CreateEntry("networks.json").Open()); replacement.Write("{}");
            }
            byte[] unchanged = File.ReadAllBytes(Path.Combine(options.DataDirectory, "mesh-networks.json"));
            Reject(() => CoordinationBackup.Restore(options.DataDirectory, damaged, true), "archive length and checksum mismatches are rejected before restoration");
            bool preserved = unchanged.SequenceEqual(File.ReadAllBytes(Path.Combine(options.DataDirectory, "mesh-networks.json")));
            check(preserved && !File.Exists(Path.Combine(options.DataDirectory, CoordinationStorage.RestoreMarker)),
                "invalid backup cannot change the live registry or leave a recovery marker");
            string target = Path.Combine(root, "restored");
            Reject(() => CoordinationBackup.Restore(target, archive, false), "restoring old permissions requires explicit rollback acknowledgement");
            var restored = CoordinationBackup.Restore(target, archive, true);
            check(File.Exists(restored.PreviousSnapshot), "restore preserves the previous registry in a separate snapshot");
            await using (var host = CoordinationHost.Create(options with { DataDirectory = target })) {
                await host.Start(token);
                check(host.InstanceId != previousInstance, "coordinator restart changes the diagnostic instance identity");
                using var handler = new HttpClientHandler { UseProxy = false, ServerCertificateCustomValidationCallback = (_, c, _, _) => c != null && Convert.ToHexString(SHA256.HashData(c.RawData)) == pin };
                using var http = new HttpClient(handler) { BaseAddress = new(host.Addresses.Single() + "/") };
                http.DefaultRequestHeaders.Authorization = new("Bearer", mesh.Pair.Auth);
                var state = await http.GetFromJsonAsync<MeshSnapshot>("v3/mesh/" + mesh.Pair.Network, token);
                check(state?.Directory == null ? false : MeshGovernance.Head(state.Directory) == MeshGovernance.Head(mesh.Directory!) && state.Directory.Members.Length == 1,
                    "restored coordinator keeps the latest revocation and authenticated membership history");
                Reject(() => CoordinationBackup.Restore(target, archive, true), "restore refuses to replace an active coordinator registry");
            }
            string marker = Path.Combine(target, CoordinationStorage.RestoreMarker);
            File.WriteAllText(marker, JsonSerializer.Serialize(new { PreviousSnapshot = restored.PreviousSnapshot }));
            Reject(() => CoordinationHost.Create(options with { DataDirectory = target }), "interrupted multi-file restoration blocks startup instead of mixing permissions");
            CoordinationBackup.Restore(target, archive, true);
            check(!File.Exists(marker) && File.Exists(restored.PreviousSnapshot), "explicit recovery completes restoration and preserves the original recovery point");
            var stored = JsonSerializer.Deserialize<Dictionary<string, MeshRegistry.Registration>>(File.ReadAllText(Path.Combine(target, "mesh-networks.json")))!;
            stored[mesh.Pair.Network] = stored[mesh.Pair.Network] with { Directory = mesh.Directory! with { Revision = mesh.Directory!.Revision + 1 } };
            File.WriteAllText(Path.Combine(target, "mesh-networks.json"), JsonSerializer.Serialize(stored));
            Reject(() => CoordinationBackup.Create(target, Path.Combine(root, "invalid.slcoord")), "a corrupted signed member table cannot be exported as a valid backup");
            Reject(() => CoordinationHost.Create(options with { DataDirectory = target }), "a corrupted signed member table fails closed on startup");
            var repaired = CoordinationBackup.Restore(target, archive, true);
            check(File.Exists(repaired.PreviousSnapshot) && File.ReadAllBytes(Path.Combine(target, "mesh-networks.json")).SequenceEqual(File.ReadAllBytes(Path.Combine(options.DataDirectory, "mesh-networks.json"))),
                "explicit restore can repair corrupted membership while preserving its original bytes");
            string bounded = Path.Combine(root, "oversize.json");
            using (var output = File.Create(bounded)) output.SetLength(CoordinationStorage.MaximumFileBytes + 1L);
            Reject(() => CoordinationStorage.Read(bounded), "persistent file size is bounded before allocating a buffer");
            Reject(() => CoordinationStorage.Decode<int>("{\"same\":1,\"same\":2}"u8.ToArray(), (_, _) => { }), "duplicate registry keys are rejected");
            Reject(() => new CoordinatorSettings(PublicUrl: "https://coord.example.test/?token=secret").Validate(), "external diagnostic URLs cannot contain token query parameters");
            var before = new DeviceProfile(); var after = ProfileChanges.Copy(before);
            after.Coordinator = after.Coordinator with { PublicUrl = "https://coord.example.test/" };
            check(ProfileChanges.Impact(before, after) != ProfileChangeImpact.RestartNetwork, "external diagnostics configuration never restarts healthy data connections");
        } finally {
            // Generated root is a direct child of the OS temporary directory.
            if (Path.GetDirectoryName(Path.GetFullPath(root)) == Path.TrimEndingDirectorySeparator(Path.GetTempPath())) Directory.Delete(root, true);
        }
    }
}
