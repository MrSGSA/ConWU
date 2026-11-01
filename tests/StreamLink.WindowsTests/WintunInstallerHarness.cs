using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink;
using StreamLink.Core;
using StreamLink.Service;

static class WintunInstallerHarness
{
    public static async Task Run(string instance, string operation, string output)
    {
        WindowsInstance.ConfigureValidation(instance);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        var store = new ProfileStore();
        if (operation == "seed") {
            if (ServiceInstaller.Installed || File.Exists(Path.Combine(ProfileStore.Root, "profile.dpapi"))) throw new IOException("Seed requires a fresh isolated instance");
            var profile = new DeviceProfile { Mesh = MeshIdentity.Create("https://127.0.0.1:1/", "", "faketcp"), Enabled = true,
                TcpStun = ["127.0.0.1:9"], UdpStun = ["127.0.0.1:9"], ListenPort = 56680, SourcePort = 56691, DeviceName = "Isolated Wintun Upgrade" };
            store.Save(profile);
            File.WriteAllText(output, JsonSerializer.Serialize(new { identity = WintunIdentity.For(profile.Mesh.Pair.Network, profile.Mesh.Self.Slot), network = profile.Mesh.Pair.Network }));
            return;
        }
        if (operation == "hold-identity") {
            var mesh = store.LoadForMaintenance().Mesh!;
            using var lease = WintunIdentity.For(mesh.Pair.Network, mesh.Self.Slot).Acquire();
            File.WriteAllText(output, "held");
            var watch = Stopwatch.StartNew();
            while (!File.Exists(output + ".release") && watch.Elapsed < TimeSpan.FromMinutes(4)) await Task.Delay(100);
            return;
        }
        if (operation != "ready") throw new ArgumentException("Unknown harness operation");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        ControlReply? status = null;
        try {
            while (true) {
                timeout.Token.ThrowIfCancellationRequested();
                try {
                    status = await ServiceProtocol.Call(new("status"), timeout.Token);
                    if (status.Ok && status.ServiceReady && status.Status?.Adapter?.Loaded == true) break;
                } catch (IOException) { }
                await Task.Delay(250, timeout.Token);
            }
        } finally {
            File.WriteAllText(output, JsonSerializer.Serialize(new { status?.Ok, status?.Version, status?.ServiceReady, status = status?.Status,
                identity = store.LoadForMaintenance().Mesh is { } mesh ? WintunIdentity.For(mesh.Pair.Network, mesh.Self.Slot) : null,
                profileHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(ProfileStore.Root, "profile.dpapi")))) }, new JsonSerializerOptions { WriteIndented = true }));
        }
    }
}
