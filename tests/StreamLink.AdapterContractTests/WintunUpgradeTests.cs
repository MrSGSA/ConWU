using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json;
using StreamLink.Core;

static class WintunUpgradeTests
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)] delegate IntPtr Create(string name, string type, ref Guid guid);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void Close(IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)] delegate IntPtr Start(IntPtr adapter, uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void End(IntPtr session);
    static bool Present(Guid guid) => NetworkInterface.GetAllNetworkInterfaces().Any(n => Guid.TryParse(n.Id, out var id) && id == guid);
    static void Check(bool ok, string name, List<object> checks)
    {
        checks.Add(new { name, status = ok ? "Pass" : "Fail" }); if (!ok) throw new IOException(name);
    }
    public static int LeaseChild(string network)
    {
        try { using var lease = WintunIdentity.For(network, 1).Acquire(); return 1; }
        catch (IOException) { return 0; }
    }
    public static void Run(string components, string output)
    {
        if (File.Exists(output)) throw new IOException("Use fresh evidence");
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var checks = new List<object>(); var messages = new List<string>(); string? failure = null;
        var foreignBefore = NetworkInterface.GetAllNetworkInterfaces().Select(n => n.Id).ToHashSet();
        var mesh = MeshIdentity.Create("https://example.com/", "", "faketcp");
        var identity = WintunIdentity.For(mesh.Pair.Network, 1);
        IntPtr library = IntPtr.Zero, raw = IntPtr.Zero, session = IntPtr.Zero;
        Close? close = null; End? end = null;
        try {
            using (identity.Acquire()) {
                var info = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
                if (Path.GetFileNameWithoutExtension(Environment.ProcessPath!).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) info.ArgumentList.Add(typeof(WintunUpgradeTests).Assembly.Location);
                info.ArgumentList.Add("--wintun-lease-child"); info.ArgumentList.Add(mesh.Pair.Network);
                using var child = Process.Start(info)!;
                if (!child.WaitForExit(10000)) throw new IOException("lease child did not exit");
                Check(child.ExitCode == 0, "cross-process identity lease excludes second owner", checks);
                bool blocked = false;
                try { WintunMaintenance.PrepareUpgrade(components, mesh.Pair.Network, 1); }
                catch (IOException) { blocked = true; }
                Check(blocked, "maintenance rejects a held identity lease before touching devices", checks);
            }
            using (identity.Acquire()) Check(true, "lease becomes available after owner exit", checks);

            // Real signed Wintun device, with a fixture handle retained solely
            // to keep a dormant PnP node present. This models a leftover node;
            // it is not a claim that a live service was forcibly uninstalled.
            library = NativeLibrary.Load(Path.GetFullPath(Path.Combine(components, "wintun.dll")));
            T Api<T>(string symbol) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, symbol));
            var create = Api<Create>("WintunCreateAdapter"); close = Api<Close>("WintunCloseAdapter");
            var start = Api<Start>("WintunStartSession"); end = Api<End>("WintunEndSession");
            var guid = identity.Guid;
            raw = create(identity.Name, "StreamLink", ref guid);
            if (raw == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastPInvokeError(), "isolated official fixture creation failed");
            session = start(raw, 0x400000);
            if (session == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastPInvokeError());
            bool activeRejected = false;
            try { WintunMaintenance.PrepareUpgrade(components, mesh.Pair.Network, 1, messages.Add); }
            catch (IOException ex) when (ex.Message.Contains("活动会话")) { activeRejected = true; }
            Check(activeRejected && Present(guid), "legacy active session without new lease cannot be removed", checks);
            end(session); session = IntPtr.Zero;
            var result = WintunMaintenance.PrepareUpgrade(components, mesh.Pair.Network, 1, messages.Add);
            Check(result.Adapter == "RemovedStaleAdapter" && !result.RebootRequired && !Present(guid), "dormant owned PnP node uninstalled without reboot", checks);
            Check(result.Driver == "PreservedOtherAdapters", "foreign shared Wintun driver preserved", checks);
            close(raw); raw = IntPtr.Zero;

            // Same GUID is insufficient: a different tunnel owner is preserved.
            raw = create(identity.Name, "Other Test Owner", ref guid);
            if (raw == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastPInvokeError());
            bool foreignRejected = false;
            try { WintunMaintenance.PrepareUpgrade(components, mesh.Pair.Network, 1, messages.Add); }
            catch (IOException ex) when (ex.Message.Contains("身份或驱动")) { foreignRejected = true; }
            Check(foreignRejected && Present(guid), "same GUID with foreign owner label preserved", checks);
            close(raw); raw = IntPtr.Zero;

            for (int round = 1; round <= 3; round++) {
                WintunMaintenance.PrepareUpgrade(components, mesh.Pair.Network, 1, messages.Add);
                using (var adapter = new NativeAdapter(components, mesh.Pair.Network, 1)) {
                    Check(adapter.InterfaceLuid != null && Present(identity.Guid), $"round {round}: native adapter reopens at same identity", checks);
                }
                var cleaned = WintunMaintenance.PrepareUpgrade(components, mesh.Pair.Network, 1, messages.Add);
                Check(!cleaned.RebootRequired && !Present(identity.Guid), $"round {round}: close and upgrade cleanup complete without reboot", checks);
            }
        } catch (Exception ex) { failure = ex.ToString(); }
        finally {
            if (session != IntPtr.Zero) end!(session);
            if (raw != IntPtr.Zero) close!(raw);
            if (library != IntPtr.Zero) NativeLibrary.Free(library);
            var foreignAfter = NetworkInterface.GetAllNetworkInterfaces().Select(n => n.Id).ToHashSet();
            bool preserved = foreignBefore.IsSubsetOf(foreignAfter);
            checks.Add(new { name = "all pre-existing interface identities preserved", status = preserved ? "Pass" : "Fail" });
            if (!preserved) failure = (failure ?? "") + " pre-existing interface disappeared";
            File.WriteAllText(output, JsonSerializer.Serialize(new { status = failure == null ? "Pass" : "Fail", identity, checks, messages, failure,
                limitations = "Isolated signed Wintun on this host; dormant PnP fixture retains a handle. Shared-driver deletion not exercised because foreign Wintun devices exist. No reboot or physical WAN streaming test." }, new JsonSerializerOptions { WriteIndented = true }));
        }
        if (failure != null) throw new IOException(failure);
    }
}
