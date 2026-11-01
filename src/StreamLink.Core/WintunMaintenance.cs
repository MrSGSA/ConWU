using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace StreamLink.Core;

public sealed record WintunMaintenanceResult(string Adapter, string Driver, int OtherAdapters, bool RebootRequired);

// Installer-only maintenance. The caller must stop and join its old service and
// hold its protected runtime.lock. This additional lease excludes every newer
// native owner of the same network/slot, including another validation instance.
[SupportedOSPlatform("windows")]
public static class WintunMaintenance
{
    static readonly Guid NetClass = new("4d36e972-e325-11ce-bfc1-08002be10318");
    const string DriverHash = "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE";
    sealed record Device(string Id, string Service, string Hardware, string Friendly, Guid? Interface)
    {
        public bool Wintun => Service.Equals("wintun", StringComparison.OrdinalIgnoreCase) ||
            Hardware.Split('\0').Any(x => x.Equals("Wintun", StringComparison.OrdinalIgnoreCase)) ||
            Id.StartsWith(@"SWD\WINTUN\", StringComparison.OrdinalIgnoreCase) || Id.StartsWith(@"ROOT\WINTUN\", StringComparison.OrdinalIgnoreCase);
    }

    public static WintunMaintenanceResult PrepareUpgrade(string components, string network, int slot, Action<string>? log = null)
    {
        var identity = WintunIdentity.For(network, slot);
        using var lease = identity.Acquire();
        void Note(string text) => log?.Invoke(text);
        Note("等待旧 Wintun 网卡完成移除：" + identity.Name);
        var watch = Stopwatch.StartNew();
        Device? target;
        while ((target = Find(identity)) != null && watch.Elapsed < TimeSpan.FromSeconds(3)) Thread.Sleep(100);
        string adapter = "AlreadyAbsent";
        if (target != null) {
            RequireOwned(target, identity);
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            // Older releases have no identity lease. Never remove a live session
            // or a conflicting name even after the intended service has exited.
            if (interfaces.Any(n => Guid.TryParse(n.Id, out var id) && id == identity.Guid && n.OperationalStatus == OperationalStatus.Up))
                throw new IOException("旧 Wintun 网卡仍有活动会话；未卸载，更新已停止");
            if (interfaces.Any(n => n.Name.Equals(identity.Name, StringComparison.OrdinalIgnoreCase) && (!Guid.TryParse(n.Id, out var id) || id != identity.Guid)))
                throw new IOException("同名网卡不属于本实例；未卸载，更新已停止");
            Note("自动卸载本实例遗留的 Wintun 网卡");
            bool reboot = Remove(identity);
            if (reboot) throw new IOException("Windows 已接受本网卡卸载，但要求重启才能完成；请重启后再次更新（未卸载共享驱动）");
            adapter = "RemovedStaleAdapter";
        }
        watch.Restart();
        while (Find(identity) != null || NetworkInterface.GetAllNetworkInterfaces().Any(n => Guid.TryParse(n.Id, out var id) && id == identity.Guid)) {
            if (watch.Elapsed >= TimeSpan.FromSeconds(15)) throw new IOException("旧 Wintun 网卡移除仍未完成；更新已停止，请稍后重试。Windows 持续占用时仍可能需要重启");
            Thread.Sleep(100);
        }

        // The official API serializes against Wintun create/delete. Only call it
        // with zero enumerated Wintun devices (including disconnected/phantom
        // ones). Unknown or foreign adapters are never removed to make room.
        int others = Devices().Count(d => d.Wintun);
        if (others != 0) {
            Note($"本网卡已清理；保留共享 Wintun 驱动（还有 {others} 个其他网卡）");
            return new(adapter, "PreservedOtherAdapters", others, false);
        }
        string driver = Path.GetFullPath(Path.Combine(components, "wintun.dll"));
        if (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(driver))) != DriverHash) throw new IOException("Wintun 维护组件校验失败");
        IntPtr library = NativeLibrary.Load(driver, typeof(WintunMaintenance).Assembly, DllImportSearchPath.UseDllDirectoryForDependencies | DllImportSearchPath.System32);
        try {
            var delete = Marshal.GetDelegateForFunctionPointer<DeleteDriver>(NativeLibrary.GetExport(library, "WintunDeleteDriver"));
            if (!delete()) {
                int error = Marshal.GetLastPInvokeError();
                // Driver cleanup is optional once our adapter is absent. A
                // concurrently created foreign adapter must not make us force it.
                Note($"本网卡已清理；官方 Wintun 驱动清理未完成（{error}），保留驱动供新版复用");
                return new(adapter, "PreservedDriverError:" + error, 0, false);
            }
        } finally { NativeLibrary.Free(library); }
        Note("已清理闲置 Wintun 驱动；新版按需重新加载");
        return new(adapter, "RemovedUnusedDriver", 0, false);
    }

    static Device? Find(WintunIdentity identity) => Devices().SingleOrDefault(d => d.Id.Equals(identity.DeviceId, StringComparison.OrdinalIgnoreCase));
    static void RequireOwned(Device device, WintunIdentity identity)
    {
        if (!device.Id.Equals(identity.DeviceId, StringComparison.OrdinalIgnoreCase) || device.Interface != identity.Guid ||
            !device.Service.Equals("wintun", StringComparison.OrdinalIgnoreCase) || device.Friendly != "StreamLink Tunnel")
            throw new IOException("遗留网卡身份或驱动与本实例不符，未卸载任何设备");
    }
    static bool Remove(WintunIdentity identity)
    {
        using var set = OpenSet(); var info = Info();
        if (!SetupDiOpenDeviceInfo(set, identity.DeviceId, IntPtr.Zero, 0, ref info)) {
            if (Marshal.GetLastWin32Error() == unchecked((int)0xe000020b)) return false; // already removed
            throw new Win32Exception(Marshal.GetLastWin32Error(), "重新核对 Wintun 设备失败");
        }
        RequireOwned(Read(set, ref info), identity);
        if (!DiUninstallDevice(IntPtr.Zero, set, ref info, 0, out bool reboot)) throw new Win32Exception(Marshal.GetLastWin32Error(), "卸载本实例 Wintun 网卡失败");
        return reboot;
    }
    static Device[] Devices()
    {
        using var set = OpenSet(); var rows = new List<Device>();
        for (uint index = 0; ; index++) {
            var info = Info();
            if (!SetupDiEnumDeviceInfo(set, index, ref info)) {
                int error = Marshal.GetLastWin32Error(); if (error == 259) break;
                throw new Win32Exception(error, "枚举网络设备失败，未清理共享驱动");
            }
            rows.Add(Read(set, ref info));
        }
        return rows.ToArray();
    }
    static Device Read(DeviceSet set, ref DeviceInfo info)
    {
        var id = new StringBuilder(1024);
        if (!SetupDiGetDeviceInstanceId(set, ref info, id, (uint)id.Capacity, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
        string service = Property(set, ref info, 4), hardware = Property(set, ref info, 1), friendly = Property(set, ref info, 12), driver = Property(set, ref info, 9);
        Guid? guid = null;
        // Never use an unchecked device registry property as a registry path.
        string prefix = NetClass.ToString("B") + @"\";
        if (driver.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && driver[prefix.Length..] is { Length: 4 } index && index.All(char.IsAsciiDigit)) {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\" + driver);
            if (Guid.TryParse(key?.GetValue("NetCfgInstanceId") as string, out var found)) guid = found;
        }
        return new(id.ToString(), service, hardware, friendly, guid);
    }
    static string Property(DeviceSet set, ref DeviceInfo info, uint property)
    {
        byte[] value = new byte[16384];
        if (!SetupDiGetDeviceRegistryProperty(set, ref info, property, out _, value, (uint)value.Length, out uint length)) {
            int error = Marshal.GetLastWin32Error(); if (error == 13) return ""; // absent property
            throw new Win32Exception(error, "读取网卡身份失败，未执行清理");
        }
        return Encoding.Unicode.GetString(value, 0, checked((int)length)).TrimEnd('\0');
    }
    static DeviceSet OpenSet()
    {
        var guid = NetClass; var set = SetupDiGetClassDevs(ref guid, null, IntPtr.Zero, 0);
        if (set.IsInvalid) { int error = Marshal.GetLastWin32Error(); set.Dispose(); throw new Win32Exception(error); }
        return set;
    }
    static DeviceInfo Info() => new() { Size = (uint)Marshal.SizeOf<DeviceInfo>() };
    [StructLayout(LayoutKind.Sequential)] struct DeviceInfo { public uint Size; public Guid Class; public uint DevInst; public UIntPtr Reserved; }
    sealed class DeviceSet : SafeHandleZeroOrMinusOneIsInvalid
    {
        public DeviceSet() : base(true) { }
        protected override bool ReleaseHandle() => SetupDiDestroyDeviceInfoList(handle);
    }
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] delegate bool DeleteDriver();
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern DeviceSet SetupDiGetClassDevs(ref Guid guid, string? enumerator, IntPtr parent, uint flags);
    [DllImport("setupapi.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiEnumDeviceInfo(DeviceSet set, uint index, ref DeviceInfo info);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiGetDeviceInstanceId(DeviceSet set, ref DeviceInfo info, StringBuilder id, uint size, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiGetDeviceRegistryProperty(DeviceSet set, ref DeviceInfo info, uint property, out uint type, [Out] byte[] buffer, uint size, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiOpenDeviceInfo(DeviceSet set, string id, IntPtr parent, uint flags, ref DeviceInfo info);
    [DllImport("setupapi.dll")] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("newdev.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool DiUninstallDevice(IntPtr parent, DeviceSet set, ref DeviceInfo info, uint flags, [MarshalAs(UnmanagedType.Bool)] out bool reboot);
}
