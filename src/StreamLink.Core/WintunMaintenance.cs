using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
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
            RequireNoNameConflict(identity, interfaces);
            Note("自动卸载本实例遗留的 Wintun 网卡");
            bool reboot = Remove(identity);
            if (reboot) throw new IOException("Windows 已接受本网卡卸载，但要求重启才能完成；请重启后再次更新（未卸载共享驱动）");
            adapter = "RemovedStaleAdapter";
        }
        watch.Restart();
        bool recycled = false;
        while (true) {
            bool devicePresent = Find(identity) != null;
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            RequireNoNameConflict(identity, interfaces);
            var residual = interfaces.SingleOrDefault(n => Guid.TryParse(n.Id, out var id) && id == identity.Guid);
            if (!devicePresent && residual == null) break;
            // IP Helper can retain an Up row (and an Npcap filter row) long
            // after the owning process and the actual PnP device have gone.
            // Do not treat that cached Up bit as a live Wintun session, and do
            // not ignore it either: reset only this proven, vacant identity
            // through official Create/Close, with no session or IP mutation.
            if (!devicePresent && residual != null && !recycled && watch.Elapsed >= TimeSpan.FromSeconds(1)) {
                RequireOrphanIdentity(identity, residual.Name, residual.Description);
                if (Find(identity) != null) throw new IOException("Wintun 设备在恢复前重新出现；未接管或卸载，请等待原实例退出");
                Note("旧设备节点已移除，Windows 仍保留接口记录；正在使用官方 Wintun 恢复本实例接口状态");
                RecycleOrphanInterface(components, identity);
                recycled = true; adapter = "RecycledOrphanInterface";
                watch.Restart();
                continue;
            }
            if (watch.Elapsed >= TimeSpan.FromSeconds(15)) throw new IOException($"旧 Wintun 网卡移除仍未完成（设备节点={devicePresent}，接口记录={residual != null}，已尝试接口恢复={recycled}）；更新已停止。请保留日志，Windows 持续占用时仍可能需要重启");
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
        IntPtr library = LoadOfficialLibrary(components);
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

    static void RequireNoNameConflict(WintunIdentity identity, NetworkInterface[] interfaces)
    {
        if (interfaces.Any(n => n.Name.Equals(identity.Name, StringComparison.OrdinalIgnoreCase) && (!Guid.TryParse(n.Id, out var id) || id != identity.Guid)))
            throw new IOException("同名网卡不属于本实例；未卸载，更新已停止");
    }
    internal static void RequireOrphanIdentity(WintunIdentity identity, string name, string description)
    {
        // IP Helper adds " #2", " #3", ... when several adapters share a
        // device description. This is separate from the exact PnP FriendlyName.
        const string numbered = "StreamLink Tunnel #";
        bool ownType = description == "StreamLink Tunnel" ||
            description.StartsWith(numbered, StringComparison.Ordinal) &&
            int.TryParse(description.AsSpan(numbered.Length), NumberStyles.None, CultureInfo.InvariantCulture, out int copy) && copy >= 2;
        if (!name.Equals(identity.Name, StringComparison.OrdinalIgnoreCase) || !ownType)
            throw new IOException($"残留接口名称或类型与本实例不符（名称={name}，类型={description}）；未重建残留接口");
    }
    static IntPtr LoadOfficialLibrary(string components)
    {
        string driver = Path.GetFullPath(Path.Combine(components, "wintun.dll"));
        if (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(driver))) != DriverHash) throw new IOException("Wintun 维护组件校验失败");
        return NativeLibrary.Load(driver, typeof(WintunMaintenance).Assembly, DllImportSearchPath.UseDllDirectoryForDependencies | DllImportSearchPath.System32);
    }
    static void RecycleOrphanInterface(string components, WintunIdentity identity)
    {
        IntPtr library = LoadOfficialLibrary(components);
        try {
            var create = Marshal.GetDelegateForFunctionPointer<CreateAdapter>(NativeLibrary.GetExport(library, "WintunCreateAdapter"));
            var close = Marshal.GetDelegateForFunctionPointer<CloseAdapter>(NativeLibrary.GetExport(library, "WintunCloseAdapter"));
            var getLuid = Marshal.GetDelegateForFunctionPointer<GetLuid>(NativeLibrary.GetExport(library, "WintunGetAdapterLUID"));
            var guid = identity.Guid;
            IntPtr adapter = create(identity.Name, "StreamLink", ref guid);
            if (adapter == IntPtr.Zero) {
                int error = Marshal.GetLastPInvokeError();
                throw new Win32Exception(error, $"官方 Wintun 未能恢复本实例的残留接口（0x{error:X8}）；未操作其他网卡");
            }
            try {
                getLuid(adapter, out ulong luid);
                uint error = ConvertInterfaceLuidToGuid(ref luid, out var actual);
                if (error != 0 || actual != identity.Guid) throw new IOException("Wintun 恢复接口的实际身份不符，已关闭本次创建的句柄");
            } finally { close(adapter); }
        } finally { NativeLibrary.Free(library); }
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
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)] delegate IntPtr CreateAdapter(string name, string type, ref Guid guid);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void CloseAdapter(IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void GetLuid(IntPtr adapter, out ulong luid);
    [DllImport("iphlpapi.dll")] static extern uint ConvertInterfaceLuidToGuid(ref ulong luid, out Guid guid);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern DeviceSet SetupDiGetClassDevs(ref Guid guid, string? enumerator, IntPtr parent, uint flags);
    [DllImport("setupapi.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiEnumDeviceInfo(DeviceSet set, uint index, ref DeviceInfo info);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiGetDeviceInstanceId(DeviceSet set, ref DeviceInfo info, StringBuilder id, uint size, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiGetDeviceRegistryProperty(DeviceSet set, ref DeviceInfo info, uint property, out uint type, [Out] byte[] buffer, uint size, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiOpenDeviceInfo(DeviceSet set, string id, IntPtr parent, uint flags, ref DeviceInfo info);
    [DllImport("setupapi.dll")] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("newdev.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool DiUninstallDevice(IntPtr parent, DeviceSet set, ref DeviceInfo info, uint flags, [MarshalAs(UnmanagedType.Bool)] out bool reboot);
}
