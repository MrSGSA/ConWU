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
    public static WintunMaintenanceResult PrepareUpgrade(string components, string network, int slot, Action<string>? log = null, string? ownerNetwork=null)
    {
        var scope=WintunIdentity.For(ownerNetwork??network,ownerNetwork==null?slot:1);
        using var lease=scope.Acquire();
        var legacyIdentity=WintunIdentity.For(network,slot);
        using var legacyLease=legacyIdentity.Guid==scope.Guid?null:legacyIdentity.Acquire();
        var legacy=ownerNetwork==null?null:new WintunAdapterJournal.LegacyScope(network,slot);
        var identities=WintunAdapterJournal.Read(scope,legacy);
        string adapter="AlreadyAbsent";int cached=0;
        foreach(var identity in identities){
            var watch=Stopwatch.StartNew();Device? target;
            while((target=Find(identity))!=null&&watch.Elapsed<TimeSpan.FromSeconds(3))Thread.Sleep(100);
            var interfaces=WindowsInterfaceInventory.Read();RequireNoNameConflict(identity,interfaces);
            if(target!=null){
                RequireOwned(target,identity);
                if(interfaces.Any(n=>n.Guid==identity.Guid&&n.OperationalStatus==OperationalStatus.Up))
                    throw new IOException("旧 Wintun 网卡仍有活动会话；未卸载，更新已停止");
                log?.Invoke("自动卸载本实例遗留的 Wintun 网卡");
                if(Remove(identity))throw new IOException("Windows 要求重启才能完成本网卡卸载；请重启后再次更新（未卸载共享驱动）");
                adapter="RemovedStaleAdapter";
            }
            watch.Restart();
            while(Find(identity)!=null){
                if(watch.Elapsed>=TimeSpan.FromSeconds(15))throw new IOException("本实例 Wintun 设备节点移除未完成；更新已停止，请保留日志");
                Thread.Sleep(100);
            }
            var residual=WindowsInterfaceInventory.Read().SingleOrDefault(n=>n.Guid==identity.Guid);
            if(residual!=null){RequireOrphanIdentity(identity,residual.Name,residual.Description);cached++;}
        }
        // PnP absence, the exclusive lease and exact GUID/name/type establish
        // ownership. IP Helper may still cache an Up row. Never recreate that
        // removed GUID: Windows can fail class setup with 4319. A fresh official
        // generation will reuse the profile's IP, under the same owner lease.
        // Persist any legacy cached identity before the installer can replace
        // the profile's old network, but do not allocate an actual adapter.
        WintunAdapterJournal.RememberLegacy(scope,legacy);
        int others=Devices().Count(d=>d.Wintun);
        if(others!=0){
            log?.Invoke($"本网卡设备已清理；保留共享 Wintun 驱动（还有 {others} 个其他网卡）");
            return new(adapter,"PreservedOtherAdapters",others,false);
        }
        if(cached!=0){
            log?.Invoke($"本网卡设备已清理；Windows 仍缓存 {cached} 个已关闭接口，保留官方驱动供新版复用");
            return new(adapter,"PreservedCachedInterfaces",0,false);
        }
        log?.Invoke("本实例网卡已清理；保留共享官方 Wintun 驱动供其他应用及新版复用");
        return new(adapter,"PreservedSharedDriver",0,false);
    }

    static void RequireNoNameConflict(WintunIdentity identity, WindowsInterfaceIdentity[] interfaces)
    {
        if (interfaces.Any(n => n.Name.Equals(identity.Name, StringComparison.OrdinalIgnoreCase) && n.Guid != identity.Guid))
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
    static Device? Find(WintunIdentity identity)
    {
        // Query only this exact device. Enumerating and reading every phantom
        // network adapter repeatedly can consume the entire preparation budget.
        using var set=IdentitySet();var info=Info();
        if(!SetupDiOpenDeviceInfo(set,identity.DeviceId,IntPtr.Zero,0,ref info)){
            int error=Marshal.GetLastWin32Error();
            if(error==unchecked((int)0xe000020b))return null;
            throw new Win32Exception(error,"查询本实例 Wintun 设备失败，未执行恢复");
        }
        return Read(set,ref info);
    }
    internal static bool DevicePresent(WintunIdentity identity)=>Find(identity)!=null;
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
    static DeviceSet IdentitySet()
    {
        var guid=NetClass;var set=SetupDiCreateDeviceInfoList(ref guid,IntPtr.Zero);
        if(set.IsInvalid){int error=Marshal.GetLastWin32Error();set.Dispose();throw new Win32Exception(error);}
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
    [DllImport("setupapi.dll",SetLastError=true)]static extern DeviceSet SetupDiCreateDeviceInfoList(ref Guid guid,IntPtr parent);
    [DllImport("setupapi.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiEnumDeviceInfo(DeviceSet set, uint index, ref DeviceInfo info);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiGetDeviceInstanceId(DeviceSet set, ref DeviceInfo info, StringBuilder id, uint size, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiGetDeviceRegistryProperty(DeviceSet set, ref DeviceInfo info, uint property, out uint type, [Out] byte[] buffer, uint size, out uint required);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiOpenDeviceInfo(DeviceSet set, string id, IntPtr parent, uint flags, ref DeviceInfo info);
    [DllImport("setupapi.dll")] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("newdev.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool DiUninstallDevice(IntPtr parent, DeviceSet set, ref DeviceInfo info, uint flags, [MarshalAs(UnmanagedType.Bool)] out bool reboot);
}
