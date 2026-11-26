#[cfg(windows)]
use anyhow::Context;
use anyhow::{Result, ensure};
use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    path::Path,
    sync::{Arc, Mutex},
};
pub trait Adapter: Send + Sync {
    fn read(&self) -> Result<Option<Vec<u8>>>;
    fn write(&self, packet: &[u8]) -> Result<bool>;
    fn provider(&self) -> &'static str;
    fn warnings(&self) -> Vec<serde_json::Value> {
        Vec::new()
    }
    #[cfg(windows)]
    fn route_interface(&self, _local: Ipv4Addr, _peer: Ipv4Addr) -> Option<u32> {
        None
    }
    #[cfg(windows)]
    fn routes_to_peer(&self, local: Ipv4Addr, peer: Ipv4Addr) -> bool {
        self.route_interface(local, peer).is_some()
    }
}
pub struct Memory {
    outgoing: Mutex<VecDeque<Vec<u8>>>,
    incoming: Mutex<VecDeque<Vec<u8>>>,
}
impl Memory {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            outgoing: Mutex::new(VecDeque::new()),
            incoming: Mutex::new(VecDeque::new()),
        })
    }
    pub fn inject(&self, packet: Vec<u8>) -> Result<()> {
        ensure!(packet.len() <= 1280, "lab packet exceeds MTU");
        let mut q = self.outgoing.lock().unwrap();
        ensure!(q.len() < 512, "lab source queue full");
        q.push_back(packet);
        Ok(())
    }
    pub fn drain(&self) -> Vec<Vec<u8>> {
        let mut q = self.incoming.lock().unwrap();
        let count = q.len().min(100);
        q.drain(..count).collect()
    }
}
impl Adapter for Memory {
    fn read(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.outgoing.lock().unwrap().pop_front())
    }
    fn write(&self, p: &[u8]) -> Result<bool> {
        let mut q = self.incoming.lock().unwrap();
        if q.len() >= 512 {
            return Ok(false);
        }
        q.push_back(p.to_vec());
        Ok(true)
    }
    fn provider(&self) -> &'static str {
        "Isolated.Memory"
    }
}
pub fn open(
    network: &str,
    ip: Ipv4Addr,
    components: &Path,
    cancel: &tokio_util::sync::CancellationToken,
    legacy: Option<&crate::model::LegacyAdapter>,
) -> Result<Arc<dyn Adapter>> {
    #[cfg(target_os = "linux")]
    {
        let _ = (components, cancel, legacy);
        return Ok(Arc::new(linux::Tun::open(network, ip)?));
    }
    #[cfg(windows)]
    {
        return Ok(Arc::new(windows::Wintun::open(
            network, ip, components, cancel, legacy,
        )?));
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    anyhow::bail!("this experimental desktop backend supports Windows and Linux")
}
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    };
    pub struct Tun {
        file: File,
        warnings: Vec<serde_json::Value>,
    }
    impl Tun {
        pub fn open(network: &str, ip: Ipv4Addr) -> Result<Self> {
            ensure!(conwu_core::valid_id(network), "invalid owned network");
            let warnings = crate::routes::inspect(ip, &[])?;
            let name = format!("cwru{}", &network[..8]);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open("/dev/net/tun")?;
            let mut request = [0u8; 40];
            request[..name.len()].copy_from_slice(name.as_bytes());
            request[16..18].copy_from_slice(&(0x1001u16).to_ne_bytes());
            // SAFETY: ifreq storage is initialized, its name fits IFNAMSIZ,
            // and file remains owned for the temporary interface lifetime.
            ensure!(
                unsafe { libc::ioctl(file.as_raw_fd(), 0x400454ca as _, request.as_mut_ptr(),) }
                    >= 0,
                "TUNSETIFF failed: {}",
                std::io::Error::last_os_error()
            );
            let address = std::process::Command::new("ip")
                .args(["addr", "add", &format!("{ip}/24"), "dev", &name])
                .status()?;
            ensure!(
                address.success(),
                "could not configure owned virtual address"
            );
            let up = std::process::Command::new("ip")
                .args(["link", "set", "dev", &name, "mtu", "1280", "up"])
                .status()?;
            ensure!(up.success(), "could not activate owned TUN");
            Ok(Self { file, warnings })
        }
    }
    impl Adapter for Tun {
        fn read(&self) -> Result<Option<Vec<u8>>> {
            let mut bytes = vec![0; 1280];
            match (&self.file).read(&mut bytes) {
                Ok(0) => Ok(None),
                Ok(n) => {
                    bytes.truncate(n);
                    Ok(Some(bytes))
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(e.into()),
            }
        }
        fn write(&self, packet: &[u8]) -> Result<bool> {
            match (&self.file).write(packet) {
                Ok(n) => Ok(n == packet.len()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
                Err(e) => Err(e.into()),
            }
        }
        fn provider(&self) -> &'static str {
            "Linux.TUN"
        }
        fn warnings(&self) -> Vec<serde_json::Value> {
            self.warnings.clone()
        }
    }
}
#[cfg(windows)]
mod windows {
    use super::*;
    use std::{ffi::c_void, os::windows::ffi::OsStrExt};
    type Handle = *mut c_void;
    type Create = unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> Handle;
    type Close = unsafe extern "system" fn(Handle);
    type Start = unsafe extern "system" fn(Handle, u32) -> Handle;
    type AdapterLuid = unsafe extern "system" fn(Handle, *mut u64);
    #[repr(C)]
    #[derive(PartialEq, Eq)]
    struct AdapterGuid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn ConvertInterfaceLuidToGuid(luid: *const u64, guid: *mut AdapterGuid) -> u32;
        fn ConvertInterfaceGuidToLuid(guid: *const AdapterGuid, luid: *mut u64) -> u32;
    }
    #[repr(C)]
    struct DeviceInfo {
        size: u32,
        class: AdapterGuid,
        dev_inst: u32,
        reserved: usize,
    }
    #[link(name = "setupapi")]
    unsafe extern "system" {
        fn SetupDiCreateDeviceInfoList(class: *const AdapterGuid, parent: Handle) -> Handle;
        fn SetupDiOpenDeviceInfoW(
            set: Handle,
            id: *const u16,
            parent: Handle,
            flags: u32,
            info: *mut DeviceInfo,
        ) -> i32;
        fn SetupDiDestroyDeviceInfoList(set: Handle) -> i32;
    }
    fn device_present(id: uuid::Uuid) -> Result<bool> {
        let set = unsafe { SetupDiCreateDeviceInfoList(std::ptr::null(), std::ptr::null_mut()) };
        ensure!(set != (-1isize as Handle), "无法核对旧虚拟网卡设备");
        let mut info = DeviceInfo {
            size: std::mem::size_of::<DeviceInfo>() as u32,
            class: AdapterGuid {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            dev_inst: 0,
            reserved: 0,
        };
        let name = format!(r"SWD\WINTUN\{{{}}}", id.hyphenated()).to_ascii_uppercase();
        let found = unsafe {
            SetupDiOpenDeviceInfoW(
                set,
                wide(&name).as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut info,
            )
        } != 0;
        let error = std::io::Error::last_os_error();
        unsafe { SetupDiDestroyDeviceInfoList(set) };
        if !found {
            ensure!(
                matches!(
                    error.raw_os_error().map(|e| e as u32),
                    Some(0xe000020b | 433 | 1168)
                ),
                "旧虚拟网卡设备查询失败：{error}"
            );
        }
        Ok(found)
    }
    type Receive = unsafe extern "system" fn(Handle, *mut u32) -> *mut u8;
    type Release = unsafe extern "system" fn(Handle, *const u8);
    type Allocate = unsafe extern "system" fn(Handle, u32) -> *mut u8;
    type Send = unsafe extern "system" fn(Handle, *const u8);
    pub struct Wintun {
        _library: libloading::Library,
        adapter: Handle,
        luid: u64,
        session: Handle,
        close: Close,
        end: Close,
        receive: Receive,
        release: Release,
        allocate: Allocate,
        send: Send,
        rx: Mutex<()>,
        tx: Mutex<()>,
        owner: crate::store::Store,
        generation: serde_json::Value,
        legacy: Option<crate::legacy_wintun::Guard>,
        warnings: Vec<serde_json::Value>,
    }
    // Wintun handles are process-owned. RX and TX each have their own guard;
    // Arc ownership prevents library/session teardown while a caller is active.
    unsafe impl std::marker::Send for Wintun {}
    unsafe impl Sync for Wintun {}
    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(Some(0))
            .collect()
    }
    fn wait_until(until: std::time::Instant, cancel: &tokio_util::sync::CancellationToken) -> Result<()> {
        while std::time::Instant::now() < until {
            ensure!(!cancel.is_cancelled(), "虚拟网卡准备已取消");
            let remaining = until.saturating_duration_since(std::time::Instant::now());
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(100)));
        }
        Ok(())
    }

    fn settle_legacy(closed_at: i64, cancel: &tokio_util::sync::CancellationToken) -> Result<()> {
        let now = conwu_core::unix_seconds() * 1000;
        let elapsed = if closed_at > 0 && closed_at <= now {
            (now - closed_at).min(30000)
        } else {
            0
        };
        let until =
            std::time::Instant::now() + std::time::Duration::from_millis((30000 - elapsed) as u64);
        wait_until(until, cancel)
    }

    fn creation_retry_delay(error: &std::io::Error, remaining: std::time::Duration,
        backoff: std::time::Duration,
    ) -> Option<std::time::Duration> {
        (error.raw_os_error() == Some(4319) && !remaining.is_zero()).then(|| remaining.min(backoff))
    }
    unsafe extern "system" fn logger(level: i32, _: u64, message: *const u16) {
        if message.is_null() {
            return;
        }
        let mut length = 0;
        while length < 4096 && unsafe { *message.add(length) } != 0 {
            length += 1;
        }
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(message, length) });
        if level >= 2 {
            tracing::warn!("Wintun：{text}");
        } else {
            tracing::debug!("Wintun：{text}");
        }
    }
    fn configure_ip(
        luid: u64,
        ip: Ipv4Addr,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        use windows_sys::Win32::{
            NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
            Networking::WinSock::*,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut row = MIB_IPINTERFACE_ROW::default();
        loop {
            ensure!(!cancel.is_cancelled(), "虚拟网卡准备已取消");
            unsafe {
                InitializeIpInterfaceEntry(&mut row);
            }
            row.Family = AF_INET;
            row.InterfaceLuid = NET_LUID_LH { Value: luid };
            let error = unsafe { GetIpInterfaceEntry(&mut row) };
            if error == 0 {
                break;
            }
            ensure!(
                matches!(error, 2 | 21 | 1168) && std::time::Instant::now() < deadline,
                "无法读取本网络的IP接口：{}",
                std::io::Error::from_raw_os_error(error as i32)
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        row.NlMtu = 1280;
        row.SitePrefixLength = 0;
        row.ForwardingEnabled = false;
        row.WeakHostSend = false;
        row.WeakHostReceive = false;
        row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
        row.DadTransmits = 0;
        let error = unsafe { SetIpInterfaceEntry(&mut row) };
        ensure!(
            error == 0,
            "无法配置本网络的IP接口：{}",
            std::io::Error::from_raw_os_error(error as i32)
        );
        let mut address = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe {
            InitializeUnicastIpAddressEntry(&mut address);
            address.InterfaceLuid = NET_LUID_LH { Value: luid };
            address.Address.Ipv4.sin_family = AF_INET;
            address.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        }
        address.OnLinkPrefixLength = 24;
        address.DadState = IpDadStatePreferred;
        ensure!(!cancel.is_cancelled(), "虚拟网卡准备已取消");
        let error = unsafe { CreateUnicastIpAddressEntry(&address) };
        ensure!(
            error == 0,
            "无法配置本机虚拟IP：{}",
            std::io::Error::from_raw_os_error(error as i32)
        );
        Ok(())
    }
    fn verified_orphans(
        network: &str,
        history: &[uuid::Uuid],
        legacy: Option<&crate::legacy_wintun::Guard>,
    ) -> Result<(
        Vec<u64>,
        Vec<uuid::Uuid>,
        std::collections::HashSet<uuid::Uuid>,
    )> {
        use windows_sys::Win32::NetworkManagement::{
            IpHelper::{GetIfEntry2, MIB_IF_ROW2},
            Ndis::NET_LUID_LH,
        };
        let mut luids = Vec::new();
        let mut retained = Vec::new();
        let mut all = std::collections::HashSet::new();
        let mut identities = history
            .iter()
            .map(|id| {
                (
                    *id,
                    legacy
                        .map(|l| l.expected_name(*id))
                        .unwrap_or_else(|| format!("ConWU-{}-{}", &network[..8], id.simple())),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        if let Some(legacy) = legacy {
            for (id, name) in legacy.identities() {
                if let Some(prior) = identities.insert(*id, name.clone()) {
                    ensure!(
                        prior.eq_ignore_ascii_case(name),
                        "网卡代次的两份记录名称不一致"
                    );
                }
            }
        }
        for (id, expected_name) in identities {
            ensure!(
                !device_present(id)?,
                "本网络已记录的旧网卡仍在使用，未创建第二个实例"
            );
            let (data1, data2, data3, data4) = id.as_fields();
            let guid = AdapterGuid {
                data1,
                data2,
                data3,
                data4: *data4,
            };
            let mut luid = 0;
            if unsafe { ConvertInterfaceGuidToLuid(&guid, &mut luid) } != 0 {
                continue;
            }
            let mut row = MIB_IF_ROW2::default();
            row.InterfaceLuid = NET_LUID_LH { Value: luid };
            ensure!(
                unsafe { GetIfEntry2(&mut row) } == 0,
                "无法复核本网络已关闭的接口"
            );
            let text = |v: &[u16]| {
                String::from_utf16_lossy(&v[..v.iter().position(|c| *c == 0).unwrap_or(v.len())])
            };
            let alias = text(&row.Alias);
            let description = text(&row.Description);
            let kind = if legacy.is_some() {
                "StreamLink Tunnel"
            } else {
                "ConWU Tunnel"
            };
            let numbered = format!("{kind} #");
            let own_type = description == kind
                || description
                    .strip_prefix(&numbered)
                    .is_some_and(|s| s.parse::<u32>().is_ok_and(|n| n >= 2));
            ensure!(
                alias.eq_ignore_ascii_case(&expected_name) && own_type,
                "旧接口的名称或类型不属于本网络，未忽略冲突"
            );
            luids.push(luid);
            all.insert(id);
            if history.contains(&id) {
                retained.push(id);
            }
        }
        Ok((luids, retained, all))
    }
    impl Wintun {
        pub fn open(
            network: &str,
            ip: Ipv4Addr,
            components: &Path,
            cancel: &tokio_util::sync::CancellationToken,
            legacy_scope: Option<&crate::model::LegacyAdapter>,
        ) -> Result<Self> {
            ensure!(conwu_core::valid_id(network), "invalid network identity");
            let path = std::path::absolute(components.join("wintun.dll"))?;
            ensure!(
                path.is_file(),
                "缺少官方 wintun.dll，实验不会自动安装或替换驱动"
            );
            // SAFETY: explicit absolute component path and restricted dependent
            // DLL search prevent loading a same-named DLL from the working dir.
            let library: libloading::Library = unsafe {
                libloading::os::windows::Library::load_with_flags(&path, 0x100 | 0x1000)?
            }
            .into();
            unsafe {
                type SetLogger =
                    unsafe extern "system" fn(unsafe extern "system" fn(i32, u64, *const u16));
                let set_logger: SetLogger = *library.get(b"WintunSetLogger\0")?;
                set_logger(logger);
                let create: Create = *library.get(b"WintunCreateAdapter\0")?;
                let get_luid: AdapterLuid = *library.get(b"WintunGetAdapterLUID\0")?;
                let close: Close = *library.get(b"WintunCloseAdapter\0")?;
                let start: Start = *library.get(b"WintunStartSession\0")?;
                let end: Close = *library.get(b"WintunEndSession\0")?;
                let receive: Receive = *library.get(b"WintunReceivePacket\0")?;
                let release: Release = *library.get(b"WintunReleaseReceivePacket\0")?;
                let allocate: Allocate = *library.get(b"WintunAllocateSendPacket\0")?;
                let send: Send = *library.get(b"WintunSendPacket\0")?;
                let root = std::path::PathBuf::from(
                    std::env::var_os("ProgramData").context("缺少ProgramData目录")?,
                )
                .join("ConWU-Wintun")
                .join(network);
                let owner = crate::store::Store::open(&root).context("本网卡仍由其他实例持有")?;
                if let Some(scope) = legacy_scope {
                    ensure!(scope.network == network, "旧网卡作用域与本网络不符");
                }
                let mut legacy = legacy_scope
                    .map(crate::legacy_wintun::Guard::open)
                    .transpose()?;
                if let Some(legacy) = legacy.as_ref() {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                    loop {
                        let mut present = false;
                        for id in legacy.identities().keys() {
                            present |= device_present(*id)?;
                        }
                        if !present {
                            break;
                        }
                        ensure!(!cancel.is_cancelled(), "旧网卡准备已取消");
                        ensure!(
                            std::time::Instant::now() < deadline,
                            "原版虚拟网卡尚未退出，未创建第二个实例"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
                let journal = owner.checked_file("generation.json")?;
                let mut history = Vec::new();
                if journal.is_file() {
                    ensure!(
                        std::fs::metadata(&journal)?.len() <= 65536,
                        "虚拟网卡代次记录过大"
                    );
                    let previous: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&journal)?)?;
                    let id = uuid::Uuid::parse_str(
                        previous["id"].as_str().context("虚拟网卡代次记录无效")?,
                    )?;
                    if let Some(prior) = previous.get("history") {
                        history = serde_json::from_value::<Vec<uuid::Uuid>>(prior.clone())?;
                        ensure!(
                            history.len() <= 511 && history.iter().all(|g| !g.is_nil()),
                            "虚拟网卡代次历史无效"
                        );
                    }
                    if !history.contains(&id) {
                        history.push(id);
                    }
                    ensure!(
                        previous["network"] == network
                            && previous["name"]
                                == legacy
                                    .as_ref()
                                    .map(|l| l.name(id))
                                    .unwrap_or_else(|| format!(
                                        "ConWU-{}-{}",
                                        &network[..8],
                                        id.simple()
                                    )),
                        "虚拟网卡所有权记录不符"
                    );
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                    while device_present(id)? {
                        ensure!(!cancel.is_cancelled(), "虚拟网卡准备已取消");
                        ensure!(
                            std::time::Instant::now() < deadline,
                            "旧虚拟网卡设备尚未释放，未重叠创建新代次"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
                let (ignored, retained, legacy_retained) =
                    verified_orphans(network, &history, legacy.as_ref())?;
                if let Some(legacy) = legacy.as_ref() {
                    if !ignored.is_empty() || legacy.failed_create() {
                        settle_legacy(legacy.closed_at(), cancel)?;
                    }
                }
                let warnings = crate::routes::inspect(ip, &ignored)?;
                history = retained;
                // A removed GUID can remain cached as Up in IP Helper. Follow
                // the original generation journal and never recreate that GUID.
                // The old PnP instances have been checked and any stale IP
                // Helper rows have been attributed by GUID, LUID and alias.
                // Retry only when the driver reports a device-class transition.
                let mut retry_until = None;
                let mut backoff = std::time::Duration::from_millis(750);
                let (adapter, expected, generation) = loop {
                    ensure!(!cancel.is_cancelled(), "虚拟网卡准备已取消");
                    let id = uuid::Uuid::new_v4();
                    let (data1, data2, data3, data4) = id.as_fields();
                    let expected = AdapterGuid {
                        data1,
                        data2,
                        data3,
                        data4: *data4,
                    };
                    let name = legacy
                        .as_ref()
                        .map(|l| l.name(id))
                        .unwrap_or_else(|| format!("ConWU-{}-{}", &network[..8], id.simple()));
                    let mut generation = serde_json::json!({"network":network,"id":id,"name":name,"closed":false,"closedAt":0,"failedCreate":false,"history":history});
                    owner.write("generation.json", &serde_json::to_vec(&generation)?, true)?;
                    if let Some(legacy) = legacy.as_mut() {
                        legacy.record(id, &legacy_retained)?;
                    }
                    let adapter = create(
                        wide(&name).as_ptr(),
                        wide(if legacy.is_some() {
                            "StreamLink"
                        } else {
                            "ConWU"
                        })
                        .as_ptr(),
                        (&expected as *const AdapterGuid).cast(),
                    );
                    if !adapter.is_null() {
                        break (adapter, expected, generation);
                    }
                    let error = std::io::Error::last_os_error();
                    generation["closed"] = serde_json::json!(true);
                    generation["closedAt"] = serde_json::json!(conwu_core::unix_seconds() * 1000);
                    generation["failedCreate"] = serde_json::json!(true);
                    owner.write("generation.json", &serde_json::to_vec(&generation)?, false)?;
                    if let Some(legacy) = legacy.as_mut() {
                        legacy.closed(true)?;
                    }
                    let now = std::time::Instant::now();
                    let deadline = *retry_until.get_or_insert(now + std::time::Duration::from_secs(30));
                    let delay = creation_retry_delay(&error, deadline.saturating_duration_since(now), backoff)
                        .with_context(|| format!("WintunCreateAdapter failed: {error}"))?;
                    tracing::info!(retry_ms = delay.as_millis(), errno = 4319, "Windows 网卡类配置尚未完成");
                    wait_until(now + delay, cancel)?;
                    ensure!(!device_present(id)?, "创建失败的旧网卡尚未释放，未创建第二个实例");
                    backoff = (backoff * 2).min(std::time::Duration::from_secs(8));
                    if !history.contains(&id) {
                        history.push(id);
                    }
                };
                let mut luid = 0u64;
                get_luid(adapter, &mut luid);
                let mut actual = AdapterGuid {
                    data1: 0,
                    data2: 0,
                    data3: 0,
                    data4: [0; 8],
                };
                if ConvertInterfaceLuidToGuid(&luid, &mut actual) != 0 || actual != expected {
                    close(adapter);
                    anyhow::bail!("同名虚拟网卡不属于本网络，未接管该设备");
                }
                if let Err(error) = configure_ip(luid, ip, cancel) {
                    close(adapter);
                    return Err(error);
                }
                let session = start(adapter, 4 * 1024 * 1024);
                if session.is_null() {
                    close(adapter);
                    anyhow::bail!("WintunStartSession failed")
                }
                let driver = Self {
                    _library: library,
                    adapter,
                    luid,
                    session,
                    close,
                    end,
                    receive,
                    release,
                    allocate,
                    send,
                    rx: Mutex::new(()),
                    tx: Mutex::new(()),
                    owner,
                    generation,
                    legacy,
                    warnings,
                };
                ensure!(!cancel.is_cancelled(), "虚拟网卡准备已取消");
                Ok(driver)
            }
        }
    }
    impl Adapter for Wintun {
        fn read(&self) -> Result<Option<Vec<u8>>> {
            let _guard = self.rx.lock().unwrap();
            let mut size = 0;
            let pointer = unsafe { (self.receive)(self.session, &mut size) };
            if pointer.is_null() {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(259) {
                    return Ok(None);
                }
                return Err(e.into());
            }
            let packet = if size <= 1280 {
                Some(unsafe { std::slice::from_raw_parts(pointer, size as usize) }.to_vec())
            } else {
                None
            };
            unsafe { (self.release)(self.session, pointer) };
            Ok(packet)
        }
        fn write(&self, p: &[u8]) -> Result<bool> {
            ensure!(p.len() <= 1280, "virtual packet exceeds MTU");
            let _guard = self.tx.lock().unwrap();
            let pointer = unsafe { (self.allocate)(self.session, p.len() as u32) };
            if pointer.is_null() {
                return Ok(false);
            }
            unsafe {
                std::ptr::copy_nonoverlapping(p.as_ptr(), pointer, p.len());
                (self.send)(self.session, pointer)
            };
            Ok(true)
        }
        fn provider(&self) -> &'static str {
            "Official.Wintun"
        }
        fn warnings(&self) -> Vec<serde_json::Value> {
            self.warnings.clone()
        }
        fn route_interface(&self, local: Ipv4Addr, peer: Ipv4Addr) -> Option<u32> {
            use windows_sys::Win32::{
                NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2},
                Networking::WinSock::{AF_INET, SOCKADDR_INET},
            };
            let mut dst = SOCKADDR_INET::default();
            dst.Ipv4.sin_family = AF_INET;
            dst.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(peer.octets());
            let mut route = MIB_IPFORWARD_ROW2::default();
            let mut src = SOCKADDR_INET::default();
            let matches = unsafe {
                GetBestRoute2(
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &dst,
                    0,
                    &mut route,
                    &mut src,
                ) == 0
                    && route.InterfaceLuid.Value == self.luid
                    && src.si_family == AF_INET
                      && src.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes() == local.octets()
            };
            (matches && route.InterfaceIndex != 0).then_some(route.InterfaceIndex)
        }
    }
    impl Drop for Wintun {
        fn drop(&mut self) {
            unsafe {
                (self.end)(self.session);
                (self.close)(self.adapter);
            }
            self.generation["closed"] = serde_json::json!(true);
            self.generation["closedAt"] = serde_json::json!(conwu_core::unix_seconds() * 1000);
            if let Ok(bytes) = serde_json::to_vec(&self.generation) {
                let _ = self.owner.write("generation.json", &bytes, false);
            }
            if let Some(legacy) = self.legacy.as_mut() {
                if let Err(error) = legacy.closed(false) {
                    tracing::warn!("保存兼容网卡关闭记录失败：{error}");
                }
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn creation_retries_class_cleanup_within_the_remaining_budget() {
        use std::time::Duration;
        let transition = std::io::Error::from_raw_os_error(4319);
        let backoff = Duration::from_millis(750);
        assert_eq!(creation_retry_delay(&transition, Duration::from_secs(30), backoff), Some(backoff));
        assert_eq!(creation_retry_delay(&transition, Duration::from_millis(100), backoff), Some(Duration::from_millis(100)));
        assert_eq!(creation_retry_delay(&transition, Duration::ZERO, backoff), None);
        assert_eq!(creation_retry_delay(&std::io::Error::from_raw_os_error(5), Duration::from_secs(30), backoff), None);
    }
}
