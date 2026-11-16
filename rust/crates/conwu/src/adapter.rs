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
pub fn open(network: &str, ip: Ipv4Addr, components: &Path) -> Result<Arc<dyn Adapter>> {
    #[cfg(target_os = "linux")]
    {
        let _ = components;
        return Ok(Arc::new(linux::Tun::open(network, ip)?));
    }
    #[cfg(windows)]
    {
        return Ok(Arc::new(windows::Wintun::open(network, ip, components)?));
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
    }
    impl Tun {
        pub fn open(network: &str, ip: Ipv4Addr) -> Result<Self> {
            ensure!(conwu_core::valid_id(network), "invalid owned network");
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
                unsafe {
                    libc::ioctl(
                        file.as_raw_fd(),
                        0x400454ca as libc::c_ulong,
                        request.as_mut_ptr(),
                    )
                } >= 0,
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
            Ok(Self { file })
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
    }
}
#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        ffi::c_void,
        os::windows::{ffi::OsStrExt, process::CommandExt},
    };
    type Handle = *mut c_void;
    type Create = unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> Handle;
    type Close = unsafe extern "system" fn(Handle);
    type Start = unsafe extern "system" fn(Handle, u32) -> Handle;
    type Receive = unsafe extern "system" fn(Handle, *mut u32) -> *mut u8;
    type Release = unsafe extern "system" fn(Handle, *const u8);
    type Allocate = unsafe extern "system" fn(Handle, u32) -> *mut u8;
    type Send = unsafe extern "system" fn(Handle, *const u8);
    pub struct Wintun {
        _library: libloading::Library,
        adapter: Handle,
        session: Handle,
        close: Close,
        end: Close,
        receive: Receive,
        release: Release,
        allocate: Allocate,
        send: Send,
        rx: Mutex<()>,
        tx: Mutex<()>,
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
    impl Wintun {
        pub fn open(network: &str, ip: Ipv4Addr, components: &Path) -> Result<Self> {
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
                let create: Create = *library.get(b"WintunCreateAdapter\0")?;
                let close: Close = *library.get(b"WintunCloseAdapter\0")?;
                let start: Start = *library.get(b"WintunStartSession\0")?;
                let end: Close = *library.get(b"WintunEndSession\0")?;
                let receive: Receive = *library.get(b"WintunReceivePacket\0")?;
                let release: Release = *library.get(b"WintunReleaseReceivePacket\0")?;
                let allocate: Allocate = *library.get(b"WintunAllocateSendPacket\0")?;
                let send: Send = *library.get(b"WintunSendPacket\0")?;
                let name = format!("ConWU Rust {}", &network[..8]);
                let adapter = create(
                    wide(&name).as_ptr(),
                    wide("ConWU Rust experiment").as_ptr(),
                    std::ptr::null(),
                );
                ensure!(
                    !adapter.is_null(),
                    "WintunCreateAdapter failed: {}",
                    std::io::Error::last_os_error()
                );
                let session = start(adapter, 4 * 1024 * 1024);
                if session.is_null() {
                    close(adapter);
                    anyhow::bail!("WintunStartSession failed")
                }
                let driver = Self {
                    _library: library,
                    adapter,
                    session,
                    close,
                    end,
                    receive,
                    release,
                    allocate,
                    send,
                    rx: Mutex::new(()),
                    tx: Mutex::new(()),
                };
                let status = std::process::Command::new("netsh.exe")
                    .args([
                        "interface",
                        "ipv4",
                        "set",
                        "address",
                        &format!("name={name}"),
                        "source=static",
                        &format!("address={ip}"),
                        "mask=255.255.255.0",
                        "store=active",
                    ])
                    .creation_flags(0x08000000)
                    .stdout(std::process::Stdio::null())
                    .status()?;
                ensure!(status.success(), "无法配置本机实验网卡地址");
                let status = std::process::Command::new("netsh.exe")
                    .args([
                        "interface",
                        "ipv4",
                        "set",
                        "subinterface",
                        &name,
                        "mtu=1280",
                        "store=active",
                    ])
                    .creation_flags(0x08000000)
                    .stdout(std::process::Stdio::null())
                    .status()?;
                ensure!(status.success(), "无法配置实验网卡 MTU");
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
    }
    impl Drop for Wintun {
        fn drop(&mut self) {
            unsafe {
                (self.end)(self.session);
                (self.close)(self.adapter);
            }
        }
    }
}
