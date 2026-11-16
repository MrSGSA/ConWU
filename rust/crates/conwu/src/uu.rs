use crate::backend::{App, revision};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
#[derive(Default)]
struct Counters {
    sent: u64,
    received: u64,
    buckets: BTreeMap<i64, u64>,
}
#[derive(Default)]
struct State {
    active: bool,
    pids: Vec<u32>,
    error: String,
    networks: BTreeMap<String, Counters>,
    owners: HashSet<(u8, u16)>,
}
static STATE: OnceLock<Mutex<State>> = OnceLock::new();
fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| Mutex::new(State::default()))
}
pub fn status(app: &App) -> Value {
    let db = app.db.read().unwrap();
    let settings = db.device_settings["uuTakeover"].clone();
    let s = state().lock().unwrap();
    let now = conwu_core::unix_seconds();
    let mut sent = 0;
    let mut received = 0;
    let rows=s.networks.iter().map(|(id,c)|{sent+=c.sent;received+=c.received;let a=c.buckets.get(&(now-1)).copied().unwrap_or(0);let b=c.buckets.get(&(now-2)).copied().unwrap_or(0);json!({"id":id,"trafficObserved":a>=16384&&b>=16384,"sentBytes":c.sent,"receivedBytes":c.received,"bytesPerSecond":(a+b)/2})}).collect::<Vec<_>>();
    json!({"supported":cfg!(windows),"settings":settings,"revision":revision(&settings),"state":if !s.error.is_empty(){"Error"}else if s.active{"Active"}else{"Idle"},"message":if !s.error.is_empty(){s.error.as_str()}else if s.active{"已自动接管 UU 选路，串流流量以右侧计数为准"}else{"等待开启功能、网络直连及 UU 运行"},"rulesActive":s.active,"processes":s.pids,"networks":rows,"sentBytes":sent,"receivedBytes":received})
}
pub async fn configure(app: &App, action: Value) -> Result<Value> {
    ensure!(cfg!(windows), "UU 远程接管目前支持 Windows");
    let mut next = app.db.read().unwrap().clone();
    let settings = json!({"enabled":action["settings"]["enabled"].as_bool().unwrap_or(false),"automatic":true});
    if let Some(expected) = action["expectedRevision"].as_str() {
        ensure!(
            expected == revision(&next.device_settings["uuTakeover"]),
            "UU 设置已改变，请刷新"
        );
    }
    next.device_settings["uuTakeover"] = settings;
    app.commit(next)?;
    Ok(Value::Null)
}
pub fn observe(id: &str, p: &[u8], outbound: bool) {
    if p.len() < 28 || p[0] >> 4 != 4 {
        return;
    }
    let ihl = (p[0] & 15) as usize * 4;
    if ihl < 20 || p.len() < ihl + 8 || u16::from_be_bytes([p[6], p[7]]) & 0x1fff != 0 {
        return;
    }
    let port = u16::from_be_bytes(
        p[ihl + if outbound { 0 } else { 2 }..ihl + if outbound { 2 } else { 4 }]
            .try_into()
            .unwrap(),
    );
    let mut s = state().lock().unwrap();
    if !s.active || !s.owners.contains(&(p[9], port)) {
        return;
    }
    let c = s.networks.entry(id.into()).or_default();
    if outbound {
        c.sent += p.len() as u64
    } else {
        c.received += p.len() as u64
    }
    if p.len() >= ihl + 808 {
        let now = conwu_core::unix_seconds();
        c.buckets.retain(|k, _| *k >= now - 5 && *k <= now + 1);
        *c.buckets.entry(now).or_default() += p.len() as u64;
    }
}
pub fn start(app: Arc<App>) {
    let tracker = app.engine.tracker.clone();
    tracker.spawn(async move{let mut gate:Option<Gate>=None;let mut signature=String::new();loop{if app.engine.cancel.is_cancelled(){break}let enabled=app.db.read().unwrap().device_settings["uuTakeover"]["enabled"]==true;let networks=app.db.read().unwrap().networks.iter().filter_map(|n|app.engine.current(&n.id).filter(|r|r.metrics.read().unwrap().connected&&!n.paused).and_then(|_|n.profile.as_ref().and_then(|p|p.local_ip().ok())).map(|ip|(n.id.clone(),ip.to_string()))).collect::<Vec<_>>();
            let result=if enabled&&!networks.is_empty(){processes()}else{Ok(vec![])};match result {Ok(pids)=>{let new=format!("{pids:?}/{networks:?}");if new!=signature {gate.take();state().lock().unwrap().active=false;signature=new;if !pids.is_empty(){match Gate::open(&app.engine.components,&networks,&pids){Ok(g)=>{gate=Some(g);let mut s=state().lock().unwrap();s.active=true;s.error.clear();s.pids=pids.clone();},Err(e)=>{state().lock().unwrap().error=e.to_string();signature.clear();}}}}
                if gate.is_some(){match owners(&pids){Ok(owners)=>state().lock().unwrap().owners=owners,Err(e)=>{gate.take();let mut s=state().lock().unwrap();s.active=false;s.error=e.to_string();signature.clear();}}}
            },Err(e)=>{gate.take();let mut s=state().lock().unwrap();s.active=false;s.error=e.to_string();}}
            tokio::select!{_=app.engine.cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(500))=>{}}
        }drop(gate);state().lock().unwrap().active=false;});
}
#[cfg(not(windows))]
struct Gate;
#[cfg(not(windows))]
impl Gate {
    fn open(_: &std::path::Path, _: &[(String, String)], _: &[u32]) -> Result<Self> {
        anyhow::bail!("UU 远程无 Linux 客户端")
    }
}
#[cfg(not(windows))]
fn processes() -> Result<Vec<u32>> {
    Ok(vec![])
}
#[cfg(not(windows))]
fn owners(_: &[u32]) -> Result<HashSet<(u8, u16)>> {
    Ok(HashSet::new())
}
#[cfg(windows)]
use windows::{Gate, owners, processes};
#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        ffi::{CString, c_void},
        os::windows::ffi::OsStringExt,
        path::Path,
    };
    type Open = unsafe extern "C" fn(*const i8, i32, i16, u64) -> *mut c_void;
    type Close = unsafe extern "C" fn(*mut c_void) -> i32;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn K32EnumProcesses(ids: *mut u32, bytes: u32, used: *mut u32) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn QueryFullProcessImageNameW(
            handle: *mut c_void,
            flags: u32,
            path: *mut u16,
            length: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetExtendedTcpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            kind: i32,
            reserved: u32,
        ) -> u32;
        fn GetExtendedUdpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            kind: i32,
            reserved: u32,
        ) -> u32;
    }
    fn allowed(pid: u32) -> Option<*mut c_void> {
        unsafe {
            let handle = OpenProcess(0x1000 | 0x100000, 0, pid);
            if handle.is_null() {
                return None;
            }
            let mut buffer = vec![0u16; 32768];
            let mut n = buffer.len() as u32;
            if QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut n) == 0 {
                CloseHandle(handle);
                return None;
            }
            let path =
                std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..n as usize]));
            let file = path.file_name()?.to_string_lossy();
            let root = path.parent()?;
            let valid = matches!(
                file.to_ascii_lowercase().as_str(),
                "gameviewer.exe" | "gameviewerserver.exe"
            ) && ["ProgramFiles", "ProgramFiles(x86)"]
                .iter()
                .filter_map(std::env::var_os)
                .any(|p| {
                    root.to_string_lossy().eq_ignore_ascii_case(
                        &std::path::PathBuf::from(p)
                            .join("Netease/GameViewer/bin")
                            .to_string_lossy(),
                    )
                });
            if valid {
                Some(handle)
            } else {
                CloseHandle(handle);
                None
            }
        }
    }
    pub fn processes() -> Result<Vec<u32>> {
        let mut ids = vec![0u32; 16384];
        let mut used = 0;
        ensure!(
            unsafe { K32EnumProcesses(ids.as_mut_ptr(), (ids.len() * 4) as u32, &mut used) } != 0,
            "无法识别 UU 进程"
        );
        let mut result = vec![];
        for pid in &ids[..used as usize / 4] {
            if let Some(handle) = allowed(*pid) {
                unsafe { CloseHandle(handle) };
                result.push(*pid);
            }
        }
        Ok(result)
    }
    pub struct Gate {
        _library: libloading::Library,
        handle: *mut c_void,
        close: Close,
        pins: Vec<*mut c_void>,
    }
    // Only the polling owner opens/closes these handles. OS handle lifetime is
    // pinned throughout rule ownership; no pointer references Rust memory.
    unsafe impl Send for Gate {}
    impl Gate {
        pub fn open(
            components: &Path,
            networks: &[(String, String)],
            pids: &[u32],
        ) -> Result<Self> {
            ensure!(pids.len() <= 32 && networks.len() <= 32, "UU 选路规则过大");
            let path = std::path::absolute(components.join("WinDivert.dll"))?;
            let library: libloading::Library =
                unsafe { libloading::os::windows::Library::load_with_flags(path, 0x1100)? }.into();
            let (open, close) = unsafe {
                (
                    *library.get::<Open>(b"WinDivertOpen\0")?,
                    *library.get::<Close>(b"WinDivertClose\0")?,
                )
            };
            let mut pins = vec![];
            for pid in pids {
                let Some(handle) = allowed(*pid) else {
                    for h in pins {
                        unsafe { CloseHandle(h) };
                    }
                    anyhow::bail!("UU 进程已改变")
                };
                pins.push(handle);
            }
            let pid = pids
                .iter()
                .map(|p| format!("processId == {p}"))
                .collect::<Vec<_>>()
                .join(" or ");
            let ips = networks
                .iter()
                .map(|(_, ip)| format!("localAddr != {ip}"))
                .collect::<Vec<_>>()
                .join(" and ");
            let filter = CString::new(format!(
                "({pid}) and event == 3 and {ips} and localAddr != 0.0.0.0 and localAddr != 127.0.0.1 and localAddr != :: and localAddr != ::1"
            ))?;
            let handle = unsafe { open(filter.as_ptr(), 3, 0, 2 | 4) };
            if handle as isize == -1 {
                for h in pins {
                    unsafe { CloseHandle(h) };
                }
                anyhow::bail!("UU 选路规则启用失败：{}", std::io::Error::last_os_error())
            }
            Ok(Self {
                _library: library,
                handle,
                close,
                pins,
            })
        }
    }
    impl Drop for Gate {
        fn drop(&mut self) {
            unsafe {
                (self.close)(self.handle);
                for h in &self.pins {
                    CloseHandle(*h);
                }
            }
        }
    }
    pub fn owners(pids: &[u32]) -> Result<HashSet<(u8, u16)>> {
        let mut own = HashSet::new();
        let mut foreign = HashSet::new();
        for tcp in [false, true] {
            let mut size = 0;
            let table = |p, size: &mut u32| unsafe {
                if tcp {
                    GetExtendedTcpTable(p, size, 0, 2, 5, 0)
                } else {
                    GetExtendedUdpTable(p, size, 0, 2, 1, 0)
                }
            };
            let code = table(std::ptr::null_mut(), &mut size);
            ensure!(
                matches!(code, 0 | 122) && size <= 16 * 1024 * 1024,
                "套接字归属查询失败"
            );
            let mut bytes = vec![0u8; size as usize];
            ensure!(
                table(bytes.as_mut_ptr().cast(), &mut size) == 0 && size >= 4,
                "套接字归属表变化，请重试"
            );
            let count = u32::from_ne_bytes(bytes[..4].try_into()?) as usize;
            let width = if tcp { 24 } else { 12 };
            ensure!(4 + count * width <= size as usize, "套接字表截断");
            for row in bytes[4..4 + count * width].chunks_exact(width) {
                let pid = u32::from_ne_bytes(
                    row[if tcp { 20 } else { 8 }..if tcp { 24 } else { 12 }].try_into()?,
                );
                let at = if tcp { 8 } else { 4 };
                let port = u16::from_be_bytes(row[at..at + 2].try_into()?);
                let item = (if tcp { 6 } else { 17 }, port);
                if pids.contains(&pid) {
                    own.insert(item);
                } else {
                    foreign.insert(item);
                }
            }
        }
        own.retain(|p| !foreign.contains(p));
        Ok(own)
    }
}
