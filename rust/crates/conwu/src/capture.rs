//! One process-owned WinDivert capture per retained TCP source mapping. Workers
//! get PID-bound sessions, not another capture handle or permission to rebind.
use crate::native::Descriptor;
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

static SESSIONS: OnceLock<Mutex<HashMap<uuid::Uuid, Weak<Session>>>> = OnceLock::new();
fn registry() -> &'static Mutex<HashMap<uuid::Uuid, Weak<Session>>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}
pub fn find(d: &Descriptor) -> Option<Arc<Session>> {
    registry()
        .lock()
        .unwrap()
        .get(&d.attach)
        .and_then(Weak::upgrade)
}
pub fn revoke(d: &Descriptor) {
    if let Some(s) = find(d) {
        s.active.store(false, Ordering::Release);
    }
}
pub fn retire(d: &Descriptor) {
    registry().lock().unwrap().remove(&d.attach);
}

struct State {
    peer: SocketAddr,
    hypotheses: HashMap<SocketAddr, u32>,
    own_isn: Option<u32>,
    began: Option<Instant>,
    frozen: bool,
    received: u64,
    sent: u64,
    drops: u64,
    packets: u32,
    bytes: u64,
    window: Instant,
    wire: [u64; 5],
}
pub struct Session {
    owner: Arc<Owner>,
    descriptor: Descriptor,
    active: AtomicBool,
    state: Mutex<State>,
    input: mpsc::Sender<Vec<u8>>,
    output: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
}
impl Session {
    pub fn activate(&self) {
        let mut s = self.state.lock().unwrap();
        if s.began.is_none() {
            s.began = Some(Instant::now());
        }
        self.active.store(true, Ordering::Release);
    }
    pub fn peer(&self) -> SocketAddr {
        self.state.lock().unwrap().peer
    }
    pub fn freeze(&self) {
        self.state.lock().unwrap().frozen = true;
    }
    pub fn status(&self) -> serde_json::Value {
        let s = self.state.lock().unwrap();
        serde_json::json!({"local":self.descriptor.local,"announced":self.descriptor.peer,"actual":s.peer,"hypotheses":s.hypotheses.len(),"learned":s.peer!=self.descriptor.peer,"frozen":s.frozen,"received":s.received,"sent":s.sent,"queueDrops":s.drops,"wirePackets":s.wire})
    }
    pub async fn receive(&self) -> Result<Vec<u8>> {
        self.output
            .lock()
            .await
            .recv()
            .await
            .context("捕获会话已关闭")
    }
    pub fn send(&self, bytes: &[u8], kind: u8) -> Result<bool> {
        ensure!(
            kind <= 4 && (self.descriptor.wire_metadata || kind == 0),
            "原生 worker 未获报文类别授权"
        );
        let p = Packet::parse(bytes, true).context("原生 worker 返回无效 TCP 报文")?;
        ensure!(
            p.source == self.descriptor.local,
            "原生 worker 更换了本机端点"
        );
        ensure!(
            !matches!(kind, 2 | 4) || p.payload > 0 && p.flags & 7 == 0,
            "TCP 控制报文不能使用业务预算"
        );
        let mut s = self.state.lock().unwrap();
        if !self.active.load(Ordering::Acquire) || self.owner.stop.is_cancelled() {
            return Ok(false);
        }
        if p.target != s.peer {
            let learn = self.descriptor.peer_reflexive
                && !s.frozen
                && s.began
                    .is_some_and(|t| t.elapsed() < Duration::from_secs(8));
            let remote = s.hypotheses.get(&p.target).copied();
            ensure!(
                learn
                    && remote.is_some_and(|r| p.ack == r.wrapping_add(1))
                    && s.own_isn.is_some_and(|own| p.flags == 18 && p.seq == own
                        || p.flags == 16 && p.seq == own.wrapping_add(1)),
                "原生 worker 使用未经观察的对端端点"
            );
            let occupied = self.owner.sessions.lock().unwrap().iter().any(|(id, w)| {
                *id != self.descriptor.attach
                    && w.upgrade()
                        .is_some_and(|other| other.descriptor.peer == p.target)
            });
            ensure!(!occupied, "新的对端端点已被其他捕获会话占用");
            s.peer = p.target;
            s.hypotheses.clear();
        }
        if s.window.elapsed() >= Duration::from_secs(1) {
            s.window = Instant::now();
            s.packets = 0;
            s.bytes = 0;
        }
        // Business delivery has no artificial handshake-rate cap. Bounds apply
        // to shape/control traffic; all queues remain independently bounded.
        if kind != 2 {
            if s.packets >= 60 || s.bytes + bytes.len() as u64 > 65536 {
                s.drops += 1;
                return Ok(false);
            }
            s.packets += 1;
            s.bytes += bytes.len() as u64;
        }
        if p.flags == 2 && p.payload == 0 {
            s.own_isn.get_or_insert(p.seq);
        }
        let sent = self.owner.io.inject(bytes)?;
        if sent {
            s.sent += 1;
            s.wire[kind as usize] += 1;
        }
        Ok(sent)
    }
    fn incoming(&self, bytes: &[u8], packet: &Packet) -> bool {
        if !self.active.load(Ordering::Acquire) {
            return false;
        }
        let mut s = self.state.lock().unwrap();
        let mut allowed = packet.source == s.peer;
        if !allowed
            && self.descriptor.peer_reflexive
            && !s.frozen
            && packet.source.ip() == self.descriptor.peer.ip()
            && packet.source != self.descriptor.observer
            && packet.payload == 0
            && matches!(packet.flags, 2 | 18)
            && s.began
                .is_some_and(|t| t.elapsed() < Duration::from_secs(8))
            && s.own_isn
                .is_some_and(|isn| packet.flags == 2 || packet.ack == isn.wrapping_add(1))
        {
            if let Some(old) = s.hypotheses.get(&packet.source) {
                allowed = *old == packet.seq;
            } else if s.hypotheses.len() < 4 {
                s.hypotheses.insert(packet.source, packet.seq);
                allowed = true;
            }
        }
        if allowed {
            s.received += 1;
            if self.input.try_send(bytes.to_vec()).is_err() {
                s.drops += 1;
            }
        }
        allowed
    }
}
pub struct Owner {
    local: SocketAddr,
    observer: SocketAddr,
    io: Arc<WinDivert>,
    stop: CancellationToken,
    sessions: Mutex<HashMap<uuid::Uuid, Weak<Session>>>,
    receiver: Mutex<Option<tokio::task::JoinHandle<Result<()>>>>,
    unknown: mpsc::Sender<SocketAddr>,
    unknown_receiver: Mutex<Option<mpsc::Receiver<SocketAddr>>>,
}
impl Owner {
    pub fn open(
        components: &std::path::Path,
        local: SocketAddr,
        observer: SocketAddr,
        parent: &CancellationToken,
    ) -> Result<Arc<Self>> {
        let io = Arc::new(WinDivert::open(
            &components.join("WinDivert.dll"),
            local,
            observer,
        )?);
        let (unknown, unknown_receiver) = mpsc::channel(16);
        let owner = Arc::new(Self {
            local,
            observer,
            io: io.clone(),
            stop: parent.child_token(),
            sessions: Mutex::new(HashMap::new()),
            receiver: Mutex::new(None),
            unknown,
            unknown_receiver: Mutex::new(Some(unknown_receiver)),
        });
        let weak = Arc::downgrade(&owner);
        let stop = owner.stop.clone();
        let task = tokio::task::spawn_blocking(move || {
            let mut bytes = vec![0; 65535];
            let mut address = [0u8; 80];
            while !stop.is_cancelled() {
                let n = match io.receive(&mut bytes, &mut address) {
                    Ok(n) => n,
                    Err(e) => {
                        if stop.is_cancelled() {
                            break;
                        }
                        stop.cancel();
                        return Err(e);
                    }
                };
                let Some(p) = Packet::parse(&bytes[..n], false) else {
                    continue;
                };
                let outbound =
                    u32::from_le_bytes(address[8..12].try_into().unwrap()) & (1 << 17) != 0;
                let Some(owner) = weak.upgrade() else { break };
                let (local, remote) = if outbound {
                    (p.source, p.target)
                } else {
                    (p.target, p.source)
                };
                if local != owner.local || remote == owner.observer {
                    io.reinject(&bytes[..n], &address)?;
                    continue;
                }
                if outbound {
                    continue;
                } // suppress kernel RST/ACK for this source only
                let sessions = owner
                    .sessions
                    .lock()
                    .unwrap()
                    .values()
                    .filter_map(Weak::upgrade)
                    .collect::<Vec<_>>();
                let known = sessions.iter().any(|s| s.descriptor.peer == remote);
                let mut handled = false;
                for session in sessions {
                    if session.incoming(&bytes[..n], &p) {
                        handled = true;
                        break;
                    }
                }
                if !known && !handled && p.flags == 2 && p.payload == 0 {
                    let _ = owner.unknown.try_send(remote);
                }
            }
            Ok(())
        });
        *owner.receiver.lock().unwrap() = Some(task);
        Ok(owner)
    }
    pub fn register(self: &Arc<Self>, descriptor: Descriptor) -> Result<Arc<Session>> {
        ensure!(
            descriptor.broker
                && descriptor.local == self.local
                && descriptor.observer == self.observer
                && !self.stop.is_cancelled(),
            "捕获所有者与原生接入不符"
        );
        descriptor.frame(1, 1)?;
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.strong_count() > 0);
        ensure!(
            sessions.len() < 8
                && !sessions
                    .values()
                    .filter_map(Weak::upgrade)
                    .any(|s| s.descriptor.peer == descriptor.peer
                        || descriptor.peer_reflexive
                            && s.descriptor.peer_reflexive
                            && s.descriptor.peer.ip() == descriptor.peer.ip()),
            "捕获端点已占用或超过会话上限"
        );
        let (input, output) = mpsc::channel(64);
        let id = descriptor.attach;
        let session = Arc::new(Session {
            state: Mutex::new(State {
                peer: descriptor.peer,
                hypotheses: HashMap::new(),
                own_isn: None,
                began: None,
                frozen: false,
                received: 0,
                sent: 0,
                drops: 0,
                packets: 0,
                bytes: 0,
                window: Instant::now(),
                wire: [0; 5],
            }),
            descriptor,
            owner: self.clone(),
            active: AtomicBool::new(false),
            input,
            output: tokio::sync::Mutex::new(output),
        });
        sessions.insert(id, Arc::downgrade(&session));
        registry()
            .lock()
            .unwrap()
            .retain(|_, s| s.strong_count() > 0);
        registry()
            .lock()
            .unwrap()
            .insert(id, Arc::downgrade(&session));
        Ok(session)
    }
    pub fn take_unknown(&self) -> Option<mpsc::Receiver<SocketAddr>> {
        self.unknown_receiver.lock().unwrap().take()
    }
    pub async fn close(&self) -> Result<()> {
        self.stop.cancel();
        self.io.shutdown();
        let task = self.receiver.lock().unwrap().take();
        if let Some(task) = task {
            task.await??;
        }
        Ok(())
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.stop.cancel();
        self.io.shutdown();
    }
}

struct Packet {
    source: SocketAddr,
    target: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: usize,
}
impl Packet {
    fn checksums(bytes: &[u8]) -> bool {
        if Self::parse(bytes, false).is_none() {
            return false;
        }
        fn sum(bytes: &[u8], initial: u32) -> u32 {
            let mut s = initial;
            for p in bytes.chunks(2) {
                s += if p.len() == 2 {
                    u16::from_be_bytes([p[0], p[1]]) as u32
                } else {
                    (p[0] as u32) << 8
                };
            }
            s
        }
        fn correct(mut s: u32) -> bool {
            while s >> 16 != 0 {
                s = (s & 65535) + (s >> 16);
            }
            s == 65535
        }
        let v6 = bytes[0] >> 4 == 6;
        let at = if v6 { 40 } else { (bytes[0] & 15) as usize * 4 };
        let total = if v6 {
            40 + u16::from_be_bytes(bytes[4..6].try_into().unwrap()) as usize
        } else {
            u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize
        };
        if !v6 && !correct(sum(&bytes[..at], 0)) {
            return false;
        }
        let pseudo = if v6 {
            sum(&bytes[8..40], 0)
        } else {
            sum(&bytes[12..20], 0)
        };
        correct(sum(&bytes[at..total], pseudo + 6 + (total - at) as u32))
    }
    fn parse(bytes: &[u8], exact: bool) -> Option<Self> {
        if bytes.len() < 40 {
            return None;
        }
        let (at, total, source, target) = match bytes[0] >> 4 {
            4 => {
                let at = (bytes[0] & 15) as usize * 4;
                let total = u16::from_be_bytes(bytes[2..4].try_into().ok()?) as usize;
                if bytes[9] != 6
                    || u16::from_be_bytes(bytes[6..8].try_into().ok()?) & 0x3fff != 0
                    || at < 20
                {
                    return None;
                }
                (
                    at,
                    total,
                    IpAddr::from(<[u8; 4]>::try_from(&bytes[12..16]).ok()?),
                    IpAddr::from(<[u8; 4]>::try_from(&bytes[16..20]).ok()?),
                )
            }
            6 => {
                if bytes.len() < 60 || bytes[6] != 6 {
                    return None;
                }
                (
                    40,
                    40 + u16::from_be_bytes(bytes[4..6].try_into().ok()?) as usize,
                    IpAddr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?),
                    IpAddr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?),
                )
            }
            _ => return None,
        };
        if total > bytes.len() || total < at + 20 || exact && total != bytes.len() {
            return None;
        }
        let tcp = (bytes[at + 12] >> 4) as usize * 4;
        if tcp < 20 || at + tcp > total {
            return None;
        }
        let mut options = &bytes[at + 20..at + tcp];
        while !options.is_empty() {
            let kind = options[0];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                options = &options[1..];
                continue;
            }
            if options.len() < 2 {
                return None;
            }
            let n = options[1] as usize;
            if n < 2 || n > options.len() || kind == 8 && n != 10 {
                return None;
            }
            options = &options[n..];
        }
        let source = SocketAddr::new(
            source,
            u16::from_be_bytes(bytes[at..at + 2].try_into().ok()?),
        );
        let target = SocketAddr::new(
            target,
            u16::from_be_bytes(bytes[at + 2..at + 4].try_into().ok()?),
        );
        if source.port() == 0 || target.port() == 0 {
            return None;
        }
        Some(Self {
            source,
            target,
            seq: u32::from_be_bytes(bytes[at + 4..at + 8].try_into().ok()?),
            ack: u32::from_be_bytes(bytes[at + 8..at + 12].try_into().ok()?),
            flags: bytes[at + 13],
            payload: total - at - tcp,
        })
    }
}
type Handle = *mut std::ffi::c_void;
type Open = unsafe extern "C" fn(*const std::ffi::c_char, i32, i16, u64) -> Handle;
type Recv = unsafe extern "C" fn(Handle, *mut u8, u32, *mut u32, *mut u8) -> i32;
type Send = unsafe extern "C" fn(Handle, *const u8, u32, *mut u32, *const u8) -> i32;
type Close = unsafe extern "C" fn(Handle) -> i32;
type Shutdown = unsafe extern "C" fn(Handle, i32) -> i32;
type Set = unsafe extern "C" fn(Handle, i32, u64) -> i32;
type Checksum = unsafe extern "C" fn(*mut u8, u32, *mut u8, u64) -> i32;
struct WinDivert {
    _library: libloading::Library,
    handle: usize,
    recv: Recv,
    send: Send,
    close: Close,
    stop: Shutdown,
    checksum: Checksum,
}
// WinDivert supports one receive thread and simultaneous injection/shutdown.
unsafe impl std::marker::Send for WinDivert {}
unsafe impl Sync for WinDivert {}
impl WinDivert {
    fn open(path: &std::path::Path, local: SocketAddr, observer: SocketAddr) -> Result<Self> {
        ensure!(
            local.port() != 0
                && !local.ip().is_unspecified()
                && !local.ip().is_loopback()
                && local.is_ipv4() == observer.is_ipv4()
                && local != observer,
            "捕获需要已保留的物理源端点"
        );
        let ip = if local.is_ipv4() { "ip" } else { "ipv6" };
        let filter = std::ffi::CString::new(format!(
            "!loopback and {ip} and tcp and ((inbound and {ip}.DstAddr == {} and tcp.DstPort == {} and ({ip}.SrcAddr != {} or tcp.SrcPort != {})) or (outbound and {ip}.SrcAddr == {} and tcp.SrcPort == {} and ({ip}.DstAddr != {} or tcp.DstPort != {})))",
            local.ip(),
            local.port(),
            observer.ip(),
            observer.port(),
            local.ip(),
            local.port(),
            observer.ip(),
            observer.port()
        ))?;
        let library: libloading::Library = unsafe {
            libloading::os::windows::Library::load_with_flags(std::path::absolute(path)?, 0x1100)?
        }
        .into();
        unsafe {
            let open: Open = *library.get(b"WinDivertOpen\0")?;
            let recv = *library.get(b"WinDivertRecv\0")?;
            let send = *library.get(b"WinDivertSend\0")?;
            let close: Close = *library.get(b"WinDivertClose\0")?;
            let stop = *library.get(b"WinDivertShutdown\0")?;
            let set: Set = *library.get(b"WinDivertSetParam\0")?;
            let checksum = *library.get(b"WinDivertHelperCalcChecksums\0")?;
            let handle = open(filter.as_ptr(), 0, 100, 16);
            ensure!(
                handle as isize != -1,
                "捕获打开失败：{}",
                std::io::Error::last_os_error()
            );
            if set(handle, 0, 4096) == 0
                || set(handle, 1, 100) == 0
                || set(handle, 2, 4 * 1024 * 1024) == 0
            {
                close(handle);
                anyhow::bail!("无法设置有界捕获队列");
            }
            Ok(Self {
                _library: library,
                handle: handle as usize,
                recv,
                send,
                close,
                stop,
                checksum,
            })
        }
    }
    fn receive(&self, bytes: &mut [u8], address: &mut [u8; 80]) -> Result<usize> {
        let mut n = 0;
        ensure!(
            unsafe {
                (self.recv)(
                    self.handle as Handle,
                    bytes.as_mut_ptr(),
                    bytes.len() as u32,
                    &mut n,
                    address.as_mut_ptr(),
                )
            } != 0,
            "捕获接收失败：{}",
            std::io::Error::last_os_error()
        );
        ensure!(n as usize <= bytes.len(), "捕获长度越界");
        let flags = u32::from_le_bytes(address[8..12].try_into().unwrap());
        let required = if flags & (1 << 20) != 0 {
            1 << 22
        } else {
            (1 << 21) | (1 << 22)
        };
        if flags & required != required
            && unsafe { (self.checksum)(bytes.as_mut_ptr(), n, address.as_mut_ptr(), 0) } == 0
        {
            return Ok(0);
        }
        if !Packet::checksums(&bytes[..n as usize]) {
            return Ok(0);
        }
        Ok(n as usize)
    }
    fn inject(&self, bytes: &[u8]) -> Result<bool> {
        let mut data = bytes.to_vec();
        let mut address = [0; 80];
        let flags = (1u32 << 17) | (1 << 22) | if bytes[0] >> 4 == 6 { 1 << 20 } else { 1 << 21 };
        address[8..12].copy_from_slice(&flags.to_le_bytes());
        ensure!(
            unsafe {
                (self.checksum)(
                    data.as_mut_ptr(),
                    data.len() as u32,
                    address.as_mut_ptr(),
                    0,
                )
            } != 0,
            "无法设置注入校验和"
        );
        self.reinject(&data, &address)
    }
    fn reinject(&self, bytes: &[u8], address: &[u8; 80]) -> Result<bool> {
        let mut n = 0;
        let sent = unsafe {
            (self.send)(
                self.handle as Handle,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut n,
                address.as_ptr(),
            )
        };
        Ok(sent != 0 && n as usize == bytes.len())
    }
    fn shutdown(&self) {
        unsafe { (self.stop)(self.handle as Handle, 3) };
    }
}
impl Drop for WinDivert {
    fn drop(&mut self) {
        self.shutdown();
        unsafe { (self.close)(self.handle as Handle) };
    }
}
