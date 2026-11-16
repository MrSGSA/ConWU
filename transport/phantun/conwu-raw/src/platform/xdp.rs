//! AF_XDP-only Windows Mimic adapter. No WinDivert handles or fallback path.
use crate::Config;
use fake_tcp::tun::TunDevice;
use std::{
    ffi::{CStr, c_char, c_void},
    io,
    net::SocketAddrV4,
    ptr::NonNull,
    sync::{Arc, RwLock},
};
use tokio::sync::Notify;

#[repr(C)]
struct NativeConfig {
    local_ip: u32,
    remote_ip: u32,
    local_port: u16,
    remote_port: u16,
    server: u32,
    peer_reflexive: u32,
    protected_ip: u32,
    protected_port: u16,
    reserved: u16,
}
unsafe extern "C" {
    fn cw_xdp_open(
        config: *const NativeConfig,
        receive: unsafe extern "C" fn(*mut c_void, *const u8, u32),
        failure: unsafe extern "C" fn(*mut c_void, *const c_char),
        context: *mut c_void,
        error: *mut c_char,
        error_size: u32,
    ) -> *mut c_void;
    fn cw_xdp_send(device: *mut c_void, ipv4: *const u8, length: u32) -> u32;
    fn cw_xdp_protect(device: *mut c_void, peer_ip: u32, peer_port: u16);
    fn cw_xdp_interfaces(device: *mut c_void) -> u32;
    fn cw_xdp_queues(device: *mut c_void) -> u32;
    fn cw_xdp_close(device: *mut c_void);
}
struct Callbacks {
    sender: flume::Sender<Vec<u8>>,
    failure: RwLock<Option<String>>,
    failed: Notify,
}
unsafe extern "C" fn receive(context: *mut c_void, packet: *const u8, length: u32) {
    // The native adapter validates UMEM bounds and invokes this synchronously;
    // the bytes are copied before its receive descriptor is recycled.
    let state = unsafe { &*context.cast::<Callbacks>() };
    if (40..=1500).contains(&length) {
        let packet = unsafe { std::slice::from_raw_parts(packet, length as usize) };
        let _ = state.sender.try_send(packet.to_vec());
    }
}
unsafe extern "C" fn failure(context: *mut c_void, message: *const c_char) {
    let state = unsafe { &*context.cast::<Callbacks>() };
    let message = unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned();
    *state.failure.write().unwrap() = Some(message);
    state.failed.notify_one();
}
struct Native {
    pointer: NonNull<c_void>,
    // Kept until close has detached rules and joined every native receiver.
    _callbacks: Arc<Callbacks>,
}
// Native send rings/route cache are serialized; protection is atomic; close
// runs after the last shared Rust owner, joins callbacks, then releases UMEM.
unsafe impl Send for Native {}
unsafe impl Sync for Native {}
impl Drop for Native {
    fn drop(&mut self) {
        unsafe { cw_xdp_close(self.pointer.as_ptr()) }
    }
}
pub struct Device {
    native: Native,
    state: Arc<Callbacks>,
    received: flume::Receiver<Vec<u8>>,
}
fn ip(endpoint: SocketAddrV4) -> u32 {
    u32::from_ne_bytes(endpoint.ip().octets())
}
impl Device {
    pub fn open(config: &Config) -> io::Result<Self> {
        let (sender, received) = flume::bounded(512);
        let state = Arc::new(Callbacks {
            sender,
            failure: RwLock::new(None),
            failed: Notify::new(),
        });
        let native_config = NativeConfig {
            local_ip: ip(config.source),
            remote_ip: ip(config.remote),
            local_port: config.source.port(),
            remote_port: config.remote.port(),
            server: u32::from(config.server),
            peer_reflexive: u32::from(config.peer_reflexive),
            protected_ip: config.protected_tcp_peer.map(ip).unwrap_or(0),
            protected_port: config.protected_tcp_peer.map(|p| p.port()).unwrap_or(0),
            reserved: 0,
        };
        let mut error = [0 as c_char; 2048];
        let pointer = unsafe {
            cw_xdp_open(
                &native_config,
                receive,
                failure,
                Arc::as_ptr(&state).cast_mut().cast(),
                error.as_mut_ptr(),
                error.len() as u32,
            )
        };
        let pointer = NonNull::new(pointer).ok_or_else(|| {
            let text = unsafe { CStr::from_ptr(error.as_ptr()) }.to_string_lossy();
            io::Error::other(format!("Mimic XDP 启动失败：{text}。请安装或修复微软 XDP 1.4 运行时并检查网卡绑定；不会回退到 WinDivert"))
        })?;
        let native = Native {
            pointer,
            _callbacks: state.clone(),
        };
        crate::event(
            serde_json::json!({"event":"xdp-ready","abi":1,"backend":"xdp-afxdp-generic",
            "interfaces":unsafe {cw_xdp_interfaces(pointer.as_ptr())},
            "receiveQueues":unsafe {cw_xdp_queues(pointer.as_ptr())},"backendFallback":false}),
        );
        Ok(Self {
            native,
            state,
            received,
        })
    }
    fn check(&self) -> io::Result<()> {
        match self.state.failure.read().unwrap().as_ref() {
            Some(message) => Err(io::Error::other(format!(
                "Mimic XDP 接收器已停止：{message}"
            ))),
            None => Ok(()),
        }
    }
    fn inject(&self, bytes: &[u8]) -> io::Result<()> {
        self.check()?;
        if bytes.len() > 1500 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XDP IPv4 packet too large",
            ));
        }
        let result = unsafe {
            cw_xdp_send(
                self.native.pointer.as_ptr(),
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        };
        match result {
            0 => Ok(()),
            1237 => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "XDP transmit ring is full",
            )),
            error => Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
}
#[async_trait::async_trait]
impl TunDevice for Device {
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            self.check()?;
            tokio::select! {
                packet = self.received.recv_async() => {
                    self.check()?;
                    let packet = packet.map_err(|_| io::Error::other("XDP receive queue closed"))?;
                    if packet.len() <= buffer.len() {
                        buffer[..packet.len()].copy_from_slice(&packet);
                        return Ok(packet.len());
                    }
                },
                _ = self.state.failed.notified() => self.check()?,
            }
        }
    }
    async fn send(&self, buffer: &[u8]) -> io::Result<usize> {
        self.inject(buffer)?;
        Ok(buffer.len())
    }
    fn try_send(&self, buffer: &[u8]) -> io::Result<()> {
        self.inject(buffer)
    }
    fn name(&self) -> String {
        "xdp-afxdp-generic".into()
    }
    fn protect_tcp_peer(&self, peer: SocketAddrV4) -> io::Result<()> {
        self.check()?;
        unsafe { cw_xdp_protect(self.native.pointer.as_ptr(), ip(peer), peer.port()) };
        Ok(())
    }
}
