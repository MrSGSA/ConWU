//! PID-bound prepared-start ABI used by the existing UDP2RAW worker. Parent
//! ownership lasts until confirmed child exit, including ambiguous IPC errors.
use anyhow::{Context, Result, ensure};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::Command,
    sync::{mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
type Io = Box<dyn Stream>;

#[derive(Clone)]
pub struct Descriptor {
    pub attach: Uuid,
    pub lease: Uuid,
    pub generation: Uuid,
    pub local: SocketAddr,
    pub observer: SocketAddr,
    pub peer: SocketAddr,
    pub server: bool,
    pub broker: bool,
    pub wire_metadata: bool,
    pub peer_reflexive: bool,
}
impl Descriptor {
    pub fn frame(&self, kind: u16, sequence: u32) -> Result<Vec<u8>> {
        ensure!(
            !self.attach.is_nil()
                && !self.lease.is_nil()
                && !self.generation.is_nil()
                && self.local.is_ipv4() == self.peer.is_ipv4()
                && self.local.is_ipv4() == self.observer.is_ipv4()
                && self.local.port() != 0
                && self.observer.port() != 0
                && self.peer.port() != 0
                && self.local != self.peer
                && self.observer != self.peer
                && self.local != self.observer,
            "原生接入的端点或所有权无效"
        );
        ensure!(
            !self.wire_metadata || self.broker,
            "原生报文计量需要捕获所有者"
        );
        ensure!(
            !self.peer_reflexive || self.broker && self.wire_metadata && self.local.is_ipv4(),
            "来源学习需要独立 IPv4 捕获及计量"
        );
        ensure!(
            self.local.is_ipv4() || self.broker,
            "IPv6 原生接入需要捕获 broker"
        );
        let mut frame = vec![0; if self.local.is_ipv4() { 96 } else { 144 }];
        frame[..4].copy_from_slice(b"SLNA");
        let abi = if frame.len() == 96 { 1u16 } else { 2 };
        frame[4..6].copy_from_slice(&abi.to_le_bytes());
        frame[6..8].copy_from_slice(&kind.to_le_bytes());
        let size = frame.len() as u32;
        frame[8..12].copy_from_slice(&size.to_le_bytes());
        frame[12..16].copy_from_slice(&sequence.to_le_bytes());
        for (at, id) in [(16, self.attach), (32, self.lease), (48, self.generation)] {
            frame[at..at + 16].copy_from_slice(&id.to_bytes_le());
        }
        for (at, extra, endpoint) in [
            (64, 96, self.local),
            (70, 112, self.observer),
            (76, 128, self.peer),
        ] {
            match endpoint.ip() {
                std::net::IpAddr::V4(ip) => frame[at..at + 4].copy_from_slice(&ip.octets()),
                std::net::IpAddr::V6(ip) => frame[extra..extra + 16].copy_from_slice(&ip.octets()),
            }
            frame[at + 4..at + 6].copy_from_slice(&endpoint.port().to_le_bytes());
        }
        frame[82] = if self.server { 2 } else { 1 };
        frame[83] = 2;
        frame[84..88].copy_from_slice(&10000u32.to_le_bytes());
        frame[88..92].copy_from_slice(&1u32.to_le_bytes());
        frame[92] = self.broker as u8;
        frame[93] = self.wire_metadata as u8;
        frame[94] = self.peer_reflexive as u8;
        Ok(frame)
    }
}
enum Action {
    Start(oneshot::Sender<Result<()>>),
    Stop,
}
pub struct Attachment {
    queue: mpsc::Sender<Action>,
    pub cancel: CancellationToken,
    pub finished: CancellationToken,
    pub descriptor: Descriptor,
    began: Mutex<Option<Instant>>,
}
impl Attachment {
    pub async fn prepare(
        mut command: Command,
        descriptor: Descriptor,
        temp: &std::path::Path,
        parent: &CancellationToken,
        #[cfg(windows)] session: Option<Arc<crate::capture::Session>>,
    ) -> Result<Arc<Self>> {
        let server = Server::create(temp)?;
        #[cfg(windows)]
        let raw = if descriptor.broker {
            Some(Server::named(&format!(
                "StreamLink.Raw.{}",
                &server.name[18..]
            ))?)
        } else {
            None
        };
        command
            .arg("--managed-pipe")
            .arg(&server.name)
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let mut child = command.spawn()?;
        let pid = child.id().context("原生子进程未启动")?;
        let cancel = parent.child_token();
        let finished = CancellationToken::new();
        let setup = async {
            let mut io = server.accept(pid).await?;
            #[cfg(windows)]
            let hello = descriptor.frame(1, 1)?;
            #[cfg(windows)]
            if let Some(raw) = raw {
                let session = session.context("捕获会话缺失")?;
                let stop = cancel.clone();
                let hello = hello.clone();
                tokio::spawn(async move {
                    let result = raw_channel(raw, pid, hello, session, stop.clone()).await;
                    if result.is_err() {
                        stop.cancel();
                    }
                });
            }
            exchange(&mut io, &descriptor, 1, 2, 1).await?;
            Ok::<_, anyhow::Error>(io)
        };
        let io = tokio::select! { _=cancel.cancelled()=>Err(anyhow::anyhow!("原生准备已取消")),
        status=child.wait()=>match status { Ok(status)=>Err(anyhow::anyhow!("原生组件在接入前退出（退出码 {:?}）",status.code())), Err(error)=>Err(error.into()) },
        result=tokio::time::timeout(Duration::from_secs(20),setup)=>match result{Ok(result)=>result,Err(error)=>Err(anyhow::anyhow!("原生接入准备超时：{error}"))} };
        let mut io = match io {
            Ok(io) => io,
            Err(e) => {
                cancel.cancel();
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(e);
            }
        };
        let (queue, mut actions) = mpsc::channel(16);
        let attachment = Arc::new(Self {
            queue,
            cancel: cancel.clone(),
            finished: finished.clone(),
            descriptor: descriptor.clone(),
            began: Mutex::new(None),
        });
        let weak = Arc::downgrade(&attachment);
        tokio::spawn(async move {
            let _finished = finished.drop_guard();
            let _stop = cancel.clone().drop_guard();
            let mut sequence = 2u32;
            let mut heartbeat = tokio::time::interval(Duration::from_secs(2));
            heartbeat.tick().await;
            let prepared = Instant::now();
            loop {
                tokio::select! {
                    biased;
                    _=cancel.cancelled()=>break,
                    _=child.wait()=>break,
                    action=actions.recv()=>match action {
                        Some(Action::Start(reply))=>{
                            let Some(owned)=weak.upgrade() else {break};
                            let already = owned.began.lock().unwrap().is_some();
                            #[cfg(windows)] if let Some(s) = crate::capture::find(&descriptor) {s.activate();}
                            let result = if already {Ok(())} else {exchange(&mut io,&descriptor,3,7,sequence).await};
                            sequence = sequence.saturating_add(!already as u32);
                            if result.is_ok() && !already {*owned.began.lock().unwrap()=Some(Instant::now());}
                            let failed = result.is_err(); let _=reply.send(result); if failed {break;}
                        },
                        Some(Action::Stop)|None=>break,
                    },
                    _=heartbeat.tick()=>{
                        if weak.upgrade().is_none_or(|a|a.began.lock().unwrap().is_none()&&prepared.elapsed()>Duration::from_secs(28)){break;}
                        if exchange(&mut io,&descriptor,6,6,sequence).await.is_err(){break;}
                        sequence=sequence.saturating_add(1);
                    }
                }
            }
            #[cfg(windows)]
            crate::capture::revoke(&descriptor);
            let _ = exchange(&mut io, &descriptor, 4, 5, sequence).await;
            drop(io);
            let _ = child.kill().await;
            let _ = child.wait().await;
            #[cfg(windows)]
            crate::capture::retire(&descriptor);
        });
        Ok(attachment)
    }
    pub async fn start(&self) -> Result<()> {
        ensure!(!self.cancel.is_cancelled(), "原生准备已失效");
        let (tx, rx) = oneshot::channel();
        self.queue.send(Action::Start(tx)).await?;
        tokio::time::timeout(Duration::from_secs(4), rx).await??
    }
    pub async fn close(&self) -> Result<()> {
        let _ = self.queue.try_send(Action::Stop);
        self.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(6), self.finished.cancelled())
            .await
            .context("原生子进程尚未确认退出")?;
        Ok(())
    }
}
impl Drop for Attachment {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
async fn exchange(
    io: &mut Io,
    d: &Descriptor,
    kind: u16,
    expected: u16,
    sequence: u32,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        io.write_all(&d.frame(kind, sequence)?).await?;
        let mut response = vec![0; d.frame(expected, sequence)?.len()];
        io.read_exact(&mut response).await?;
        ensure!(
            response == d.frame(expected, sequence)?,
            "原生控制回执的身份、端点或代次不符"
        );
        Ok(())
    })
    .await
    .context("原生控制回执超时")?
}

struct Server {
    name: String,
    #[cfg(windows)]
    listener: tokio::net::windows::named_pipe::NamedPipeServer,
    #[cfg(target_os = "linux")]
    listener: tokio::net::UnixListener,
    #[cfg(target_os = "linux")]
    _cleanup: UnixSocketCleanup,
}
#[cfg(target_os = "linux")]
struct UnixSocketCleanup(PathBuf);
#[cfg(target_os = "linux")]
impl Drop for UnixSocketCleanup {
    fn drop(&mut self) {
        // Never recurse: these are precisely the two names created by us.
        let _ = std::fs::remove_file(self.0.join("c"));
        let _ = std::fs::remove_dir(&self.0);
    }
}
impl Server {
    fn create(temp: &std::path::Path) -> Result<Self> {
        #[cfg(windows)]
        {
            let _ = temp;
            Self::named(&format!("StreamLink.Attach.{}", conwu_core::id()))
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::create_dir_all(temp)?;
            let directory = temp.join(format!("cwa-{}", &conwu_core::id()[..16]));
            std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
            let cleanup = UnixSocketCleanup(directory.clone());
            let path = directory.join("c");
            let name = path.to_str().context("原生 IPC 路径无效")?.to_owned();
            ensure!(name.len() < 108, "原生 IPC 临时目录过长");
            let listener = tokio::net::UnixListener::bind(&path)?;
            Ok(Self {
                name,
                listener,
                _cleanup: cleanup,
            })
        }
    }
    #[cfg(windows)]
    fn named(name: &str) -> Result<Self> {
        use tokio::net::windows::named_pipe::ServerOptions;
        use windows_sys::Win32::{Foundation::LocalFree, Security::SECURITY_ATTRIBUTES};
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text: *const u16,
                revision: u32,
                descriptor: *mut *mut std::ffi::c_void,
                size: *mut u32,
            ) -> i32;
        }
        let sid = crate::store::current_sid()?;
        let text = format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            } != 0,
            "无法保护原生管道"
        );
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let result = unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    format!(r"\\.\pipe\{name}"),
                    (&attributes as *const SECURITY_ATTRIBUTES)
                        .cast_mut()
                        .cast(),
                )
        };
        unsafe { LocalFree(descriptor) };
        Ok(Self {
            name: name.into(),
            listener: result?,
        })
    }
    async fn accept(self, pid: u32) -> Result<Io> {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn GetNamedPipeClientProcessId(pipe: *mut std::ffi::c_void, pid: *mut u32) -> i32;
            }
            self.listener.connect().await?;
            let mut actual = 0;
            ensure!(
                unsafe { GetNamedPipeClientProcessId(self.listener.as_raw_handle(), &mut actual) }
                    != 0
                    && actual == pid,
                "原生管道不是所启动的子进程"
            );
            Ok(Box::new(self.listener))
        }
        #[cfg(target_os = "linux")]
        {
            let (socket, _) = self.listener.accept().await?;
            let peer = socket.peer_cred()?;
            ensure!(
                peer.pid() == Some(pid as i32) && peer.uid() == unsafe { libc::geteuid() },
                "原生 Unix 管道身份不符"
            );
            // The child has connected; no later process needs this name.
            Ok(Box::new(socket))
        }
    }
}
#[cfg(windows)]
async fn raw_channel(
    server: Server,
    pid: u32,
    identity: Vec<u8>,
    session: Arc<crate::capture::Session>,
    stop: CancellationToken,
) -> Result<()> {
    let mut io = tokio::select! {_=stop.cancelled()=>return Ok(()),r=tokio::time::timeout(Duration::from_secs(20),server.accept(pid))=>r??};
    let mut received = vec![0; identity.len()];
    io.read_exact(&mut received).await?;
    ensure!(received == identity, "原生捕获管道身份不符");
    io.write_all(&identity).await?;
    let (read, write) = tokio::io::split(io);
    let incoming = async {
        let mut read = read;
        loop {
            let word = read.read_u32_le().await?;
            let size = (word & 65535) as usize;
            let kind = (word >> 16) as u8;
            ensure!(word >> 16 <= 4 && size >= 40, "原生报文类别或大小无效");
            let mut bytes = vec![0; size];
            read.read_exact(&mut bytes).await?;
            session.send(&bytes, kind)?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let outgoing = async {
        let mut write = write;
        loop {
            let bytes = session.receive().await?;
            write.write_u32_le(bytes.len() as u32).await?;
            write.write_all(&bytes).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {_=stop.cancelled()=>Ok(()),r=incoming=>r,r=outgoing=>r}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_abi_guids_and_tuple_are_not_network_order() -> Result<()> {
        let d = Descriptor {
            attach: Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff")?,
            lease: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            local: "192.0.2.1:40000".parse()?,
            observer: "203.0.113.1:3478".parse()?,
            peer: "198.51.100.1:50000".parse()?,
            server: false,
            broker: false,
            wire_metadata: false,
            peer_reflexive: false,
        };
        let f = d.frame(1, 1)?;
        assert_eq!(
            &f[16..24],
            &[0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66]
        );
        assert_eq!(&f[68..70], &40000u16.to_le_bytes());
        assert_eq!(f[83], 2);
        assert_eq!(f.len(), 96);
        let mut invalid = d.clone();
        invalid.peer = invalid.observer;
        assert!(invalid.frame(1, 1).is_err());
        Ok(())
    }
}
