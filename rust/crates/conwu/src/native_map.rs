//! Retained source socket + shared capture + prepared workers for FakeTCP SO.
//! The ordinary entry path remains available on the same public receiver.
use crate::{
    discovery::{self, TcpObservation},
    native::{Attachment, Descriptor},
    runtime::Engine,
    transport::Pipe,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use tokio::sync::mpsc;
use tokio::{net::UdpSocket, process::Command};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct Mapping {
    tracker: tokio_util::task::TaskTracker,
    pub local: SocketAddr,
    pub observer: SocketAddr,
    target: SocketAddr,
    components: PathBuf,
    lease: Uuid,
    pub(crate) generation: Uuid,
    observation: tokio::sync::Mutex<Option<TcpObservation>>,
    mapped: Mutex<LastObservation>,
    workers: tokio::sync::Mutex<HashMap<SocketAddr, Worker>>,
    pub peers: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>,
    pub cancel: CancellationToken,
    _firewall: Option<crate::raw::Firewall>,
    #[cfg(windows)]
    capture: Arc<crate::capture::Owner>,
}
#[derive(Clone, Copy)]
struct LastObservation {
    endpoint: SocketAddr,
    confirmed: Instant,
    available: bool,
}
struct Worker {
    attachment: Arc<Attachment>,
    client: bool,
    bridge: SocketAddr,
    app: Option<Arc<UdpSocket>>,
    stop: CancellationToken,
    last: Arc<Mutex<Instant>>,
    candidate_pipe: Option<CancellationToken>,
    #[cfg(windows)]
    session: Arc<crate::capture::Session>,
}

impl Worker {
    fn has_candidate_pipe(&self) -> bool {
        self.candidate_pipe.as_ref().is_some_and(|pipe| !pipe.is_cancelled())
    }

    fn live(&self, idle_limit: Duration) -> bool {
        !self.attachment.cancel.is_cancelled()
            && (self.has_candidate_pipe() || self.last.lock().unwrap().elapsed() < idle_limit)
    }
}

impl Mapping {
    pub async fn open(
        engine: &Engine,
        port: u16,
        target: SocketAddr,
        stun: &[String],
        parent: &CancellationToken,
    ) -> Result<Arc<Self>> {
        let observed = discovery::observe_tcp(port, stun, engine, "faketcp").await?;
        Self::from_observation(engine, observed, target, Arc::default(), None, parent)
    }

    pub(crate) async fn fresh_sender(&self, engine: &Engine) -> Result<Arc<Self>> {
        let source = SocketAddr::new(self.local.ip(), 0);
        let observed = tokio::time::timeout(discovery::TCP_OBSERVER_ATTEMPT,
            discovery::observe_tcp_from(source, self.observer)).await??;
        let firewall = crate::raw::Firewall::open("faketcp", true, observed.local, self.target)?;
        firewall.protect(observed.local, observed.observer)?;
        Self::from_observation(engine, observed, self.target, self.peers.clone(), Some(firewall), &self.cancel)
    }

    fn from_observation(
        engine: &Engine,
        observed: TcpObservation,
        target: SocketAddr,
        peers: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>,
        firewall: Option<crate::raw::Firewall>,
        parent: &CancellationToken,
    ) -> Result<Arc<Self>> {
        let local = observed.local;
        let observer = observed.observer;
        let mapped = observed.mapped;
        let cancel = parent.child_token();
        let accept_unknown = firewall.is_none();
        #[cfg(windows)]
        let capture = crate::capture::Owner::open(&engine.components, local, observer, &cancel)?;
        let mapping = Arc::new(Self {
            tracker: engine.tracker.clone(),
            local,
            observer,
            target,
            components: engine.components.clone(),
            lease: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            observation: tokio::sync::Mutex::new(Some(observed)),
            mapped: Mutex::new(LastObservation { endpoint: mapped, confirmed: Instant::now(), available: true }),
            workers: tokio::sync::Mutex::new(HashMap::new()),
            peers,
            cancel,
            _firewall: firewall,
            #[cfg(windows)]
            capture,
        });
        #[cfg(windows)]
        let unknown = accept_unknown.then(|| mapping.capture.take_unknown()).flatten();
        #[cfg(target_os = "linux")]
        let unknown = accept_unknown.then(|| linux_incoming(local, mapping.cancel.clone())).transpose()?;
        if let Some(mut unknown) = unknown {
            let weak = Arc::downgrade(&mapping);
            let stop = mapping.cancel.clone();
            tokio::spawn(async move {
                let mut rate = (Instant::now(), 0u8);
                loop {
                    let peer = tokio::select! {_=stop.cancelled()=>break,p=unknown.recv()=>match p{Some(p)=>p,None=>break}};
                    if rate.0.elapsed() > Duration::from_secs(1) {
                        rate = (Instant::now(), 0);
                    }
                    if rate.1 >= 2 {
                        continue;
                    }
                    rate.1 += 1;
                    let Some(mapping) = weak.upgrade() else { break };
                    if mapping.workers.lock().await.contains_key(&peer) {
                        continue;
                    }
                    let _ = mapping.punch(peer, false, &[], false).await;
                }
            });
        }
        Ok(mapping)
    }
    pub fn mapped(&self) -> SocketAddr {
        self.mapped.lock().unwrap().endpoint
    }
    pub fn observed_endpoint(&self) -> Option<SocketAddr> {
        let last = self.mapped.lock().unwrap();
        last.available.then_some(last.endpoint)
    }
    pub(crate) fn observation(&self) -> &tokio::sync::Mutex<Option<TcpObservation>> {
        &self.observation
    }
    pub fn status(&self) -> serde_json::Value {
        let workers=self.workers.try_lock().ok().map(|workers|workers.values().map(|w|{
            let mut value=serde_json::json!({"peer":w.attachment.descriptor.peer,"protocolClient":w.client,"armed":!w.attachment.cancel.is_cancelled(),"generation":self.generation});
            #[cfg(windows)]{value["capture"]=w.session.status();}
            value
        }).collect::<Vec<_>>()).unwrap_or_default();
        serde_json::json!({"backend":"prepared-start","local":self.local,"mapped":self.mapped(),"observer":self.observer,"workers":workers})
    }
    pub async fn refresh(&self) -> Result<SocketAddr> {
        let mut observed = self.observation.lock().await;
        let last = *self.mapped.lock().unwrap();
        ensure!(!self.cancel.is_cancelled(), "同源接收器已关闭");
        if last.available && last.confirmed.elapsed() < Duration::from_secs(4) {
            return Ok(last.endpoint);
        }
        match discovery::renew_native_observation(&mut observed, self.local, self.observer).await {
            Ok(mapped) => {
                *self.mapped.lock().unwrap() = LastObservation { endpoint: mapped, confirmed: Instant::now(), available: true };
                Ok(mapped)
            }
            Err(error) => {
                let grace = Duration::from_secs(30);
                self.mapped.lock().unwrap().available = false;
                if last.confirmed.elapsed() >= grace && !self.workers.lock().await.values().any(|worker| worker.live(grace)) {
                    self.cancel.cancel();
                }
                Err(error.context("同源 STUN 暂未确认公网候选"))
            }
        }
    }
    pub async fn prepare(
        &self,
        peer: SocketAddr,
        client: bool,
        learning: bool,
    ) -> Result<Arc<Attachment>> {
        self.prepare_worker(peer, client, learning, false).await
    }

    pub(crate) async fn prepare_burst(&self, peer: SocketAddr, client: bool) -> Result<Arc<Attachment>> {
        self.prepare_worker(peer, client, false, true).await
    }

    async fn prepare_worker(&self, peer: SocketAddr, client: bool, learning: bool, fresh: bool) -> Result<Arc<Attachment>> {
        ensure!(
            peer.is_ipv4()
                && peer != self.observer
                && peer != self.local
                && !self.cancel.is_cancelled(),
            "FakeTCP 同步候选无效"
        );
        let mut workers = self.workers.lock().await;
        if let Some(old) = workers.get(&peer) {
            if old.live(Duration::from_secs(12))
                && old.client == client
                && !(fresh && old.attachment.started())
            {
                return Ok(old.attachment.clone());
            }
            ensure!(old.attachment.cancel.is_cancelled() || !old.has_candidate_pipe(),
                "FakeTCP 对端已有正在使用的候选桥");
        }
        if let Some(old) = workers.remove(&peer) {
            old.stop.cancel();
            old.attachment.close().await?;
        }
        let stale = workers
            .iter()
            .filter(|(_, w)| !w.live(Duration::from_secs(30)))
            .map(|(p, _)| *p)
            .collect::<Vec<_>>();
        for peer in stale {
            if let Some(old) = workers.remove(&peer) {
                old.stop.cancel();
                old.attachment.close().await?;
            }
        }
        ensure!(workers.len() < 8, "同源 FakeTCP 准备资源已达到上限");
        let descriptor = Descriptor {
            attach: Uuid::new_v4(),
            lease: self.lease,
            generation: self.generation,
            local: self.local,
            observer: self.observer,
            peer,
            server: !client,
            broker: cfg!(windows),
            wire_metadata: cfg!(windows) && learning,
            peer_reflexive: cfg!(windows) && learning,
        };
        #[cfg(windows)]
        let session = self.capture.register(descriptor.clone())?;
        let proxy = crate::raw::bind_bridge().await?;
        let bridge = if client {
            let reserve = UdpSocket::bind("127.0.0.1:0").await?;
            reserve.local_addr()?
        } else {
            proxy.local_addr()?
        };
        let executable = self.components.join(if cfg!(windows) {
            "udp2raw-native.exe"
        } else {
            "udp2raw-native"
        });
        ensure!(executable.is_file(), "缺少 FakeTCP prepared-start 组件");
        let mut command = Command::new(executable);
        command
            .current_dir(&self.components)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(target_os = "linux")]
        command.stdout(Stdio::piped());
        let bind = if client { bridge } else { self.local };
        let remote = if client { peer } else { bridge };
        command.args([
            if client { "-c" } else { "-s" },
            "-l",
            &bind.to_string(),
            "-r",
            &remote.to_string(),
            "-k",
            conwu_core::pairing::CARRIAGE_KEY,
            "--raw-mode",
            "faketcp",
            "--fix-gro",
            "--seq-mode",
            "3",
            "--fake-http",
            "test.ustc.edu.cn",
            "--log-level",
            "2",
            "--disable-color",
        ]);
        command.env("STREAMLINK_ALLOW_DRIVER_INSTALL", "0");
        let attachment = Attachment::prepare(
            command,
            descriptor,
            &std::env::temp_dir(),
            &self.cancel,
            #[cfg(windows)]
            Some(session.clone()),
        )
        .await?;
        let stop = attachment.cancel.child_token();
        let last = Arc::new(Mutex::new(Instant::now()));
        if client {
            proxy.connect(bridge).await?;
            let relay = crate::raw::bind_bridge().await?;
            relay.connect(self.target).await?;
            let relay_address = relay.local_addr()?;
            self.peers.lock().unwrap().insert(relay_address, peer);
            let app = proxy.clone();
            let token = stop.clone();
            let last = last.clone();
            let peers = self.peers.clone();
            tokio::spawn(async move {
                let mut incoming = [0; 2049];
                let mut outgoing = [0; 2049];
                loop {
                    tokio::select! {_=token.cancelled()=>break,r=app.recv(&mut incoming)=>match r{Ok(n)if n<=2048=>{*last.lock().unwrap()=Instant::now();if relay.send(&incoming[..n]).await.is_err(){break}},_=>break},
                    r=relay.recv(&mut outgoing)=>match r{Ok(n)if n<=2048=>{*last.lock().unwrap()=Instant::now();if app.send(&outgoing[..n]).await.is_err(){break}},_=>break}}
                }
                peers.lock().unwrap().remove(&relay_address);
            });
        } else {
            let token = stop.clone();
            let target = self.target;
            let addresses = self.peers.clone();
            let ingress = proxy.clone();
            let last = last.clone();
            tokio::spawn(async move {
                let mut relays: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
                let mut incoming = [0; 2049];
                loop {
                    let received = tokio::select! {_=token.cancelled()=>break,r=ingress.recv_from(&mut incoming)=>r};
                    let Ok((n, from)) = received else { break };
                    if n > 2048 || !from.ip().is_loopback() {
                        continue;
                    }
                    *last.lock().unwrap() = Instant::now();
                    if !relays.contains_key(&from) {
                        if relays.len() >= 32 {
                            continue;
                        }
                        let Ok(relay) = crate::raw::bind_bridge().await else {
                            break;
                        };
                        if relay.connect(target).await.is_err() {
                            break;
                        }
                        let Ok(local) = relay.local_addr() else { break };
                        addresses.lock().unwrap().insert(local, peer);
                        let receiver = relay.clone();
                        let sender = ingress.clone();
                        let stop = token.clone();
                        let addresses = addresses.clone();
                        let last = last.clone();
                        tokio::spawn(async move {
                            let mut bytes = [0; 2049];
                            loop {
                                let r = tokio::select! {_=stop.cancelled()=>break,r=receiver.recv(&mut bytes)=>r};
                                match r {
                                    Ok(n) if n <= 2048 => {
                                        *last.lock().unwrap() = Instant::now();
                                        if sender.send_to(&bytes[..n], from).await.is_err() {
                                            break;
                                        }
                                    }
                                    _ => break,
                                }
                            }
                            addresses.lock().unwrap().remove(&local);
                        });
                        relays.insert(from, relay);
                    }
                    if relays[&from].send(&incoming[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
        workers.insert(
            peer,
            Worker {
                attachment: attachment.clone(),
                client,
                bridge,
                app: client.then_some(proxy),
                stop,
                last,
                candidate_pipe: None,
                #[cfg(windows)]
                session,
            },
        );
        Ok(attachment)
    }
    pub async fn punch(
        &self,
        peer: SocketAddr,
        client: bool,
        greeting: &[u8],
        learning: bool,
    ) -> Result<()> {
        let attachment = self.prepare(peer, client, learning).await?;
        self.start_punch(peer, greeting, &attachment).await
    }

    async fn start_punch(&self, peer: SocketAddr, greeting: &[u8], attachment: &Attachment) -> Result<()> {
        attachment.start().await?;
        if !greeting.is_empty() {
            let workers = self.workers.lock().await;
            if let Some(app) = workers.get(&peer).and_then(|w| w.app.clone()) {
                app.send(greeting).await?;
            }
        }
        Ok(())
    }
    pub async fn client_pipe(
        &self,
        peer: SocketAddr,
        learning: bool,
        parent: &CancellationToken,
    ) -> Result<Pipe> {
        let attachment = self.prepare(peer, true, learning).await?;
        let socket = self.client_socket(peer, &attachment).await?;
        Ok(crate::raw::udp_pipe(socket, parent, &self.tracker))
    }
    pub(crate) async fn candidate_pipe(
        &self,
        peer: SocketAddr,
        guard: crate::raw::Firewall,
        learning: bool,
        parent: &CancellationToken,
    ) -> Result<Pipe> {
        let attachment = self.prepare(peer, true, learning).await?;
        self.leased_candidate_pipe(peer, attachment, Some(guard), parent).await
    }

    pub(crate) async fn member_candidate_pipe(
        &self,
        peer: SocketAddr,
        parent: &CancellationToken,
    ) -> Result<Pipe> {
        let attachment = self.prepare_burst(peer, true).await?;
        self.leased_candidate_pipe(peer, attachment, None, parent).await
    }

    async fn leased_candidate_pipe(
        &self,
        peer: SocketAddr,
        attachment: Arc<Attachment>,
        guard: Option<crate::raw::Firewall>,
        parent: &CancellationToken,
    ) -> Result<Pipe> {
        let socket = self.client_socket(peer, &attachment).await?;
        let mut workers = self.workers.lock().await;
        let worker = workers.get_mut(&peer)
            .filter(|worker| Arc::ptr_eq(&worker.attachment, &attachment))
            .context("原生准备已取消")?;
        ensure!(!worker.has_candidate_pipe(), "FakeTCP 对端已有正在使用的候选桥");
        let lease = attachment.cancel.clone().drop_guard();
        let pipe = crate::raw::udp_pipe(socket, parent, &self.tracker);
        let stop = pipe.cancel.clone();
        worker.candidate_pipe = Some(stop.clone());
        drop(workers);
        self.tracker.spawn(async move {
            let _guard = guard;
            let _lease = lease;
            stop.cancelled().await;
        });
        Ok(pipe)
    }
    async fn client_socket(
        &self,
        peer: SocketAddr,
        attachment: &Arc<Attachment>,
    ) -> Result<Arc<UdpSocket>> {
        attachment.start().await?;
        let bridge = self
            .workers
            .lock()
            .await
            .get(&peer)
            .filter(|worker| Arc::ptr_eq(&worker.attachment, attachment))
            .context("原生准备已取消")?
            .bridge;
        let socket = crate::raw::bind_bridge().await?;
        socket.connect(bridge).await?;
        Ok(socket)
    }
    pub async fn freeze(&self, peer: SocketAddr) {
        #[cfg(windows)]
        for worker in self.workers.lock().await.values() {
            if worker.session.peer() == peer {
                worker.session.freeze();
            }
        }
        #[cfg(not(windows))]
        let _ = peer;
    }
    pub async fn close(&self) -> Result<()> {
        self.cancel.cancel();
        let mut workers = self.workers.lock().await;
        let closing = workers.values().map(|worker| async move {
            worker.stop.cancel();
            worker.attachment.close().await
        });
        for result in futures_util::future::join_all(closing).await {
            result?;
        }
        workers.clear();
        #[cfg(windows)]
        self.capture.close().await?;
        if let Some(observed) = self.observation.lock().await.take() {
            if let Ok(stream) = observed.stream.into_std() {
                let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
            }
        }
        Ok(())
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(target_os = "linux")]
fn linux_incoming(
    local: SocketAddr,
    stop: CancellationToken,
) -> Result<mpsc::Receiver<SocketAddr>> {
    use std::os::fd::AsRawFd;
    let socket = socket2::Socket::new(
        socket2::Domain::from(libc::AF_PACKET),
        socket2::Type::RAW,
        Some(socket2::Protocol::from(
            (libc::ETH_P_IP as u16).to_be() as i32
        )),
    )?;
    socket.set_nonblocking(true)?;
    let (tx, rx) = mpsc::channel(16);
    tokio::task::spawn_blocking(move || {
        let mut bytes = vec![0u8; 65549];
        while !stop.is_cancelled() {
            let mut poll = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 100) } <= 0 {
                continue;
            }
            let n = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    0,
                )
            };
            if n < 54 {
                continue;
            }
            let n = n as usize;
            let ip = if bytes[12..14] == [0x81, 0] || bytes[12..14] == [0x88, 0xa8] {
                18
            } else {
                14
            };
            if n < ip + 40 {
                continue;
            }
            let p = &bytes[ip..n];
            if p[0] >> 4 != 4 || p[9] != 6 || u16::from_be_bytes([p[6], p[7]]) & 0x3fff != 0 {
                continue;
            }
            let at = (p[0] & 15) as usize * 4;
            if at < 20 || p.len() < at + 20 {
                continue;
            }
            let header = (p[at + 12] >> 4) as usize * 4;
            if header < 20
                || p.len() < at + header
                || p[at + 13] != 2
                || u16::from_be_bytes([p[2], p[3]]) as usize != at + header
            {
                continue;
            }
            let target = SocketAddr::new(
                std::net::Ipv4Addr::new(p[16], p[17], p[18], p[19]).into(),
                u16::from_be_bytes([p[at + 2], p[at + 3]]),
            );
            if target != local {
                continue;
            }
            let source = SocketAddr::new(
                std::net::Ipv4Addr::new(p[12], p[13], p[14], p[15]).into(),
                u16::from_be_bytes([p[at], p[at + 1]]),
            );
            if source.port() != 0 {
                let _ = tx.try_send(source);
            }
        }
    });
    Ok(rx)
}
