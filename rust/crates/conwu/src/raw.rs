//! Existing audited packet carriers remain independent processes with their
//! upstream licenses. No CLR process participates in this adapter.
use crate::{runtime::Engine, transport::Pipe};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UdpSocket,
    process::{Child, Command},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

const BRIDGE_QUEUE: usize = 128;
const MAX_DATAGRAM: usize = 2048;
const BRIDGE_RECEIVE_BUFFER: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct LocalCarrierError {
    mode: String,
    source: Arc<anyhow::Error>,
}
impl std::fmt::Display for LocalCarrierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "本机 {} 承载组件未就绪：{}", self.mode, self.source)
    }
}
impl std::error::Error for LocalCarrierError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref().as_ref())
    }
}
struct Helper {
    process: Child,
    commands: Option<mpsc::Sender<Value>>,
}
impl Helper {
    async fn finish(mut self) {
        if let Some(commands) = self.commands.take() {
            let _ = tokio::time::timeout(
                Duration::from_millis(500),
                commands.send(json!({"command":"stop"})),
            )
            .await;
            if matches!(
                tokio::time::timeout(Duration::from_secs(3), self.process.wait()).await,
                Ok(Ok(_))
            ) {
                return;
            }
        }
        let _ = self.process.kill().await;
    }
}

async fn wait_for_helper(child: &mut Option<Helper>) {
    if let Some(child) = child {
        let _ = child.process.wait().await;
    } else {
        std::future::pending().await
    }
}

#[derive(Clone)]
pub struct Control {
    commands: mpsc::Sender<Value>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<io::Result<Option<u64>>>>>>,
    peers: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>,
    peer_opened: Arc<tokio::sync::Notify>,
    handshake_stages: Arc<Mutex<HashMap<(SocketAddr, &'static str), (i64, Option<u32>)>>>,
    pub source: SocketAddr,
    pub confirms_syn: bool,
}

struct PendingReply<'a> {
    pending: &'a Mutex<HashMap<String, oneshot::Sender<io::Result<Option<u64>>>>>,
    id: String,
}

impl Drop for PendingReply<'_> {
    fn drop(&mut self) {
        self.pending.lock().unwrap().remove(&self.id);
    }
}

impl Control {
    #[cfg(test)]
    pub(crate) fn test_probe_control(source: SocketAddr, answer: bool) -> Self {
        let (commands, mut queue) = mpsc::channel::<Value>(4);
        let pending = Arc::new(Mutex::new(HashMap::<String, oneshot::Sender<io::Result<Option<u64>>>>::new()));
        let replies = pending.clone();
        tokio::spawn(async move {
            while let Some(command) = queue.recv().await {
                if answer && matches!(command["command"].as_str(), Some("probe" | "pair-probe"))
                    && let Some(reply) = replies.lock().unwrap().remove(command["id"].as_str().unwrap()) {
                    let _ = reply.send(Ok(Some(conwu_core::nat_tcp_punch::burst::submission_micros())));
                }
            }
        });
        Self { commands, pending, peers: Default::default(), peer_opened: Default::default(),
            handshake_stages: Default::default(), source, confirms_syn: true }
    }

    pub(crate) fn visit_handshakes(&self, ip: IpAddr, since: i64, mut visit: impl FnMut(SocketAddr, &'static str, i64, Option<u32>)) {
        for (&(peer, stage), &(at, injected)) in self.handshake_stages.lock().unwrap().iter() {
            if peer.ip() == ip && at >= since { visit(peer, stage, at, injected); }
        }
    }
    pub(crate) fn ticket_queued(&self, peer: SocketAddr) {
        let mut stages = self.handshake_stages.lock().unwrap();
        if stages.keys().any(|(p, _)| *p == peer) {
            let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
            stages.insert((peer, "ticket_queued"), (at, None));
        }
    }
    pub async fn punch(&self, peer: SocketAddr, hello: &[u8]) -> Result<()> {
        ensure!(peer.is_ipv4() && hello.len() <= 128, "协同探测参数无效");
        let mut command = json!({"command":"punch","peer":peer.to_string()});
        if !hello.is_empty() {
            command["hello"] = json!(hex::encode(hello));
        }
        self.commands.send(command).await?;
        Ok(())
    }
    pub async fn protect(&self, peer: SocketAddr) -> Result<()> {
        self.confirmed("protect", peer, Duration::from_secs(2)).await.map(drop)
    }

    pub async fn probe(&self, peer: SocketAddr, wait: Duration, pairing_round: Option<uuid::Uuid>) -> Result<u64> {
        ensure!(self.confirms_syn && peer.is_ipv4(), "承载不支持 TCP SYN 发送确认");
        let command = match pairing_round {
            Some(round) => json!({"command":"pair-probe", "peer":peer, "round":round.simple().to_string()}),
            None => json!({"command":"probe", "peer":peer}),
        };
        self.request(command, conwu_core::id(), wait)
            .await.context("未确认承载已提交 TCP SYN")
            .map(|sent| sent.unwrap_or_else(conwu_core::nat_tcp_punch::burst::submission_micros))
    }
    pub(crate) async fn discard_pair_probe(&self, peer: SocketAddr, round: uuid::Uuid) -> Result<()> {
        self.request(json!({"command":"discard-pair-probe","peer":peer,"round":round.simple().to_string()}),
            conwu_core::id(), Duration::from_secs(2)).await?;
        self.handshake_stages.lock().unwrap().retain(|(target, _), _| *target != peer);
        Ok(())
    }

    async fn confirmed(&self, command: &str, peer: SocketAddr, wait: Duration) -> Result<Option<u64>> {
        self.request(json!({"command":command,"peer":peer}), conwu_core::id(), wait).await
    }

    async fn request(&self, mut command: Value, id: String, wait: Duration) -> Result<Option<u64>> {
        command["id"] = json!(&id);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id.clone(), tx);
        let _reply = PendingReply { pending: &self.pending, id: id.clone() };
        tokio::time::timeout(wait, async {
            self.commands
                .send(command)
                .await?;
            Ok(rx.await??)
        }).await?
    }
}
pub async fn prepare_observer(
    engine: &Engine,
    mode: &str,
    port: u16,
    remote: SocketAddr,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(table) = engine
        .raw_tables
        .lock()
        .unwrap()
        .get(&(mode.into(), port))
        .filter(|_| mode != "tcpraw")
        .cloned()
    {
        let key = format!("{table}/{remote}");
        let mut observers = engine.raw_observers.lock().unwrap();
        if !observers.contains(&key) {
            ensure!(observers.len() < 256, "本机观察服务保护表超过限制");
            run(
                "nft",
                &[
                    "insert",
                    "rule",
                    "inet",
                    &table,
                    "input",
                    "ip",
                    "saddr",
                    &remote.ip().to_string(),
                    "tcp",
                    "sport",
                    &remote.port().to_string(),
                    "tcp",
                    "dport",
                    &port.to_string(),
                    "accept",
                ],
            )?;
            observers.insert(key);
        }
    }
    let control = engine
        .raw_controls
        .lock()
        .unwrap()
        .get(&(mode.into(), port))
        .cloned();
    if let Some(control) = control {
        control.protect(remote).await?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Capture {
    Exact,
    LearnPort,
    SharedSource,
    Peer(Ipv4Addr),
}

impl Capture {
    fn for_recovery(mode: &str, peer: SocketAddr) -> Self {
        match (mode, peer.ip()) {
            ("mimic", IpAddr::V4(ip)) if cfg!(windows) => Self::Peer(ip),
            _ => Self::Exact,
        }
    }
}

async fn spawn(
    engine: &Engine,
    mode: &str,
    server: bool,
    source: SocketAddr,
    remote: SocketAddr,
    stun: &[String],
    capture: Capture,
    purpose: &'static str,
) -> Result<(Helper, SocketAddr, Option<Control>)> {
    let executable = engine.components.join(format!(
        "{}{}",
        if mode == "phantun" {
            "conwu-phantun"
        } else if mode == "faketcp" {
            "udp2raw-native"
        } else {
            "conwu-raw"
        },
        if cfg!(windows) { ".exe" } else { "" }
    ));
    ensure!(
        executable.is_file(),
        "缺少所选承载组件：{}",
        executable.display()
    );
    let mut cmd = Command::new(&executable);
    cmd.kill_on_drop(true)
        .current_dir(&engine.components)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);
    if mode == "faketcp" {
        if !stun.is_empty() {
            let mut observers = vec![];
            for server in stun.iter().take(8) {
                observers.extend(
                    crate::discovery::endpoint(server)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .filter(SocketAddr::is_ipv4)
                        .map(|s| s.to_string()),
                );
            }
            cmd.env(
                "CONWU_TCP_OBSERVERS",
                observers.into_iter().take(32).collect::<Vec<_>>().join(";"),
            );
        }
        let bridge = if server {
            source
        } else {
            SocketAddr::from(([127, 0, 0, 1], free_udp()?))
        };
        cmd.args([
            if server { "-s" } else { "-c" },
            "-l",
            &bridge.to_string(),
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
        cmd.env("STREAMLINK_DIRECT_RENDEZVOUS", "1");
        cmd.env("STREAMLINK_ALLOW_DRIVER_INSTALL", "0");
        if !server {
            cmd.args([
                "--source-ip",
                &source.ip().to_string(),
                "--source-port",
                &source.port().to_string(),
            ]);
        }
        let mut child = cmd.spawn()?;
        let stdout = child.stdout.take();
        tokio::spawn(async move {
            if let Some(out) = stdout {
                let mut lines = BufReader::new(out).lines();
                while let Ok(Some(_)) = lines.next_line().await {}
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        ensure!(child.try_wait()?.is_none(), "FakeTCP 组件启动失败");
        return Ok((
            Helper {
                process: child,
                commands: None,
            },
            bridge,
            None,
        ));
    }
    cmd.args([
        if server { "--server" } else { "--client" },
        "--source",
        &source.to_string(),
        "--remote",
        &remote.to_string(),
        "--parent",
        &std::process::id().to_string(),
    ]);
    if mode != "phantun" {
        cmd.args(["--carrier", mode]);
    }
    if capture == Capture::LearnPort {
        cmd.arg("--peer-reflexive");
    }
    if let Capture::Peer(ip) = capture {
        cmd.args(["--peer-ip", &ip.to_string()]);
    }
    if cfg!(windows) && mode == "mimic" && matches!(capture, Capture::SharedSource | Capture::Peer(_)) {
        // The candidates own different remote tuples on one local port.
        // WinDivert can filter each tuple without sharing an XDP queue.
        cmd.env("CONWU_MIMIC_IO", "windivert");
    }
    if !source.ip().is_unspecified() {
        for observer in stun.iter().take(8) {
            if let Some(peer) = crate::discovery::endpoint(observer)
                .await
                .unwrap_or_default()
                .into_iter()
                .find(SocketAddr::is_ipv4)
            {
                cmd.args(["--protected-tcp-peer", &peer.to_string()]);
                break;
            }
        }
    }
    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().context("组件输出不可用")?;
    let mut lines = BufReader::new(stdout).lines();
    // NDIS can rebind the XDP runtime while Windows is recreating several
    // Wintun adapters after a restart. Do not kill a healthy XDP initializer
    // using the short ordinary helper deadline; shutdown still cancels it.
    let startup_timeout = if cfg!(windows) && mode == "mimic" {
        Duration::from_secs(45)
    } else {
        Duration::from_secs(8)
    };
    let ready = tokio::time::timeout(startup_timeout, async {
        while let Some(line) = lines.next_line().await? {
            ensure!(line.len() <= 4096, "组件消息过长");
            if let Some((_, json)) = line.split_once(' ') {
                if let Ok(v) = serde_json::from_str::<Value>(json) {
                    if v["event"] == "failed" || v["event"] == "peer-failed" {
                        anyhow::bail!(
                            "承载组件启动失败：{}",
                            v["reason"].as_str().unwrap_or("组件未就绪")
                        )
                    }
                    if v["event"] == "backend-fallback" {
                        let reason =
                            crate::logging::redact(v["reason"].as_str().unwrap_or("XDP 未就绪"));
                        let _ = engine.events.try_send(crate::runtime::Event::Log {
                            level: "WARN".into(),
                            text: format!("Mimic 已回退至 WinDivert：{reason}"),
                        });
                    }
                    if v["event"] == "ready" {
                        ensure!(
                            v["abi"] == 1
                                && v["pid"].as_u64() == Some(child.id().unwrap_or(0) as u64)
                                && v["source"] == source.to_string(),
                            "承载组件身份不符"
                        );
                        return Ok(v);
                    }
                }
            }
        }
        anyhow::bail!("组件未报告就绪")
    });
    let ready = tokio::select! {
        _ = engine.cancel.cancelled() => Err(anyhow::anyhow!("承载组件启动已取消")),
        result = ready => result.unwrap_or_else(|_| Err(anyhow::anyhow!("等待承载组件报告就绪超时"))),
    };
    let ready = match ready {
        Ok(ready) => ready,
        Err(error) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(error);
        }
    };
    let role = if server { "监听端" } else { "主动连接端" };
    if let Some(backend) = ready["backend"].as_str() {
        let _ = engine.events.try_send(crate::runtime::Event::Log {
            level: "INFO".into(),
            text: format!("{mode} {role}已就绪（{purpose} · {}）", crate::logging::redact(backend)),
        });
    }
    let udp = if server {
        remote
    } else {
        ready["udp"]
            .as_str()
            .context("组件未提供转发入口")?
            .parse()?
    };
    ensure!(udp.ip().is_loopback(), "承载桥接必须只监听本机");
    let mut input = child.stdin.take().context("组件控制输入不可用")?;
    let (commands, mut queue) = mpsc::channel::<Value>(32);
    let pending = Arc::new(Mutex::new(HashMap::<String, oneshot::Sender<io::Result<Option<u64>>>>::new()));
    let replies = pending.clone();
    let diagnostic = engine.events.clone();
    let carrier = mode.to_owned();
    let peers = Arc::new(Mutex::new(HashMap::<SocketAddr, SocketAddr>::new()));
    let peer_events = peers.clone();
    let peer_opened = Arc::new(tokio::sync::Notify::new());
    let notify_peer = peer_opened.clone();
    let handshake_stages = Arc::new(Mutex::new(HashMap::new()));
    let progress = handshake_stages.clone();
    tokio::spawn(async move {
        while let Some(command) = queue.recv().await {
            // EOF is the existing Rust helpers' graceful stop signal. It drops
            // their fake TCP sockets and sends RST before capture is detached.
            if command["command"] == "stop" {
                break;
            }
            let mut line = serde_json::to_vec(&command).unwrap();
            line.push(b'\n');
            if input.write_all(&line).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            if line.len() > 4096 {
                break;
            }
            if let Some((_, body)) = line.split_once(' ') {
                if let Ok(v) = serde_json::from_str::<Value>(body) {
                    if v["event"] == "candidate-handshake" {
                        let stage = match v["stage"].as_str() {
                            Some("sent-syn") => "tx_syn",
                            Some("sent-syn-ack") => "tx_syn_ack",
                            Some("sent-ack") => "tx_ack",
                            Some("received-first") => "rx_first",
                            Some("received-syn") => "rx_syn",
                            Some("received-syn-ack") => "rx_syn_ack",
                            Some("received-final-ack") => "rx_final_ack",
                            Some("received-rst") => "rx_rst",
                            _ => continue,
                        };
                        if let (Some(peer), Some(at)) = (
                            v["peer"].as_str().and_then(|s| s.parse::<SocketAddr>().ok()), v["at"].as_i64()
                        ) {
                            let mut stages = progress.lock().unwrap();
                            let injected = v["driverInjectedBytes"].as_u64().and_then(|n| u32::try_from(n).ok());
                            stages.retain(|_, (last, _)| at.saturating_sub(*last) < 60_000);
                            if stages.len() < 256 || stages.contains_key(&(peer, stage)) {
                                stages.insert((peer, stage), (at, injected));
                            }
                        }
                    }
                    if v["event"] == "failed" || v["event"] == "peer-failed" {
                        let reason =
                            crate::logging::redact(v["reason"].as_str().unwrap_or("承载组件退出"));
                        let _ = diagnostic.try_send(crate::runtime::Event::Log {
                            level: "WARN".into(),
                            text: if reason == "raw carrier peer closed" {
                                format!("{carrier} {role}收到 FIN/RST（{purpose}），此次连接已关闭")
                            } else {
                                format!("{carrier} {role}运行失败（{purpose}）：{reason}")
                            },
                        });
                    }
                    if matches!(v["event"].as_str(), Some("protected" | "syn-sent" | "probe-rejected" | "pair-probe-discarded")) {
                        if let Some(id) = v["id"].as_str() {
                            if let Some(reply) = replies.lock().unwrap().remove(id) {
                                let result = if v["event"] == "probe-rejected" {
                                    Err(v["errno"].as_i64().and_then(|code| i32::try_from(code).ok())
                                        .map(io::Error::from_raw_os_error)
                                        .unwrap_or_else(|| io::Error::other(v["reason"].as_str().unwrap_or("helper rejected probe").to_owned())))
                                } else { Ok(v["submittedUs"].as_u64()) };
                                let _ = reply.send(result);
                            }
                        }
                    }
                    if let Some(udp) = v["udp"]
                        .as_str()
                        .and_then(|s| s.parse::<SocketAddr>().ok())
                        .filter(|a| a.ip().is_loopback())
                    {
                        let mut peers = peer_events.lock().unwrap();
                        if v["event"] == "peer-closed" {
                            peers.remove(&udp);
                        }
                        if v["event"] == "peer-opened" && peers.len() < 128 {
                            if let Some(peer) = v["peer"]
                                .as_str()
                                .and_then(|s| s.parse::<SocketAddr>().ok())
                                .filter(conwu_core::code::valid_endpoint)
                            {
                                peers.insert(udp, peer);
                                notify_peer.notify_one();
                                let mut stages = progress.lock().unwrap();
                                if stages.keys().any(|(p, _)| *p == peer) {
                                    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
                                    stages.insert((peer, "bridge_opened"), (at, None));
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    let control = server.then(|| Control {
        commands: commands.clone(),
        pending,
        peers,
        peer_opened,
        handshake_stages,
        source,
        confirms_syn: ready["synConfirmation"] == true,
    });
    Ok((
        Helper {
            process: child,
            commands: Some(commands),
        },
        udp,
        control,
    ))
}
pub async fn connect(
    engine: &Arc<Engine>,
    mode: &str,
    remote: SocketAddr,
    port: u16,
    parent: &CancellationToken,
) -> Result<Pipe> {
    connect_ref(engine, mode, remote, port, parent, "已配对网络重连").await
}
pub async fn connect_ref(
    engine: &Engine,
    mode: &str,
    remote: SocketAddr,
    port: u16,
    parent: &CancellationToken,
    purpose: &'static str,
) -> Result<Pipe> {
    connect_local(engine, mode, remote, port, parent, purpose)
        .await
        .map_err(|source| {
            LocalCarrierError {
                mode: mode.into(),
                source: Arc::new(source),
            }
            .into()
        })
}
async fn connect_local(
    engine: &Engine,
    mode: &str,
    remote: SocketAddr,
    port: u16,
    parent: &CancellationToken,
    purpose: &'static str,
) -> Result<Pipe> {
    ensure!(remote.is_ipv4(), "数据报 TCP 承载当前只支持 IPv4");
    let ip = crate::discovery::local_route(remote)?;
    let source = SocketAddr::new(ip, if port == 0 { free_tcp()? } else { port });
    let guard = Firewall::open(mode, false, source, remote)?;
    let (child, bridge, _) = spawn(engine, mode, false, source, remote, &[], Capture::Exact, purpose).await?;
    let socket = bind_bridge().await?;
    socket.connect(bridge).await?;
    Ok(udp_pipe_with_helper(
        socket,
        parent,
        Some(child),
        Some(guard),
        &engine.tracker,
    ))
}
pub struct ClientObservation {
    pub local: SocketAddr,
    pub mapped: SocketAddr,
    pub observer: SocketAddr,
    tcp: tokio::sync::Mutex<Option<crate::discovery::TcpObservation>>,
    native: Option<Arc<crate::native_map::Mapping>>,
    guard: Option<Firewall>,
}

pub(crate) struct CandidateReceiver {
    pub socket: Arc<UdpSocket>,
    pub control: Control,
    child: Option<Helper>,
    guard: Option<Firewall>,
}

pub(crate) struct MemberReceiver {
    pub(crate) control: Control,
    stop: CancellationToken,
    finished: CancellationToken,
}

impl MemberReceiver {
    pub(crate) async fn finish(self) {
        self.stop.cancel();
        self.finished.cancelled().await;
    }

    pub(crate) fn owns_peer(&self, peer: SocketAddr) -> bool {
        self.control.peers.lock().unwrap().values().any(|address| *address == peer)
    }

    pub(crate) fn retain(self, tracker: &TaskTracker, route: CancellationToken) {
        tracker.spawn(async move {
            tokio::select! {
                _ = route.cancelled() => {},
                _ = self.finished.cancelled() => {},
            }
            self.finish().await;
        });
    }
}

impl Drop for MemberReceiver {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl CandidateReceiver {
    #[cfg(test)]
    pub(crate) async fn test_member_bridge(local: SocketAddr, peer: SocketAddr) -> Result<(Self, UdpSocket)> {
        let socket = bind_bridge().await?;
        let bridge = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let control = Control::test_probe_control(local, true);
        control.peers.lock().unwrap().insert(bridge.local_addr()?, peer);
        Ok((Self { socket, control, child: None, guard: None }, bridge))
    }

    pub(crate) async fn finish(mut self) {
        if let Some(child) = self.child.take() { child.finish().await; }
    }
    pub(crate) fn bridges(&self) -> Vec<SocketAddr> {
        self.control.peers.lock().unwrap().keys().copied().collect()
    }

    pub(crate) fn peer(&self, bridge: SocketAddr) -> Option<SocketAddr> {
        self.control.peers.lock().unwrap().get(&bridge).copied()
    }

    pub(crate) async fn wait_bridge(&self) {
        self.control.peer_opened.notified().await;
    }

    pub(crate) async fn select(
        &mut self,
        bridge: SocketAddr,
        engine: &Engine,
        stop: &CancellationToken,
    ) -> Result<Pipe> {
        self.socket.connect(bridge).await?;
        Ok(udp_pipe_with_helper(self.socket.clone(), stop, self.child.take(), self.guard.take(), &engine.tracker))
    }

    pub(crate) fn serve_member(
        mut self, engine: &Arc<Engine>, mode: &str, parent: &CancellationToken, lifetime: &TaskTracker,
    ) -> MemberReceiver {
        let stop = parent.child_token();
        let finished = CancellationToken::new();
        let worker_stop = stop.clone();
        let worker_finished = finished.clone();
        let peers = self.control.peers.clone();
        let socket = self.socket.clone();
        let mut child = self.child.take();
        let firewall = self.guard.take();
        let server = engine.clone();
        let mode = mode.to_owned();
        let lifetime = lifetime.token();
        engine.tracker.spawn(async move {
            let _lifetime = lifetime;
            let _finished = worker_finished.drop_guard();
            let _firewall = firewall;
            let bridges = TaskTracker::new();
            serve_listener(&server, &mode, socket, &mut child, Some(&peers), &worker_stop,
                &CancellationToken::new(), &bridges).await;
            worker_stop.cancel();
            if let Some(child) = child {
                child.finish().await;
            }
            bridges.close();
            bridges.wait().await;
        });
        MemberReceiver { control: self.control.clone(), stop, finished }
    }
}

impl Drop for CandidateReceiver {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            tokio::spawn(child.finish());
        }
    }
}

impl ClientObservation {
    pub(crate) fn tcp_observation(&self) -> &tokio::sync::Mutex<Option<crate::discovery::TcpObservation>> {
        self.native.as_ref().map_or(&self.tcp, |mapping| mapping.observation())
    }

    pub(crate) async fn retain_stun(&self) -> Result<crate::discovery::StunLease> {
        let observed = self.tcp.lock().await.take().context("缺少从机 TCP STUN 连接")?;
        Ok(crate::discovery::StunLease::start(observed, true).await?)
    }

    /// One ready capture receives the host's first SYN while port prediction runs.
    pub(crate) async fn prepare_mimic_candidates(
        &self,
        engine: &Engine,
        peer: SocketAddr,
    ) -> Result<CandidateReceiver> {
        let IpAddr::V4(ip) = peer.ip() else { anyhow::bail!("Mimic 同源候选需要 IPv4"); };
        ensure!(crate::discovery::local_route(peer)? == self.local.ip(), "主机与 TCP STUN 使用不同的本机出口");
        let socket = bind_bridge().await?;
        let (child, _, control) = spawn(
            engine, "mimic", true, self.local, socket.local_addr()?, &[self.observer.to_string()],
            Capture::Peer(ip), "首次配对多候选",
        ).await?;
        let control = control.context("Mimic 多候选控制不可用")?;
        Ok(CandidateReceiver { socket, control, child: Some(child), guard: None })
    }

    /// Bind and observe the actual replacement socket on the agreed reflector.
    pub(crate) async fn rotated(local: SocketAddr, observer: SocketAddr, used: &[u16]) -> Result<Self> {
        for _ in 0..8 {
            let port = free_tcp()?;
            if port == local.port() || used.contains(&port) { continue; }
            let source = SocketAddr::new(local.ip(), port);
            match tokio::time::timeout(crate::discovery::TCP_OBSERVER_ATTEMPT,
                crate::discovery::observe_tcp_from(source, observer)).await? {
                Ok(observation) => return Ok(Self::tcp(observation)),
                Err(error) if crate::discovery::stun_address_in_use(&error) => continue,
                Err(error) => return Err(error),
            }
        }
        anyhow::bail!("未能为新轮次分配不同的本地 TCP 端口")
    }

    pub(crate) async fn recovery_receiver(&self, engine: &Engine, mode: &str, peer: SocketAddr) -> Result<CandidateReceiver> {
        let socket = bind_bridge().await?;
        let guard = Firewall::open(mode, true, self.local, peer)?;
        if mode != "tcpraw" { guard.protect(self.local, self.observer)?; }
        let (child, _, control) = spawn(engine, mode, true, self.local, socket.local_addr()?,
            &[self.observer.to_string()], Capture::for_recovery(mode, peer), "成员重连独立发送端").await?;
        Ok(CandidateReceiver { socket, control: control.context("恢复发送端缺少控制句柄")?, child: Some(child), guard: Some(guard) })
    }

    pub(crate) async fn candidate_pipe(
        &self,
        engine: &Engine,
        mode: &str,
        remote: SocketAddr,
        only_candidate: bool,
        parent: &CancellationToken,
    ) -> Result<Pipe> {
        ensure!(remote != self.observer && remote != self.local, "原始 TCP 候选与本地观察端点冲突");
        let guard = Firewall::open(mode, false, self.local, remote)?;
        if let Some(mapping) = &self.native {
            return mapping.candidate_pipe(remote, guard, only_candidate, parent).await;
        }
        let capture = if only_candidate && cfg!(windows) && mode == "mimic" {
            Capture::LearnPort
        } else {
            Capture::SharedSource
        };
        self.helper_pipe(engine, mode, remote, guard, capture, parent).await
    }

    pub fn tcp(observed: crate::discovery::TcpObservation) -> Self {
        Self {
            local: observed.local,
            mapped: observed.mapped,
            observer: observed.observer,
            tcp: tokio::sync::Mutex::new(Some(observed)),
            native: None,
            guard: None,
        }
    }
    pub async fn start(&self, peer: SocketAddr, coordinated: bool, parent: &CancellationToken) -> Result<Option<Pipe>> {
        if let Some(mapping) = &self.native {
            return Ok(Some(mapping.client_pipe(peer, coordinated, parent).await?));
        }
        Ok(None)
    }
}
impl Drop for ClientObservation {
    fn drop(&mut self) {
        if let Some(mapping) = self.native.take() {
            let guard = self.guard.take();
            tokio::spawn(async move {
                let _guard = guard;
                while mapping.close().await.is_err() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        }
    }
}
pub async fn observe_client(
    engine: &Engine,
    mode: &str,
    observers: &[String],
    require_keepalive: bool,
    parent: &CancellationToken,
) -> Result<ClientObservation> {
    if mode == "faketcp" {
        let target = UdpSocket::bind("127.0.0.1:0").await?.local_addr()?;
        let mapping = crate::native_map::Mapping::open(
            engine,
            free_tcp()?,
            target,
            observers,
            parent,
        )
        .await?;
        return Ok(ClientObservation {
            local: mapping.local,
            mapped: mapping.mapped(),
            observer: mapping.observer,
            tcp: tokio::sync::Mutex::new(None),
            native: Some(mapping),
            guard: None,
        });
    }
    let port = free_tcp()?;
    let observed = if require_keepalive {
        crate::discovery::observe_tcp_with_keepalive(port, observers, engine, mode).await?
    } else {
        crate::discovery::observe_tcp(port, observers, engine, mode).await?
    };
    Ok(ClientObservation::tcp(observed))
}

impl ClientObservation {
    pub async fn prepare_raw(
        &mut self,
        engine: &Engine,
        mode: &str,
        remote: SocketAddr,
        coordinated: bool,
        parent: &CancellationToken,
    ) -> Result<Option<Pipe>> {
        if let Some(mapping) = &self.native {
            self.guard = Some(Firewall::open(mode, false, self.local, remote)?);
            mapping.prepare(remote, true, coordinated).await?;
            return Ok(None);
        }
        let capture = if cfg!(windows) && coordinated && mode == "mimic" {
            Capture::LearnPort
        } else {
            Capture::Exact
        };
        let guard = Firewall::open(mode, false, self.local, remote)?;
        self.helper_pipe(engine, mode, remote, guard, capture, parent).await.map(Some)
    }

    async fn helper_pipe(
        &self,
        engine: &Engine,
        mode: &str,
        remote: SocketAddr,
        guard: Firewall,
        capture: Capture,
        parent: &CancellationToken,
    ) -> Result<Pipe> {
        let (child, bridge, _) = spawn(
            engine, mode, false, self.local, remote, &[self.observer.to_string()],
            capture, "首次配对",
        ).await?;
        let socket = bind_bridge().await?;
        socket.connect(bridge).await?;
        Ok(udp_pipe_with_helper(socket, parent, Some(child), Some(guard), &engine.tracker))
    }
}
pub(crate) async fn bind_bridge() -> Result<Arc<UdpSocket>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    // Absorb a short frame burst in loopback without increasing the application queue.
    if let Err(error) = socket2::SockRef::from(&socket).set_recv_buffer_size(BRIDGE_RECEIVE_BUFFER)
    {
        tracing::debug!(%error, "无法调整本地承载收包缓冲区");
    }
    Ok(Arc::new(socket))
}

pub(crate) fn udp_pipe(
    socket: Arc<UdpSocket>,
    parent: &CancellationToken,
    tracker: &TaskTracker,
) -> Pipe {
    udp_pipe_with_helper(socket, parent, None, None, tracker)
}

fn forward_datagram(queue: &mpsc::Sender<Vec<u8>>, bytes: &[u8]) -> bool {
    use mpsc::error::TrySendError;

    match queue.try_reserve() {
        Ok(permit) => permit.send(bytes.to_vec()),
        // A late datagram can be lost without restarting the encrypted path.
        Err(TrySendError::Full(_)) => {}
        Err(TrySendError::Closed(_)) => return false,
    }
    true
}

fn oversized_datagram(_error: &io::Error) -> bool {
    #[cfg(windows)]
    return _error.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE);
    #[cfg(not(windows))]
    false
}

fn udp_pipe_with_helper(
    socket: Arc<UdpSocket>,
    parent: &CancellationToken,
    mut child: Option<Helper>,
    guard: Option<Firewall>,
    tracker: &TaskTracker,
) -> Pipe {
    let (tx, mut outgoing) = mpsc::channel::<Vec<u8>>(BRIDGE_QUEUE);
    let (incoming, rx) = mpsc::channel(BRIDGE_QUEUE);
    let cancel = parent.child_token();
    let stop = cancel.clone();
    tracker.spawn(async move {
        let _guard = guard;
        let mut buffer = [0u8; MAX_DATAGRAM + 1];
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = wait_for_helper(&mut child) => break,
                result = socket.recv(&mut buffer) => match result {
                    Ok(n) if n <= MAX_DATAGRAM => {
                        if !forward_datagram(&incoming, &buffer[..n]) {
                            break;
                        }
                    }
                    Ok(_) => continue,
                    Err(error) if oversized_datagram(&error) => continue,
                    Err(_) => break,
                },
                frame = outgoing.recv() => {
                    let Some(frame) = frame else { break };
                    tokio::select! {
                        _ = stop.cancelled() => break,
                        result = socket.send(&frame) => if result.is_err() { break; },
                    }
                }
            }
        }
        stop.cancel();
        if let Some(child) = child {
            child.finish().await;
        }
    });
    Pipe {
        tx,
        rx,
        cancel,
        pin: String::new(),
    }
}
pub async fn listen(
    engine: &Arc<Engine>,
    mode: &str,
    port: u16,
    stun: &[String],
    autonomous: bool,
    stop: CancellationToken,
    finished: CancellationToken,
    require_observation: bool,
) -> Result<Option<LocalCarrierError>> {
    let socket = bind_bridge().await?;
    let target = socket.local_addr()?;
    let (mapping, observation_error) = if mode == "faketcp" && autonomous {
        let open = || crate::native_map::Mapping::open(engine, port, target, stun, &stop);
        let mapping = if require_observation {
            crate::assistance::retry_pair_step("准备 FakeTCP 同源接收器", |error| {
                !crate::discovery::stun_address_in_use(error) && crate::discovery::transient_observer(error)
            }, |_| open()).await
        } else { open().await };
        match mapping {
            Ok(mapping) => (Some(mapping), None),
            Err(error) if require_observation => return Err(error),
            Err(error) => {
                // An unavailable STUN server must not disable the ordinary
                // FakeTCP receiver reachable through UPnP or a public address.
                tracing::warn!(%error, "FakeTCP 同源观察暂未建立，保留普通入口监听");
                (None, Some(LocalCarrierError { mode: mode.into(), source: Arc::new(error) }))
            }
        }
    } else {
        (None, None)
    };
    let source = if let Some(mapping) = &mapping {
        mapping.local
    } else if autonomous {
        let route_target = if let Some(server) = stun.first() {
            crate::discovery::endpoint(server)
                .await
                .unwrap_or_default()
                .into_iter()
                .find(SocketAddr::is_ipv4)
        } else {
            None
        }
        .unwrap_or("1.1.1.1:3478".parse()?);
        SocketAddr::new(crate::discovery::local_route(route_target)?, port)
    } else {
        SocketAddr::from(([0, 0, 0, 0], port))
    };
    let guard = Firewall::open(mode, true, source, target)?;
    let (mut child, control) = if let Some(mapping) = &mapping {
        let mut observers = engine.raw_observers.lock().unwrap();
        ensure!(observers.len() < 256, "本机观察服务保护表超过限制");
        guard.protect(source, mapping.observer)?;
        observers.insert(format!("{}/{}", guard.name, mapping.observer));
        (None, None)
    } else {
        let (child, _, control) = spawn(
            engine,
            mode,
            true,
            source,
            target,
            if autonomous { stun } else { &[] },
            Capture::Exact,
            "网络接收",
        )
        .await?;
        (Some(child), control)
    };
    let key = (mode.to_owned(), port);
    let peer_addresses = mapping
        .as_ref()
        .map(|m| m.peers.clone())
        .or_else(|| control.as_ref().map(|c| c.peers.clone()));
    let mapping_failed = mapping
        .as_ref()
        .map(|m| m.cancel.clone())
        .unwrap_or_else(CancellationToken::new);
    engine
        .raw_tables
        .lock()
        .unwrap()
        .insert(key.clone(), guard.name.clone());
    if let Some(control) = control {
        engine
            .raw_controls
            .lock()
            .unwrap()
            .insert(key.clone(), control);
    }
    if let Some(mapping) = &mapping {
        engine
            .fake_mappings
            .write()
            .unwrap()
            .insert(port, mapping.clone());
    }
    let engine = engine.clone();
    let tracker = engine.tracker.clone();
    tracker.spawn(async move {
        let _finished = finished.drop_guard();
        let guard = guard;
        serve_listener(&engine, &key.0, socket, &mut child, peer_addresses.as_ref(), &stop,
            &mapping_failed, &engine.tracker).await;
        stop.cancel();
        if let Some(child) = child {
            child.finish().await;
        }
        if let Some(mapping) = mapping {
            while mapping.close().await.is_err() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            engine.fake_mappings.write().unwrap().remove(&port);
        }
        let mut tables = engine.raw_tables.lock().unwrap();
        if tables.get(&key) == Some(&guard.name) {
            tables.remove(&key);
            engine.raw_controls.lock().unwrap().remove(&key);
        }
        drop(tables);
        let prefix = format!("{}/", guard.name);
        engine.raw_observers.lock().unwrap().retain(|entry| !entry.starts_with(&prefix));
    });
    Ok(observation_error)
}
async fn serve_listener(
    engine: &Arc<Engine>,
    mode: &str,
    socket: Arc<UdpSocket>,
    child: &mut Option<Helper>,
    peer_addresses: Option<&Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>>,
    stop: &CancellationToken,
    mapping_failed: &CancellationToken,
    tracker: &TaskTracker,
) {
    let mut peers = HashMap::<SocketAddr, mpsc::Sender<Vec<u8>>>::new();
    let mut buffer = [0; MAX_DATAGRAM + 1];
    loop {
        let result = tokio::select! {
            _ = stop.cancelled() => break,
            _ = mapping_failed.cancelled() => break,
            _ = wait_for_helper(child) => break,
            result = socket.recv_from(&mut buffer) => result,
        };
        let (n, from) = match result {
            Ok((n, from)) if n <= MAX_DATAGRAM && from.ip().is_loopback() => (n, from),
            Ok(_) => continue,
            Err(error) if oversized_datagram(&error)
                || matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused) => continue,
            Err(_) => break,
        };
        if let Some(peer) = peers.get(&from) {
            if forward_datagram(peer, &buffer[..n]) {
                continue;
            }
            peers.remove(&from);
        }
        if peers.len() >= 32 {
            peers.retain(|_, tx| !tx.is_closed());
            if peers.len() >= 32 {
                continue;
            }
        }

        let (outgoing, mut to_remote) = mpsc::channel::<Vec<u8>>(BRIDGE_QUEUE);
        let (incoming, rx) = mpsc::channel(BRIDGE_QUEUE);
        let token = stop.child_token();
        let pipe = Pipe { tx: outgoing, rx, cancel: token.clone(), pin: String::new() };
        forward_datagram(&incoming, &buffer[..n]);
        peers.insert(from, incoming);

        let socket = socket.clone();
        tracker.spawn(async move {
            loop {
                let frame = tokio::select! {
                    _ = token.cancelled() => break,
                    result = to_remote.recv() => match result { Some(frame) => frame, None => break },
                };
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = socket.send_to(&frame, from) => {},
                }
            }
        });
        let server = engine.clone();
        let mode = mode.to_owned();
        let addresses = peer_addresses.cloned();
        tracker.spawn(async move {
            let mut endpoint = SocketAddr::from(([0, 0, 0, 0], 0));
            if let Some(addresses) = addresses {
                for _ in 0..10 {
                    if let Some(peer) = addresses.lock().unwrap().get(&from).copied() {
                        endpoint = peer;
                        break;
                    }
                    tokio::select! {
                        _ = pipe.cancel.cancelled() => return,
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                    }
                }
            }
            server.serve(pipe, mode, endpoint, None).await;
        });
    }
}

pub(crate) fn free_tcp() -> Result<u16> {
    Ok(std::net::TcpListener::bind("0.0.0.0:0")?
        .local_addr()?
        .port())
}
fn free_udp() -> Result<u16> {
    Ok(std::net::UdpSocket::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}
pub(crate) struct Firewall {
    name: String,
    #[cfg(windows)]
    installed: bool,
}
impl Firewall {
    pub(crate) fn open(
        mode: &str,
        server: bool,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<Self> {
        let name = format!("conwu_rust_{}", conwu_core::id());
        #[cfg(target_os = "linux")]
        {
            run("nft", &["add", "table", "inet", &name])?;
            let firewall = Self { name };
            let hook = if mode == "tcpraw" { "output" } else { "input" };
            run(
                "nft",
                &[
                    "add",
                    "chain",
                    "inet",
                    &firewall.name,
                    hook,
                    "{",
                    "type",
                    "filter",
                    "hook",
                    hook,
                    "priority",
                    "-150",
                    ";",
                    "policy",
                    "accept",
                    ";",
                    "}",
                ],
            )?;
            let mut rule = vec![
                "add".into(),
                "rule".into(),
                "inet".into(),
                firewall.name.clone(),
                hook.into(),
            ];
            if mode == "tcpraw" {
                rule.extend([
                    "ip".into(),
                    "ttl".into(),
                    "1".into(),
                    "tcp".into(),
                    "sport".into(),
                    local.port().to_string(),
                ]);
            } else {
                rule.extend(["tcp".into(), "dport".into(), local.port().to_string()]);
                if !server {
                    rule.extend([
                        "ip".into(),
                        "saddr".into(),
                        remote.ip().to_string(),
                        "tcp".into(),
                        "sport".into(),
                        remote.port().to_string(),
                    ]);
                }
            }
            rule.push("drop".into());
            run("nft", &rule.iter().map(String::as_str).collect::<Vec<_>>())?;
            return Ok(firewall);
        }
        #[cfg(windows)]
        {
            let _ = (mode, remote);
            if server {
                run(
                    "netsh.exe",
                    &[
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        &format!("name={name}"),
                        "dir=in",
                        "action=allow",
                        "protocol=TCP",
                        &format!("localport={}", local.port()),
                    ],
                )?;
            }
            Ok(Self { name, installed: server })
        }
    }
}
impl Firewall {
    pub(crate) fn protect(&self, local: SocketAddr, observer: SocketAddr) -> Result<()> {
        #[cfg(target_os = "linux")]
        run(
            "nft",
            &[
                "insert",
                "rule",
                "inet",
                &self.name,
                "input",
                "ip",
                "saddr",
                &observer.ip().to_string(),
                "tcp",
                "sport",
                &observer.port().to_string(),
                "tcp",
                "dport",
                &local.port().to_string(),
                "accept",
            ],
        )?;
        #[cfg(windows)]
        let _ = (local, observer);
        Ok(())
    }
}
impl Drop for Firewall {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        let _ = run("nft", &["delete", "table", "inet", &self.name]);
        #[cfg(windows)]
        if self.installed {
            let _ = run(
                "netsh.exe",
                &[
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}", self.name),
                ],
            );
        }
    }
}
fn run(executable: &str, args: &[&str]) -> Result<()> {
    let mut cmd = std::process::Command::new(executable);
    cmd.args(args).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    ensure!(
        cmd.status()?.success(),
        "实验防火墙规则配置失败：{executable}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn fallback_receiver_error_preserves_address_in_use() {
        #[cfg(windows)]
        let code = 10048;
        #[cfg(not(windows))]
        let code = libc::EADDRINUSE;
        let source = anyhow::Error::new(std::io::Error::from_raw_os_error(code)).context("连接 TCP STUN 观察器");
        let stored = super::LocalCarrierError { mode: "faketcp".into(), source: std::sync::Arc::new(source) };
        let error = anyhow::Error::new(stored.clone()).context("FakeTCP 同源接收器尚未准备完成");
        assert!(crate::discovery::stun_address_in_use(&error));
        assert!(error.chain().any(|cause| cause.downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.raw_os_error() == Some(code))));
    }
    use super::*;

    #[test]
    fn recovery_receivers_use_only_supported_capture_arguments() {
        let peer = "198.51.100.4:43200".parse().unwrap();
        for mode in ["tcpraw", "phantun"] {
            assert!(Capture::for_recovery(mode, peer) == Capture::Exact);
        }
        assert_eq!(matches!(Capture::for_recovery("mimic", peer), Capture::Peer(_)), cfg!(windows));
    }

    #[tokio::test]
    async fn mimic_round_summary_excludes_earlier_helper_events() -> Result<()> {
        let local = "192.0.2.1:50801".parse()?;
        let peer: SocketAddr = "198.51.100.1:51001".parse()?;
        let control = Control::test_probe_control(local, false);
        let old = SocketAddr::new(peer.ip(), 51002);
        control.handshake_stages.lock().unwrap().extend([
            ((old, "tx_syn"), (1, Some(48))),
            ((peer, "tx_syn"), (48136, Some(48))),
        ]);
        let mut seen = vec![];
        control.visit_handshakes(peer.ip(), 48136, |addr, _, at, _| seen.push((addr, at - 48136)));
        assert_eq!(seen, [(peer, 0)]);
        Ok(())
    }

    #[tokio::test]
    async fn mimic_member_timeout_drains_the_receiver_before_the_next_round() -> Result<()> {
        let app = crate::tests::app().await?;
        let local = SocketAddr::from(([127, 0, 0, 1], free_tcp()?));
        let remote: SocketAddr = "198.51.100.1:51001".parse()?;
        let retire = CancellationToken::new();
        let socket = bind_bridge().await?;
        let weak_socket = Arc::downgrade(&socket);
        let control = Control::test_probe_control(local, false);
        control.peers.lock().unwrap().insert(socket.local_addr()?, remote);
        control.handshake_stages.lock().unwrap().insert((remote, "tx_syn"), (42, Some(48)));
        let old_events = Arc::downgrade(&control.handshake_stages);
        let old_targets = Arc::downgrade(&control.peers);
        let lifetime = TaskTracker::new();
        let listener = CandidateReceiver { socket, control, child: None, guard: None }
            .serve_member(&app.engine, "mimic", &retire, &lifetime);
        assert!(listener.owns_peer(remote));
        let round = tokio::time::timeout(Duration::ZERO, std::future::pending::<()>()).await;
        assert!(round.is_err());
        tokio::time::timeout(Duration::from_secs(1), listener.finish()).await?;
        assert!(weak_socket.upgrade().is_none());
        assert!(old_events.upgrade().is_none() && old_targets.upgrade().is_none());
        assert!(!retire.is_cancelled());

        let replacement = CandidateReceiver {
            socket: bind_bridge().await?, control: Control::test_probe_control(local, true),
            child: None, guard: None,
        }.serve_member(&app.engine, "mimic", &retire, &lifetime);
        assert!(!replacement.owns_peer(remote));
        replacement.control.probe(remote, Duration::from_secs(1), Some(uuid::Uuid::new_v4())).await?;
        replacement.finish().await;
        Ok(())
    }

    #[test]
    fn full_peer_queue_remains_open() {
        let (tx, mut rx) = mpsc::channel(1);
        assert!(forward_datagram(&tx, b"first"));
        assert!(forward_datagram(&tx, b"overflow"));
        assert_eq!(rx.try_recv().unwrap(), b"first");
        assert!(forward_datagram(&tx, b"next"));
        assert_eq!(rx.try_recv().unwrap(), b"next");
        drop(rx);
        assert!(!forward_datagram(&tx, b"closed"));
    }

    #[tokio::test]
    async fn udp_bridge_survives_overflow_and_packets_of_invalid_size() -> Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let bridge = UdpSocket::bind("127.0.0.1:0").await?;
        socket.connect(bridge.local_addr()?).await?;
        bridge.connect(socket.local_addr()?).await?;
        let tracker = TaskTracker::new();
        let parent = CancellationToken::new();
        let mut pipe = udp_pipe(Arc::new(socket), &parent, &tracker);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            for sent in 0..BRIDGE_QUEUE {
                bridge.send(b"queued").await?;
                while pipe.rx.len() <= sent {
                    tokio::task::yield_now().await;
                }
            }
            bridge.send(b"overflow").await?;
            bridge.send(&[0; MAX_DATAGRAM + 64]).await?;

            let mut buffer = [0; 32];
            pipe.tx.send(b"reverse".to_vec()).await?;
            let n = bridge.recv(&mut buffer).await?;
            assert_eq!(&buffer[..n], b"reverse");
            assert!(!pipe.cancel.is_cancelled());

            for _ in 0..BRIDGE_QUEUE {
                assert_eq!(pipe.rx.recv().await.as_deref(), Some(b"queued".as_slice()));
            }
            bridge.send(b"next").await?;
            while let Some(frame) = pipe.rx.recv().await {
                if frame == b"next" {
                    return Ok(());
                }
            }
            anyhow::bail!("bridge closed before forwarding the next packet")
        })
        .await;
        drop(pipe);
        tracker.close();
        tracker.wait().await;
        result?
    }
}
