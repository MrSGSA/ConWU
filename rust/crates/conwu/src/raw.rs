//! Existing audited packet carriers remain independent processes with their
//! upstream licenses. No CLR process participates in this adapter.
use crate::{runtime::Engine, transport::Pipe};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
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

#[derive(Debug)]
pub(crate) struct LocalCarrierError {
    mode: String,
    source: anyhow::Error,
}
impl std::fmt::Display for LocalCarrierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "本机 {} 承载组件未就绪：{}", self.mode, self.source)
    }
}
impl std::error::Error for LocalCarrierError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
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
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
    peers: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>,
}
impl Control {
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
        let id = conwu_core::id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id.clone(), tx);
        let result = async {
            self.commands
                .send(json!({"command":"protect","peer":peer.to_string(),"id":id}))
                .await?;
            tokio::time::timeout(Duration::from_secs(2), rx).await??;
            Ok(())
        }
        .await;
        self.pending.lock().unwrap().remove(&id);
        result
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

async fn spawn(
    engine: &Engine,
    mode: &str,
    server: bool,
    source: SocketAddr,
    remote: SocketAddr,
    stun: &[String],
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
    if let Some(backend) = ready["backend"].as_str() {
        let _ = engine.events.try_send(crate::runtime::Event::Log {
            level: "INFO".into(),
            text: format!("{mode} 承载已就绪（{}）", crate::logging::redact(backend)),
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
    let pending = Arc::new(Mutex::new(HashMap::<String, oneshot::Sender<()>>::new()));
    let replies = pending.clone();
    let diagnostic = engine.events.clone();
    let peers = Arc::new(Mutex::new(HashMap::<SocketAddr, SocketAddr>::new()));
    let peer_events = peers.clone();
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
                    if v["event"] == "failed" || v["event"] == "peer-failed" {
                        let reason =
                            crate::logging::redact(v["reason"].as_str().unwrap_or("承载组件退出"));
                        let _ = diagnostic.try_send(crate::runtime::Event::Log {
                            level: "WARN".into(),
                            text: format!("承载组件运行失败：{reason}"),
                        });
                    }
                    if v["event"] == "protected" {
                        if let Some(id) = v["id"].as_str() {
                            if let Some(reply) = replies.lock().unwrap().remove(id) {
                                let _ = reply.send(());
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
    connect_ref(engine, mode, remote, port, parent).await
}
pub async fn connect_ref(
    engine: &Engine,
    mode: &str,
    remote: SocketAddr,
    port: u16,
    parent: &CancellationToken,
) -> Result<Pipe> {
    connect_local(engine, mode, remote, port, parent)
        .await
        .map_err(|source| {
            LocalCarrierError {
                mode: mode.into(),
                source,
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
) -> Result<Pipe> {
    ensure!(remote.is_ipv4(), "数据报 TCP 承载当前只支持 IPv4");
    let ip = crate::discovery::local_route(remote)?;
    let source = SocketAddr::new(ip, if port == 0 { free_tcp()? } else { port });
    let guard = Firewall::open(mode, false, source, remote)?;
    let (child, bridge, _) = spawn(engine, mode, false, source, remote, &[]).await?;
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
    _tcp: Option<crate::discovery::TcpObservation>,
    native: Option<Arc<crate::native_map::Mapping>>,
    guard: Option<Firewall>,
}
impl ClientObservation {
    pub fn tcp(observed: crate::discovery::TcpObservation) -> Self {
        Self {
            local: observed.local,
            mapped: observed.mapped,
            observer: observed.observer,
            _tcp: Some(observed),
            native: None,
            guard: None,
        }
    }
    pub async fn start(&self, peer: SocketAddr) -> Result<()> {
        if let Some(mapping) = &self.native {
            mapping.prepare(peer, true, false).await?.start().await?;
        }
        Ok(())
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
pub async fn observed_client(
    engine: &Engine,
    mode: &str,
    remote: SocketAddr,
    observer: &str,
    parent: &CancellationToken,
) -> Result<(Pipe, ClientObservation)> {
    if mode == "faketcp" {
        let target = UdpSocket::bind("127.0.0.1:0").await?.local_addr()?;
        let mapping = crate::native_map::Mapping::open(
            engine,
            free_tcp()?,
            target,
            &[observer.into()],
            parent,
        )
        .await?;
        let guard = Firewall::open(mode, false, mapping.local, remote)?;
        let pipe = mapping.client_pipe(remote, parent, false).await?;
        return Ok((
            pipe,
            ClientObservation {
                local: mapping.local,
                mapped: mapping.mapped(),
                observer: mapping.observer,
                _tcp: None,
                native: Some(mapping),
                guard: Some(guard),
            },
        ));
    }
    let observed =
        crate::discovery::observe_tcp(free_tcp()?, &[observer.into()], engine, mode).await?;
    let guard = Firewall::open(mode, false, observed.local, remote)?;
    let (child, bridge, _) = spawn(
        engine,
        mode,
        false,
        observed.local,
        remote,
        &[observed.observer.to_string()],
    )
    .await?;
    let socket = bind_bridge().await?;
    socket.connect(bridge).await?;
    Ok((
        udp_pipe_with_helper(socket, parent, Some(child), Some(guard), &engine.tracker),
        ClientObservation::tcp(observed),
    ))
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
) -> Result<()> {
    let socket = bind_bridge().await?;
    let target = socket.local_addr()?;
    let mapping = if mode == "faketcp" && autonomous {
        match crate::native_map::Mapping::open(engine, port, target, stun, &stop).await {
            Ok(mapping) => Some(mapping),
            Err(error) => {
                // An unavailable STUN server must not disable the ordinary
                // FakeTCP receiver reachable through UPnP or a public address.
                tracing::warn!(%error, "FakeTCP 同源观察暂未建立，保留普通入口监听");
                None
            }
        }
    } else {
        None
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
        let mut peers = HashMap::<SocketAddr, mpsc::Sender<Vec<u8>>>::new();
        let mut buffer = [0; MAX_DATAGRAM + 1];
        loop {
            let result = tokio::select! {
                _ = stop.cancelled() => break,
                _ = mapping_failed.cancelled() => break,
                _ = wait_for_helper(&mut child) => break,
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
            engine.tracker.spawn(async move {
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
            let mode = key.0.clone();
            let addresses = peer_addresses.clone();
            engine.tracker.spawn(async move {
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
    Ok(())
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
            Ok(Self { name })
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
    use super::*;

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
