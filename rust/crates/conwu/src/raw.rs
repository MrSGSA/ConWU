//! Existing audited packet carriers remain independent processes with their
//! upstream licenses. No CLR process participates in this adapter.
use crate::{runtime::Engine, transport::Pipe};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::SocketAddr,
    process::Stdio,
    sync::{Arc, Mutex, OnceLock},
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
fn stoppers() -> &'static Mutex<HashMap<u32, mpsc::WeakSender<Value>>> {
    static STOPPERS: OnceLock<Mutex<HashMap<u32, mpsc::WeakSender<Value>>>> = OnceLock::new();
    STOPPERS.get_or_init(|| Mutex::new(HashMap::new()))
}
async fn finish_child(child: &mut Child) {
    let stop = child
        .id()
        .and_then(|pid| stoppers().lock().unwrap().remove(&pid))
        .and_then(|s| s.upgrade());
    let graceful = stop.is_some();
    if let Some(stop) = stop {
        let _ = tokio::time::timeout(
            Duration::from_millis(500),
            stop.send(json!({"command":"stop"})),
        )
        .await;
    }
    child.stdin.take();
    if !graceful
        || tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .is_err()
    {
        let _ = child.kill().await;
    }
    let _ = child.wait().await;
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
) -> Result<(Child, SocketAddr)> {
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
        return Ok((child, bridge));
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
                        anyhow::bail!("承载组件启动失败：{}", v["reason"].as_str().unwrap_or("组件未就绪"))
                    }
                    if v["event"] == "backend-fallback" {
                        let reason = crate::logging::redact(v["reason"].as_str().unwrap_or("XDP 未就绪"));
                        let _ = engine.events.try_send(crate::runtime::Event::Log {
                            level: "WARN".into(), text: format!("Mimic 已回退至 WinDivert：{reason}"),
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
            level: "INFO".into(), text: format!("{mode} 承载已就绪（{}）",crate::logging::redact(backend)),
        });
    }
    let mut input = child.stdin.take().context("组件控制输入不可用")?;
    let (commands, mut queue) = mpsc::channel::<Value>(32);
    if let Some(pid) = child.id() {
        stoppers().lock().unwrap().insert(pid, commands.downgrade());
    }
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
    let keep_commands = commands.clone();
    tokio::spawn(async move {
        let _keep_commands = keep_commands;
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
    if server {
        engine.raw_controls.lock().unwrap().insert(
            (mode.into(), source.port()),
            Control {
                commands,
                pending,
                peers,
            },
        );
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
    Ok((child, udp))
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
        .map_err(|source| LocalCarrierError { mode: mode.into(), source }.into())
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
    let (child, bridge) = spawn(engine, mode, false, source, remote, &[]).await?;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    socket.connect(bridge).await?;
    Ok(udp_pipe(
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
    let (child, bridge) = spawn(
        engine,
        mode,
        false,
        observed.local,
        remote,
        &[observed.observer.to_string()],
    )
    .await?;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    socket.connect(bridge).await?;
    Ok((
        udp_pipe(socket, parent, Some(child), Some(guard), &engine.tracker),
        ClientObservation::tcp(observed),
    ))
}
pub(crate) fn udp_pipe(
    socket: Arc<UdpSocket>,
    parent: &CancellationToken,
    child: Option<Child>,
    guard: Option<Firewall>,
    tracker: &TaskTracker,
) -> Pipe {
    let (tx, mut outgoing) = mpsc::channel::<Vec<u8>>(128);
    let (incoming, rx) = mpsc::channel(128);
    let cancel = parent.child_token();
    let stop = cancel.clone();
    tracker.spawn(async move {
        let _guard = guard;
        let mut child = child;
        let _cancel = stop.clone().drop_guard();
        let mut buffer = [0u8; 2049];
        loop {
            tokio::select! {_=stop.cancelled()=>break,n=socket.recv(&mut buffer)=>match n{Ok(n)if n<=2048=>{if incoming.try_send(buffer[..n].to_vec()).is_err(){break}},_=>break},frame=outgoing.recv()=>match frame{Some(frame)=>{if socket.send(&frame).await.is_err(){break}},None=>break},_=tokio::time::sleep(Duration::from_secs(1))=>{if child.as_mut().is_some_and(|c|c.try_wait().ok().flatten().is_some()){break}}}
        }
        if let Some(child) = &mut child {
            finish_child(child).await;
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
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
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
    engine
        .raw_tables
        .lock()
        .unwrap()
        .insert((mode.into(), port), guard.name.clone());
    if let Some(mapping) = &mapping {
        prepare_observer(engine, mode, port, mapping.observer).await?;
        engine
            .fake_mappings
            .write()
            .unwrap()
            .insert(port, mapping.clone());
    }
    let child = if mapping.is_some() {
        None
    } else {
        let (child, _) = spawn(
            engine,
            mode,
            true,
            source,
            target,
            if autonomous { stun } else { &[] },
        )
        .await?;
        Some(child)
    };
    let peer_addresses = mapping.as_ref().map(|m| m.peers.clone()).or_else(|| {
        engine
            .raw_controls
            .lock()
            .unwrap()
            .get(&(mode.into(), port))
            .map(|c| c.peers.clone())
    });
    let mapping_failed = mapping
        .as_ref()
        .map(|m| m.cancel.clone())
        .unwrap_or_else(CancellationToken::new);
    let engine = engine.clone();
    let mode = mode.to_string();
    let tracker = engine.tracker.clone();
    tracker.spawn(async move{let _finished=finished.drop_guard();let _stop=stop.clone().drop_guard();let _guard=guard;let mut child=child;let mut peers:HashMap<SocketAddr,mpsc::Sender<Vec<u8>>>=HashMap::new();let mut buffer=[0;2049];let(tx,mut sends)=mpsc::channel::<(SocketAddr,Vec<u8>)>(256);
        loop{tokio::select!{_=stop.cancelled()=>break,_=mapping_failed.cancelled()=>break,n=socket.recv_from(&mut buffer)=>{let Ok((n,from))=n else{break};if n>2048||!from.ip().is_loopback(){continue}if let Some(peer)=peers.get(&from){if peer.try_send(buffer[..n].to_vec()).is_ok(){continue}peers.remove(&from);}
            if peers.len()>=32{peers.retain(|_,tx|!tx.is_closed());if peers.len()>=32{continue}}
            let(outgoing,mut to_remote)=mpsc::channel(128);let(incoming,rx)=mpsc::channel(128);let token=stop.child_token();let pipe=Pipe{tx:outgoing,rx,cancel:token.clone(),pin:String::new()};let sender=tx.clone();engine.tracker.spawn(async move{loop{tokio::select!{_=token.cancelled()=>break,r=to_remote.recv()=>match r{Some(r)=>{if sender.send((from,r)).await.is_err(){break}},None=>break}}}});let _=incoming.try_send(buffer[..n].to_vec());peers.insert(from,incoming);let server=engine.clone();let mode=mode.clone();let addresses=peer_addresses.clone();engine.tracker.spawn(async move{
                let mut endpoint = "0.0.0.0:0".parse().unwrap();
                if let Some(addresses) = addresses { for _ in 0..10 {
                    if let Some(peer) = addresses.lock().unwrap().get(&from).copied() { endpoint=peer; break; }
                    tokio::select! { _=pipe.cancel.cancelled()=>return, _=tokio::time::sleep(Duration::from_millis(10))=>{} }
                }}
                server.serve(pipe,mode,endpoint,None).await;
            });},
            frame=sends.recv()=>if let Some((to,bytes))=frame{let _=socket.send_to(&bytes,to).await;},_=tokio::time::sleep(Duration::from_secs(1))=>{if child.as_mut().is_some_and(|c|c.try_wait().ok().flatten().is_some()){break}}
        }}if let Some(mut child)=child{finish_child(&mut child).await;}
        if let Some(mapping)=mapping {
            while mapping.close().await.is_err(){tokio::time::sleep(Duration::from_secs(1)).await;}
            engine.fake_mappings.write().unwrap().remove(&port);
        }
        let owned=engine.raw_tables.lock().unwrap().get(&(mode.clone(),port)).is_some_and(|t|t==&_guard.name);
        if owned {engine.raw_tables.lock().unwrap().remove(&(mode.clone(),port));engine.raw_controls.lock().unwrap().remove(&(mode.clone(),port));engine.raw_observers.lock().unwrap().retain(|s|!s.starts_with(&format!("{}/",_guard.name)));}
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
