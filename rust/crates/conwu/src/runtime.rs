use crate::{
    adapter::{self, Adapter, Memory},
    discovery,
    model::{Entry, Network, Settings},
    pkarr,
    transport::{self, Pipe, TlsIdentity},
};
use anyhow::{Context, Result, ensure};
use conwu_core::{
    code::{DirectCode, stream_mode},
    crypto as c,
    identity::{self, Member, Profile},
    link::{self, Link},
    pairing::{self, Host, KeyExchange, Reply, Request},
    unix_seconds,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

mod candidates;
use candidates::CandidateAttempts;

pub enum Event {
    DepartureDelivered {
        id: String,
    },
    Joined {
        id: String,
        profile: Profile,
        settings: Settings,
        approved: Value,
        peer_name: String,
        bootstrap: SocketAddr,
        reply: oneshot::Sender<Result<()>>,
    },
    GuestState {
        id: String,
        state: Value,
    },
    Departure {
        network: String,
        notice: Value,
        reply: oneshot::Sender<Result<Value>>,
    },
    Discovery {
        id: String,
        sequence: i64,
        reply: oneshot::Sender<Result<()>>,
    },
    Snapshot {
        id: String,
        snapshot: conwu_core::metadata::Snapshot,
    },
    Log {
        level: String,
        text: String,
    },
}
#[derive(Default, Clone)]
pub struct Metrics {
    pub managed: Value,
    pub stream_flows: Value,
    pub connected: bool,
    pub since: i64,
    pub rtt: Option<f64>,
    pub sent: u64,
    pub received: u64,
    pub dropped: u64,
    pub endpoint: String,
    pub phase: String,
    pub error: String,
    pub adapter: String,
    pub route_warnings: Vec<Value>,
    pub peer_paused: bool,
    pub pkarr: Value,
    pub local_endpoints: Vec<String>,
}
struct Route {
    nomination: Option<conwu_core::path::Nomination>,
    path: uuid::Uuid,
    flow: Option<Arc<crate::flow::Group>>,
    tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    endpoint: SocketAddr,
    challenge: i64,
    rtt_recorded: bool,
    verified: bool,
    seen: Instant,
    challenged: Instant,
}
struct Peer {
    link: Link,
    routes: BTreeMap<String, Route>,
    chosen: Option<String>,
    assembly: Option<conwu_core::metadata::Assembly>,
}
pub struct Running {
    dialing: Arc<tokio::sync::Mutex<()>>,
    network_finished: CancellationToken,
    discovery_finished: CancellationToken,
    managed_finished: CancellationToken,
    refresh: tokio::sync::Notify,
    pub(crate) boot: uuid::Uuid,
    peer_state: Mutex<Option<conwu_core::rendezvous::State>>,
    observed_source: RwLock<Option<SocketAddr>>,
    pub config: RwLock<Arc<Network>>,
    pub metrics: RwLock<Metrics>,
    pub memory: Option<Arc<Memory>>,
    adapter: Arc<dyn Adapter>,
    peer: Mutex<Option<Peer>>,
    pub cancel: CancellationToken,
}
#[derive(PartialEq, Eq)]
struct ListenerPolicy {
    stun: Vec<String>,
    autonomous: bool,
    tls_peer: Option<String>,
}
struct Listener {
    cancel: CancellationToken,
    finished: CancellationToken,
    policy: ListenerPolicy,
}
pub struct Engine {
    pub store: Arc<crate::store::Store>,
    pub fake_mappings: RwLock<HashMap<u16, Arc<crate::native_map::Mapping>>>,
    pub(crate) stun_cursor: Mutex<HashMap<(String, u16), usize>>,
    assists: Mutex<HashMap<String, CancellationToken>>,
    pub flow_groups: Mutex<HashMap<String, Arc<crate::flow::Group>>>,
    pub device_name: RwLock<String>,
    pub node_private: RwLock<String>,
    pub raw_controls: Mutex<HashMap<(String, u16), crate::raw::Control>>,
    pub raw_tables: Mutex<HashMap<(String, u16), String>>,
    pub raw_observers: Mutex<std::collections::HashSet<String>>,
    pub networks: RwLock<HashMap<String, Arc<Running>>>,
    pub rooms: Mutex<HashMap<String, (Host, String)>>,
    listeners: Mutex<HashMap<(String, u16), Listener>>,
    listener_transaction: tokio::sync::Mutex<()>,
    pub guest_states: RwLock<HashMap<String, Value>>,
    guests: Mutex<HashMap<String, CancellationToken>>,
    pub identity: TlsIdentity,
    pub events: mpsc::Sender<Event>,
    pub tracker: TaskTracker,
    pub cancel: CancellationToken,
    pub components: PathBuf,
    pub memory: bool,
    pub pkarr: Arc<pkarr::Client>,
    semaphore: Arc<Semaphore>,
}
impl Engine {
    pub fn new(
        store: Arc<crate::store::Store>,
        identity: TlsIdentity,
        events: mpsc::Sender<Event>,
        components: PathBuf,
        memory: bool,
        pkarr: Arc<pkarr::Client>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            fake_mappings: RwLock::new(HashMap::new()),
            stun_cursor: Mutex::new(HashMap::new()),
            assists: Mutex::new(HashMap::new()),
            flow_groups: Mutex::new(HashMap::new()),
            device_name: RwLock::new("ConWU".into()),
            node_private: RwLock::new(String::new()),
            raw_controls: Mutex::new(HashMap::new()),
            raw_tables: Mutex::new(HashMap::new()),
            raw_observers: Mutex::new(std::collections::HashSet::new()),
            networks: RwLock::new(HashMap::new()),
            rooms: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            listener_transaction: tokio::sync::Mutex::new(()),
            guest_states: RwLock::new(HashMap::new()),
            guests: Mutex::new(HashMap::new()),
            identity,
            events,
            tracker: TaskTracker::new(),
            cancel: CancellationToken::new(),
            components,
            memory,
            pkarr,
            semaphore: Arc::new(Semaphore::new(32)),
        })
    }
    pub fn current(&self, id: &str) -> Option<Arc<Running>> {
        self.networks.read().unwrap().get(id).cloned()
    }
    pub async fn notify_directory(&self, id: &str, directory: identity::Directory) -> Result<()> {
        let Some(running) = self.current(id) else {
            return Ok(());
        };
        let profile = running
            .config
            .read()
            .unwrap()
            .profile
            .clone()
            .context("网络身份缺失")?;
        conwu_core::metadata::successor(
            &directory,
            profile.directory.as_ref().context("成员目录缺失")?,
        )?;
        let snapshot = conwu_core::metadata::Snapshot {
            directory,
            nodes: vec![],
            traversal: vec![],
            capabilities: Default::default(),
        };
        for _ in 0..3 {
            let frames = conwu_core::metadata::frames(&snapshot)?;
            {
                let mut guard = running.peer.lock().unwrap();
                let Some(peer) = guard.as_mut() else {
                    return Ok(());
                };
                let targets = peer
                    .routes
                    .values()
                    .filter(|r| r.verified)
                    .map(|r| r.tx.clone())
                    .collect::<Vec<_>>();
                for payload in frames {
                    if let Some(frame) = peer.link.synchronize(&payload)? {
                        let frame = link::wrap(&profile.pair.network, &frame)?;
                        for tx in &targets {
                            let _ = tx.try_send(frame.clone());
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        Ok(())
    }
    pub fn find_wire(&self, wire: &str) -> Option<Arc<Running>> {
        self.networks
            .read()
            .unwrap()
            .values()
            .find(|r| {
                r.config
                    .read()
                    .unwrap()
                    .profile
                    .as_ref()
                    .is_some_and(|p| p.pair.network == wire)
            })
            .cloned()
    }
    pub async fn install(self: &Arc<Self>, network: Network) -> Result<()> {
        if self
            .current(&network.id)
            .is_some_and(|r| r.cancel.is_cancelled())
        {
            self.remove(&network.id).await?;
        }
        let profile = network.profile.as_ref().context("网络身份尚未批准")?;
        profile.validate()?;
        ensure!(
            profile
                .directory
                .as_ref()
                .is_some_and(|d| d.members.len() <= 2),
            "Rust 实验版仅接收主从双机网络；旧多成员网络需要单独迁移"
        );
        network.settings.validate()?;
        let mut observers = network.settings.tcp_stun.clone();
        if network.settings.discovery_mode == "coordinator" && !network.settings.service.is_empty()
        {
            if let Ok(url) = url::Url::parse(&network.settings.service) {
                if url.path() == "/" {
                    if let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default())
                    {
                        observers.insert(0, format!("{host}:{port}"));
                    }
                }
            }
        }
        if let Some(prior) = self.current(&network.id) {
            let old = prior.config.read().unwrap().clone();
            let previous = old.profile.as_ref().context("旧身份缺失")?;
            ensure!(
                previous.pair.network == profile.pair.network && previous.member == profile.member,
                "运行中的本机身份不可替换"
            );
            self.listen(
                network.settings.mode()?,
                network.settings.listen_port,
                &observers,
                !network.settings.existing_only(),
                if !network.created_here && profile.pair.mode == "https" {
                    profile.pair.transport_key_pin.as_deref()
                } else {
                    None
                },
            )
            .await?;
            if remote_member(previous) != remote_member(profile) {
                let next_peer = remote_member(profile)
                    .map(|m| {
                        Ok::<_, anyhow::Error>(Peer {
                            link: Link::new(profile.member.slot, m.slot, *profile.shared_key(&m)?)?,
                            routes: BTreeMap::new(),
                            chosen: None,
                            assembly: None,
                        })
                    })
                    .transpose()?;
                let mut peer = prior.peer.lock().unwrap();
                if let Some(p) = peer.as_ref() {
                    for route in p.routes.values() {
                        route.cancel.cancel();
                    }
                }
                *peer = next_peer;
            } else if old.settings.listen_port != network.settings.listen_port
                || old.settings.source_port != network.settings.source_port
                || old.settings.stream_flow_lanes != network.settings.stream_flow_lanes
            {
                // Metadata revisions and subscription updates must not reset the
                // link's epoch/replay state or interrupt healthy data routes.
                if let Some(peer) = prior.peer.lock().unwrap().as_mut() {
                    for route in peer.routes.values() {
                        route.cancel.cancel();
                    }
                    peer.routes.clear();
                    peer.chosen = None;
                }
            }
            let old_key = (old.settings.mode()?.to_owned(), old.settings.listen_port);
            let new_key = (
                network.settings.mode()?.to_owned(),
                network.settings.listen_port,
            );
            *prior.config.write().unwrap() = Arc::new(network);
            prior.refresh.notify_one();
            if old_key != new_key {
                self.release_unused_listener(&old_key).await?;
            }
            return Ok(());
        }
        let memory = self.memory.then(Memory::new);
        let adapter: Arc<dyn Adapter> = if let Some(m) = &memory {
            m.clone()
        } else {
            let id = profile.pair.network.clone();
            let ip = profile.local_ip()?;
            let path = self.components.clone();
            let cancel = self.cancel.clone();
            let legacy = network.legacy_adapter.clone();
            tokio::task::spawn_blocking(move || {
                adapter::open(&id, ip, &path, &cancel, legacy.as_ref())
            })
            .await??
        };
        let peer = profile
            .directory
            .as_ref()
            .and_then(|d| d.members.iter().find(|m| m.slot != profile.member.slot))
            .map(|m| {
                Ok::<_, anyhow::Error>(Peer {
                    link: Link::new(profile.member.slot, m.slot, *profile.shared_key(m)?)?,
                    routes: BTreeMap::new(),
                    chosen: None,
                    assembly: None,
                })
            })
            .transpose()?;
        let metrics = Metrics {
            adapter: adapter.provider().into(),
            route_warnings: adapter.warnings(),
            phase: if peer.is_none() {
                "等待另一台设备加入"
            } else {
                "等待对方上线"
            }
            .into(),
            ..Default::default()
        };
        let id = network.id.clone();
        let mode = network.settings.mode()?.to_string();
        let port = network.settings.listen_port;
        self.listen(
            &mode,
            port,
            &observers,
            !network.settings.existing_only(),
            if !network.created_here && profile.pair.mode == "https" {
                profile.pair.transport_key_pin.as_deref()
            } else {
                None
            },
        )
        .await?;
        let running = Arc::new(Running {
            dialing: Arc::new(tokio::sync::Mutex::new(())),
            network_finished: CancellationToken::new(),
            discovery_finished: CancellationToken::new(),
            managed_finished: CancellationToken::new(),
            refresh: tokio::sync::Notify::new(),
            boot: uuid::Uuid::new_v4(),
            peer_state: Mutex::new(None),
            observed_source: RwLock::new(None),
            config: RwLock::new(Arc::new(network)),
            metrics: RwLock::new(metrics),
            memory,
            adapter,
            peer: Mutex::new(peer),
            cancel: self.cancel.child_token(),
        });
        self.networks.write().unwrap().insert(id, running.clone());
        let engine = self.clone();
        let run = running.clone();
        self.tracker.spawn(async move {
            let _finished = run.network_finished.clone().drop_guard();
            engine.network_loop(run).await;
        });
        let engine = self.clone();
        let run = running.clone();
        self.tracker.spawn(async move {
            let _finished = run.discovery_finished.clone().drop_guard();
            engine.discovery_loop(run).await;
        });
        let engine = self.clone();
        self.tracker.spawn(async move {
            let _finished = running.managed_finished.clone().drop_guard();
            crate::managed::run(engine, running).await;
        });
        Ok(())
    }
    pub async fn remove(&self, id: &str) -> Result<()> {
        self.cancel_guest(id);
        if let Some(stop) = self.assists.lock().unwrap().remove(id) {
            stop.cancel();
        }
        // Keep the cancelled generation registered until its tasks have released
        // their sockets. A timed out stop must not allow a new generation to
        // bind the same port while the old owner is still alive.
        let removed = self.current(id);
        if let Some(r) = removed {
            r.cancel.cancel();
            if let Some(peer) = r.peer.lock().unwrap().as_mut() {
                for route in peer.routes.values() {
                    route.cancel.cancel();
                }
            }
            tokio::time::timeout(Duration::from_secs(45), async {
                tokio::join!(
                    r.network_finished.cancelled(),
                    r.discovery_finished.cancelled(),
                    r.managed_finished.cancelled()
                );
            })
            .await
            .context("旧网络资源尚未释放，请稍后重试")?;
            let key = {
                let n = r.config.read().unwrap();
                (n.settings.mode()?.to_owned(), n.settings.listen_port)
            };
            {
                let mut networks = self.networks.write().unwrap();
                if networks
                    .get(id)
                    .is_some_and(|current| Arc::ptr_eq(current, &r))
                {
                    networks.remove(id);
                }
            }
            self.release_unused_listener(&key).await?;
        }
        self.rooms.lock().unwrap().remove(id);
        self.cancel_guest(id);
        Ok(())
    }
    async fn release_unused_listener(&self, key: &(String, u16)) -> Result<()> {
        let _transaction = self.listener_transaction.lock().await;
        let used = self.networks.read().unwrap().values().any(|r| {
            let n = r.config.read().unwrap();
            n.settings.mode().ok() == Some(key.0.as_str()) && n.settings.listen_port == key.1
        });
        if !used {
            let old = self.listeners.lock().unwrap().remove(key);
            if let Some(old) = old {
                Self::stop_listener(old).await?;
            }
        }
        Ok(())
    }
    async fn stop_listener(listener: Listener) -> Result<()> {
        listener.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(25), listener.finished.cancelled())
            .await
            .context("旧监听未能及时释放，请查看承载组件状态")?;
        Ok(())
    }
    pub fn cancel_guest(&self, id: &str) {
        let mut guests = self.guests.lock().unwrap();
        if let Some(c) = guests.remove(id) {
            c.cancel();
        }
        self.guest_states.write().unwrap().remove(id);
    }
    pub fn refresh_discovery(&self, id: &str) -> Result<()> {
        self.current(id)
            .context("网络尚未运行")?
            .refresh
            .notify_one();
        Ok(())
    }
    async fn listen(
        self: &Arc<Self>,
        mode: &str,
        port: u16,
        stun: &[String],
        autonomous: bool,
        tls_peer: Option<&str>,
    ) -> Result<()> {
        let _transaction = self.listener_transaction.lock().await;
        let key = (mode.into(), port);
        let policy = ListenerPolicy {
            stun: if stream_mode(mode) || !autonomous {
                vec![]
            } else {
                stun.to_vec()
            },
            autonomous: !stream_mode(mode) && autonomous,
            tls_peer: if mode == "https" {
                tls_peer.map(str::to_owned)
            } else {
                None
            },
        };
        let unchanged = self
            .listeners
            .lock()
            .unwrap()
            .get(&key)
            .is_some_and(|l| l.policy == policy && !l.finished.is_cancelled());
        if unchanged {
            return Ok(());
        }
        let old = self.listeners.lock().unwrap().remove(&key);
        if let Some(old) = old {
            Self::stop_listener(old).await?;
        }
        let finished = CancellationToken::new();
        if !stream_mode(mode) {
            let stop = self.cancel.child_token();
            crate::raw::listen(
                self,
                mode,
                port,
                stun,
                autonomous,
                stop.clone(),
                finished.clone(),
            )
            .await?;
            self.listeners.lock().unwrap().insert(
                key,
                Listener {
                    cancel: stop,
                    finished,
                    policy,
                },
            );
            return Ok(());
        }
        let listener = transport::listener(port, false).await?;
        let ipv6 = transport::listener(port, true).await.ok();
        let cancel = self.cancel.child_token();
        self.listeners.lock().unwrap().insert(
            key,
            Listener {
                cancel: cancel.clone(),
                finished: finished.clone(),
                policy,
            },
        );
        let mut tasks = Vec::new();
        for listener in std::iter::once(listener).chain(ipv6) {
            let engine = self.clone();
            let stop = cancel.clone();
            let mode = mode.to_string();
            let tls_peer = tls_peer.map(str::to_owned);
            tasks.push(async move {
                loop {
                    let accept = tokio::select! {_=stop.cancelled()=>break,r=listener.accept()=>r};
                    let Ok((socket, endpoint)) = accept else {
                        break;
                    };
                    let Ok(permit) = engine.semaphore.clone().try_acquire_owned() else {
                        drop(socket);
                        continue;
                    };
                    let server = engine.clone();
                    let mode = mode.clone();
                    let token = stop.child_token();
                    let tls_peer = tls_peer.clone();
                    engine.tracker.spawn(async move {
                        let _permit = permit;
                        let handshake = async {
                            if let Some(pin) = tls_peer {
                                transport::client_socket(&mode, socket, &pin, false, &token).await
                            } else {
                                transport::accept(&mode, socket, &server.identity, &token).await
                            }
                        };
                        if let Ok(pipe) =
                            tokio::select! {_=token.cancelled()=>return,r=handshake=>r}
                        {
                            server.serve(pipe, mode, endpoint, None).await;
                        }
                    });
                }
            });
        }
        self.tracker.spawn(async move {
            let _finished = finished.drop_guard();
            futures_util::future::join_all(tasks).await;
        });
        Ok(())
    }
    async fn try_dial(
        self: &Arc<Self>,
        id: &str,
        endpoint: SocketAddr,
        running: &Arc<Running>,
    ) -> bool {
        #[cfg(feature = "lab-api")]
        if std::env::var_os("CONWU_LAB_ONLY_MEMBER_ASSIST").is_some() {
            return false;
        }
        if running.cancel.is_cancelled() || running.metrics.read().unwrap().connected {
            return false;
        }
        let Ok(_dialing) = running.dialing.try_lock() else {
            return false;
        };
        let _ = self.dial_reserved(id, endpoint, running).await;
        true
    }
    async fn dial_reserved(self: &Arc<Self>, id: &str, endpoint: SocketAddr, running: &Arc<Running>) -> Result<()> {
        #[cfg(feature = "lab-api")]
        ensure!(
            std::env::var_os("CONWU_LAB_FORCE_MANAGED").is_none(),
            "实验强制验证受管路径"
        );
        ensure!(!running.cancel.is_cancelled(), "网络已取消");
        if running.metrics.read().unwrap().connected {
            return Ok(());
        }
        if running.peer.lock().unwrap().as_ref().is_some_and(|peer| {
            let link_online = peer.link.connected();
            peer.routes.values().any(|route| {
                route.endpoint == endpoint
                    && !route.cancel.is_cancelled()
                    && route.seen.elapsed() < Duration::from_secs(15)
                    && (!route.verified || link_online)
            })
        }) {
            return Ok(());
        }
        let config = running.config.read().unwrap().clone();
        let profile = config.profile.as_ref().unwrap();
        let mode = config.settings.mode()?;
        if !config.settings.existing_only() && !stream_mode(mode) {
            if mode == "faketcp" {
                let mapping = self
                    .fake_mappings
                    .read()
                    .unwrap()
                    .get(&config.settings.listen_port)
                    .cloned();
                if let Some(mapping) = mapping {
                    let greeting = {
                        let mut peer = running.peer.lock().unwrap();
                        let peer = peer.as_mut().context("尚无已批准成员")?;
                        link::wrap(&profile.pair.network, &peer.link.hello()?)?
                    };
                    mapping
                        .punch(endpoint, !config.created_here, &greeting, false)
                        .await?;
                    return Ok(());
                }
                // A normal client can still reach the peer's explicit/UPnP
                // receiver when STUN is temporarily unavailable locally.
                if config.created_here {
                    return Ok(());
                }
            }
            let control = self
                .raw_controls
                .lock()
                .unwrap()
                .get(&(mode.into(), config.settings.listen_port))
                .cloned();
            if let Some(control) = control {
                let greeting = {
                    let mut peer = running.peer.lock().unwrap();
                    let peer = peer.as_mut().context("尚无已批准成员")?;
                    link::wrap(&profile.pair.network, &peer.link.hello()?)?
                };
                control.punch(endpoint, &greeting).await?;
                return Ok(());
            }
        }
        let pipe = if stream_mode(mode) {
            let port = if config.settings.existing_only() {
                0
            } else {
                config.settings.listen_port
            };
            let local = running.observed_source.read().unwrap()
                .filter(|source| source.port() == port && source.is_ipv4() == endpoint.is_ipv4());
            let local = match local {
                Some(local) => local,
                None => SocketAddr::new(discovery::local_route(endpoint)?, port),
            };
            tokio::select! {_=running.cancel.cancelled()=>anyhow::bail!("network stopped"),r=transport::connect_role_from(mode,endpoint,profile.pair.transport_key_pin.as_deref().unwrap_or(""),local,!config.created_here,&self.identity,&running.cancel)=>r?}
        } else {
            crate::raw::connect(
                self,
                mode,
                endpoint,
                config.settings.source_port,
                &running.cancel,
            )
            .await?
        };
        let server = self.clone();
        let mode = mode.to_string();
        let id = id.to_string();
        self.tracker.spawn(async move {
            server.serve(pipe, mode, endpoint, Some(id)).await;
        });
        Ok(())
    }
    pub async fn serve(
        self: Arc<Self>,
        pipe: Pipe,
        mode: String,
        endpoint: SocketAddr,
        outbound: Option<String>,
    ) {
        self.serve_inner(pipe, mode, endpoint, outbound, None).await;
    }
    pub(crate) async fn serve_managed(
        self: Arc<Self>,
        pipe: Pipe,
        endpoint: SocketAddr,
        id: String,
        context: conwu_core::path::Context,
        revision: i64,
        remaining: Duration,
    ) {
        self.serve_inner(
            pipe,
            "faketcp".into(),
            endpoint,
            Some(id),
            Some((context, revision, remaining)),
        )
        .await;
    }
    async fn serve_inner(
        self: Arc<Self>,
        mut pipe: Pipe,
        mode: String,
        endpoint: SocketAddr,
        outbound: Option<String>,
        nomination: Option<(conwu_core::path::Context, i64, Duration)>,
    ) {
        let route = conwu_core::id();
        let mut accepted = std::collections::HashSet::<String>::new();
        let mut last_valid = Instant::now();
        let mut last_route_check = Instant::now();
        let mut flow: Option<Arc<crate::flow::Group>> = None;
        if let Some(id) = outbound {
            if let Some(running) = self.current(&id) {
                let n = running.config.read().unwrap().clone();
                if n.settings.stream_flow_lanes && stream_mode(&mode) {
                    if let Some(profile) = n.profile.as_ref() {
                        let mut groups = self.flow_groups.lock().unwrap();
                        if groups.len() < 16 {
                            if let Ok(group) =
                                crate::flow::Group::client(&self, profile, &route, &pipe, endpoint)
                            {
                                groups.insert(group.key.clone(), group.clone());
                                flow = Some(group);
                            }
                        }
                    }
                }
                if self.attach(
                    &running,
                    &route,
                    &pipe,
                    endpoint,
                    flow.clone(),
                    nomination.clone(),
                ) {
                    accepted.insert(id);
                }
            }
        }
        loop {
            if last_route_check.elapsed() >= Duration::from_secs(1) {
                last_route_check = Instant::now();
                if last_valid.elapsed() >= Duration::from_secs(18) {
                    break;
                }
                if !accepted.is_empty()
                    && accepted.iter().all(|id| {
                        self.current(id).is_none_or(|r| {
                            r.peer.lock().unwrap().as_ref().is_none_or(|p| {
                                p.routes.get(&route).is_none_or(|p| p.cancel.is_cancelled())
                            })
                        })
                    })
                {
                    break;
                }
            }
            if flow.as_ref().is_some_and(|g| g.cancel.is_cancelled()) {
                break;
            }
            let frame = tokio::select! {_=self.cancel.cancelled()=>break,_=pipe.cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(3))=>continue,p=pipe.rx.recv()=>match p{Some(p)=>p,None=>break}};
            if conwu_core::stream::is_control(&frame) && stream_mode(&mode) {
                if frame[5] == 5 {
                    let key = hex::encode(&frame[28..44]);
                    let group = self.flow_groups.lock().unwrap().get(&key).cloned();
                    if let Some(group) = group {
                        if group.mode() == mode {
                            let _ = group.accept_aux(&self, pipe, &frame).await;
                            return;
                        }
                    }
                    break;
                }
                if flow.is_none() && frame[5] == 1 {
                    let wire = hex::encode(&frame[8..24]);
                    if let Some(running) = self.find_wire(&wire) {
                        let n = running.config.read().unwrap().clone();
                        if n.settings.stream_flow_lanes && n.settings.mode().ok() == Some(&mode) {
                            let mut groups = self.flow_groups.lock().unwrap();
                            let key = hex::encode(&frame[28..44]);
                            if groups.len() < 16 && !groups.contains_key(&key) {
                                if let Ok(group) = crate::flow::Group::server(
                                    &self,
                                    n.profile.as_ref().unwrap(),
                                    &route,
                                    &pipe,
                                    endpoint,
                                    &frame,
                                ) {
                                    groups.insert(group.key.clone(), group.clone());
                                    flow = Some(group);
                                }
                            }
                        }
                    }
                } else if let Some(group) = &flow {
                    group.handle(&frame);
                }
                continue;
            }
            if frame.starts_with(b"SLP1") {
                if self.pair_request(&frame, &pipe.tx).await {
                    last_valid = Instant::now();
                }
                continue;
            }
            let Some((wire, body)) = link::unwrap(&frame) else {
                continue;
            };
            if nomination
                .as_ref()
                .is_some_and(|(context, _, _)| context.network_id != wire)
            {
                continue;
            }
            if flow.as_ref().is_some_and(|g| g.network != wire) {
                continue;
            }
            let Some(running) = self.find_wire(&wire) else {
                continue;
            };
            let id = {
                let n = running.config.read().unwrap();
                if n.settings.mode().ok() != Some(&mode) {
                    continue;
                }
                n.id.clone()
            };
            if !accepted.contains(&id) {
                if !self.attach(&running, &route, &pipe, endpoint, flow.clone(), None) {
                    continue;
                }
                accepted.insert(id);
            }
            if running.receive(body, &route, &self.events) {
                last_valid = Instant::now();
            }
        }
        if let Some(flow) = flow {
            flow.close();
        }
        for id in accepted {
            if let Some(running) = self.current(&id) {
                if let Some(peer) = running.peer.lock().unwrap().as_mut() {
                    peer.routes.remove(&route);
                    if peer.chosen.as_ref() == Some(&route) {
                        peer.chosen = None;
                    }
                }
            }
        }
    }
    fn attach(
        &self,
        running: &Running,
        id: &str,
        pipe: &Pipe,
        endpoint: SocketAddr,
        flow: Option<Arc<crate::flow::Group>>,
        nomination: Option<(conwu_core::path::Context, i64, Duration)>,
    ) -> bool {
        let n = running.config.read().unwrap();
        let mut guard = running.peer.lock().unwrap();
        let Some(peer) = guard.as_mut() else {
            return false;
        };
        if peer.routes.len() >= 8 {
            return false;
        }
        let path = uuid::Uuid::new_v4();
        let nomination = match nomination {
            Some((context, revision, remaining)) => {
                match conwu_core::path::Nomination::new(context, path, revision, remaining, true) {
                    Ok(n) => Some(n),
                    Err(_) => return false,
                }
            }
            None => None,
        };
        let route = Route {
            path,
            nomination,
            tx: flow
                .as_ref()
                .map(|f| f.tx.clone())
                .unwrap_or_else(|| pipe.tx.clone()),
            flow,
            cancel: pipe.cancel.child_token(),
            endpoint,
            challenge: i64::from_be_bytes(c::random()),
            rtt_recorded: false,
            verified: false,
            seen: Instant::now(),
            challenged: Instant::now() - Duration::from_secs(6),
        };
        if let Ok(hello) = peer.link.hello() {
            let _ = route
                .tx
                .try_send(link::wrap(&n.profile.as_ref().unwrap().pair.network, &hello).unwrap());
        }
        peer.routes.insert(id.into(), route);
        true
    }
    async fn pair_request(&self, frame: &[u8], tx: &mpsc::Sender<Vec<u8>>) -> bool {
        let Ok(request) = pairing::decode::<Request>(frame) else {
            return false;
        };
        if !conwu_core::valid_id(&request.id) {
            return false;
        }
        if request.method == "member-leave" {
            if let Some(notice) = request.departure {
                let network = notice["n"].as_str().unwrap_or("").to_string();
                let (send, recv) = oneshot::channel();
                if self
                    .events
                    .try_send(Event::Departure {
                        network,
                        notice,
                        reply: send,
                    })
                    .is_ok()
                {
                    if let Ok(Ok(Ok(receipt))) =
                        tokio::time::timeout(Duration::from_secs(2), recv).await
                    {
                        let response = json!({"Id":request.id,"Departure":receipt});
                        if let Ok(bytes) = pairing::encode(&response) {
                            let _ = tx.try_send(bytes);
                        }
                        return true;
                    }
                }
            }
            return false;
        }
        let mut rooms = self.rooms.lock().unwrap();
        let mut admission_target = None;
        if request.method == "join"
            && request.entry_admission
            && request.code == pairing::ENTRY_LOCATOR
        {
            let mut eligible =
                self.networks
                    .read()
                    .unwrap()
                    .iter()
                    .filter_map(|(id, running)| {
                        let n = running.config.read().unwrap();
                        let p = n.profile.as_ref()?;
                        if !n.enabled
                            || n.paused
                            || p.owner_private.is_empty()
                            || p.directory.as_ref()?.closed
                            || !request.target_network.is_empty()
                                && request.target_network != p.pair.network
                        {
                            return None;
                        }
                        let known =
                            request.identity.as_ref().is_some_and(|i| {
                                i.valid(&request.commitment)
                                    && identity::network_id(&i.public_key).ok().is_some_and(
                                        |device| {
                                            p.directory.as_ref().unwrap().members.iter().any(|m| {
                                                m.slot != p.member.slot && m.device == device
                                            })
                                        },
                                    )
                            });
                        let former = request
                            .rejoin
                            .as_ref()
                            .is_some_and(|p2| p2["Network"] == p.pair.network);
                        if p.directory.as_ref().unwrap().members.len() >= 2 && !known && !former {
                            return None;
                        }
                        if rooms.get(id).is_some_and(|(h, _)| {
                            h.ticket.expires > unix_seconds()
                                && h.state.outcome.is_empty()
                                && (!h.state.approved || !h.delivered)
                                && !h.state.candidate.is_empty()
                                && (!h.entry_admission
                                    || h.state.guest_commitment != request.commitment)
                        }) {
                            return None;
                        }
                        Some((
                            if known {
                                0
                            } else if former {
                                1
                            } else {
                                2
                            },
                            id.clone(),
                        ))
                    })
                    .collect::<Vec<_>>();
            eligible.sort();
            if let Some((_, id)) = eligible.first() {
                admission_target = Some(id.clone());
                if !rooms.get(id).is_some_and(|(h, _)| {
                    h.entry_admission
                        && h.ticket.expires > unix_seconds()
                        && h.state.outcome.is_empty()
                        && !h.state.approved
                }) {
                    if let Ok(mut host) = Host::new(
                        &self.device_name.read().unwrap(),
                        Some(&self.node_private.read().unwrap()),
                    ) {
                        host.entry_admission = true;
                        rooms.insert(id.clone(), (host, String::new()));
                    }
                }
            } else {
                return false;
            }
        }
        for (network, (host, _)) in rooms.iter_mut() {
            if admission_target.as_ref().is_some_and(|id| id != network) {
                continue;
            }
            let matches = if request.method == "join" {
                request.entry_admission == host.entry_admission
                    && request.code
                        == if host.entry_admission {
                            pairing::ENTRY_LOCATOR
                        } else {
                            &host.ticket.code
                        }
            } else {
                request.room == host.ticket.room
            };
            if !matches {
                continue;
            }
            let wire = self
                .current(network)
                .and_then(|r| {
                    r.config
                        .read()
                        .unwrap()
                        .profile
                        .as_ref()
                        .map(|p| p.pair.network.clone())
                })
                .unwrap_or_default();
            if let Some(reply) = host.handle(frame, &wire) {
                let _ = tx.try_send(reply);
                return true;
            }
        }
        false
    }
    pub fn pairing(&self, id: &str) -> Value {
        if let Some(v) = self.guest_states.read().unwrap().get(id) {
            return v.clone();
        }
        if let Some((host, code)) = self.rooms.lock().unwrap().get(id) {
            let s = &host.state;
            let expired = host.ticket.expires <= unix_seconds();
            let active = !expired && !host.delivered && s.outcome.is_empty();
            let pending = active && !s.approved && !s.candidate.is_empty();
            let (phase, message) = if host.delivered && s.approved {
                ("Completed", "已批准，网络配置已交付")
            } else if s.outcome == "Rejected" {
                ("Rejected", "已拒绝申请")
            } else if s.outcome == "Cancelled" {
                ("Cancelled", "申请已取消")
            } else if expired {
                ("Expired", "配对会话已过期")
            } else if s.approved {
                ("Delivering", "已批准，正在交付网络配置")
            } else if pending {
                ("Pending", "请核对校验码后批准")
            } else {
                ("Waiting", "等待另一台设备输入直连码")
            };
            // The room remains available for configuration/ACK retries even
            // after the user has decided. A delivery is not another approval.
            return json!({"active":active,"pending":pending,"phase":phase,"approved":s.approved,"delivered":host.delivered,"outcome":s.outcome,"owner":true,"code":code,"verification":host.sas().unwrap_or_default(),"candidate":s.candidate,"peerName":s.guest_name,"expires":s.expires,"state":message,"format":"compact","method":"direct","direct":true,"proposedIp":s.requested_ip});
        }
        Value::Null
    }
    pub fn create_code(
        self: &Arc<Self>,
        id: &str,
        endpoint: SocketAddr,
        name: &str,
        node_private: &str,
    ) -> Result<String> {
        let running = self.current(id).context("请先启动该网络")?;
        let n = running.config.read().unwrap();
        let p = n.profile.as_ref().unwrap();
        ensure!(
            !p.owner_private.is_empty() && !n.paused,
            "请在主机连接网络后生成直连码"
        );
        let mut rooms = self.rooms.lock().unwrap();
        if let Some((prior, _)) = rooms.get(id) {
            ensure!(
                !prior.state.approved || prior.delivered || prior.ticket.expires <= unix_seconds(),
                "上一台设备仍在接收批准信息"
            );
        }
        let host = Host::new(name, Some(node_private))?;
        let code = DirectCode {
            endpoint,
            mode: p.pair.mode.clone(),
            room: host.ticket.code.clone(),
            punch: p.pair.mode == "mimic"
                && n.settings.discovery_mode == "pkarr"
                && !n.settings.existing_only(),
            coordinator: false,
        }
        .issue()?;
        rooms.insert(id.into(), (host, code.clone()));
        drop(rooms);
        drop(n);
        if DirectCode::import(&code)?.punch {
            self.first_contact(id, code.clone())?;
        }
        Ok(code)
    }
    fn first_contact(self: &Arc<Self>, id: &str, code: String) -> Result<()> {
        let running = self.current(id).context("网络已移除")?;
        let stop = running.cancel.child_token();
        let seed = c::hash(format!("conwu-mimic-first-contact-v1/{code}").as_bytes());
        let source = pkarr::source(&seed);
        if let Some(old) = self.assists.lock().unwrap().insert(id.into(), stop.clone()) {
            old.cancel();
        }
        let engine = self.clone();
        let id = id.to_owned();
        let gateways = running
            .config
            .read()
            .unwrap()
            .settings
            .pkarr_gateways
            .clone();
        self.tracker.spawn(async move {
            let until=unix_seconds()+300;let mut targets=std::collections::HashSet::new();
            while unix_seconds()<until&&!stop.is_cancelled() {
                if let Ok(record)=tokio::select!{_=stop.cancelled()=>break,r=engine.pkarr.resolve(&source,"mimic",&gateways)=>r} {
                    let a=record.announcement;
                    if a.state.as_deref()==Some("conwu-mimic-first-contact-v1")&&a.endpoints.len()==1&&a.expires<=unix_seconds()+100 {
                        if let Ok(peer)=crate::assistance::candidate(&a.endpoints[0]) {
                            if crate::discovery::public(peer.ip())&&(targets.contains(&peer)||targets.len()<8){targets.insert(peer);let _=engine.punch_unpaired(&id,peer).await;}
                        }
                    }
                }
                tokio::select!{_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(4))=>{}}
            }
        });
        Ok(())
    }
    pub async fn assist_code(self: &Arc<Self>, id: &str, endpoint: SocketAddr) -> Result<()> {
        let running = self.current(id).context("网络已移除")?;
        let n = running.config.read().unwrap().clone();
        let (room, commitment) = self
            .rooms
            .lock()
            .unwrap()
            .get(id)
            .map(|(h, _)| (h.ticket.code.clone(), h.key.commitment.clone()))
            .context("配对房间不存在")?;
        let client = crate::assistance::Client::open(
            &n.settings.service,
            &n.settings.certificate_pin,
            false,
        )
        .await?;
        ensure!(
            crate::discovery::public(client.endpoint.ip()),
            "辅助直连码需要公网 IPv4 协调节点"
        );
        let native_prepare = n.settings.mode()? == "faketcp";
        let state=client.room("create",&json!({"Endpoint":endpoint.to_string(),"HostRoom":room,"Commitment":commitment,"Mode":n.settings.mode()?,"Ready":!native_prepare})).await?;
        let code = DirectCode {
            endpoint: client.endpoint,
            mode: n.settings.mode()?.into(),
            room: state["Room"].as_str().unwrap().into(),
            punch: false,
            coordinator: true,
        }
        .issue()?;
        self.rooms
            .lock()
            .unwrap()
            .get_mut(id)
            .context("配对房间已取消")?
            .1 = code;
        let stop = running.cancel.child_token();
        if let Some(prior) = self.assists.lock().unwrap().insert(id.into(), stop.clone()) {
            prior.cancel();
        }
        let engine = self.clone();
        let id = id.to_owned();
        self.tracker.spawn(async move {
            let key = state["Room"].as_str().unwrap().to_owned();
            let mut prior = uuid::Uuid::nil();
            let mut retry = String::new();
            let mut ready = !native_prepare;
            let mut probe_stop = stop.child_token();
            loop {
                if state["Expires"].as_i64().unwrap_or(0) <= unix_seconds() {
                    break;
                }
                // Once the direct pairing has reached the commitment reveal,
                // further coordinator hints cannot improve that connection.
                if engine.rooms.lock().unwrap().get(&id)
                    .is_none_or(|(host, _)| !host.state.guest_public.is_empty())
                {
                    break;
                }
                let input = json!({"Token":state["Token"],"Endpoint":endpoint.to_string(),"Ready":ready,"RetryRound":retry});
                let sent = Instant::now();
                let updated = tokio::select! {_=stop.cancelled()=>break,r=client.room(&key,&input)=>r};
                let round_trip = sent.elapsed();
                if let Ok(updated) = updated {
                    let matching = ["Room", "Token", "HostRoom", "Commitment", "HostEndpoint", "Mode"]
                        .iter().all(|k| updated[*k] == state[*k]);
                    if !matching { break; }
                    if native_prepare && !ready {
                        if let Some(peer) = updated["GuestEndpoint"].as_str()
                            .and_then(|s| crate::assistance::candidate(s).ok())
                        {
                            let local = engine.current(&id).map(|r| r.config.read().unwrap().settings.listen_port);
                            let mapping = local.and_then(|p| engine.fake_mappings.read().unwrap().get(&p).cloned());
                            if let Some(mapping) = mapping {
                                ready = tokio::select! {
                                    _=stop.cancelled()=>break,
                                    result=mapping.prepare(peer,false,false)=>result.is_ok(),
                                };
                            }
                        }
                    }
                    match crate::assistance::Schedule::read(&updated, round_trip) {
                        Ok(crate::assistance::Schedule::Expired(round)) if round != prior => {
                            retry = round.to_string();
                        }
                        Ok(crate::assistance::Schedule::Ready(round, delay)) if round != prior => {
                            if let Some(peer) = updated["GuestEndpoint"].as_str()
                                .and_then(|s| crate::assistance::candidate(s).ok())
                            {
                                prior = round;
                                retry.clear();
                                probe_stop.cancel();
                                probe_stop = stop.child_token();
                                let host = engine.clone();
                                let task_id = id.clone();
                                let token = probe_stop.clone();
                                engine.tracker.spawn(async move {
                                    tokio::select! {_=token.cancelled()=>return,_=tokio::time::sleep(delay)=>{}}
                                    let _ = tokio::select! {_=token.cancelled()=>Ok(()),r=host.punch_unpaired(&task_id,peer)=>r};
                                });
                            }
                        }
                        Err(_) => break,
                        _ => {}
                    }
                }
                tokio::select! {_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(400))=>{}}
            }
            probe_stop.cancel();
            let _ = client.room(&key,&json!({"Token":state["Token"],"Close":true})).await;
        });
        Ok(())
    }
    async fn punch_unpaired(self: &Arc<Self>, id: &str, endpoint: SocketAddr) -> Result<()> {
        let running = self.current(id).context("网络已移除")?;
        let n = running.config.read().unwrap().clone();
        let mode = n.settings.mode()?;
        if stream_mode(mode) {
            let local = *running.observed_source.read().unwrap();
            let local = match local.filter(|source| source.port() == n.settings.listen_port) {
                Some(local) => local,
                None => SocketAddr::new(discovery::local_route(endpoint)?, n.settings.listen_port),
            };
            let pipe = transport::connect_role_from(
                mode,
                endpoint,
                "",
                local,
                false,
                &self.identity,
                &running.cancel,
            )
            .await?;
            let engine = self.clone();
            let mode = mode.to_owned();
            self.tracker.spawn(async move {
                engine.serve(pipe, mode, endpoint, None).await;
            });
        } else {
            if mode == "faketcp" {
                let mapping = self
                    .fake_mappings
                    .read()
                    .unwrap()
                    .get(&n.settings.listen_port)
                    .cloned()
                    .context("FakeTCP 同源接收器未就绪")?;
                mapping.punch(endpoint, false, &[], false).await?;
                return Ok(());
            }
            let control = self
                .raw_controls
                .lock()
                .unwrap()
                .get(&(mode.to_owned(), n.settings.listen_port))
                .cloned()
                .context("此原始承载尚无同步探测控制句柄")?;
            control.punch(endpoint, &[]).await?;
        }
        Ok(())
    }
    async fn network_loop(self: Arc<Self>, running: Arc<Running>) {
        let mut timer = tokio::time::interval(Duration::from_millis(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_control = Instant::now() - Duration::from_secs(10);
        let mut last_metadata = Instant::now() - Duration::from_secs(10);
        let mut metadata_revision = 0;
        loop {
            tokio::select! {_=running.cancel.cancelled()=>break,_=timer.tick()=>{}}
            let n = running.config.read().unwrap().clone();
            let Some(profile) = n.profile.as_ref() else {
                break;
            };
            let mut peer_guard = running.peer.lock().unwrap();
            let Some(peer) = peer_guard.as_mut() else {
                continue;
            };
            if peer.link.connected() {
                for route in peer.routes.values_mut() {
                    if let Some(nomination) = route.nomination.as_mut() {
                        for control in nomination.tick() {
                            if let Ok(Some(frame)) = peer.link.control(&control) {
                                let _ = route
                                    .tx
                                    .try_send(link::wrap(&profile.pair.network, &frame).unwrap());
                            }
                        }
                        if nomination.stage == conwu_core::path::Stage::Cancelled {
                            route.cancel.cancel();
                        }
                    }
                }
            }
            if last_control.elapsed() >= Duration::from_secs(1) {
                last_control = Instant::now();
                peer.routes.retain(|_, r| {
                    !r.cancel.is_cancelled() && r.seen.elapsed() < Duration::from_secs(15)
                });
                for route in peer.routes.values_mut() {
                    let message = if !peer.link.connected() {
                        peer.link.hello().ok()
                    } else {
                        if route.challenged.elapsed() > Duration::from_secs(5) {
                            route.challenge = i64::from_be_bytes(c::random());
                            route.challenged = Instant::now();
                            route.rtt_recorded = false;
                        }
                        peer.link.probe(route.challenge).ok().flatten()
                    };
                    if let Some(m) = message {
                        let _ = route
                            .tx
                            .try_send(link::wrap(&profile.pair.network, &m).unwrap());
                    }
                }
                if peer
                    .chosen
                    .as_ref()
                    .is_none_or(|id| peer.routes.get(id).is_none_or(|r| !r.verified))
                {
                    peer.chosen = peer
                        .routes
                        .iter()
                        .find(|(_, r)| r.verified)
                        .map(|(id, _)| id.clone());
                }
                let connected = peer.chosen.is_some() && peer.link.connected();
                let mut metrics = running.metrics.write().unwrap();
                if metrics.connected != connected {
                    if !connected {
                        // A healthy channel may use a 60-second discovery
                        // interval. Loss must wake that sleeper immediately
                        // so both NATs can take part in the next round.
                        running.refresh.notify_one();
                    }
                    let _ = self.events.try_send(Event::Log {
                        level: "INFO".into(),
                        text: format!(
                            "网络 {}：{}",
                            n.name,
                            if connected {
                                "已建立直连"
                            } else {
                                "直连已中断，正在恢复"
                            }
                        ),
                    });
                }
                if connected && !metrics.connected {
                    metrics.since = unix_seconds();
                }
                metrics.connected = connected;
                metrics.phase = if n.paused {
                    "已断开连接，保持入口与控制信息更新"
                } else if connected {
                    "已直连"
                } else {
                    "等待对方上线"
                }
                .into();
                if let Some(id) = &peer.chosen {
                    let endpoint = peer.routes[id].endpoint;
                    metrics.endpoint = if endpoint.ip().is_unspecified() {
                        String::new()
                    } else {
                        endpoint.to_string()
                    };
                    metrics.stream_flows=peer.routes[id].flow.as_ref().map(|f|f.status()).unwrap_or_else(||json!({"negotiated":false,"connections":1,"splitActive":false,"rejectedPackets":0}));
                }
                if connected && last_metadata.elapsed() > Duration::from_secs(3) {
                    last_metadata = Instant::now();
                    metadata_revision = (unix_seconds() * 1000).max(metadata_revision + 1);
                    let own = metrics.local_endpoints.clone();
                    let name = self.device_name.read().unwrap().clone();
                    let source = c::unb64(&n.pkarr_seed)
                        .ok()
                        .and_then(|s| s.as_slice().try_into().ok())
                        .map(|s| pkarr::source(&s));
                    let announcement = conwu_core::metadata::Announcement {
                        slot: profile.member.slot,
                        device: profile.member.device.clone(),
                        revision: metadata_revision,
                        expires: unix_seconds() + 120,
                        endpoint: own
                            .iter()
                            .find(|s| s.parse::<SocketAddr>().is_ok_and(|e| e.is_ipv4()))
                            .cloned()
                            .unwrap_or_default(),
                        name,
                        traversal: crate::managed::capabilities(&running)
                            .and_then(|c| serde_json::to_value(c).ok()),
                        pkarr_source: source,
                        existing_endpoints: Some(own),
                        existing_entry_only: n.settings.existing_only(),
                        connection_paused: n.paused,
                    };
                    if let Ok(envelope) =
                        conwu_core::metadata::Envelope::seal(profile, &announcement)
                    {
                        let snapshot = conwu_core::metadata::Snapshot {
                            capabilities: Default::default(),
                            traversal: vec![],
                            directory: profile.directory.clone().unwrap(),
                            nodes: vec![envelope],
                        };
                        if let Ok(frames) = conwu_core::metadata::frames(&snapshot) {
                            for frame in frames {
                                if let Ok(Some(m)) = peer.link.synchronize(&frame) {
                                    if let Some(route) =
                                        peer.chosen.as_ref().and_then(|id| peer.routes.get(id))
                                    {
                                        let _ = route.tx.try_send(
                                            link::wrap(&profile.pair.network, &m).unwrap(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            let mut addresses = None;
            let mut sent = 0;
            let mut dropped = 0;
            let mut adapter_error = None;
            for _ in 0..64 {
                let packet = match running.adapter.read() {
                    Ok(Some(p)) => p,
                    Ok(None) => break,
                    Err(e) => {
                        adapter_error = Some(e.to_string());
                        break;
                    }
                };
                if n.paused || !n.enabled || !link::valid_packet(&packet) {
                    dropped += 1;
                    continue;
                }
                let (local, remote) = *addresses.get_or_insert_with(|| {
                    let local = profile.local_ip().unwrap().octets();
                    let remote = remote_member(profile)
                        .map(|member| member_ip(profile, &member).unwrap().octets());
                    (local, remote)
                });
                if packet[12..16] != local {
                    dropped += 1;
                    continue;
                }
                let Some(remote) = remote else {
                    continue;
                };
                if packet[16..20] != remote {
                    continue;
                }
                let Some(route) = peer.chosen.as_ref().and_then(|id| peer.routes.get(id)) else {
                    dropped += 1;
                    continue;
                };
                let lane = if route.flow.as_ref().is_some_and(|f| f.negotiated()) {
                    conwu_core::stream::lane(&packet)
                } else {
                    0
                };
                if let Ok(Some(bytes)) = peer.link.data(&packet, lane) {
                    if route
                        .tx
                        .try_send(link::wrap(&profile.pair.network, &bytes).unwrap())
                        .is_ok()
                    {
                        crate::uu::observe(&n.id, &packet, true);
                        sent += packet.len() as u64;
                    } else {
                        dropped += 1;
                    }
                }
            }
            if sent != 0 || dropped != 0 || adapter_error.is_some() {
                let mut metrics = running.metrics.write().unwrap();
                metrics.sent += sent;
                metrics.dropped += dropped;
                if let Some(error) = adapter_error {
                    metrics.error = error;
                    drop(metrics);
                    running.cancel.cancel();
                    break;
                }
            }
        }
    }
    async fn discovery_loop(self: Arc<Self>, running: Arc<Running>) {
        let mut last_publish = 0i64;
        let mut last_sequence = 0i64;
        let mut mapping: Option<discovery::TcpObservation> = None;
        let mut gateway: Option<crate::gateway::Lease> = None;
        let mut next_gateway = 0;
        let mut last_own = Vec::new();
        let mut last_ack = uuid::Uuid::nil();
        let mut last_assist_round = None;
        let mut candidate_attempts = CandidateAttempts::default();
        let mut last_connected_since = 0;
        let mut mimic_bootstrap_wait = None;
        loop {
            let n = running.config.read().unwrap().clone();
            let Some(profile) = n.profile.as_ref() else {
                break;
            };
            let mode = n.settings.mode().unwrap();
            let restart = self
                .listeners
                .lock()
                .unwrap()
                .get(&(mode.into(), n.settings.listen_port))
                .is_none_or(|l| l.finished.is_cancelled());
            if restart {
                let mut observers = n.settings.tcp_stun.clone();
                if n.settings.discovery_mode == "coordinator" {
                    if let Ok(url) = url::Url::parse(&n.settings.service) {
                        if let (Some(host), Some(port)) =
                            (url.host_str(), url.port_or_known_default())
                        {
                            observers.insert(0, format!("{host}:{port}"));
                        }
                    }
                }
                if let Err(e) = self
                    .listen(
                        mode,
                        n.settings.listen_port,
                        &observers,
                        !n.settings.existing_only(),
                        if !n.created_here && mode == "https" {
                            profile.pair.transport_key_pin.as_deref()
                        } else {
                            None
                        },
                    )
                    .await
                {
                    running.metrics.write().unwrap().error = format!("接收器恢复失败：{e}");
                }
            }
            let now = unix_seconds();
            let local = n
                .settings
                .existing_entries
                .iter()
                .filter(|e| e.peer_slot == 0)
                .cloned()
                .collect::<Vec<_>>();
            let mut own = tokio::select! {_=running.cancel.cancelled()=>break,r=discovery::resolve(&local,mode,&self.pkarr,&n.settings.pkarr_gateways)=>r};
            if !n.settings.existing_only()
                && n.settings.extra.get("disableGatewayMapping") != Some(&json!(true))
            {
                if gateway
                    .as_ref()
                    .is_some_and(|g| g.port() != n.settings.listen_port)
                {
                    if let Some(old) = gateway.take() {
                        let _ = old.close().await;
                    }
                    next_gateway = 0;
                }
                if gateway.as_ref().is_none_or(|g| g.renew <= Instant::now()) && now >= next_gateway
                {
                    if let Some(lease) = gateway.as_mut() {
                        if lease.extend().await.is_err() && lease.expires <= Instant::now() {
                            gateway = None;
                        }
                    } else {
                        gateway = crate::gateway::Lease::acquire(
                            n.settings.listen_port,
                            n.settings.port_control_mapping,
                        )
                        .await
                        .ok();
                    }
                    next_gateway = now + 15;
                }
                if let Some(g) = gateway.as_ref().filter(|g| g.expires > Instant::now()) {
                    own.push(g.endpoint);
                }
            } else if let Some(g) = gateway.take() {
                let _ = g.close().await;
            }
            if !n.settings.existing_only() {
                if let Some(candidate) =
                    discovery::ipv6_candidate(n.settings.listen_port).filter(|_| stream_mode(mode))
                {
                    own.push(candidate)
                }
                if mode == "faketcp" {
                    mapping = None;
                    let current = self
                        .fake_mappings
                        .read()
                        .unwrap()
                        .get(&n.settings.listen_port)
                        .cloned();
                    if let Some(current) = current {
                        if let Ok(candidate) = current.refresh().await {
                            own.push(candidate);
                        }
                        if running.metrics.read().unwrap().connected {
                            let peer = running.metrics.read().unwrap().endpoint.parse().ok();
                            if let Some(peer) = peer {
                                current.freeze(peer).await;
                            }
                        }
                    }
                } else {
                    let mut observers = n.settings.tcp_stun.clone();
                    if n.settings.discovery_mode == "coordinator"
                        && let Ok(url) = url::Url::parse(&n.settings.service)
                        && url.path() == "/"
                        && let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default())
                    {
                        observers.insert(0, format!("{host}:{port}"));
                    }
                    mapping = tokio::select! {
                        _ = running.cancel.cancelled() => break,
                        result = discovery::refresh_or_observe_tcp(mapping.take(), n.settings.listen_port, &observers, &self, mode) => result.ok(),
                    };
                    if let Some(observed) = &mapping {
                        own.push(observed.mapped);
                    }
                }
            }
            *running.observed_source.write().unwrap() = mapping.as_ref().map(|m| m.local);
            running.metrics.write().unwrap().local_endpoints =
                own.iter().map(ToString::to_string).collect();
            let mut peer_candidates: Vec<SocketAddr> = Vec::new();
            let mut coordinator_available = false;
            if n.settings.discovery_mode == "pkarr"
                && !n.settings.existing_only()
                && !n.peer_pkarr.is_empty()
            {
                if let Ok(record) = tokio::select! { _ = running.cancel.cancelled() => break, result = self.pkarr.resolve(&n.peer_pkarr, mode, &n.settings.pkarr_gateways) => result }
                {
                    peer_candidates = record
                        .announcement
                        .endpoints
                        .iter()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    if let Some(peer) = remote_member(profile) {
                        if let Ok(state) = conwu_core::rendezvous::State::open(
                            profile,
                            &peer,
                            &n.peer_pkarr,
                            &record.announcement,
                        ) {
                            let acknowledged = state.acknowledged_boot == running.boot;
                            let mut metrics = running.metrics.write().unwrap();
                            if !metrics.pkarr.is_object() {
                                metrics.pkarr = json!({});
                            }
                            metrics.pkarr["peerState"] = json!({"name":state.name,"boot":state.boot,"entry":state.entry,"acknowledged":acknowledged,"observedAt":state.observed_at});
                            *running.peer_state.lock().unwrap() = Some(state);
                        }
                    }
                }
            }
            if n.settings.discovery_mode == "coordinator"
                && !n.settings.existing_only()
                && !n.settings.service.is_empty()
            {
                let announcement = conwu_core::metadata::Announcement {
                    slot: profile.member.slot,
                    device: profile.member.device.clone(),
                    revision: now * 1000,
                    expires: now + 120,
                    endpoint: own
                        .iter()
                        .find(|e| e.is_ipv4())
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    name: self.device_name.read().unwrap().clone(),
                    traversal: crate::managed::capabilities(&running)
                        .and_then(|c| serde_json::to_value(c).ok()),
                    pkarr_source: None,
                    existing_endpoints: Some(own.iter().map(ToString::to_string).collect()),
                    existing_entry_only: false,
                    connection_paused: n.paused,
                };
                if let Ok(envelope) = conwu_core::metadata::Envelope::seal(profile, &announcement) {
                    let name = self.device_name.read().unwrap().clone();
                    let exchange =
                        crate::coordinator::exchange(&n.settings, profile, &envelope, &name);
                    if let Ok(snapshot) =
                        tokio::select! {_=running.cancel.cancelled()=>break,r=exchange=>r}
                    {
                        tokio::select! {
                            _ = running.cancel.cancelled() => break,
                            _ = self.events.send(Event::Snapshot { id: n.id.clone(), snapshot }) => {}
                        }
                    }
                }
                if !running.metrics.read().unwrap().connected && remote_member(profile).is_some() {
                    if let Some(endpoint) = own
                        .iter()
                        .find(|e| e.is_ipv4() && discovery::public(e.ip()))
                        .copied()
                    {
                        if let Ok(client) = crate::assistance::Client::open(
                            &n.settings.service,
                            &n.settings.certificate_pin,
                            false,
                        )
                        .await
                        {
                            if let Ok(reservation) = running.dialing.clone().try_lock_owned() {
                                let connected_since = running.metrics.read().unwrap().since;
                                // Later attempts in the same outage use the regular schedule.
                                let wait = last_assist_round.is_none_or(|(_, since)| since != connected_since)
                                    && n.settings.existing_entries.iter().all(|entry| entry.peer_slot >= 0);
                                let response = tokio::select! {
                                    _ = running.cancel.cancelled() => break,
                                    response = client.member(profile, running.boot, endpoint, wait) => response,
                                };
                                if let Ok((state, rtt)) = response {
                                    if state["Version"] == 1 && state["Mode"] == mode {
                                        coordinator_available = true;
                                        if let Some(peer) = state["PeerEndpoint"]
                                            .as_str()
                                            .and_then(|s| crate::assistance::candidate(s).ok())
                                            .filter(|p| discovery::public(p.ip()))
                                        {
                                            let schedule = crate::assistance::Schedule::read(&state, rtt);
                                            if let Ok(crate::assistance::Schedule::Expired(round)) = &schedule {
                                                last_assist_round = Some((*round, connected_since));
                                            }
                                            if let Ok(crate::assistance::Schedule::Ready(round, delay)) = schedule
                                                && last_assist_round.is_none_or(|(previous, _)| previous != round)
                                            {
                                                last_assist_round = Some((round, connected_since));
                                                let engine = self.clone();
                                                let id = n.id.clone();
                                                let token = running.cancel.clone();
                                                let scheduled = running.clone();
                                                self.tracker.spawn(async move {
                                                    // Reserve the source-port owner before waiting,
                                                    // so an ordinary retry cannot steal this round.
                                                    let _reservation = reservation;
                                                    tokio::select! {_=token.cancelled()=>return,_=tokio::time::sleep(delay)=>{}}
                                                    tracing::debug!(network = %id, %round, "执行成员协调建连");
                                                    let result = tokio::select! {_=token.cancelled()=>Ok(()),r=engine.dial_reserved(&id,peer,&scheduled)=>r};
                                                    if let Err(error) = result {
                                                        tracing::debug!(reason = %crate::logging::redact(&error.to_string()), "协调定时建连未完成");
                                                    }
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if n.settings.discovery_mode == "pkarr"
                && !n.settings.existing_only()
                && !n.pkarr_seed.is_empty()
                && !own.is_empty()
                && (now - last_publish >= 30
                    || own != last_own
                    || running
                        .peer_state
                        .lock()
                        .unwrap()
                        .as_ref()
                        .is_some_and(|s| s.entry != last_ack))
            {
                if let Ok(seed) = c::unb64(&n.pkarr_seed)
                    .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).map_err(anyhow::Error::from))
                {
                    let sequence = (now * 1_000_000)
                        .max(n.pkarr_sequence + 1)
                        .max(last_sequence + 1);
                    let (send, recv) = oneshot::channel(); // Sequence reservation is persisted by the event actor before publication below.
                    let reserved = tokio::select! {
                        _ = running.cancel.cancelled() => break,
                        result = self.events.send(Event::Discovery {
                            id: n.id.clone(), sequence, reply: send,
                        }) => result.is_ok()
                    };
                    let persisted = if reserved {
                        tokio::select! {
                            _ = running.cancel.cancelled() => break,
                            result = recv => matches!(result, Ok(Ok(())))
                        }
                    } else {
                        false
                    };
                    if persisted {
                        last_sequence = sequence;
                        let mut a = pkarr::Announcement {
                            version: 1,
                            mode: mode.into(),
                            expires: unix_seconds() + 180,
                            endpoints: own.iter().take(8).map(ToString::to_string).collect(),
                            state: None,
                        };
                        let source = pkarr::source(&seed);
                        if let Some(peer) = remote_member(profile) {
                            let mut state = conwu_core::rendezvous::State::new(
                                running.boot,
                                self.device_name.read().unwrap().as_str(),
                            );
                            if let Some(remote) = running
                                .peer_state
                                .lock()
                                .unwrap()
                                .as_ref()
                                .filter(|s| s.expires > now)
                            {
                                state.acknowledged_boot = remote.boot;
                                state.acknowledged_entry = remote.entry;
                            }
                            a.state = state.seal(profile, &peer, &source, &a).ok();
                        }
                        let published = tokio::select! {
                            _ = running.cancel.cancelled() => break,
                            result = self.pkarr.publish(&seed, sequence, &a, &n.settings.pkarr_gateways) => result
                        };
                        {
                            let mut metrics = running.metrics.write().unwrap();
                            let peer = metrics
                                .pkarr
                                .get("peerState")
                                .cloned()
                                .unwrap_or(Value::Null);
                            metrics.pkarr = json!({"enabled":true,"source":source,"state":if published.is_ok(){"已发布"}else{"发布重试中"},"publishedAt":if published.is_ok(){now}else{0},"error":published.as_ref().err().map(ToString::to_string).unwrap_or_default(),"endpoints":a.endpoints,"peerState":peer});
                        }
                        if published.is_ok() {
                            last_publish = now;
                            last_own = own.clone();
                            last_ack = running
                                .peer_state
                                .lock()
                                .unwrap()
                                .as_ref()
                                .map_or(uuid::Uuid::nil(), |s| s.entry);
                        }
                    }
                }
            }
            let (connected, connected_since, last_direct) = {
                let metrics = running.metrics.read().unwrap();
                (
                    metrics.connected,
                    metrics.since,
                    metrics.endpoint.parse().ok(),
                )
            };
            if connected_since != last_connected_since {
                candidate_attempts.clear();
                last_connected_since = connected_since;
                mimic_bootstrap_wait = None;
            }
            if !connected && remote_member(profile).is_some() {
                let mut entries = n
                    .settings
                    .existing_entries
                    .iter()
                    .filter(|e| e.peer_slot < 0)
                    .cloned()
                    .collect::<Vec<_>>();
                if n.settings.discovery_mode == "coordinator" && !n.settings.existing_only() {
                    if let Some(endpoints) = n
                        .settings
                        .extra
                        .get("coordinatorEndpoints")
                        .and_then(Value::as_array)
                    {
                        for e in endpoints.iter().filter_map(Value::as_str) {
                            entries.push(Entry {
                                peer_slot: -1,
                                source: e.into(),
                            });
                        }
                    }
                }
                // Direct discovery has no subscription to resolve. A peer
                // may still advertise its PKARR identity during a live link.
                let direct = !n.settings.existing_only() && n.settings.discovery_mode == "direct";
                let mut targets: Vec<SocketAddr> = if entries.is_empty() && (direct || n.peer_pkarr.is_empty())
                {
                    // Give a responding coordinator time to schedule both Mimic
                    // peers before trying the remembered address on our own.
                    // An early SYN can leave this tuple half-open at a NAT.
                    if mode == "mimic" && coordinator_available
                        && mimic_bootstrap_wait.get_or_insert_with(Instant::now).elapsed() < Duration::from_secs(15)
                    {
                        vec![]
                    } else {
                        n.bootstrap.iter().filter_map(|s| s.parse().ok()).collect()
                    }
                } else {
                    tokio::select! {_=running.cancel.cancelled()=>break,r=discovery::resolve(&entries,mode,&self.pkarr,&n.settings.pkarr_gateways)=>r}
                };
                if !n.settings.existing_only() {
                    targets.extend(peer_candidates);
                }
                let candidates = candidate_attempts.order(targets, last_direct);
                for target in candidates.into_iter().take(4) {
                    if !self.try_dial(&n.id, target, &running).await {
                        break;
                    }
                    candidate_attempts.record(target);
                }
            }
            tokio::select! {_=running.cancel.cancelled()=>break,_=running.refresh.notified()=>{last_publish=0;},_=tokio::time::sleep(Duration::from_secs(if connected{n.settings.entry_refresh_seconds.max(5).min(60)}else{5}))=>{}}
        }
        if let Some(gateway) = gateway {
            let _ = gateway.close().await;
        }
        *running.observed_source.write().unwrap() = None;
    }
    pub fn start_guest(
        self: &Arc<Self>,
        id: String,
        codes: Vec<DirectCode>,
        name: String,
        node_private: String,
        requested_ip: String,
        retained: Option<conwu_core::rejoin::Credential>,
    ) {
        self.cancel_guest(&id);
        self.guest_states.write().unwrap().insert(id.clone(),json!({"active":true,"owner":false,"state":"正在联系目标主机","code":"","verification":"","candidate":"","peerName":"","expires":unix_seconds()+300,"format":"compact","method":"direct","direct":true}));
        let stop = self.cancel.child_token();
        self.guests.lock().unwrap().insert(id.clone(), stop.clone());
        let engine = self.clone();
        self.tracker.spawn(async move {
            let mut last=anyhow::anyhow!("没有可联系的入口");
            for code in codes {
                let result=tokio::select!{_=stop.cancelled()=>return,r=engine.join(&id,&code,&name,&node_private,&requested_ip,retained.as_ref(),&stop)=>r};
                match result {Ok(())=>return,Err(e)=>last=e}
            }
            let _=engine.events.send(Event::GuestState{id,state:json!({"active":false,"owner":false,"state":last.to_string(),"error":last.to_string(),"code":"","expires":0})}).await;
        });
    }
    async fn guest_state(&self, id: &str, state: Value) {
        let guests = self.guests.lock().unwrap();
        if guests.contains_key(id) {
            self.guest_states.write().unwrap().insert(id.into(), state);
        }
    }
    async fn join(
        &self,
        id: &str,
        code: &DirectCode,
        name: &str,
        node_private: &str,
        requested_ip: &str,
        retained: Option<&conwu_core::rejoin::Credential>,
        stop: &CancellationToken,
    ) -> Result<()> {
        let key = KeyExchange::new(Some(node_private))?;
        let mut target = code.clone();
        let mut assistance = None;
        if code.coordinator {
            let client =
                crate::assistance::Client::open(&format!("https://{}/", code.endpoint), "", true)
                    .await?;
            let state=client.room("join",&json!({"Code":code.room,"RequestId":conwu_core::id(),"Commitment":key.commitment,"Mode":code.mode})).await?;
            target.endpoint =
                crate::assistance::candidate(state["HostEndpoint"].as_str().unwrap())?;
            target.room = state["HostRoom"].as_str().unwrap().into();
            assistance = Some((client, state));
        }
        let rejoin = retained
            .map(|c| c.prove(&target.room, &key.commitment))
            .transpose()?;
        let rejoin_digest = rejoin.as_ref().map(|p| p.fingerprint()).transpose()?;
        let mut request = Request {
            method: "join".into(),
            code: target.room.clone(),
            commitment: key.commitment.clone(),
            name: name.into(),
            network_settings_version: 1,
            identity: key.identity.clone(),
            requested_ip: requested_ip.into(),
            rejoin: rejoin.map(|p| serde_json::to_value(p).unwrap()),
            entry_admission: target.room == pairing::ENTRY_LOCATOR,
            ..Default::default()
        };
        let direct = async {
            #[cfg(feature = "lab-api")]
            anyhow::ensure!(
                std::env::var_os("CONWU_LAB_FORCE_ASSISTANCE").is_none(),
                "实验强制验证协同准备分支"
            );
            let mut pipe = if stream_mode(&code.mode) {
                transport::connect(&code.mode, target.endpoint, "", true, stop).await?
            } else {
                crate::raw::connect_ref(self, &code.mode, target.endpoint, 0, stop).await?
            };
            let ticket = rpc(&mut pipe, &mut request, stop)
                .await?
                .ticket
                .context("主机没有返回配对会话")?;
            Ok::<_, anyhow::Error>((pipe, ticket))
        };
        // XDP initialization already has its own 45-second bound. The first
        // contact must allow that setup plus the bounded pairing RPC to finish.
        let initial_limit = if cfg!(windows) && code.mode == "mimic" { 55 } else { 8 };
        let initial = tokio::time::timeout(Duration::from_secs(initial_limit), direct).await;
        let observation: Option<crate::raw::ClientObservation>;
        let (mut pipe, ticket) = match initial {
            Ok(Ok(connected)) => {
                observation = None;
                connected
            }
            Ok(Err(error)) if error.is::<crate::raw::LocalCarrierError>() => return Err(error),
            failure => {
                if !code.punch && !code.coordinator {
                    return match failure {
                        Ok(Err(e)) => Err(e),
                        _ => Err(anyhow::anyhow!(
                            "主机入口未回应配对，请确认地址、协议与可达性"
                        )),
                    };
                }
                self.guest_state(id,json!({"active":true,"owner":false,"state":"准备同端口候选，继续双向探测","expires":unix_seconds()+60})).await;
                let servers = if let Some((client, _)) = &assistance {
                    vec![client.endpoint.to_string()]
                } else {
                    crate::model::default_tcp_stun()
                };
                let mut pipe = if stream_mode(&code.mode) {
                    let observed =
                        discovery::observe_tcp(crate::raw::free_tcp()?, &servers, self, &code.mode)
                            .await?;
                    observation = Some(crate::raw::ClientObservation::tcp(observed));
                    None
                } else {
                    let (pipe, observed) = crate::raw::observed_client(
                        self,
                        &code.mode,
                        target.endpoint,
                        &servers[0],
                        stop,
                    )
                    .await?;
                    observation = Some(observed);
                    Some(pipe)
                };
                let observed = observation.as_ref().unwrap();
                if let Some((client, state)) = &assistance {
                    let room = state["Room"].as_str().unwrap();
                    let until = unix_seconds() + 45;
                    let mut retry = String::new();
                    loop {
                        ensure!(unix_seconds() < until, "本轮协调探测超时，未授予成员权限");
                        let input = json!({"Token":state["Token"],"Endpoint":observed.mapped.to_string(),"Ready":true,"RetryRound":retry});
                        let sent = Instant::now();
                        let update = tokio::select! {_=stop.cancelled()=>anyhow::bail!("加入已取消"),r=client.room(room,&input)=>r?};
                        ensure!(
                            [
                                "Room",
                                "Token",
                                "HostRoom",
                                "Commitment",
                                "HostEndpoint",
                                "Mode"
                            ]
                            .iter()
                            .all(|k| update[*k] == state[*k]),
                            "协调辅助绑定已改变"
                        );
                        match crate::assistance::Schedule::read(&update, sent.elapsed())? {
                            crate::assistance::Schedule::Ready(_, delay) => {
                                tokio::select! {
                                    _=stop.cancelled()=>anyhow::bail!("加入已取消"),
                                    _=tokio::time::sleep(delay)=>{}
                                }
                                break;
                            }
                            crate::assistance::Schedule::Expired(round) => {
                                retry = round.to_string();
                                self.guest_state(id,json!({"active":true,"owner":false,"state":"协调探测时间已过，正在重新同步","expires":unix_seconds()+45})).await;
                            }
                            crate::assistance::Schedule::Waiting => {}
                        }
                        tokio::select! {
                            _=stop.cancelled()=>anyhow::bail!("加入已取消"),
                            _=tokio::time::sleep(Duration::from_millis(350))=>{}
                        }
                    }
                } else {
                    let seed = c::hash(
                        format!("conwu-mimic-first-contact-v1/{}", code.issue()?).as_bytes(),
                    );
                    let announcement = pkarr::Announcement {
                        version: 1,
                        mode: "mimic".into(),
                        expires: unix_seconds() + 90,
                        endpoints: vec![observed.mapped.to_string()],
                        state: Some("conwu-mimic-first-contact-v1".into()),
                    };
                    self.pkarr
                        .publish(
                            &seed,
                            unix_seconds() * 1_000_000,
                            &announcement,
                            &crate::model::PKARR
                                .iter()
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>(),
                        )
                        .await?;
                }
                observed.start(target.endpoint).await?;
                if pipe.is_none() {
                    let socket =
                        transport::tcp_open_from(target.endpoint, observed.local).await?;
                    pipe =
                        Some(transport::client_socket(&code.mode, socket, "", true, stop).await?);
                }
                let mut pipe = pipe.unwrap();
                let ticket = rpc(&mut pipe, &mut request, stop)
                    .await?
                    .ticket
                    .context("主机尚未回应同步探测")?;
                (pipe, ticket)
            }
        };
        let _mapping_lease = observation;
        if let Some((_, state)) = &assistance {
            ensure!(
                ticket.host_commitment == state["Commitment"],
                "配对回应与协调辅助承诺不符"
            );
        }
        ensure!(
            ticket.expires > unix_seconds()
                && ticket.expires <= unix_seconds() + 360
                && conwu_core::valid_id(&ticket.room)
                && conwu_core::valid_id(&ticket.candidate)
                && pairing::valid_commitment(&ticket.host_commitment),
            "主机会话无效"
        );
        if let Some(identity) = &ticket.identity {
            ensure!(identity.valid(&ticket.host_commitment), "主机设备证明无效");
        }
        let mut request = Request {
            method: "poll".into(),
            entry_admission: target.room == pairing::ENTRY_LOCATOR,
            room: ticket.room.clone(),
            token: ticket.token.clone(),
            ..Default::default()
        };
        let initial = rpc(&mut pipe, &mut request, stop)
            .await?
            .state
            .context("主机配对状态缺失")?;
        ensure!(
            initial.guest_commitment == key.commitment && initial.candidate == ticket.candidate,
            "申请绑定不符"
        );
        let shared = key.derive(
            &initial.host_public,
            &ticket.host_commitment,
            &ticket.room,
            &ticket.candidate,
            false,
        )?;
        request.method = "reveal".into();
        request.public_key = key.public.clone();
        let _ = rpc(&mut pipe, &mut request, stop).await?;
        request.public_key.clear();
        request.method = "poll".into();
        let verification = KeyExchange::sas(&shared);
        self.guest_state(id,json!({"active":true,"owner":false,"code":"","verification":verification,"candidate":ticket.candidate,"peerName":ticket.host_name,"expires":ticket.expires,"state":"等待目标主机核对校验码并批准","format":"compact","method":"direct","direct":true})).await;
        loop {
            ensure!(
                ticket.expires > unix_seconds(),
                "本次直连码已过期，请主机重新生成"
            );
            let reply = rpc(&mut pipe, &mut request, stop).await?;
            let state = reply.state.context("缺少配对状态")?;
            ensure!(
                state.rejoin_digest == rejoin_digest,
                "重新加入证明摘要已改变"
            );
            ensure!(
                state.candidate == ticket.candidate
                    && state.guest_commitment == key.commitment
                    && state.host_public == initial.host_public,
                "主机配对状态已改变"
            );
            ensure!(
                state.outcome.is_empty(),
                "主机已结束申请：{}",
                state.outcome
            );
            if state.approved {
                ensure!((40..=44000).contains(&reply.total), "批准数据长度无效");
                let total = reply.total;
                let mut ciphertext = String::with_capacity(total);
                while ciphertext.len() < total {
                    request.method = "chunk".into();
                    request.offset = ciphertext.len();
                    let part = rpc(&mut pipe, &mut request, stop).await?;
                    ensure!(
                        part.total == total
                            && !part.part.is_empty()
                            && part.part.len() <= 800
                            && ciphertext.len() + part.part.len() <= total,
                        "批准分片无效"
                    );
                    ciphertext.push_str(&part.part);
                }
                let plaintext =
                    KeyExchange::decrypt(&shared, &ciphertext, &ticket.room, &ticket.candidate)?;
                let (profile, _, approved) = identity::import_bundle(&plaintext)?;
                ensure!(
                    profile.member.device == identity::network_id(&c::public(node_private)?)?,
                    "批准身份未绑定本机"
                );
                if let Some(host) = &ticket.identity {
                    ensure!(
                        profile
                            .directory
                            .as_ref()
                            .unwrap()
                            .members
                            .iter()
                            .any(|m| m.slot == profile.introducer_slot
                                && m.device
                                    == identity::network_id(&host.public_key).unwrap_or_default()),
                        "批准配置与主机身份不符"
                    );
                }
                if code.mode == "https" {
                    ensure!(
                        profile.pair.transport_key_pin.as_deref() == Some(&pipe.pin),
                        "批准 HTTPS 公钥与实际连接不符"
                    );
                }
                let approved = approved.context("主机没有交付独立网络设置")?;
                let mut settings = Settings::default();
                settings.inherit(&profile, &approved)?;
                let (send, recv) = oneshot::channel();
                self.events
                    .send(Event::Joined {
                        id: id.into(),
                        profile,
                        settings,
                        approved,
                        peer_name: ticket.host_name.clone(),
                        bootstrap: target.endpoint,
                        reply: send,
                    })
                    .await?;
                recv.await??;
                request.method = "received".into();
                request.offset = 0;
                let _ = rpc(&mut pipe, &mut request, stop).await;
                self.guest_state(id,json!({"active":false,"owner":false,"state":"已加入网络","expires":ticket.expires})).await;
                return Ok(());
            }
            tokio::select! {_=stop.cancelled()=>anyhow::bail!("申请已取消"),_=tokio::time::sleep(Duration::from_millis(600))=>{}}
        }
    }
    pub async fn shutdown(&self) -> Result<()> {
        self.cancel.cancel();
        self.tracker.close();
        if tokio::time::timeout(Duration::from_secs(65), self.tracker.wait())
            .await
            .is_err()
        {
            tracing::error!("后台关闭等待超时，仍持有的网络资源不会被新代次复用");
            anyhow::bail!("后台关闭等待超时；进程退出前不能复用旧网络资源");
        }
        // Closing tasks alone leaves adapters alive in these registries. Close
        // their OS handles before the service reports STOPPED or an MSI starts.
        self.networks.write().unwrap().clear();
        self.flow_groups.lock().unwrap().clear();
        self.rooms.lock().unwrap().clear();
        self.raw_controls.lock().unwrap().clear();
        self.fake_mappings.write().unwrap().clear();
        Ok(())
    }
}
impl Running {
    #[cfg(windows)]
    pub(crate) fn routes_to_peer(&self, local: Ipv4Addr, peer: Ipv4Addr) -> bool {
        self.adapter.routes_to_peer(local, peer)
    }

    pub(crate) fn receive(
        &self,
        body: &[u8],
        route_id: &str,
        events: &mpsc::Sender<Event>,
    ) -> bool {
        let n = self.config.read().unwrap();
        let profile = n.profile.as_ref().unwrap();
        let mut guard = self.peer.lock().unwrap();
        let Some(peer) = guard.as_mut() else {
            return false;
        };
        let allow_lanes = peer
            .routes
            .get(route_id)
            .and_then(|r| r.flow.as_ref())
            .is_some_and(|f| f.negotiated());
        let received = peer.link.receive(body, allow_lanes);
        if !received.authenticated {
            return false;
        }
        let Some(route) = peer.routes.get_mut(route_id) else {
            return false;
        };
        route.seen = Instant::now();
        if let Some(reply) = received.reply {
            let _ = route
                .tx
                .try_send(link::wrap(&profile.pair.network, &reply).unwrap());
        }
        if received.pong == Some(route.challenge) {
            if route.nomination.is_none() {
                route.verified = true;
            }
            // The same nonce is retried for five seconds. Only its first pong
            // measures a round trip; retries must not include idle heartbeat time.
            if !route.rtt_recorded {
                self.metrics.write().unwrap().rtt =
                    Some(route.challenged.elapsed().as_secs_f64() * 1000.0);
                route.rtt_recorded = true;
            }
            if peer.chosen.is_none() && route.verified {
                peer.chosen = Some(route_id.into());
            }
        }
        if let Some(control) = received.control {
            if let Some(nomination) = route.nomination.as_mut() {
                let responses = nomination.receive(route.path, &control);
                if nomination.switch_requested() {
                    route.verified = true;
                    if peer.chosen.is_none() {
                        peer.chosen = Some(route_id.into());
                    }
                }
                if nomination.stage == conwu_core::path::Stage::Selected {
                    self.metrics.write().unwrap().managed = json!({"phase":"Selected","attempt":nomination.attempt(),"selected":true,"fullMtuQualified":true});
                }
                // Switch locally before Commit is emitted.
                for response in responses {
                    if let Ok(Some(frame)) = peer.link.control(&response) {
                        let _ = route
                            .tx
                            .try_send(link::wrap(&profile.pair.network, &frame).unwrap());
                    }
                }
                if nomination.stage == conwu_core::path::Stage::Cancelled {
                    route.cancel.cancel();
                }
            }
        }
        if let Some(packet) = received.packet {
            let Some(remote) = remote_member(profile) else {
                return true;
            };
            if route.verified
                && !n.paused
                && n.enabled
                && link::valid_packet(&packet)
                && packet[12..16] == member_ip(profile, &remote).unwrap().octets()
                && packet[16..20] == profile.local_ip().unwrap().octets()
            {
                if self.adapter.write(&packet).is_ok_and(|written| written) {
                    crate::uu::observe(&n.id, &packet, false);
                    self.metrics.write().unwrap().received += packet.len() as u64;
                } else {
                    self.metrics.write().unwrap().dropped += 1;
                }
            }
        }
        if let Some(payload) = received.synchronization {
            if route.verified {
                if let Ok(Some(snapshot)) =
                    conwu_core::metadata::receive(&mut peer.assembly, &payload)
                {
                    let _ = events.try_send(Event::Snapshot {
                        id: n.id.clone(),
                        snapshot,
                    });
                }
            }
        }
        true
    }
}
pub fn remote_member(profile: &Profile) -> Option<Member> {
    profile
        .directory
        .as_ref()?
        .members
        .iter()
        .find(|m| m.slot != profile.member.slot)
        .cloned()
}
pub fn member_ip(profile: &Profile, member: &Member) -> Result<Ipv4Addr> {
    if let Some(ip) = &member.virtual_ip {
        return Ok(ip.parse()?);
    }
    let p = identity::prefix(&profile.pair.network)?;
    Ok(Ipv4Addr::new(p[0], p[1], p[2], member.slot))
}
pub async fn rpc(
    pipe: &mut Pipe,
    request: &mut Request,
    stop: &CancellationToken,
) -> Result<Reply> {
    request.id = conwu_core::id();
    let frame = pairing::encode(request)?;
    for _ in 0..3 {
        tokio::select! {_=stop.cancelled()=>anyhow::bail!("配对已取消"),r=pipe.tx.send(frame.clone())=>r?};
        let wait = async {
            while let Some(bytes) = pipe.rx.recv().await {
                if let Ok(reply) = pairing::decode::<Reply>(&bytes) {
                    if reply.id == request.id {
                        ensure!(reply.error.is_empty(), "{}", reply.error);
                        return Ok(reply);
                    }
                }
            }
            anyhow::bail!("主机配对连接已关闭")
        };
        match tokio::select! {_=stop.cancelled()=>anyhow::bail!("配对已取消"),r=tokio::time::timeout(Duration::from_secs(3),wait)=>r}
        {
            Ok(reply) => return reply,
            Err(_) => continue,
        }
    }
    anyhow::bail!("主机入口未回应配对，请确认入口与连接协议")
}
