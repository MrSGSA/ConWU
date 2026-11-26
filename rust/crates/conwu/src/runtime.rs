use crate::{
    adapter::{self, Adapter, Memory},
    assistance::{PAIRING_RETRIES, retry_pair_step, transient_signal},
    discovery,
    model::{Entry, Network, Settings},
    pkarr,
    transport::{self, Pipe, TlsIdentity},
};
use anyhow::{Context, Result, ensure};
use conwu_core::{
    code::{DirectCode, raw_tcp_mode, stream_mode},
    crypto as c,
    identity::{self, Member, Profile},
    link::{self, Link},
    pairing::{self, Host, KeyExchange, Reply, Request},
    unix_seconds,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

mod candidates;
mod tcp_prediction;
mod reconnect;
use candidates::CandidateAttempts;
use reconnect::RoundOutcome;

const FIRST_CONTACT_TCP_WINDOW: Duration = Duration::from_secs(6);
const RAW_CANDIDATE_CONCURRENCY: usize = 8;
const RAW_CANDIDATE_INTERVAL: Duration = Duration::from_millis(60);
const RAW_CANDIDATE_WAIT: Duration = crate::assistance::RAW_CANDIDATE_WAIT;
const RAW_CANDIDATE_HELPER_WAIT: Duration = Duration::from_secs(3);
const RAW_CANDIDATE_RPC_WAIT: Duration = Duration::from_millis(470);
const MIMIC_CANDIDATE_WINDOW: Duration = crate::assistance::MIMIC_OFFER_WINDOW;
const FAKETCP_OBSERVATION_RETRY: Duration = Duration::from_secs(4);

fn raw_candidate_attempts<T, F>(targets: impl IntoIterator<Item = SocketAddr>, run: impl Fn(usize, SocketAddr) -> F)
    -> impl futures_util::Stream<Item = T>
where F: std::future::Future<Output = T>,
{
    use futures_util::StreamExt;
    let schedule = Arc::new(tokio::sync::Mutex::new(tokio::time::Instant::now()));
    futures_util::stream::iter(targets.into_iter().enumerate()).map(move |(index, target)| {
        let run = run(index, target);
        let schedule = schedule.clone();
        async move {
            let mut next = schedule.lock().await;
            tokio::time::sleep_until(*next).await;
            *next = tokio::time::Instant::now() + RAW_CANDIDATE_INTERVAL;
            drop(next);
            run.await
        }
    }).buffer_unordered(RAW_CANDIDATE_CONCURRENCY)
}

#[cfg(test)]
#[tokio::test]
async fn raw_candidates_are_staggered_and_hold_at_most_eight_slots() -> Result<()> {
    use futures_util::StreamExt;

    let (started, mut starts) = mpsc::unbounded_channel();
    let permits = Arc::new(Semaphore::new(0));
    let gates = permits.clone();
    let candidates = (43000..43010).map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
    let task = tokio::spawn(async move {
        raw_candidate_attempts(candidates, |index, target| {
            let started = started.clone();
            let gates = gates.clone();
            async move {
                let _ = started.send((index, target.port(), tokio::time::Instant::now()));
                gates.acquire().await.unwrap().forget();
            }
        }).collect::<Vec<_>>().await
    });
    let mut previous = None;
    for index in 0..RAW_CANDIDATE_CONCURRENCY {
        let (actual, port, instant) = tokio::time::timeout(Duration::from_secs(2), starts.recv()).await?
            .context("候选未启动")?;
        assert_eq!((actual, port), (index, 43000 + index as u16));
        if let Some(previous) = previous { assert!(instant - previous >= RAW_CANDIDATE_INTERVAL); }
        previous = Some(instant);
    }
    assert!(tokio::time::timeout(Duration::from_millis(150), starts.recv()).await.is_err());
    permits.add_permits(10);
    let first = tokio::time::timeout(Duration::from_secs(2), starts.recv()).await?.unwrap();
    let second = tokio::time::timeout(Duration::from_secs(2), starts.recv()).await?.unwrap();
    assert_eq!((first.0, second.0), (8, 9));
    assert!(second.2 - first.2 >= RAW_CANDIDATE_INTERVAL);
    assert_eq!(task.await?.len(), 10);
    Ok(())
}

#[cfg(test)]
#[tokio::test]
async fn coordinated_faketcp_does_not_reuse_a_listener_without_a_ready_receiver() -> Result<()> {
    let app = crate::tests::app().await?;
    let mut settings = Settings::default();
    settings.listen_port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    settings.tcp_stun.clear();
    let key = ("faketcp".to_owned(), settings.listen_port);
    let cancel = CancellationToken::new();
    let finished = CancellationToken::new();
    let listener = Listener {
        cancel: cancel.clone(), finished: finished.clone(),
        policy: ListenerPolicy { stun: vec![], autonomous: true, tls_peer: None },
        observation_error: None,
        observation_retry_at: None,
    };
    app.engine.listeners.lock().unwrap().insert(key.clone(), listener);
    let old = cancel.clone();
    let task = tokio::spawn(async move { old.cancelled().await; finished.cancel(); });
    let result = app.engine.prepare_faketcp_receiver(&settings).await;
    assert!(cancel.is_cancelled());
    task.await?;
    assert!(result.is_err());
    assert!(!app.engine.listeners.lock().unwrap().contains_key(&key));
    Ok(())
}

#[cfg(test)]
#[tokio::test]
async fn interrupted_mimic_stop_waits_for_the_same_helper_on_retry() -> Result<()> {
    let app = crate::tests::app().await?;
    let key = ("mimic".to_owned(), 44680);
    let cancel = CancellationToken::new();
    let finished = CancellationToken::new();
    app.engine.listeners.lock().unwrap().insert(key.clone(), Listener {
        cancel: cancel.clone(), finished: finished.clone(),
        policy: ListenerPolicy { stun: vec![], autonomous: true, tls_peer: None },
        observation_error: None, observation_retry_at: None,
    });
    let mut first = Box::pin(app.engine.release_unused_listener(&key));
    assert!(futures_util::poll!(&mut first).is_pending() && cancel.is_cancelled());
    drop(first);
    let mut retry = Box::pin(app.engine.release_unused_listener(&key));
    assert!(futures_util::poll!(&mut retry).is_pending());
    assert!(app.engine.listeners.lock().unwrap().contains_key(&key));
    finished.cancel();
    retry.await?;
    assert!(!app.engine.listeners.lock().unwrap().contains_key(&key));
    app.engine.shutdown().await
}

fn coordinated_first_contact(state: &Value) -> Duration {
    if state["ProbePlan"].is_null() { FIRST_CONTACT_TCP_WINDOW } else { crate::assistance::COORDINATED_FIRST_CONTACT }
}

struct GuestExchange {
    key: KeyExchange,
    rejoin: Option<(String, conwu_core::rejoin::Proof)>,
}

#[derive(Debug)]
enum FirstContact {
    NoReply { mode: String, prediction: bool },
    TryPrediction,
    HostPortChanged,
    RetryGuestStun,
    NativeNoReply,
    RetryRound,
}
impl std::fmt::Display for FirstContact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoReply { mode, prediction: true } => write!(f, "{mode} 端口预测重试未收到主机回复"),
            Self::NoReply { mode, prediction: false } => write!(f, "协调已同步，{mode} 首次配对未收到主机回复"),
            Self::TryPrediction => f.write_str("普通双向探测未收到回复，可使用主机端口预测重试"),
            Self::HostPortChanged => f.write_str("FakeTCP 首次配对期间主机公网端口已变化，协调入口已更新"),
            Self::RetryGuestStun => f.write_str("从机 TCP STUN 映射已失效，需要重新登记"),
            Self::NativeNoReply => f.write_str("首次配对的 TCP 探测未建立直连"),
            Self::RetryRound => f.write_str("本轮双向探测未建立直连"),
        }
    }
}
impl std::error::Error for FirstContact {}

fn validate_pair_ticket(ticket: &pairing::Ticket, host: Option<&Value>) -> Result<()> {
    if let Some(host) = host {
        ensure!(
            ticket.host_commitment == host["Commitment"],
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
    Ok(())
}

fn candidate_ticket(frame: &[u8], request_id: &str, host: &Value) -> Option<pairing::Ticket> {
    let reply = pairing::decode::<Reply>(frame).ok()?;
    if reply.id != request_id || !reply.error.is_empty() {
        return None;
    }
    let ticket = reply.ticket?;
    validate_pair_ticket(&ticket, Some(host)).ok()?;
    Some(ticket)
}

async fn accept_pair_source(
    listener: Option<&tokio::net::TcpListener>,
    host: IpAddr,
) -> Result<tokio::net::TcpStream> {
    let Some(listener) = listener else { return std::future::pending().await };
    loop {
        let (stream, peer) = listener.accept().await?;
        if peer.ip() == host {
            return Ok(stream);
        }
    }
}

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
        installed: Option<oneshot::Sender<()>>,
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
    PunchSummary(Value),
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
    pub faketcp_stun_endpoint: Option<SocketAddr>,
}
struct Route {
    carrier: String,
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
    projection: Option<crate::projection::Advertisement>,
    sunshine: Option<crate::projection::Advertisement>,
    projection_companion: Option<crate::projection::Advertisement>,
}
pub struct Running {
    dialing: Arc<tokio::sync::Mutex<()>>,
    network_finished: CancellationToken,
    discovery_finished: CancellationToken,
    managed_finished: CancellationToken,
    refresh: tokio::sync::Notify,
    pub(crate) boot: uuid::Uuid,
    peer_state: Mutex<Option<conwu_core::rendezvous::State>>,
    observed_tcp: RwLock<Option<discovery::TcpAddresses>>,
    tcp_observation: tokio::sync::Mutex<Option<discovery::TcpObservation>>,
    reconnect: Mutex<reconnect::Reconnect>,
    raw_reconnect_workers: TaskTracker,
    // Scoped to this running network, including successive coordinator rounds.
    raw_sender_recovery: tcp_prediction::SenderRecovery,
    pub config: RwLock<Arc<Network>>,
    pub metrics: RwLock<Metrics>,
    pub memory: Option<Arc<Memory>>,
    adapter: RwLock<Option<Arc<dyn Adapter>>>,
    peer: Mutex<Option<Peer>>,
    pub cancel: CancellationToken,
    pub projection_listener: Mutex<crate::projection::Listener>,
    pub projection_sunshine: Mutex<crate::projection::Listener>,
    pub projection_companion: Mutex<crate::projection::Listener>,
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
    observation_error: Option<crate::raw::LocalCarrierError>,
    observation_retry_at: Option<Instant>,
}
impl Listener {
    fn observation_retry_due(&self) -> bool {
        self.observation_retry_at.is_some_and(|retry_at| Instant::now() >= retry_at)
    }
}
pub struct Engine {
    pub store: Arc<crate::store::Store>,
    pub fake_mappings: RwLock<HashMap<u16, Arc<crate::native_map::Mapping>>>,
    pub(crate) stun_cursor: Mutex<HashMap<(String, u16), usize>>,
    tcp_prediction: tcp_prediction::Cache,
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
            tcp_prediction: tcp_prediction::Cache::default(),
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
        // A signed snapshot or departure can be queued before a cold stop
        // and applied afterwards. Persisting it must respect the local stop.
        if !network.enabled {
            return self.remove(&network.id).await;
        }
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
        let observers = &network.settings.tcp_stun;
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
                false,
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
                            projection: None,
                            sunshine: None,
                            projection_companion: None,
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
            if old.settings.tcp_stun != network.settings.tcp_stun
                || old.settings.listen_port != network.settings.listen_port
            {
                let mut observation = prior.tcp_observation.lock().await;
                observation.take();
                *prior.observed_tcp.write().unwrap() = None;
                *prior.config.write().unwrap() = Arc::new(network);
            } else {
                *prior.config.write().unwrap() = Arc::new(network);
            }
            prior.refresh.notify_one();
            if old_key != new_key {
                self.release_unused_listener(&old_key).await?;
            }
            return Ok(());
        }
        let setup_started = Instant::now();
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
        let adapter_time = setup_started.elapsed();
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
                    projection: None,
                    sunshine: None,
                    projection_companion: None,
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
        let listener_started = Instant::now();
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
            false,
        )
        .await?;
        tracing::info!(%mode, adapter_ms = adapter_time.as_millis(),
            listener_ms = listener_started.elapsed().as_millis(),
            setup_ms = setup_started.elapsed().as_millis(), "网络运行实例已就绪");
        let running = Arc::new(Running {
            projection_listener: Mutex::default(),
            projection_sunshine: Mutex::default(),
            projection_companion: Mutex::default(),
            dialing: Arc::new(tokio::sync::Mutex::new(())),
            network_finished: CancellationToken::new(),
            discovery_finished: CancellationToken::new(),
            managed_finished: CancellationToken::new(),
            refresh: tokio::sync::Notify::new(),
            boot: uuid::Uuid::new_v4(),
            peer_state: Mutex::new(None),
            observed_tcp: RwLock::new(None),
            tcp_observation: tokio::sync::Mutex::new(None),
            reconnect: Mutex::default(),
            raw_reconnect_workers: TaskTracker::new(),
            raw_sender_recovery: Default::default(),
            config: RwLock::new(Arc::new(network)),
            metrics: RwLock::new(metrics),
            memory,
            adapter: RwLock::new(Some(adapter.clone())),
            peer: Mutex::new(peer),
            cancel: self.cancel.child_token(),
        });
        self.networks.write().unwrap().insert(id, running.clone());
        let engine = self.clone();
        let run = running.clone();
        self.tracker.spawn(async move {
            let _finished = run.network_finished.clone().drop_guard();
            engine.network_loop(run, adapter).await;
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
                r.raw_reconnect_workers.close();
                r.raw_reconnect_workers.wait().await;
            })
            .await
            .context("旧网络资源尚未释放，请稍后重试")?;
            let key = {
                let n = r.config.read().unwrap();
                (n.settings.mode()?.to_owned(), n.settings.listen_port)
            };
            self.release_unused_listener(&key).await?;
            r.tcp_observation.lock().await.take();
            *r.observed_tcp.write().unwrap() = None;
            // Other tasks may still hold a reference to Running. Close the
            // device here after the reader exits and any synchronous write ends.
            r.adapter.write().unwrap().take();
            {
                let mut networks = self.networks.write().unwrap();
                if networks
                    .get(id)
                    .is_some_and(|current| Arc::ptr_eq(current, &r))
                {
                    networks.remove(id);
                }
            }
        }
        self.rooms.lock().unwrap().remove(id);
        self.cancel_guest(id);
        Ok(())
    }
    pub(crate) async fn release_unused_listener(&self, key: &(String, u16)) -> Result<()> {
        let _transaction = self.listener_transaction.lock().await;
        let used = self.networks.read().unwrap().values().any(|r| {
            let n = r.config.read().unwrap();
            !r.cancel.is_cancelled() && n.settings.mode().ok() == Some(key.0.as_str()) && n.settings.listen_port == key.1
        });
        if !used {
            self.stop_listener(key).await?;
        }
        Ok(())
    }
    // Both callers hold listener_transaction. Keep the entry on timeout so a
    // retry also waits for the old helper to exit before it reuses the port.
    async fn stop_listener(&self, key: &(String, u16)) -> Result<()> {
        let finished = {
            let listeners = self.listeners.lock().unwrap();
            let Some(listener) = listeners.get(key) else { return Ok(()); };
            listener.cancel.cancel();
            listener.finished.clone()
        };
        tokio::time::timeout(Duration::from_secs(25), finished.cancelled())
            .await
            .context("旧监听未能及时释放，请查看承载组件状态")?;
        self.listeners.lock().unwrap().remove(key);
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

    pub(crate) fn note_peer_snapshot(&self, running: &Running, profile: &Profile, snapshot: &conwu_core::metadata::Snapshot) {
        let Some(presence) = reconnect::PeerPresence::read(profile, snapshot) else { return };
        let (changed, restarted) = {
            let mut reconnect = running.reconnect.lock().unwrap();
            let (changed, restarted) = reconnect.update_peer(presence);
            if restarted && profile.pair.mode == "mimic" {
                reconnect.retire_raw_listener(true);
            }
            (changed, restarted)
        };
        if restarted {
            if let Some(peer) = running.peer.lock().unwrap().as_mut() {
                for route in peer.routes.values() { route.cancel.cancel(); }
                peer.routes.clear();
                peer.chosen = None;
            }
            running.metrics.write().unwrap().connected = false;
        }
        if changed { running.refresh.notify_one(); }
    }
    async fn retire_failed_raw_listener(&self, running: &Arc<Running>, mode: &str, port: u16) -> Result<()> {
        let _transaction = self.listener_transaction.lock().await;
        if tcp_prediction::member_link_verified(running, None) {
            return Ok(());
        }
        let shared = self.networks.read().unwrap().values().any(|other| {
            if Arc::ptr_eq(other, running) || other.cancel.is_cancelled() { return false; }
            let cfg = other.config.read().unwrap();
            cfg.settings.mode().ok() == Some(mode) && cfg.settings.listen_port == port
        });
        if !shared {
            self.stop_listener(&(mode.to_owned(), port)).await?;
            running.tcp_observation.lock().await.take();
        }
        Ok(())
    }
    async fn listen(
        self: &Arc<Self>,
        mode: &str,
        port: u16,
        stun: &[String],
        autonomous: bool,
        tls_peer: Option<&str>,
        require_observation: bool,
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
        let (unchanged, observation_retry_due) = self.listeners.lock().unwrap().get(&key)
            .map(|listener| (
                listener.policy == policy && !listener.cancel.is_cancelled() && !listener.finished.is_cancelled(),
                listener.observation_retry_due(),
            )).unwrap_or_default();
        let retry_observation = observation_retry_due && !self.networks.read().unwrap().values().any(|running| {
            let network = running.config.read().unwrap();
            network.settings.mode().ok() == Some(mode)
                && network.settings.listen_port == port && running.metrics.read().unwrap().connected
        });
        if unchanged && !retry_observation && (!require_observation || self.faketcp_receiver(port).is_ok()) {
            return Ok(());
        }
        self.stop_listener(&key).await?;
        let finished = CancellationToken::new();
        if !stream_mode(mode) {
            let stop = self.cancel.child_token();
            let observation_error = crate::raw::listen(
                self,
                mode,
                port,
                stun,
                autonomous,
                stop.clone(),
                finished.clone(),
                require_observation,
            )
            .await?;
            let observation_retry_at = observation_error.as_ref()
                .map(|_| Instant::now() + FAKETCP_OBSERVATION_RETRY);
            self.listeners.lock().unwrap().insert(
                key,
                Listener {
                    cancel: stop,
                    finished,
                    policy,
                    observation_error,
                    observation_retry_at,
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
                observation_error: None,
                observation_retry_at: None,
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

    pub(crate) async fn prepare_faketcp_receiver(self: &Arc<Self>, settings: &crate::model::Settings) -> Result<()> {
        self.listen("faketcp", settings.listen_port, &settings.tcp_stun, true, None, true).await?;
        self.faketcp_receiver(settings.listen_port)?;
        Ok(())
    }

    fn faketcp_receiver(&self, port: u16) -> Result<Arc<crate::native_map::Mapping>> {
        let mapping = self.fake_mappings.read().unwrap().get(&port)
            .filter(|mapping| !mapping.cancel.is_cancelled()).cloned();
        if let Some(mapping) = mapping { return Ok(mapping); }
        if let Some(error) = self.listeners.lock().unwrap().get(&("faketcp".to_owned(), port))
            .and_then(|listener| listener.observation_error.clone())
        {
            let error = anyhow::Error::new(error);
            let reason = crate::logging::redact(&format!("{error:#}"));
            return Err(error.context(format!("FakeTCP 同源接收器启动失败：{reason}")));
        }
        anyhow::bail!("FakeTCP 同源接收器已停止，请重新启动该网络")
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
                    let greeting = running.member_greeting(profile)?;
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
                let greeting = running.member_greeting(profile)?;
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
            let local = running.observed_tcp.read().unwrap().map(|observed| observed.local)
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
        self.serve_inner(pipe, mode, endpoint, outbound, None, None).await;
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
            None,
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
        mut punch_log: Option<tcp_prediction::diagnostics::RoundLog>,
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
                    &mode,
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
                if self.pair_request(&frame, &pipe.tx, &mode, endpoint).await {
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
                if !self.attach(&running, &route, &mode, &pipe, endpoint, flow.clone(), None) {
                    continue;
                }
                accepted.insert(id);
            }
            if running.receive(body, &route, &self.events) {
                if let Some(log) = punch_log.take() {
                    log.trace.stage("mesh_authenticated");
                    log.trace.close("success");
                }
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
        carrier: &str,
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
            carrier: carrier.to_owned(),
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
    async fn pair_request(&self, frame: &[u8], tx: &mpsc::Sender<Vec<u8>>, mode: &str, endpoint: SocketAddr) -> bool {
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
                let ticket = mode == "mimic" && request.method == "join"
                    && pairing::decode::<pairing::Reply>(&reply).is_ok_and(|r| r.ticket.is_some());
                if tx.try_send(reply).is_ok() && ticket && let Some(running) = self.current(network) {
                    let port = running.config.read().unwrap().settings.listen_port;
                    if let Some(control) = self.raw_controls.lock().unwrap().get(&(mode.to_owned(), port)) {
                        control.ticket_queued(endpoint);
                    }
                }
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
            let compact = code.split_once('@').map_or(code.as_str(), |(compact, _)| compact);
            let short = crate::assistance::short_code(compact);
            let coordinated = short || DirectCode::import(compact).is_ok_and(|code| code.coordinator);
            return json!({"active":active,"pending":pending,"phase":phase,"approved":s.approved,"delivered":host.delivered,"outcome":s.outcome,"owner":true,"code":compact,"shareCode":code,"verification":host.sas().unwrap_or_default(),"candidate":s.candidate,"peerName":s.guest_name,"expires":s.expires,"state":message,"format":if short {"short"} else {"compact"},"method":if coordinated {"coordinator"} else {"direct"},"coordinated":coordinated,"direct":true,"proposedIp":s.requested_ip});
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
        if let Some(previous) = self.assists.lock().unwrap().remove(id) {
            previous.cancel();
        }
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
                            if crate::discovery::public(peer.ip())&&(targets.contains(&peer)||targets.len()<8){targets.insert(peer);let _=engine.punch_unpaired(&id,peer,None).await;}
                        }
                    }
                }
                tokio::select!{_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(4))=>{}}
            }
        });
        Ok(())
    }
    pub async fn assist_code(
        self: &Arc<Self>,
        id: &str,
        endpoint: Option<SocketAddr>,
        follow_faketcp_stun: bool,
        name: &str,
        node_private: &str,
    ) -> Result<()> {
        let running = self.current(id).context("网络已移除")?;
        let n = running.config.read().unwrap().clone();
        ensure!(
            n.enabled && !n.paused && n.profile.as_ref().is_some_and(|profile| !profile.owner_private.is_empty()),
            "请在主机连接网络后生成直连码"
        );
        let mode = n.settings.mode()?;
        let locator = crate::assistance::InviteLocator::new(
            &n.settings.service,
            &n.settings.certificate_pin,
        )?;
        let automatic = n.settings.manual_endpoint.is_empty();
        let native_prepare = mode == "faketcp";
        let follow_mapping = native_prepare && (follow_faketcp_stun || automatic);
        let native_port = n.settings.listen_port;
        let observe = async {
            if follow_mapping {
                self.prepare_faketcp_receiver(&n.settings).await?;
            }
            if !automatic || native_prepare || n.settings.tcp_stun.is_empty() {
                return Ok(None);
            }
            // Discovery and an invitation own the same observation. Opening a
            // second socket with this source and observer races Winsock connect.
            let mut current = running.tcp_observation.lock().await;
            ensure!(Arc::ptr_eq(&n, &running.config.read().unwrap()), "网络设置已改变，请重新生成直连码");
            if let Some(path) = current.as_ref()
                .filter(|path| path.local.port() == native_port && discovery::public(path.mapped.ip()))
            {
                return Ok(Some(path.addresses()));
            }
            current.take();
            let path = discovery::observe_tcp_invite(native_port, &n.settings.tcp_stun, self, mode).await?;
            ensure!(discovery::public(path.mapped.ip()), "TCP STUN 未返回公网地址");
            let addresses = path.addresses();
            *current = Some(path);
            *running.observed_tcp.write().unwrap() = Some(addresses);
            Ok::<_, anyhow::Error>(Some(addresses))
        };
        let (client, mut same_source) = tokio::try_join!(locator.connect(), observe)?;
        let endpoint = if follow_mapping {
            let mapping = self.faketcp_receiver(native_port)?;
            let observed = match mapping.observed_endpoint() {
                Some(address) => address,
                None => retry_pair_step("FakeTCP 同源观察", |error| {
                    !discovery::stun_address_in_use(error) && discovery::transient_observer(error)
                }, |_| mapping.refresh()).await?,
            };
            ensure!(discovery::public(observed.ip()), "FakeTCP TCP STUN 未返回公网地址");
            same_source = Some(discovery::TcpAddresses { local: mapping.local, mapped: observed, observer: mapping.observer });
            observed
        } else {
            same_source.map(|path| path.mapped).or(endpoint)
                .context("尚未取得公网 IPv4 候选，请等待 TCP STUN 观察或检查本机入口")?
        };
        let prediction = same_source.filter(|_| stream_mode(mode) && automatic)
            .and_then(|path| tcp_prediction::ObservedPath::new(path.local, path.mapped, path.observer));
        let probe = same_source.map(|path| crate::assistance::ProbePlan::new(mode, path.observer));
        let probe_hash = probe.as_ref().map(crate::assistance::ProbePlan::hash).transpose()?;
        let host = Host::new(name, Some(node_private))?;
        let (state, retries) = client.create_pair_room(json!({
            "Endpoint":endpoint.to_string(),"HostRoom":host.ticket.code,"Commitment":host.key.commitment,
            "Mode":mode,"Ready":!native_prepare,"TcpPrediction":prediction.is_some(),
            "RawHostPrediction":raw_tcp_mode(mode) && n.settings.manual_endpoint.is_empty(),
            "RawMultiCandidate":true,"RawRoundSync":true,"MimicEndpointRotation":mode == "mimic","ProbePlan":probe,"ProbeHash":probe_hash
        })).await?;
        if retries > 0 {
            let _ = self.events.try_send(Event::Log { level: "INFO".into(),
                text: format!("协调配对创建房间重试 {retries} 次后成功") });
        }
        let confirmed = crate::assistance::ProbePlan::read(&state, mode)?;
        ensure!(confirmed == probe, "协调器返回了不同的 TCP STUN 探测配置");
        let room = state["Room"].as_str().filter(|s| crate::assistance::short_code(s)).context("辅助会话编号无效")?;
        let code = DirectCode {
            endpoint: client.endpoint, mode: mode.into(), room: room.into(), punch: false, coordinator: true,
        }.issue()?;
        let code = locator.share_code(&code);
        {
            let mut rooms = self.rooms.lock().unwrap();
            ensure!(Arc::ptr_eq(&n, &running.config.read().unwrap()), "网络设置已改变，请重新生成直连码");
            if let Some((prior, _)) = rooms.get(id) {
                ensure!(
                    !prior.state.approved || prior.delivered || prior.ticket.expires <= unix_seconds(),
                    "上一台设备仍在接收批准信息"
                );
            }
            rooms.insert(id.into(), (host, code));
        }
        let stop = running.cancel.child_token();
        if let Some(prior) = self.assists.lock().unwrap().insert(id.into(), stop.clone()) {
            prior.cancel();
        }
        if probe.is_some()
            && let Some(path) = prediction.or_else(|| {
                same_source.filter(|_| raw_tcp_mode(mode))
                    .and_then(|path| tcp_prediction::ObservedPath::new(path.local, path.mapped, path.observer))
            })
        {
            let engine = self.clone();
            let stop = stop.clone();
            self.tracker.spawn(async move { engine.prewarm_pair_prediction(path, &stop).await; });
        }
        let engine = self.clone();
        let id = id.to_owned();
        let transport_stop = running.cancel.clone();
        self.tracker.spawn(async move {
            let source = same_source.map(|path| path.local);
            let key = state["Room"].as_str().unwrap().to_owned();
            let mut prior = uuid::Uuid::nil();
            let mut prior_started = Instant::now();
            let mut retry = String::new();
            let mut guest_endpoint = None;
            let mut prepared = None;
            let mut prepare_error_reported = false;
            let mut generation = None;
            let mut probe_stop = stop.child_token();
            let mut mimic_task = None::<tokio::task::JoinHandle<()>>;
            let mut previous_mimic = None;
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
                let mapping = if native_prepare {
                    engine.fake_mappings.read().unwrap().get(&native_port).filter(|m| !m.cancel.is_cancelled()).cloned()
                } else {
                    None
                };
                let current_generation = mapping.as_ref().map(|m| m.generation);
                if generation != current_generation {
                    prepared = None;
                    prior = uuid::Uuid::nil();
                    generation = current_generation;
                }
                let ready = !native_prepare || prepared.is_some();
                let ready_for = prepared.map(|peer: SocketAddr| peer.to_string()).unwrap_or_default();
                let mut input = json!({"Token":state["Token"],"Ready":ready,"ReadyFor":ready_for,"RetryRound":retry,"ProbeHash":state["ProbeHash"]});
                let offered = mapping.as_ref().filter(|_| follow_mapping).and_then(|m| m.observed_endpoint());
                if let Some(offered) = offered {
                    input["NextHostEndpoint"] = json!(offered);
                }
                let sent = Instant::now();
                let updated = tokio::select! {_=stop.cancelled()=>break,r=client.room(&key,&input)=>r};
                let round_trip = sent.elapsed();
                if let Ok(updated) = updated {
                    let matching = ["Room", "Token", "HostRoom", "Commitment", "Mode", "ProbePlan", "ProbeHash"]
                        .iter().all(|k| updated[*k] == state[*k]);
                    if !matching { break; }
                    let Some(reported) = updated["HostEndpoint"].as_str().and_then(|s| s.parse::<SocketAddr>().ok()) else { break };
                    if reported != endpoint && !(follow_mapping && reported.ip() == endpoint.ip()) { break; }
                    let guest = updated["GuestEndpoint"].as_str()
                        .and_then(|s| crate::assistance::candidate(s).ok());
                    if guest != guest_endpoint {
                        guest_endpoint = guest;
                        prepared = None;
                        prepare_error_reported = false;
                        prior = uuid::Uuid::nil();
                        retry.clear();
                        probe_stop.cancel();
                    }
                    if native_prepare && prepared.is_none() && let Some(peer) = guest {
                        if let Some(mapping) = mapping {
                            let result = tokio::select! {
                                _=stop.cancelled()=>break,
                                result=mapping.prepare(peer,false,false)=>result,
                            };
                            match result {
                                Ok(_) => { prepared = Some(peer); prepare_error_reported = false; }
                                Err(error) if !prepare_error_reported => {
                                    prepare_error_reported = true;
                                    let reason = crate::logging::redact(&error.to_string());
                                    let _ = engine.events.try_send(Event::Log { level: "WARN".into(),
                                        text: format!("FakeTCP 首配主机准备接收器失败，正在重试：{reason}") });
                                }
                                Err(_) => {}
                            }
                        }
                    }
                    match crate::assistance::Schedule::read_for_host(&updated, round_trip, prior, prior_started) {
                        Ok(crate::assistance::Schedule::Waiting) if !prior.is_nil() => {
                            probe_stop.cancel();
                            prior = uuid::Uuid::nil();
                            retry.clear();
                        }
                        Ok(crate::assistance::Schedule::Expired(round)) => {
                            probe_stop.cancel();
                            retry = round.to_string();
                        }
                        Ok(crate::assistance::Schedule::Ready(round, delay)) if round != prior => {
                            if let Some(peer) = guest && (!native_prepare || prepared == Some(peer)) {
                                if let Some((old_peer, old_round)) = previous_mimic {
                                    probe_stop.cancel();
                                    if let Some(task) = mimic_task.take() { let _ = task.await; }
                                    let control = engine.raw_controls.lock().unwrap().get(&("mimic".into(), native_port)).cloned();
                                    if let Some(control) = control
                                        && let Err(error) = control.discard_pair_probe(old_peer, old_round).await {
                                        tracing::warn!(%error, "Mimic 旧轮次清理尚未确认");
                                        tokio::time::sleep(Duration::from_millis(400)).await;
                                        continue;
                                    }
                                }
                                prior = round;
                                prior_started = Instant::now();
                                retry.clear();
                                probe_stop.cancel();
                                probe_stop = stop.child_token();
                                let host = engine.clone();
                                let task_id = id.clone();
                                let token = probe_stop.clone();
                                let transport_stop = transport_stop.clone();
                                let client = client.clone();
                                let running = running.clone();
                                let prediction = prediction.filter(|_| updated["TcpPrediction"] == true);
                                let mimic_pair = updated["Mode"] == "mimic" && updated["RawMultiCandidate"] == true;
                                let task = engine.tracker.spawn(async move {
                                    tokio::select! {_=token.cancelled()=>return,_=tokio::time::sleep(delay)=>{}}
                                    if updated["RawHostPrediction"] == true {
                                        let result = tokio::select! {
                                            _=token.cancelled()=>return,
                                            result=host.raw_pair_probe(&task_id, peer, &client, &updated, round, same_source, &token)=>result,
                                        };
                                        if let Err(error) = result {
                                            tracing::debug!(reason = %crate::logging::redact(&error.to_string()), "原始 TCP 首次配对预测未完成");
                                        }
                                        return;
                                    }
                                    let deadline = tokio::time::Instant::now() + coordinated_first_contact(&updated);
                                    let ordinary = tokio::select! {
                                        _=token.cancelled()=>return,
                                        result=tokio::time::timeout_at(deadline, host.punch_unpaired(&task_id,peer,source))=>result,
                                    };
                                    if let Some(path) = prediction
                                        && match ordinary { Err(_) => true, Ok(Err(ref error)) => error.is::<transport::TcpOpenError>(), _ => false }
                                    {
                                        tokio::select! {
                                            _=token.cancelled()=>return,
                                            _=tokio::time::sleep_until(deadline)=>{}
                                        }
                                        let result = host.predict_room_path(
                                            &client, &updated, true, path, &running.tcp_observation, peer, round, &token,
                                        ).await;
                                        match result {
                                            Ok(Some(socket)) => {
                                                let mode = updated["Mode"].as_str().unwrap_or_default();
                                                if let Ok(remote) = socket.peer_addr()
                                                    && let Ok(pipe) = transport::accept(mode, socket, &host.identity, &transport_stop).await
                                                {
                                                    host.serve(pipe, mode.into(), remote, None).await;
                                                }
                                            }
                                            Ok(None) => {}
                                            Err(error) => {
                                                if error.is::<discovery::StunLeaseLost>() {
                                                    running.refresh.notify_one();
                                                }
                                                tracing::debug!(
                                                    reason = %crate::logging::redact(&error.to_string()),
                                                    "首次配对 TCP 预测未完成"
                                                );
                                            }
                                        }
                                    }
                                });
                                if mimic_pair {
                                    previous_mimic = Some((peer, round));
                                    mimic_task = Some(task);
                                }
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
    async fn punch_unpaired(
        self: &Arc<Self>,
        id: &str,
        endpoint: SocketAddr,
        source: Option<SocketAddr>,
    ) -> Result<()> {
        let running = self.current(id).context("网络已移除")?;
        let n = running.config.read().unwrap().clone();
        let mode = n.settings.mode()?;
        if stream_mode(mode) {
            let local = source.or_else(|| running.observed_tcp.read().unwrap().map(|observed| observed.local));
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
    async fn network_loop(self: Arc<Self>, running: Arc<Running>, adapter: Arc<dyn Adapter>) {
        const ADAPTER_BATCH: usize = 64;
        let mut timer = tokio::time::interval(Duration::from_millis(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut drain_again = false;
        let mut last_control = Instant::now() - Duration::from_secs(10);
        let mut last_metadata = Instant::now() - Duration::from_secs(10);
        let mut metadata_revision = 0;
        let mut sent_projection = false;
        let mut sent_sunshine = false;
        let mut sent_companion = false;
        loop {
            tokio::select! {
                biased;
                _ = running.cancel.cancelled() => break,
                _ = tokio::task::yield_now(), if drain_again => {}
                _ = timer.tick(), if !drain_again => {}
            }
            drain_again = false;
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
                if connected {
                    use crate::projection::Endpoint;
                    let allowed = n.enabled && !n.paused && n.projection.allowed;
                    let (legacy, sunshine, companion) = if allowed {
                        (
                            running.projection_listener.lock().unwrap().port(n.projection.port),
                            running.projection_sunshine.lock().unwrap().port(crate::projection::SUNSHINE_PORT),
                            running.projection_companion.lock().unwrap().live_port(),
                        )
                    } else {
                        (0, 0, 0)
                    };
                    if let Some(route) = peer.chosen.as_ref().and_then(|id| peer.routes.get(id)) {
                        for (port, endpoint, sent) in [
                            (legacy, Endpoint::Legacy(legacy), &mut sent_projection),
                            (sunshine, Endpoint::Sunshine(sunshine), &mut sent_sunshine),
                            (companion, Endpoint::Companion(companion), &mut sent_companion),
                        ] {
                            if port != 0 || *sent {
                                if let Ok(Some(frame)) = peer.link.synchronize(&crate::projection::announce(endpoint)) {
                                    let _ = route.tx.try_send(link::wrap(&profile.pair.network, &frame).unwrap());
                                    *sent = true;
                                }
                            }
                        }
                    }
                }
                let mut metrics = running.metrics.write().unwrap();
                if metrics.connected != connected {
                    if connected {
                        running.reconnect.lock().unwrap().connected();
                    }
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
                        boot_id: Some(running.boot),
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
            for index in 0..ADAPTER_BATCH {
                let packet = match adapter.read() {
                    Ok(Some(p)) => p,
                    Ok(None) => break,
                    Err(e) => {
                        adapter_error = Some(e.to_string());
                        break;
                    }
                };
                // Large video bursts can fill a batch before the next Windows timer tick.
                // Yield between full batches so carrier tasks can empty their output queues.
                drain_again = index + 1 == ADAPTER_BATCH;
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
    async fn coordinate_member(
        self: &Arc<Self>, running: &Arc<Running>, network: &Network, profile: &Profile,
        endpoints: &[SocketAddr], mapping: Option<discovery::TcpAddresses>,
        client_cache: &mut Option<(String, String, crate::assistance::Client)>,
        raw_reconnect: &mut tcp_prediction::RawMemberReconnect,
    ) -> bool {
        if network.paused || running.metrics.read().unwrap().connected || remote_member(profile).is_none() {
            raw_reconnect.take();
            return false;
        }
        let public_v4 = |endpoint: &SocketAddr| endpoint.is_ipv4() && discovery::public(endpoint.ip());
        let Some(mut endpoint) = mapping.map(|path| path.mapped).filter(public_v4)
            .or_else(|| endpoints.iter().copied().find(public_v4)) else { return false; };
        let mode = profile.pair.mode.as_str();
        if !running.reconnect.lock().unwrap().delay().is_zero() { return true; }
        let Ok(reservation) = running.dialing.clone().try_lock_owned() else { return true; };
        let (request, finished, retry_raw, retire_raw) = {
            let state = running.reconnect.lock().unwrap();
            let (request, finished) = state.report();
            (request, finished, state.private_raw(), state.retiring_raw_listener())
        };
        let isolated_raw = mode == "mimic" || retry_raw && matches!(mode, "phantun" | "tcpraw");
        let prediction = mapping.filter(|observed| {
            isolated_raw || stream_mode(mode) || mode == "faketcp" || self.raw_controls.lock().unwrap()
                .get(&(mode.to_owned(), network.settings.listen_port))
                .is_some_and(|control| control.source == observed.local && control.confirms_syn)
        }).and_then(|observed| tcp_prediction::ObservedPath::for_report(observed, endpoint));
        if isolated_raw && let Some(base) = prediction {
            if retire_raw {
                if let Err(error) = self.retire_failed_raw_listener(running, mode, network.settings.listen_port).await {
                    tracing::debug!(mode, reason = %crate::logging::redact(&error.to_string()), "旧重连接收器仍在退出");
                    return true;
                }
                if !request.is_cancelled() {
                    running.reconnect.lock().unwrap().retire_raw_listener(false);
                }
            }
            let prepared = tokio::select! {
                _ = running.cancel.cancelled() => return false,
                _ = request.cancelled() => return true,
                result = raw_reconnect.prepare(base) => result,
            };
            match prepared {
                Ok(mapped) => endpoint = mapped,
                Err(error) => {
                    tracing::debug!(mode, reason = %crate::logging::redact(&error.to_string()), "成员重连的新 STUN 映射未就绪");
                    return false;
                }
            }
        }
        if !isolated_raw || prediction.is_none() {
            raw_reconnect.take();
        }
        let settings = &network.settings;
        let cached = client_cache.as_ref().filter(|(service, pin, _)| {
            *service == settings.service && *pin == settings.certificate_pin
        }).map(|(_, _, client)| client.clone());
        let negotiate = async {
            let client = match cached {
                Some(client) => client,
                None => crate::assistance::Client::open(&settings.service, &settings.certificate_pin, false).await?,
            };
            let (state, rtt) = client.member(profile, running.boot, endpoint, true, prediction.is_some(), finished).await?;
            Ok::<_, anyhow::Error>((client, state, rtt))
        };
        let result = tokio::select! {
            _ = running.cancel.cancelled() => return false,
            _ = request.cancelled() => return true,
            result = negotiate => result,
        };
        let (client, state, rtt) = match result {
            Ok(result) => result,
            Err(error) => {
                if transient_signal(&error) { *client_cache = None; }
                tracing::debug!(reason = %crate::logging::redact(&error.to_string()), "未取得成员协调响应");
                return false;
            }
        };
        if client_cache.as_ref().is_none_or(|(service, pin, _)| {
            *service != settings.service || *pin != settings.certificate_pin
        }) {
            *client_cache = Some((settings.service.clone(), settings.certificate_pin.clone(), client.clone()));
        }
        if state["Version"] != 1 || state["Mode"] != mode { return false; }
        let (Ok(crate::assistance::Schedule::Ready(round, delay)), Some(peer)) = (
            crate::assistance::Schedule::read(&state, rtt),
            state["PeerEndpoint"].as_str().and_then(|value| crate::assistance::candidate(value).ok()).filter(public_v4),
        ) else { return true; };
        let peer_boot = state["PeerBoot"].as_str().and_then(|id| id.parse().ok());
        if !running.reconnect.lock().unwrap().begin(round, peer_boot, &request) { return true; }
        let predicts = state["TcpPrediction"] == true;
        let path = prediction.filter(|_| predicts);
        let private = (isolated_raw && prediction.is_some()).then(|| raw_reconnect.take()).flatten();
        let engine = self.clone();
        let running = running.clone();
        let id = network.id.clone();
        let mode = mode.to_owned();
        let lifetime = private.as_ref().map(|_| running.raw_reconnect_workers.token());
        self.tracker.spawn(async move {
            let _lifetime = lifetime;
            let attempt = async {
                tokio::time::sleep(delay).await;
                if running.metrics.read().unwrap().connected { return RoundOutcome::Connected; }
                if let Some(path) = path {
                    let trace = tcp_prediction::diagnostics::Trace::new(round, "reconnect", "member", &mode);
                    match engine.predict_member_path(&running, &client, path, peer, &trace).await {
                        Ok(true) => return RoundOutcome::Connected,
                        Ok(false) => {},
                        Err(error) => tracing::debug!(%round, reason = %crate::logging::redact(&error.to_string()), "成员预测未完成"),
                    }
                    if trace.native_sampling_failed() { return RoundOutcome::NativeResample; }
                    if matches!(mode.as_str(), "phantun" | "tcpraw") && trace.raw_reconnect_timed_out() {
                        return RoundOutcome::RawTimedOut;
                    }
                    if !trace.used_candidates() { return RoundOutcome::Resample; }
                    let _ = engine.dial_reserved(&id, peer, &running).await;
                    return RoundOutcome::CandidatesTried;
                }
                let _ = engine.dial_reserved(&id, peer, &running).await;
                RoundOutcome::Resample
            };
            let result = if let Some(private) = private {
                tokio::select! {
                    _ = running.cancel.cancelled() => None,
                    _ = request.cancelled() => None,
                    _ = tokio::time::sleep(delay) => {
                        let trace = tcp_prediction::diagnostics::Trace::new(round, "reconnect", "member", &mode);
                        Some(match engine.predict_private_raw_member(&running, &client, private, &mode, peer, &trace, predicts, &request).await {
                            Ok(true) => RoundOutcome::Connected,
                            result => {
                                if let Err(error) = result {
                                    tracing::debug!(%round, reason = %crate::logging::redact(&error.to_string()), "独立接收器成员重连未完成");
                                }
                                if trace.used_candidates() { RoundOutcome::CandidatesTried } else { RoundOutcome::Resample }
                            }
                        })
                    },
                }
            } else {
                tokio::select! {
                    _ = running.cancel.cancelled() => None,
                    _ = request.cancelled() => None,
                    outcome = attempt => Some(outcome),
                }
            };
            if let Some(outcome) = result {
                let outcome = if tcp_prediction::member_link_verified(&running, None) { RoundOutcome::Connected } else { outcome };
                running.reconnect.lock().unwrap().complete(round, &request, outcome);
            }
            drop(reservation);
            running.refresh.notify_one();
        });
        true
    }

    async fn discovery_loop(self: Arc<Self>, running: Arc<Running>) {
        let mut last_publish = 0i64;
        let mut last_sequence = 0i64;
        let mut gateway: Option<crate::gateway::Lease> = None;
        let mut gateway_acquire: Option<tokio::task::JoinHandle<Option<crate::gateway::Lease>>> = None;
        let mut next_gateway = 0;
        let mut last_own = Vec::new();
        let mut last_ack = uuid::Uuid::nil();
        let mut candidate_attempts = CandidateAttempts::default();
        let mut last_connected_since = 0;
        let mut mimic_bootstrap_wait = None;
        let mut raw_reconnect = tcp_prediction::RawMemberReconnect::default();
        let mut member_client = None;
        loop {
            let n = running.config.read().unwrap().clone();
            let Some(profile) = n.profile.as_ref() else {
                break;
            };
            let mode = n.settings.mode().unwrap();
            let connected = running.metrics.read().unwrap().connected;
            let restart = self
                .listeners
                .lock()
                .unwrap()
                .get(&(mode.into(), n.settings.listen_port))
                .is_none_or(|l| l.finished.is_cancelled() || !connected && l.observation_retry_due());
            if restart {
                if let Err(e) = self
                    .listen(
                        mode,
                        n.settings.listen_port,
                        &n.settings.tcp_stun,
                        !n.settings.existing_only(),
                        if !n.created_here && mode == "https" {
                            profile.pair.transport_key_pin.as_deref()
                        } else {
                            None
                        },
                        false,
                    )
                    .await
                {
                    running.metrics.write().unwrap().error = format!("接收器恢复失败：{e}");
                }
            }
            let fast_poll = running.reconnect.lock().unwrap().fast_native_poll();
            let observed = *running.observed_tcp.read().unwrap();
            if !connected && !n.paused && !n.settings.existing_only() && stream_mode(mode)
                && n.settings.discovery_mode == "coordinator" && let (Some(wait), Some(observed)) = (fast_poll, observed)
                && observed.local.port() == n.settings.listen_port
            {
                tokio::select! {
                    _ = running.cancel.cancelled() => break,
                    _ = tokio::time::sleep(wait) => {},
                }
                if Arc::ptr_eq(&n, &running.config.read().unwrap())
                    && running.reconnect.lock().unwrap().take_fast_native_poll()
                {
                    // A sampling failure can re-enter member coordination
                    // immediately using the measured listener tuple.
                    self.coordinate_member(&running, &n, profile, &[], Some(observed),
                        &mut member_client, &mut raw_reconnect).await;
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
            let mut faketcp_stun_endpoint = None;
            let mut mapping = None;
            if gateway_acquire.as_ref().is_some_and(|task| task.is_finished()) {
                gateway = gateway_acquire.take().unwrap().await.ok().flatten();
            }
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
                    } else if gateway_acquire.is_none() {
                        // Discovery can use the current STUN path while the
                        // optional gateway discovery waits for local replies.
                        let port = n.settings.listen_port;
                        gateway_acquire = Some(self.tracker.spawn(async move {
                            crate::gateway::Lease::acquire(port, true).await.ok()
                        }));
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
                    running.tcp_observation.lock().await.take();
                    let current = self
                        .fake_mappings
                        .read()
                        .unwrap()
                        .get(&n.settings.listen_port)
                        .cloned();
                    if let Some(current) = current {
                        if let Ok(candidate) = current.refresh().await {
                            if !own.contains(&candidate) {
                                faketcp_stun_endpoint = Some(candidate);
                            }
                            mapping = Some(discovery::TcpAddresses { local: current.local, mapped: candidate, observer: current.observer });
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
                    let mut observation = tokio::select! {
                        _ = running.cancel.cancelled() => break,
                        observation = running.tcp_observation.lock() => observation,
                    };
                    // A settings update may have invalidated the configuration
                    // this pass cloned before obtaining the observation lock.
                    if !Arc::ptr_eq(&n, &running.config.read().unwrap()) {
                        continue;
                    }
                    *observation = tokio::select! {
                        _ = running.cancel.cancelled() => break,
                        result = discovery::refresh_or_observe_tcp(
                            observation.take(), n.settings.listen_port, &n.settings.tcp_stun, &self, mode, None,
                        ) => result.ok(),
                    };
                    mapping = observation.as_ref().map(discovery::TcpObservation::addresses);
                    drop(observation);
                    if let Some(observed) = mapping {
                        if n.settings.discovery_mode == "coordinator" {
                            self.tcp_prediction.refresh(observed).await;
                        }
                        own.push(observed.mapped);
                    }
                }
            }
            *running.observed_tcp.write().unwrap() = mapping;
            {
                let mut metrics = running.metrics.write().unwrap();
                metrics.local_endpoints = own.iter().map(ToString::to_string).collect();
                metrics.faketcp_stun_endpoint = faketcp_stun_endpoint;
            }
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
                    revision: tcp_prediction::diagnostics::unix_ms(),
                    expires: now + 120,
                    endpoint: mapping.map(|path| path.mapped).or_else(|| own.iter().find(|e| e.is_ipv4()).copied())
                        .map(|endpoint| endpoint.to_string())
                        .unwrap_or_default(),
                    name: self.device_name.read().unwrap().clone(),
                    boot_id: Some(running.boot),
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
                        self.note_peer_snapshot(&running, profile, &snapshot);
                        tokio::select! {
                            _ = running.cancel.cancelled() => break,
                            _ = self.events.send(Event::Snapshot { id: n.id.clone(), snapshot }) => {}
                        }
                    }
                }
                coordinator_available = self.coordinate_member(&running, &n, profile, &own, mapping,
                    &mut member_client, &mut raw_reconnect).await;
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
                    if coordinator_available
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
            let poll = if connected { Duration::from_secs(n.settings.entry_refresh_seconds.clamp(5, 60)) }
                else if coordinator_available {
                    let retry = running.reconnect.lock().unwrap().delay();
                    if retry.is_zero() { Duration::from_secs(1) } else { retry }
                } else { Duration::from_secs(5) };
            tokio::select! {
                _ = running.cancel.cancelled() => break,
                _ = running.refresh.notified() => { last_publish = 0; }
                _ = tokio::time::sleep(poll) => {}
                result = async { gateway_acquire.as_mut().unwrap().await }, if gateway_acquire.is_some() => {
                    gateway_acquire = None;
                    gateway = result.ok().flatten();
                }
            }
        }
        if let Some(task) = gateway_acquire
            && let Ok(Some(lease)) = task.await
        {
            let _ = lease.close().await;
        }
        if let Some(gateway) = gateway {
            let _ = gateway.close().await;
        }
        *running.observed_tcp.write().unwrap() = None;
        running.tcp_observation.lock().await.take();
    }
    pub fn start_guest(
        self: &Arc<Self>,
        id: String,
        codes: Vec<DirectCode>,
        coordinator: Option<crate::assistance::InviteLocator>,
        coordinated_only: bool,
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
                let key = match KeyExchange::new(Some(&node_private)) {
                    Ok(key) => key,
                    Err(error) => { last = error; break; }
                };
                let mut exchange = GuestExchange { key, rejoin: None };
                let mut raw_retry = code.coordinator && raw_tcp_mode(&code.mode);
                let mut retried = 0;
                loop {
                    if stop.is_cancelled() { return; }
                    let result=engine.join(&id,&code,coordinator.as_ref(),&name,&node_private,&requested_ip,retained.as_ref(),&mut exchange,raw_retry,coordinated_only,&stop).await;
                    if stop.is_cancelled() { return; }
                    let Err(error) = result else { return };
                    if retried >= PAIRING_RETRIES {
                        last = error;
                        break;
                    }
                    let reason = match error.downcast_ref() {
                        Some(FirstContact::TryPrediction) => {
                            raw_retry = true;
                            "正在协调主机 TCP 端口预测"
                        }
                        Some(FirstContact::HostPortChanged) => "主机公网端口已变化，正在用更新后的入口重试",
                        Some(FirstContact::RetryGuestStun) => "从机 TCP STUN 映射已失效，正在重新登记",
                        Some(FirstContact::RetryRound) => "正在重新同步双向探测",
                        _ => { last = error; break; }
                    };
                    retried += 1;
                    engine.guest_state(&id, json!({"active":true,"owner":false,
                        "state":format!("{reason}（重试 {retried}/{PAIRING_RETRIES}）"),"expires":unix_seconds()+60})).await;
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = tokio::time::sleep(Duration::from_millis(350)) => {}
                    }
                }
            }
            let reason = crate::logging::redact(&last.to_string());
            let _=engine.events.send(Event::GuestState{id,state:json!({"active":false,"owner":false,"state":reason,"error":reason,"code":"","expires":0})}).await;
        });
    }
    async fn guest_state(&self, id: &str, state: Value) {
        let guests = self.guests.lock().unwrap();
        if guests.contains_key(id) {
            self.guest_states.write().unwrap().insert(id.into(), state);
        }
    }
    async fn join(
        self: &Arc<Self>,
        id: &str,
        code: &DirectCode,
        coordinator: Option<&crate::assistance::InviteLocator>,
        name: &str,
        node_private: &str,
        requested_ip: &str,
        retained: Option<&conwu_core::rejoin::Credential>,
        exchange: &mut GuestExchange,
        raw_retry: bool,
        coordinated_only: bool,
        stop: &CancellationToken,
    ) -> Result<()> {
        let assistance = if code.coordinator {
            let connect = async {
                if let Some(locator) = coordinator {
                    locator.connect().await.context("无法连接直连码中的 HTTPS 协调服务器")
                } else {
                    crate::assistance::Client::open(&format!("https://{}/", code.endpoint), "", true).await
                }
            };
            let client = tokio::select! {
                _ = stop.cancelled() => anyhow::bail!("加入已取消"),
                result = connect => result?,
            };
            // After submission, keep the bounded HTTPS exchange alive long
            // enough to receive the token needed to withdraw this request.
            let input = json!({
                "Code":code.room,"RequestId":conwu_core::id(),"Commitment":exchange.key.commitment,
                "Mode":code.mode,"TcpPrediction":stream_mode(&code.mode),"RawHostPrediction":raw_retry,"RawMultiCandidate":true,"RawRoundSync":true
            });
            let (state, retries) = client.join_pair_room(&input).await.map_err(|error| {
                if coordinator.is_none() && transient_signal(&error) {
                    error.context("无法通过直连码中的 IP 访问协调服务器，请粘贴主机复制的完整直连码或填写协调地址")
                } else {
                    error
                }
            })?;
            if retries > 0 {
                let _ = self.events.try_send(Event::Log { level: "INFO".into(),
                    text: format!("协调配对提交申请重试 {retries} 次后成功") });
            }
            Some((client, state))
        } else {
            None
        };
        let result = tokio::select! {
            biased;
            _ = stop.cancelled() => Err(anyhow::anyhow!("加入已取消")),
            result = self.join_peer(id, code, exchange, name, node_private, requested_ip, retained, assistance.as_ref(), coordinated_only, stop) => result,
        };
        let Err(error) = result else { return Ok(()); };
        if let Some((client, state)) = assistance {
            let room = state["Room"].as_str().unwrap();
            let input = json!({"Token": state["Token"], "Withdraw": true});
            let withdraw = retry_pair_step("撤回并刷新协调轮次", transient_signal, |_| client.room(room, &input));
            let withdrawn = tokio::time::timeout(Duration::from_secs(4), withdraw).await;
            if let Ok(Ok(updated)) = withdrawn
                && ["Room","Token","HostRoom","Commitment","Mode"].iter().all(|k| updated[*k] == state[*k])
            {
                if error.is::<discovery::StunLeaseLost>() {
                    return Err(error.context(FirstContact::RetryGuestStun));
                }
                if matches!(error.downcast_ref(), Some(FirstContact::NoReply { .. })) {
                    if !raw_retry && state["RawPredictionSupported"] == true {
                        return Err(error.context(FirstContact::TryPrediction));
                    }
                    if updated["HostEndpoint"] != state["HostEndpoint"] {
                        return Err(error.context(FirstContact::HostPortChanged));
                    }
                    return Err(error.context(FirstContact::RetryRound));
                }
                if matches!(error.downcast_ref(), Some(FirstContact::NativeNoReply))
                    || raw_retry && (error.is::<crate::assistance::RawRoundExpired>() || transient_signal(&error))
                {
                    return Err(error.context(FirstContact::RetryRound));
                }
            }
        }
        Err(error)
    }
    async fn join_raw_candidates(
        &self,
        observed: &crate::raw::ClientObservation,
        mode: &str,
        state: &Value,
        registered: SocketAddr,
        targets: Vec<SocketAddr>,
        request: &Request,
        stop: &CancellationToken,
        trace: &tcp_prediction::diagnostics::Trace,
    ) -> Result<(Pipe, pairing::Ticket, SocketAddr)> {
        use futures_util::StreamExt;

        ensure!(
            discovery::local_route(registered)? == observed.local.ip(),
            "主机与 TCP STUN 使用不同的本机出口"
        );
        let total = targets.len();
        let legacy = total == 1 && state["ProbePlan"].is_null();
        let wait = if legacy {
            let timeout = if cfg!(windows) && mode == "mimic" { 55 } else { 16 };
            Duration::from_secs(timeout)
        } else {
            RAW_CANDIDATE_WAIT
        };
        let interval = if legacy {
            Duration::from_secs(3)
        } else {
            RAW_CANDIDATE_RPC_WAIT
        };
        let attempts = raw_candidate_attempts(targets, |index, target| async move {
                trace.socket(0, observed.local, target, "candidate_started", None);
                let trial = async {
                    let mut pipe = tokio::time::timeout(if legacy { wait } else { RAW_CANDIDATE_HELPER_WAIT },
                        observed.candidate_pipe(self, mode, target, total == 1, stop)).await??;
                    trace.socket(0, observed.local, target, "bridge_ready", None);
                    let mut request = request.clone();
                    let reply = tokio::time::timeout(wait, rpc_with_wait(&mut pipe, &mut request, stop, interval)).await??;
                    let ticket = reply.ticket.context("候选未返回配对会话")?;
                    validate_pair_ticket(&ticket, Some(state))?;
                    Ok::<_, anyhow::Error>((pipe, ticket, target))
                };
                let result = match trial.await {
                    Ok(selected) => {
                        trace.socket(0, observed.local, target, "ticket_validated", None);
                        Ok(selected)
                    }
                    Err(error) => {
                        let io = error.chain().find_map(|cause| cause.downcast_ref::<std::io::Error>());
                        let stage = if error.is::<tokio::time::error::Elapsed>() { "deadline" } else { "candidate_failed" };
                        trace.socket(0, observed.local, target, stage, io);
                        Err(error)
                    }
                };
                (index, result)
            });
        tokio::pin!(attempts);
        loop {
            let next = tokio::select! {
                _ = stop.cancelled() => anyhow::bail!("加入已取消"),
                next = attempts.next() => next,
            };
            match next {
                Some((index, Ok(selected))) => {
                    tracing::debug!(
                        mode, candidate = index + 1, total, changed = selected.2 != registered,
                        "已选择原始 TCP 主机候选"
                    );
                    return Ok(selected);
                }
                Some((index, Err(error))) => tracing::debug!(
                    mode, candidate = index + 1, total,
                    reason = %crate::logging::redact(&error.to_string()), "原始 TCP 主机候选未取得配对回应"
                ),
                None => anyhow::bail!(FirstContact::NoReply { mode: mode.to_owned(), prediction: true }),
            }
        }
    }

    async fn join_mimic_candidates(
        &self,
        prepared: &mut crate::raw::CandidateReceiver,
        log: tcp_prediction::diagnostics::RoundLog,
        stun_lease: &mut Option<discovery::StunLease>,
        client: &crate::assistance::Client,
        state: &Value,
        round: uuid::Uuid,
        registered: SocketAddr,
        request: &Request,
        stop: &CancellationToken,
    ) -> Result<(Pipe, pairing::Ticket, SocketAddr)> {
        let trace = log.trace.clone();
        trace.stage("registered_candidate");
        let result = async {
            prepared.control.punch(registered, &[]).await?;
            trace.socket(0, prepared.control.source, registered, "punch_queued", None);
            let mut request = request.clone();
            request.id = conwu_core::id();
            let frame = pairing::encode(&request)?;
            let plan = client.raw_pair_candidates(state, round);
            tokio::pin!(plan);
            let deadline = tokio::time::sleep(MIMIC_CANDIDATE_WINDOW);
            tokio::pin!(deadline);
            let mut plan_received = false;
            let retry_interval = Duration::from_secs(1);
            let mut attempts = HashMap::<SocketAddr, (u8, tokio::time::Instant)>::new();
            let mut resend = tokio::time::interval(retry_interval);
            resend.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut buffer = [0; 2049];
            loop {
                tokio::select! {
                    _ = stop.cancelled() => anyhow::bail!("加入已取消"),
                    error = discovery::StunLease::lost(stun_lease) => {
                        trace.close("stun_lease_lost");
                        return Err(error);
                    }
                    _ = &mut deadline => {
                        trace.close("ticket_timeout");
                        anyhow::bail!(FirstContact::NoReply { mode: "mimic".into(), prediction: true });
                    }
                    result = &mut plan, if !plan_received => {
                        let candidates = result?;
                        trace.ports(0, &candidates.iter().map(|c| c.port()).collect::<Vec<_>>());
                        trace.stage("offer_received");
                        for candidate in &candidates {
                            if *candidate != registered {
                                prepared.control.punch(*candidate, &[]).await?;
                                trace.socket(0, prepared.control.source, *candidate, "punch_queued", None);
                            }
                        }
                        plan_received = true;
                        if !state["ProbePlan"].is_null() {
                            let reply_by = tokio::time::Instant::now() + crate::assistance::MIMIC_REPLY_WINDOW;
                            let end = reply_by.min(deadline.deadline());
                            deadline.as_mut().reset(end);
                        }
                        let _ = self.events.try_send(Event::Log {
                            level: "INFO".into(),
                            text: format!("Mimic 从机已准备同端口接收，尝试 {} 个主机候选", candidates.len()),
                        });
                    }
                    _ = async {
                        tokio::select! { _ = resend.tick() => {}, _ = prepared.wait_bridge() => {} }
                    } => {
                        for bridge in prepared.bridges() {
                            let now = tokio::time::Instant::now();
                            let (count, next) = attempts.entry(bridge).or_insert_with(|| {
                                trace.stage("bridge_opened");
                                (0, now)
                            });
                            if *count < 3 && now >= *next && prepared.socket.send_to(&frame, bridge).await.is_ok() {
                                *count += 1;
                                *next = now + retry_interval;
                                trace.stage("ticket_requested");
                            }
                        }
                    }
                    result = prepared.socket.recv_from(&mut buffer) => {
                        let (length, bridge) = result?;
                        let Some(peer) = prepared.peer(bridge) else { continue };
                        if let Some(ticket) = candidate_ticket(&buffer[..length], &request.id, state) {
                            trace.stage("ticket_validated");
                            let pipe = prepared.select(bridge, self, stop).await?;
                            trace.stage("bridge_selected");
                            trace.close("success");
                            return Ok((pipe, ticket, peer));
                        }
                    }
                }
            }
        }.await;
        if let Err(e) = &result {
            trace.error(e);
            if e.is::<crate::assistance::RawRoundExpired>() {
                trace.close("round_expired");
            } else if transient_signal(e) {
                trace.close("signal_failed");
            } else if !stop.is_cancelled() && !e.is::<FirstContact>() && !e.is::<discovery::StunLeaseLost>() {
                trace.close("pairing_failed");
            }
        }
        result
    }

    async fn join_peer(
        self: &Arc<Self>,
        id: &str,
        code: &DirectCode,
        exchange: &mut GuestExchange,
        name: &str,
        node_private: &str,
        requested_ip: &str,
        retained: Option<&conwu_core::rejoin::Credential>,
        assistance: Option<&(crate::assistance::Client, Value)>,
        coordinated_only: bool,
        stop: &CancellationToken,
    ) -> Result<()> {
        let mut target = code.clone();
        let stream_pair = stream_mode(&code.mode);
        let raw_prediction = raw_tcp_mode(&code.mode) &&
            assistance.is_some_and(|(_, state)| state["RawHostPrediction"] == true);
        let probe = assistance.map(|(_, state)| crate::assistance::ProbePlan::read(state, &code.mode))
            .transpose()?.flatten();
        ensure!(!coordinated_only || probe.is_some(), "协调服务器未提供统一探测配置");
        if raw_prediction {
            tracing::debug!(mode = %code.mode, "首次配对进入原始 TCP 主机端口预测");
        }
        if let Some((_, state)) = assistance {
            target.endpoint = crate::assistance::candidate(state["HostEndpoint"].as_str().unwrap())?;
            target.room = state["HostRoom"].as_str().unwrap().into();
        }
        let key = &exchange.key;
        // A lost first reply can leave the original commitment pending at the host.
        if let Some(credential) = retained && exchange.rejoin.as_ref().is_none_or(|(room, _)| room != &target.room) {
            exchange.rejoin = Some((target.room.clone(), credential.prove(&target.room, &key.commitment)?));
        }
        let rejoin = exchange.rejoin.as_ref().map(|(_, proof)| proof);
        let rejoin_digest = rejoin.map(|p| p.fingerprint()).transpose()?;
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
        // XDP initialization already has its own 45-second bound. The first
        // contact must allow that setup plus the bounded pairing RPC to finish.
        let initial_limit = if cfg!(windows) && code.mode == "mimic" { 55 } else { 8 };
        let initial = if coordinated_only || probe.is_some() { None } else {
            let direct = async {
                ensure!(!raw_prediction, "普通双向探测已完成，进入端口预测");
                #[cfg(feature = "lab-api")]
                anyhow::ensure!(
                    std::env::var_os("CONWU_LAB_FORCE_ASSISTANCE").is_none(),
                    "实验强制验证协同准备分支"
                );
                let mut pipe = if stream_pair {
                    // The stream can outlive the invitation after approval.
                    transport::connect(&code.mode, target.endpoint, "", true, &self.cancel).await?
                } else {
                    crate::raw::connect_ref(self, &code.mode, target.endpoint, 0, stop, "首次配对").await?
                };
                let ticket = rpc(&mut pipe, &mut request, stop)
                    .await?
                    .ticket
                    .context("主机没有返回配对会话")?;
                Ok::<_, anyhow::Error>((pipe, ticket))
            };
            Some(tokio::time::timeout(Duration::from_secs(initial_limit), direct).await)
        };
        let mut observation: Option<crate::raw::ClientObservation>;
        let mut stun_lease = None;
        let mut stream_peer = None;
        let (mut pipe, ticket) = match initial {
            Some(Ok(Ok(connected))) => {
                observation = None;
                connected
            }
            Some(Ok(Err(error))) if error.is::<crate::raw::LocalCarrierError>() => return Err(error),
            failure => 'coordinated: {
                if !code.punch && !code.coordinator {
                    return match failure {
                        Some(Ok(Err(e))) => Err(e),
                        _ => Err(anyhow::anyhow!(
                            "主机入口未回应配对，请确认地址、协议与可达性"
                        )),
                    };
                }
                self.guest_state(id,json!({"active":true,"owner":false,"state":"准备同端口候选，继续双向探测","expires":unix_seconds()+60})).await;
                let servers = if let Some(probe) = &probe {
                    vec![probe.observer.to_string()]
                } else {
                    crate::model::default_tcp_stun()
                };
                let mut mimic_candidates = None;
                let multiple_raw_candidates = raw_prediction
                    && assistance.is_some_and(|(_, state)| state["RawMultiCandidate"] == true);
                let scoped_mimic = cfg!(windows) && code.mode == "mimic" && multiple_raw_candidates;
                let mut candidate_log = multiple_raw_candidates.then(|| {
                    let trace = tcp_prediction::diagnostics::Trace::new(
                        uuid::Uuid::nil(), "first_pair", "dial", &code.mode,
                    );
                    trace.attempt(0, "dial");
                    trace.stage("observe_stun");
                    tcp_prediction::diagnostics::RoundLog::new(trace, &self.events)
                });
                let observers = if assistance.is_some() || stream_pair { &servers[..] } else { &servers[..1] };
                let observe = || crate::raw::observe_client(self, &code.mode, observers, scoped_mimic && probe.is_none(), stop);
                let mut observed = if probe.is_some() {
                    retry_pair_step("从机 TCP STUN 观察", discovery::transient_observer, |_| observe()).await?
                } else {
                    observe().await?
                };
                if let Some(log) = &candidate_log { log.trace.stage("stun_observed"); }
                let mut pipe = if stream_pair {
                    None
                } else {
                    if scoped_mimic {
                        // Capture must be ready before signalling; a cached host
                        // profile can produce its first SYN as soon as the round starts.
                        let log = candidate_log.as_mut().unwrap();
                        let prepare = async {
                            let prepared = tokio::time::timeout(Duration::from_secs(6),
                                observed.prepare_mimic_candidates(self, target.endpoint)).await.ok().and_then(Result::ok);
                            Ok::<_, anyhow::Error>(prepared)
                        };
                        let (prepared, lease) = tokio::try_join!(prepare, observed.retain_stun())?;
                        mimic_candidates = prepared;
                        if let Some(prepared) = &mimic_candidates {
                            log.trace.source(0, "mimic_helper");
                            log.mimic = Some((prepared.control.clone(), target.endpoint, true));
                        }
                        log.watch_mimic(&self.components, observed.local, target.endpoint);
                        log.stun_lease = Some(lease.status());
                        stun_lease = Some(lease);
                        log.trace.stage("stun_ready_checked");
                    }
                    let pipe = if raw_prediction { None } else {
                        observed.prepare_raw(self, &code.mode, target.endpoint, assistance.is_some(), stop).await?
                    };
                    pipe
                };
                observation = Some(observed);
                let observed = observation.as_mut().unwrap();
                if let Some(plan) = &probe {
                    ensure!(observed.observer == plan.observer, "从机 TCP STUN 与协调计划不符");
                    let _ = self.events.try_send(Event::Log { level: "INFO".into(), text: format!(
                        "{} 配对观测器 {}，公网端点 {}，探测配置 {}", code.mode, observed.observer, observed.mapped, plan.hash()?
                    ) });
                }
                // Use the scheduling and ordinary connect window to collect
                // the guest profile on the pinned observer.
                let _prewarm = if stream_pair && probe.is_some()
                    && assistance.is_some_and(|(_, state)| state["TcpPrediction"] == true)
                    && observed.mapped.ip() != target.endpoint.ip()
                    && let Some(path) = tcp_prediction::ObservedPath::new(observed.local, observed.mapped, observed.observer)
                {
                    let warmup = stop.child_token();
                    let cancel = warmup.clone();
                    let engine = self.clone();
                    self.tracker.spawn(async move { engine.prewarm_pair_prediction(path, &cancel).await; });
                    Some(warmup.drop_guard())
                } else {
                    None
                };
                let accept = if assistance.is_some() && stream_mode(&code.mode) {
                    transport::listener_on(observed.local).ok()
                } else {
                    None
                };
                let mut scheduled = None;
                if let Some((client, state)) = assistance {
                    let trace = candidate_log.as_ref().map(|log| log.trace.clone());
                    let endpoint = observed.mapped.to_string();
                    let room = state["Room"].as_str().unwrap();
                    let mut retry = String::new();
                    let negotiate = async {
                        loop {
                            let input = json!({"Token":state["Token"],"Endpoint":endpoint,"Ready":true,"RetryRound":retry,"ProbeHash":state["ProbeHash"]});
                            let input = &input;
                            let (update, round_trip) = retry_pair_step("同步双向探测", transient_signal, |_| async move {
                                let sent = Instant::now();
                                Ok((client.room(room, input).await?, sent.elapsed()))
                            }).await?;
                            ensure!(
                                [
                                    "Room",
                                    "Token",
                                    "HostRoom",
                                    "Commitment",
                                    "HostEndpoint",
                                    "Mode",
                                    "RawMultiCandidate",
                                    "ProbePlan",
                                    "ProbeHash"
                                ]
                                .iter()
                                .all(|k| update[*k] == state[*k]),
                                "协调辅助绑定已改变"
                            );
                            match crate::assistance::Schedule::read(&update, round_trip)? {
                                crate::assistance::Schedule::Ready(round, delay) => {
                                    if let Some(trace) = &trace {
                                        trace.set_round(round);
                                        if probe.is_some() { trace.stage("plan_confirmed"); }
                                    }
                                    tokio::select! {
                                        _=stop.cancelled()=>anyhow::bail!("加入已取消"),
                                        _=tokio::time::sleep(delay)=>{}
                                    }
                                    let phase = if raw_prediction { format!("已同步，正在等待 {} 主机端口预测", code.mode) }
                                        else { format!("已同步双向探测，正在尝试 {} 握手", code.mode) };
                                    self.guest_state(id,json!({"active":true,"owner":false,
                                        "state":phase,
                                        "expires":unix_seconds()+45})).await;
                                    return Ok((round, update));
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
                    };
                    scheduled = Some(tokio::select! {
                        result = tokio::time::timeout(Duration::from_secs(45), negotiate) =>
                            result.context("本轮协调探测超时，未授予成员权限")??,
                        error = discovery::StunLease::lost(&mut stun_lease) => {
                            if let Some(trace) = &trace {
                                trace.error(&error);
                                trace.close("stun_lease_lost");
                            }
                            return Err(error);
                        }
                    });
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
                let mut carrier_target = target.endpoint;
                if raw_prediction
                    && let Some((client, _)) = assistance
                    && let Some((round, state)) = scheduled.as_ref()
                    && state["RawMultiCandidate"] == true
                {
                    if let Some(mut prepared) = mimic_candidates {
                        let mut log = candidate_log.take().context("Mimic 配对诊断状态缺失")?;
                        let mut round = *round;
                        let mut state = state.clone();
                        let mut retries = 0;
                        let mut used_ports = vec![observed.local.port()];
                        let (pipe, ticket, selected) = loop {
                            match self.join_mimic_candidates(
                                &mut prepared, log, &mut stun_lease, client, &state, round,
                                target.endpoint, &request, stop,
                            ).await {
                                Ok(selected) => break selected,
                                Err(error) if retries < PAIRING_RETRIES && state["MimicRoundRetry"] == true
                                    && (error.is::<FirstContact>() || error.is::<crate::assistance::RawRoundExpired>()) =>
                                {
                                    let rotate = state["MimicEndpointRotation"] == true;
                                    let trace = tcp_prediction::diagnostics::Trace::new(uuid::Uuid::nil(), "first_pair", "dial", "mimic");
                                    trace.attempt(0, "dial");
                                    if rotate {
                                        prepared.finish().await;
                                        drop(stun_lease.take());
                                        trace.stage("rotate_stun_path");
                                        let local = observed.local;
                                        let observer = observed.observer;
                                        *observed = retry_pair_step("轮换 Mimic 从机映射", discovery::transient_observer,
                                            |_| crate::raw::ClientObservation::rotated(local, observer, &used_ports)).await?;
                                        used_ports.push(observed.local.port());
                                        prepared = observed.prepare_mimic_candidates(self, target.endpoint).await?;
                                        stun_lease = Some(observed.retain_stun().await?);
                                    }
                                    (round, state) = client.retry_mimic_round(&state, round, rotate.then_some(observed.mapped), stop).await?;
                                    retries += 1;
                                    trace.set_round(round);
                                    trace.source(0, "mimic_helper");
                                    trace.stage("plan_confirmed");
                                    log = tcp_prediction::diagnostics::RoundLog::new(trace, &self.events);
                                    log.mimic = Some((prepared.control.clone(), target.endpoint, true));
                                    log.watch_mimic(&self.components, observed.local, target.endpoint);
                                    log.stun_lease = stun_lease.as_ref().map(discovery::StunLease::status);
                                }
                                Err(error) if retries == PAIRING_RETRIES && error.is::<FirstContact>() => {
                                    anyhow::bail!("{error}（已自动重试 {retries} 次）");
                                }
                                Err(error) => return Err(error),
                            }
                        };
                        target.endpoint = selected;
                        break 'coordinated (pipe, ticket);
                    }
                    let log = candidate_log.take().context("原始 TCP 配对诊断状态缺失")?;
                    let trace = &log.trace;
                    trace.stage("await_candidates");
                    let observe = discovery::TcpAddresses { local: observed.local, mapped: observed.mapped, observer: observed.observer };
                    let candidates = async {
                        client.raw_pair_candidates(state, *round).await
                            .inspect_err(|e| {
                                trace.close("signal_failed"); trace.error(e);
                            })
                    };
                    let attempt = discovery::StunLease::during(observed.tcp_observation(), observe,
                        tokio::time::Instant::now() + Duration::from_secs(3), |status| trace.stun_lease(status), candidates,
                        |candidates| async {
                        self.guest_state(id,json!({"active":true,"owner":false,
                            "state":format!("正在用 {} 验证 {} 个主机入口", code.mode, candidates.len()),"expires":unix_seconds()+60})).await;
                        let ports: Vec<_> = candidates.iter().map(SocketAddr::port).collect();
                        trace.ports(0, &ports);
                        trace.stage("candidate_connect");
                        let _watch = if !cfg!(windows) && code.mode == "mimic" {
                            tcp_prediction::watch_fallback(&self.components, observed.local, target.endpoint, &ports, trace)
                        } else { None };
                        self.join_raw_candidates(
                            observed, &code.mode, state, target.endpoint, candidates, &request, stop, trace,
                        ).await.inspect_err(|e| {
                            trace.error(e); trace.close("no_valid_ticket");
                        })
                    });
                    let (pipe, ticket, selected) = tokio::select! {
                        _ = stop.cancelled() => anyhow::bail!("加入已取消"),
                        result = attempt => result?,
                        error = discovery::StunLease::lost(&mut stun_lease) => {
                            trace.error(&error);
                            trace.close("stun_lease_lost");
                            return Err(error);
                        }
                    };
                    trace.stage("bridge_selected");
                    trace.close("success");
                    target.endpoint = selected;
                    break 'coordinated (pipe, ticket);
                }
                let raw_round = if raw_prediction {
                    let (client, _) = assistance.context("原始 TCP 预测缺少协调服务")?;
                    let (round, state) = scheduled.as_ref().context("原始 TCP 预测缺少协调轮次")?;
                    carrier_target = client.raw_pair_target(state, *round).await?;
                    tracing::debug!(mode = %code.mode, changed = carrier_target != target.endpoint, "已选择原始 TCP 主机候选");
                    self.guest_state(id,json!({"active":true,"owner":false,
                        "state":format!("正在用 {} 验证主机入口", code.mode),"expires":unix_seconds()+60})).await;
                    pipe = observed.prepare_raw(self, &code.mode, carrier_target, true, stop).await?;
                    Some((client, *round, state))
                } else { None };
                if let Some(started) = observed.start(carrier_target, assistance.is_some(), stop).await? {
                    pipe = Some(started);
                }
                if pipe.is_none() {
                    let incoming = || accept_pair_source(accept.as_ref(), target.endpoint.ip());
                    let deadline = tokio::time::Instant::now() + scheduled.as_ref().map_or(FIRST_CONTACT_TCP_WINDOW, |(_, state)| coordinated_first_contact(state));
                    let regular = if accept.is_some() {
                        tokio::select! {
                            Ok(socket) = transport::tcp_open_from(target.endpoint, observed.local) => Ok(socket),
                            Ok(socket) = incoming() => Ok(socket),
                            _ = tokio::time::sleep_until(deadline) => Err(anyhow::anyhow!("首次配对同端口建连超时")),
                        }
                    } else {
                        transport::tcp_open_from(target.endpoint, observed.local).await
                    };
                    let socket = match regular {
                        Ok(socket) => socket,
                        Err(error) => {
                            let (Some((client, _)), Some((round, state))) = (assistance, &scheduled) else {
                                return Err(error);
                            };
                            if state["TcpPrediction"] != true {
                                return Err(error.context(FirstContact::NativeNoReply));
                            }
                            self.guest_state(id,json!({
                                "active":true,"owner":false,"state":"正在由协调服务器同步 TCP 端口预测",
                                "expires":unix_seconds()+30
                            })).await;
                            let path = tcp_prediction::ObservedPath::new(observed.local, observed.mapped, observed.observer)
                                .context("首次配对预测需要公网 IPv4")?;
                            let prediction = async {
                                tokio::time::sleep_until(deadline).await;
                                self.predict_room_path(
                                    client, state, false, path, observed.tcp_observation(),
                                    target.endpoint, *round, stop,
                                ).await
                            };
                            tokio::select! {
                                result = prediction => result.map_err(|error| {
                                    if transient_signal(&error) || discovery::transient_observer(&error) {
                                        error.context(FirstContact::NativeNoReply)
                                    } else {
                                        error
                                    }
                                })?.context(FirstContact::NativeNoReply)?,
                                Ok(socket) = incoming() => socket,
                            }
                        }
                    };
                    stream_peer = Some(socket.peer_addr()?);
                    pipe = Some(transport::client_socket(
                        &code.mode, socket, "", true, &self.cancel,
                    ).await?);
                }
                let mut pipe = pipe.unwrap();
                let rpc = rpc(&mut pipe, &mut request, stop);
                let reply = if let Some((client, round, state)) = raw_round {
                    // Queue the first carrier write before declaring readiness. The
                    // Mimic helper needs its initial flow to learn a changed peer port.
                    let announce = async {
                        client.raw_pair_update(state, round, None, true).await.map(|_| ())
                    };
                    tokio::try_join!(biased; rpc, announce).map(|(reply, ())| reply)
                } else {
                    rpc.await
                };
                let ticket = reply.map_err(|e| {
                        if scheduled.is_some() && raw_tcp_mode(&code.mode) &&
                            e.downcast_ref::<std::io::Error>().is_some_and(|e| matches!(e.kind(),
                                std::io::ErrorKind::TimedOut | std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe)) {
                            e.context(FirstContact::NoReply { mode: code.mode.clone(), prediction: raw_prediction })
                        } else {
                            anyhow::anyhow!("{}{}首次配对未取得主机会话：{e}",
                                if scheduled.is_some() { "协调已同步，" } else { "" }, code.mode)
                        }
                    })?
                    .ticket
                    .context("主机尚未回应同步探测")?;
                target.endpoint = carrier_target;
                (pipe, ticket)
            }
        };
        validate_pair_ticket(&ticket, assistance.map(|(_, state)| state))?;
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
                ensure!(profile.pair.mode == code.mode, "批准的承载与直连码不符");
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
                let keep_carrier = stream_pair || (assistance.is_some() && raw_tcp_mode(&code.mode));
                let (installed, wait_install) = oneshot::channel();
                self.events
                    .send(Event::Joined {
                        id: id.into(),
                        profile,
                        settings,
                        approved,
                        peer_name: ticket.host_name.clone(),
                        bootstrap: target.endpoint,
                        installed: keep_carrier.then_some(installed),
                        reply: send,
                    })
                    .await?;
                recv.await??;
                request.method = "received".into();
                request.offset = 0;
                let _ = if stream_pair {
                    rpc_with_wait(&mut pipe, &mut request, stop, Duration::from_millis(400)).await
                } else {
                    rpc(&mut pipe, &mut request, stop).await
                };
                self.guest_state(id,json!({"active":false,"owner":false,"state":"已加入网络","expires":ticket.expires})).await;
                if keep_carrier {
                    let engine = self.clone();
                    let id = id.to_owned();
                    let mode = code.mode.clone();
                    let peer = stream_peer.unwrap_or(target.endpoint);
                    let observation = observation.filter(|_| !stream_pair);
                    self.tracker.spawn(async move {
                        let _lease = observation;
                        tokio::select! {
                            _ = pipe.cancel.cancelled() => return,
                            ready = wait_install => if ready.is_err() { return; },
                        }
                        let Some(running) = engine.current(&id) else { return };
                        let closed = pipe.cancel.clone();
                        let serve = engine.serve(pipe, mode, peer, Some(id));
                        tokio::pin!(serve);
                        tokio::select! {
                            _ = running.cancel.cancelled() => { closed.cancel(); serve.await; }
                            _ = &mut serve => {}
                        }
                    });
                }
                return Ok(());
            }
            tokio::select! {_=stop.cancelled()=>anyhow::bail!("申请已取消"),_=tokio::time::sleep(Duration::from_millis(250))=>{}}
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
    fn member_greeting(&self, profile: &Profile) -> Result<Vec<u8>> {
        let mut peer = self.peer.lock().unwrap();
        let peer = peer.as_mut().context("尚无已批准成员")?;
        link::wrap(&profile.pair.network, &peer.link.hello()?)
    }

    #[cfg(windows)]
    pub(crate) fn projection_route(
        &self,
        network: &Network,
    ) -> Option<crate::projection::ProjectionRoute> {
        if self.cancel.is_cancelled()
            || !network.enabled || network.paused || !network.projection.allowed
            || self.metrics.read().unwrap().peer_paused
        {
            return None;
        }
        let profile = network.profile.as_ref().filter(|profile| profile.pair.direct)?;
        let current = self.config.read().unwrap();
        let local = current.profile.as_ref()?;
        let remote = remote_member(profile)?;
        if profile.pair.network != local.pair.network || profile.member != local.member
            || remote_member(local).as_ref() != Some(&remote)
        {
            return None;
        }
        let interface = {
            let guard = self.adapter.read().unwrap();
            let adapter = guard.as_ref()?;
            if adapter.provider() != "Official.Wintun" { return None; }
            adapter.route_interface(profile.local_ip().ok()?, member_ip(profile, &remote).ok()?)?
        };
        let guard = self.peer.lock().unwrap();
        let peer = guard.as_ref()?;
        let route = peer.routes.get(peer.chosen.as_ref()?)?;
        if !peer.link.connected() || !route.verified || route.cancel.is_cancelled() {
            return None;
        }
        let remote_port = peer.projection.as_ref().map_or(0, |ad| ad.port(peer.link.remote_epoch()));
        Some(crate::projection::ProjectionRoute {
            carrier: route.carrier.clone(),
            remote_port,
            sunshine_port: peer.sunshine.as_ref().map_or(0, |ad| ad.port(peer.link.remote_epoch())),
            companion_port: peer.projection_companion.as_ref().map_or(0, |ad| ad.port(peer.link.remote_epoch())),
            interface,
            video_datagrams: crate::projection::supports_video_datagrams(&local.pair.mode),
        })
    }

    #[cfg(windows)]
    pub(crate) fn routes_to_peer(&self, local: Ipv4Addr, peer: Ipv4Addr) -> bool {
        self.adapter.read().unwrap().as_ref().is_some_and(|adapter| adapter.routes_to_peer(local, peer))
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
                if self.adapter.read().unwrap().as_ref().is_some_and(|adapter| adapter.write(&packet).unwrap_or(false)) {
                    crate::uu::observe(&n.id, &packet, false);
                    self.metrics.write().unwrap().received += packet.len() as u64;
                } else {
                    self.metrics.write().unwrap().dropped += 1;
                }
            }
        }
        if let Some(payload) = received.synchronization {
            if route.verified {
                if let Some(endpoint) = crate::projection::parse(&payload) {
                    use crate::projection::{Advertisement, Endpoint};
                    match endpoint {
                        Endpoint::Legacy(port) => Advertisement::receive(&mut peer.projection, port, body),
                        Endpoint::Sunshine(port) => Advertisement::receive(&mut peer.sunshine, port, body),
                        Endpoint::Companion(port) => Advertisement::receive(&mut peer.projection_companion, port, body),
                    }
                } else if let Ok(Some(snapshot)) =
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
    rpc_with_wait(pipe, request, stop, Duration::from_secs(3)).await
}

async fn rpc_with_wait(
    pipe: &mut Pipe,
    request: &mut Request,
    stop: &CancellationToken,
    interval: Duration,
) -> Result<Reply> {
    request.id = conwu_core::id();
    let frame = pairing::encode(request)?;
    for _ in 0..3 {
        tokio::select! {
            _=stop.cancelled()=>anyhow::bail!("配对已取消"),
            r=pipe.tx.send(frame.clone())=>r.map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "配对承载已关闭"))?
        };
        let wait = async {
            while let Some(bytes) = pipe.rx.recv().await {
                if let Ok(reply) = pairing::decode::<Reply>(&bytes) {
                    if reply.id == request.id {
                        ensure!(reply.error.is_empty(), "{}", reply.error);
                        return Ok(reply);
                    }
                }
            }
            Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "配对承载已关闭，未收到对机回复").into())
        };
        match tokio::select! {_=stop.cancelled()=>anyhow::bail!("配对已取消"),r=tokio::time::timeout(interval,wait)=>r}
        {
            Ok(reply) => return reply,
            Err(_) => continue,
        }
    }
    let stage = match request.method.as_str() {
        "join" => "申请加入",
        "poll" => "查询配对状态",
        "reveal" => "交换校验信息",
        "chunk" => "接收已批准的网络配置",
        "received" => "确认配置已收到",
        _ => "配对请求",
    };
    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("等待主机回应超时（{stage}）")).into())
}
