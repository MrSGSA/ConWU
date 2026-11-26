pub(crate) mod diagnostics;
pub(super) mod wire;
mod raw_member;
pub(super) use raw_member::RawMemberReconnect;
use diagnostics::{RoundLog, Trace};
use super::{Engine, Running, remote_member};
use crate::{
    assistance::{Client, PredictionOffer, PredictionRole, PredictionUpdate, ProbePlan, RoomPredictionReply},
    discovery::{self, StunLease, StunLeaseLost, TcpAddresses, TcpObservation},
    transport,
};
use anyhow::{Context, Result, ensure};
use conwu_core::{
    identity::{Member, Profile},
    nat_tcp_punch::{
        burst::{AnchorSockets, Burst, BurstOptions, ConnectAttempt, PreparedAnchor, PreparedBurst},
        estimator::{
            BurstTiming, MappingObservation, NatPortEstimator, NatRegime, PortDomain, bracket_stride_span,
            has_anchor_phase_shift, rank_candidates_with_timing, short_bracket_candidates,
        },
        handover::{DialOptions, dial_candidates_observed, handover},
    },
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpStream, time};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_WARMUP_ROUNDS: usize = 10;
const STABLE_WARMUP_PAIRS: usize = 6;
const WARMUP_WAIT: Duration = Duration::from_secs(12);
const ANCHOR_GRACE: Duration = Duration::from_millis(150);
const OPEN_WAIT: Duration = crate::assistance::NATIVE_OPEN_WAIT;
const ATTEMPT_WINDOW: Duration = crate::assistance::NATIVE_ATTEMPT_WINDOW;
const PLAN_WAIT: Duration = Duration::from_secs(15);
const OFFER_WAIT: Duration = crate::assistance::NATIVE_OFFER_WAIT;
const SIGNAL_POLL: Duration = Duration::from_millis(250);
const PUBLISH_WAIT: Duration = Duration::from_millis(1500);
const RAW_SAMPLE_WAIT: Duration = Duration::from_secs(20);
const ANCHOR_REUSE_DELAY: Duration = Duration::from_secs(120);
const RAW_TAIL_DELAY: Duration = Duration::from_millis(4);
const RAW_MEMBER_OFFER_WAIT: Duration = Duration::from_secs(6);
const RAW_MEMBER_WINDOW: Duration = Duration::from_secs(8);
const FAKETCP_MEMBER_WINDOW: Duration = Duration::from_secs(12);
const FAKETCP_MESH_WAIT: Duration = Duration::from_secs(4);
const MIMIC_NO_PROGRESS: Duration = Duration::from_secs(7);

struct RawMemberTiming {
    round: Duration,
    offer: Duration,
    publish: Duration,
    mesh: Duration,
}

#[derive(Default)]
pub(super) struct SenderRecovery(Mutex<Option<SocketAddr>>);

impl SenderRecovery {
    async fn replacement(&self, path: ObservedPath, peer: SocketAddr) -> Result<Option<crate::raw::ClientObservation>> {
        if *self.0.lock().unwrap() != Some(peer) { return Ok(None); }
        let observation = crate::raw::ClientObservation::rotated(path.local.into(), path.observer.into(), &[]).await?;
        if observation.mapped.ip() != IpAddr::V4(*path.mapped.ip()) { return Err(ExitChanged.into()); }
        Ok(Some(observation))
    }

    fn missing_receipt(&self, peer: SocketAddr) { *self.0.lock().unwrap() = Some(peer); }

    fn authenticated(&self, peer: SocketAddr) {
        let mut failed = self.0.lock().unwrap();
        if *failed == Some(peer) { *failed = None; }
    }
}

impl RawMemberTiming {
    fn for_mode(mode: &str) -> Self {
        match mode {
            "mimic" => Self {
                round: Duration::from_secs(20), offer: Duration::from_secs(12),
                publish: Duration::from_secs(4), mesh: Duration::from_secs(4),
            },
            _ => Self {
                round: if mode == "faketcp" { FAKETCP_MEMBER_WINDOW } else { RAW_MEMBER_WINDOW },
                offer: RAW_MEMBER_OFFER_WAIT, publish: PUBLISH_WAIT,
                mesh: if mode == "faketcp" { FAKETCP_MESH_WAIT } else { super::RAW_CANDIDATE_WAIT },
            },
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct ObservedPath {
    local: SocketAddrV4,
    mapped: SocketAddrV4,
    observer: SocketAddrV4,
}

impl ObservedPath {
    pub(super) fn for_report(
        observation: TcpAddresses,
        endpoint: SocketAddr,
    ) -> Option<Self> {
        if observation.mapped != endpoint {
            return None;
        }
        Self::new(observation.local, observation.mapped, observation.observer)
    }

    pub(super) fn new(local: SocketAddr, mapped: SocketAddr, observer: SocketAddr) -> Option<Self> {
        let (SocketAddr::V4(local), SocketAddr::V4(mapped), SocketAddr::V4(observer)) =
            (local, mapped, observer)
        else {
            return None;
        };
        Some(Self { local, mapped, observer })
    }

    fn addresses(self) -> TcpAddresses {
        TcpAddresses {
            local: self.local.into(),
            mapped: self.mapped.into(),
            observer: self.observer.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Egress {
    observer: SocketAddrV4,
    interface: u32,
    local: Ipv4Addr,
    public: Ipv4Addr,
}

impl Egress {
    async fn read(path: ObservedPath) -> Result<Self> {
        let local = *path.local.ip();
        let interface =
            tokio::task::spawn_blocking(move || interface(path.observer, local)).await??;
        Ok(Self {
            observer: path.observer,
            interface,
            local,
            public: *path.mapped.ip(),
        })
    }
}

#[cfg(windows)]
fn interface(observer: SocketAddrV4, local: Ipv4Addr) -> Result<u32> {
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2},
        Networking::WinSock::{AF_INET, SOCKADDR_INET},
    };
    let mut target = SOCKADDR_INET::default();
    target.Ipv4.sin_family = AF_INET;
    target.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(observer.ip().octets());
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: The output structs and IPv4 destination are valid for GetBestRoute2.
    let valid = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &target,
            0,
            &mut route,
            &mut source,
        ) == 0
            && source.si_family == AF_INET
            && source.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes() == local.octets()
    };
    ensure!(valid, "TCP STUN 出口已改变");
    Ok(route.InterfaceIndex)
}

#[cfg(target_os = "linux")]
fn interface(observer: SocketAddrV4, local: Ipv4Addr) -> Result<u32> {
    let output = std::process::Command::new("ip")
        .args(["-j", "route", "get", &observer.ip().to_string()])
        .output()?;
    ensure!(output.status.success(), "TCP STUN 出口查询失败");
    let routes: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let row = &routes[0];
    let source: Ipv4Addr = row["prefsrc"]
        .as_str()
        .context("TCP STUN 出口缺少源地址")?
        .parse()?;
    ensure!(source == local, "TCP STUN 出口已改变");
    let name = std::ffi::CString::new(row["dev"].as_str().context("TCP STUN 出口缺少接口")?)?;
    // SAFETY: The interface name is NUL terminated for the duration of the call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    ensure!(index != 0, "TCP STUN 出口接口已消失");
    Ok(index)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn interface(_observer: SocketAddrV4, _local: Ipv4Addr) -> Result<u32> {
    anyhow::bail!("当前平台未提供 TCP 预测出口识别")
}

#[derive(Clone)]
struct Estimate {
    samples: usize,
    domain: PortDomain,
    alternate_domain: Option<PortDomain>,
    regime: NatRegime,
}

impl Estimate {
    fn role_hint(&self) -> Option<PredictionRole> {
        match self.regime {
            NatRegime::Strided { .. } => Some(PredictionRole::Strided),
            NatRegime::Sequential { .. } => Some(PredictionRole::Sequential),
            _ => None,
        }
    }

    fn budget(&self) -> Option<usize> {
        match self.regime {
            NatRegime::Sequential { .. } | NatRegime::Strided { .. } => Some(4),
            NatRegime::BoundedRandom { min, max } if u32::from(max) - u32::from(min) < 128 => {
                Some(16)
            }
            NatRegime::BoundedRandom { .. } | NatRegime::Random => None,
        }
    }

    fn candidates(&self, observation: MappingObservation) -> Vec<u16> {
        self.ranked(observation, None)
    }

    fn ranked(&self, observation: MappingObservation, timing: Option<BurstTiming>) -> Vec<u16> {
        let Some(limit) = self.budget() else {
            return Vec::new();
        };
        let rank = |domain| {
            let limit = if has_anchor_phase_shift(domain, observation, &self.regime)
                || timing.is_some() && bracket_stride_span(domain, observation, &self.regime).is_some_and(|span| span > 12)
            {
                limit.max(8)
            } else {
                limit
            };
            let limit = limit.max(short_bracket_candidates(domain, observation, &self.regime))
                .min(crate::assistance::MAX_PORTS);
            rank_candidates_with_timing(domain, observation, &self.regime, limit, timing)
        };
        let primary = rank(self.domain);
        let Some(domain) = self.alternate_domain.filter(|domain| {
            domain.contains(observation.p1)
                && observation.p2.is_none_or(|port| domain.contains(port))
        }) else {
            return primary;
        };
        let alternate = rank(domain);
        if alternate == primary {
            return primary;
        }

        // A fixed carrier port can cross the allocator boundary even when
        // neither anchor did. Preserve the ordering within each hypothesis.
        let mut ports = Vec::new();
        for i in 0..primary.len().max(alternate.len()) {
            for &port in [primary.get(i), alternate.get(i)].into_iter().flatten() {
                if !ports.contains(&port) {
                    ports.push(port);
                    if ports.len() == crate::assistance::MAX_PORTS {
                        return ports;
                    }
                }
            }
        }
        ports
    }
}

#[derive(Default)]
pub(super) struct Cache(Mutex<HashMap<SocketAddrV4, Arc<CachedEgress>>>);

struct CachedEgress {
    key: Egress,
    profile: tokio::sync::Mutex<Option<Estimate>>,
    raw_anchor_ports: Mutex<HashMap<u16, time::Instant>>,
    retired: CancellationToken,
}

impl Cache {
    pub(super) async fn refresh(&self, observation: TcpAddresses) {
        let Some(path) =
            ObservedPath::for_report(observation, observation.mapped)
        else {
            return;
        };
        let entry = self.0.lock().unwrap().get(&path.observer).cloned();
        if let Some(entry) = entry
            && Egress::read(path).await.as_ref().ok() != Some(&entry.key)
        {
            self.retire(&entry);
        }
    }

    fn entry(&self, key: Egress) -> Arc<CachedEgress> {
        let mut entries = self.0.lock().unwrap();
        if let Some(existing) = entries.get(&key.observer) {
            if existing.key == key {
                return existing.clone();
            }
            existing.retired.cancel();
        }
        let observer = key.observer;
        let entry = Arc::new(CachedEgress {
            key,
            profile: Default::default(),
            raw_anchor_ports: Default::default(),
            retired: CancellationToken::new(),
        });
        entries.insert(observer, entry.clone());
        entry
    }

    fn retire(&self, entry: &Arc<CachedEgress>) {
        let mut entries = self.0.lock().unwrap();
        if entries
            .get(&entry.key.observer)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            entries.remove(&entry.key.observer);
        }
        entry.retired.cancel();
    }
}

impl CachedEgress {
    fn reserve_raw_anchors(&self, middle: SocketAddrV4) -> std::io::Result<[PreparedAnchor; 2]> {
        let now = time::Instant::now();
        let mut recent = self.raw_anchor_ports.lock().unwrap();
        recent.retain(|_, used| now.duration_since(*used) < ANCHOR_REUSE_DELAY);
        let anchors = PreparedAnchor::around(middle, |port| !recent.contains_key(&port))?;
        for anchor in &anchors {
            recent.insert(anchor.port(), now);
        }
        Ok(anchors)
    }

    async fn estimate(
        &self,
        path: ObservedPath,
        stop: &CancellationToken,
        trace: Option<&Trace>,
    ) -> Result<Option<Estimate>> {
        // A directly addressable source can participate as the active dialer.
        if path.local == path.mapped {
            if let Some(t) = trace { t.profile(None, 0, "public_endpoint"); }
            return Ok(None);
        }
        let deadline = time::Instant::now() + WARMUP_WAIT;
        let Ok(mut profile) = time::timeout_at(deadline, self.profile.lock()).await else {
            if let Some(t) = trace { t.profile(None, 0, "profile_lock_timeout"); }
            return Ok(None);
        };
        if profile.is_none() {
            *profile = warmup(path, deadline, stop, trace).await?;
        } else if let (Some(t), Some(e)) = (trace, profile.as_ref()) {
            t.profile(Some(e), e.samples, "cached");
        }
        Ok(profile.clone())
    }
}

#[derive(Debug)]
struct ExitChanged;

impl std::fmt::Display for ExitChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TCP STUN 公网出口已改变")
    }
}

impl std::error::Error for ExitChanged {}

async fn start_burst(
    path: ObservedPath,
    peer: SocketAddrV4,
    warmup: bool,
    watch: Option<(std::path::PathBuf, Trace, usize)>,
    stop: &CancellationToken,
) -> Result<(Burst, Option<wire::Watch>)> {
    let stop = stop.clone();
    let burst = tokio::task::spawn_blocking(move || {
        ensure!(!stop.is_cancelled(), "TCP 预测已取消");
        let prepared = PreparedBurst::bind(BurstOptions {
            local_ip: *path.local.ip(),
            prefer_wide_delta_l: warmup,
        }).inspect_err(|_| {
            if let Some((_, trace, _)) = &watch {
                trace.stage("adjacent_ports_unavailable");
            }
        })?;
        ensure!(!stop.is_cancelled(), "TCP 预测已取消");
        let watch = watch.and_then(|(components, trace, attempt)| {
            trace.local_ports(attempt, prepared.local_ports());
            let source = SocketAddrV4::new(*path.local.ip(), prepared.local_ports().1);
            let watch = wire::Watch::open(
                &components, source, *peer.ip(), wire::PeerPorts::Burst(peer.port()), &trace, attempt,
            );
            trace.socket(attempt, source.into(), peer.into(), "connect", None);
            watch
        });
        let burst = prepared.connect([path.observer, peer, path.observer]);
        if warmup {
            // The middle open also goes to the observer during warmup.
            // Its tuple must be reusable if it becomes a formal anchor.
            burst.middle.socket.set_linger(Some(Duration::ZERO))?;
        }
        Ok::<_, anyhow::Error>((burst, watch))
    })
    .await??;
    tracing::debug!(elapsed = ?burst.0.connect_elapsed, warmup, "TCP 预测三连发");
    Ok(burst)
}

async fn reflect(
    attempt: ConnectAttempt,
    stop: &CancellationToken,
) -> Result<SocketAddr> {
    let began = time::Instant::now();
    let budget = discovery::TCP_OBSERVER_ATTEMPT;
    time::timeout(budget, async {
        let socket = attempt.into_socket()?;
        // Reusing the port against the same STUN listener can fail on Windows
        // while an earlier anchor's gracefully closed tuple is in TIME_WAIT.
        socket.set_linger(Some(Duration::ZERO))?;
        let mut stream = handover(socket, budget, stop).await?;
        let reply = discovery::stun_tcp(&mut stream).await;
        time::sleep_until(began + ANCHOR_GRACE).await;
        reply
    })
    .await?
}

async fn observe_anchors(
    anchors: AnchorSockets,
    ports: (u16, u16, u16),
    expected: Ipv4Addr,
    stop: &CancellationToken,
) -> Result<MappingObservation> {
    observe_anchor_pair(anchors.first, anchors.last, ports, expected, stop, |_, _| {}).await
}

async fn observe_anchor_pair(
    first: ConnectAttempt,
    last: ConnectAttempt,
    ports: (u16, u16, u16),
    expected: Ipv4Addr,
    stop: &CancellationToken,
    report: impl Fn(u16, &Result<SocketAddr>),
) -> Result<MappingObservation> {
    let (head, tail) = tokio::join!(reflect(first, stop), reflect(last, stop));
    report(ports.0, &head);
    report(ports.2, &tail);
    let p1 = head.context(MissingFirstAnchor)?;
    let p2 = tail.ok();
    if p1.ip() != expected || p2.is_some_and(|address| address.ip() != expected) {
        return Err(ExitChanged.into());
    }
    let (l1, l_mid, l2) = ports;
    Ok(MappingObservation {
        l1,
        l_mid,
        l2,
        p1: p1.port(),
        p2: p2.map(|address| address.port()),
    })
}

#[derive(Debug)]
struct MissingFirstAnchor;

impl std::fmt::Display for MissingFirstAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TCP STUN 首锚点未收到有效回复")
    }
}

impl std::error::Error for MissingFirstAnchor {}

async fn warmup(
    path: ObservedPath,
    deadline: time::Instant,
    stop: &CancellationToken,
    trace: Option<&Trace>,
) -> Result<Option<Estimate>> {
    let mut samples = 0;
    let mut estimator = NatPortEstimator::default();
    let mut pairs = 0;
    for _ in 0..MAX_WARMUP_ROUNDS {
        let sample = async {
            let (burst, _) = start_burst(path, path.observer, true, None, stop).await?;
            let observation = observe_anchors(
                burst.anchors,
                burst.local_ports,
                *path.mapped.ip(),
                stop,
            ).await;
            Ok::<_, anyhow::Error>(observation)
        };
        let Ok(sample) = time::timeout_at(deadline, sample).await else { break };
        let sample = sample?;
        match sample {
            Ok(observation) => {
                samples += 1;
                pairs += usize::from(observation.p2.is_some());
                estimator.observe(observation);
            }
            Err(error) if error.is::<ExitChanged>() => return Err(error),
            Err(_) => continue,
        }
        if pairs >= STABLE_WARMUP_PAIRS && estimator.regime().is_some() {
            break;
        }
    }
    tracing::debug!(complete_pairs = pairs, "TCP STUN 热身结束");
    let profile = estimator.regime().cloned().map(|regime| Estimate {
        samples,
        domain: estimator.domain(),
        alternate_domain: estimator.alternate_domain(),
        regime,
    });
    if let Some(t) = trace { t.profile(profile.as_ref(), samples, "warmup"); }
    Ok(profile)
}

enum Signal<'a> {
    Member { profile: &'a Profile, peer: &'a Member, boot: Uuid },
    Room { state: &'a serde_json::Value, slot: u8 },
}

struct Feedback {
    senders: Option<Vec<u8>>,
    offer: Option<PredictionOffer>,
}

struct SenderPlan {
    senders: Vec<u8>,
    local_slot: u8,
    can_burst: bool,
    role_hint: Option<PredictionRole>,
}

pub(super) fn member_link_verified(running: &Running, endpoint: Option<SocketAddr>) -> bool {
    running.peer.lock().unwrap().as_ref().is_some_and(|peer| {
        peer.link.connected() && peer.routes.values().any(|route| {
            route.verified && !route.cancel.is_cancelled() && endpoint.is_none_or(|value| route.endpoint == value)
        })
    })
}

async fn wait_for_member_link(running: &Running, deadline: time::Instant, endpoint: Option<SocketAddr>) -> bool {
    loop {
        if member_link_verified(running, endpoint) { return true; }
        let now = time::Instant::now();
        if now >= deadline { return false; }
        tokio::select! {
            _ = running.cancel.cancelled() => return false,
            _ = time::sleep_until((now + Duration::from_millis(35)).min(deadline)) => {}
        }
    }
}

struct Session<'a> {
    trace: Trace,
    components: &'a std::path::Path,
    client: &'a Client,
    signal: Signal<'a>,
    round: Uuid,
    plan_hash: Option<String>,
    path: ObservedPath,
    observation: &'a tokio::sync::Mutex<Option<TcpObservation>>,
    target: SocketAddrV4,
    stop: &'a CancellationToken,
}

impl Session<'_> {
    async fn signal(
        &self,
        can_burst: bool,
        role_hint: Option<PredictionRole>,
        offer: Option<PredictionOffer>,
        peer_attempt: Option<usize>,
    ) -> Result<Feedback> {
        let update = PredictionUpdate { round: self.round, can_burst, offer, role_hint, plan_hash: self.plan_hash.clone() };
        match &self.signal {
            Signal::Member { profile, peer, boot } => {
                let reply = self.client.prediction(profile, *boot, self.path.mapped.into(), update).await?;
                let offer = if let Some(attempt) = peer_attempt {
                    reply.peer_offer(&profile.pair.network, peer, self.target.into(), &profile.pair.mode, attempt)?
                        .cloned()
                } else {
                    None
                };
                Ok(Feedback { senders: reply.senders, offer })
            }
            Signal::Room { state, .. } => {
                let room = state["Room"].as_str().context("配对房间编号缺失")?;
                let reply = self.client.room(room, &serde_json::json!({"Token":state["Token"],"PredictionUpdate":update})).await?;
                ensure!(
                    ["Room", "Token", "HostRoom", "Commitment", "HostEndpoint", "GuestEndpoint", "Mode", "ProbePlan", "ProbeHash"]
                        .iter().all(|key| reply[*key] == state[*key])
                        && reply["TcpPrediction"] == true,
                    "首次配对预测与本轮端点不符"
                );
                let reply: RoomPredictionReply = serde_json::from_value(reply["Prediction"].clone())?;
                ensure!(reply.round == self.round, "首次配对预测轮次已改变");
                let offer = peer_attempt.and_then(|attempt| reply.offers.get(attempt)?.clone());
                if let Some(offer) = &offer {
                    PredictionUpdate { round: self.round, can_burst: true, offer: Some(offer.clone()), ..Default::default() }.validate()?;
                    ensure!(Some(usize::from(offer.attempt)) == peer_attempt, "端口预测候选序号无效");
                }
                Ok(Feedback { senders: reply.senders, offer })
            }
        }
    }

    async fn poll<T>(
        &self,
        can_burst: bool,
        role_hint: Option<PredictionRole>,
        wait: Duration,
        peer_attempt: Option<usize>,
        read: impl Fn(Feedback) -> Option<T>,
    ) -> Result<Option<T>> {
        let responses = async {
            loop {
                if let Some(value) = read(self.signal(can_burst, role_hint, None, peer_attempt).await?) {
                    return Ok(Some(value));
                }
                time::sleep(SIGNAL_POLL).await;
            }
        };
        time::timeout(wait, responses).await.unwrap_or(Ok(None))
    }

    async fn plan(&self, estimate: Option<&Estimate>) -> Result<Option<SenderPlan>> {
        let can_burst = estimate.is_some_and(|e| e.budget().is_some());
        let role_hint = estimate.and_then(Estimate::role_hint);
        self.trace.stage(if can_burst { "offer_sender_role" } else { "offer_dial_only" });
        let Some(senders) = self
            .poll(can_burst, role_hint, PLAN_WAIT, None, |reply| reply.senders)
            .await?
        else {
            self.trace.close("plan_timeout");
            return Ok(None);
        };
        let (local_slot, peer_slot) = match self.signal {
            Signal::Member { profile, peer, .. } => (profile.member.slot, peer.slot),
            Signal::Room { slot, .. } => (slot, 1 - slot),
        };
        ensure!(
            senders.len() <= 2
                && senders
                    .iter()
                    .all(|slot| *slot == local_slot || *slot == peer_slot),
            "TCP 预测调度无效"
        );
        ensure!(!can_burst || !senders.is_empty(), "协调器遗漏了可用预测发送端");
        ensure!(can_burst || !senders.contains(&local_slot), "协调器分配了本端无法执行的发送角色");
        self.trace.stage("plan_confirmed");
        if senders.is_empty() {
            self.trace.close("neither_can_burst");
            return Ok(None);
        }
        Ok(Some(SenderPlan { senders, local_slot, can_burst, role_hint }))
    }

    async fn run(&self, estimate: Option<Estimate>) -> Result<Option<TcpStream>> {
        let Some(SenderPlan { senders, local_slot, can_burst, role_hint }) = self.plan(estimate.as_ref()).await? else { return Ok(None); };
        let mut last_error = None;
        let attempts = senders.len();
        for (attempt, sender) in senders.into_iter().enumerate() {
            let next = time::Instant::now() + ATTEMPT_WINDOW;
            self.trace.attempt(attempt, if sender == local_slot { "burst" } else { "dial" });
            let result = if sender == local_slot {
                let estimate = estimate.as_ref().context("TCP 预测没有本机画像")?;
                self.burst(estimate, attempt as u8).await
            } else {
                self.dial(can_burst, role_hint, attempt).await
            };
            match result {
                Ok(Some(stream)) => return Ok(Some(stream)),
                Ok(None) => {}
                Err(error) if error.is::<ExitChanged>() || error.is::<StunLeaseLost>() => {
                    return Err(error);
                }
                Err(error) => {
                    self.trace.error(&error);
                    self.trace.close("attempt_failed");
                    if last_error.is_none() || error.chain().any(|e| e.downcast_ref::<std::io::Error>().is_some_and(|e| e.raw_os_error().is_some())) {
                        last_error = Some(error);
                    }
                }
            }
            if attempt + 1 < attempts {
                time::sleep_until(next).await;
            }
        }
        if let Some(error) = last_error { return Err(error); }
        Ok(None)
    }

    async fn run_raw(&self, engine: &Arc<Engine>, running: &Arc<Running>, n: &crate::model::Network,
        entry: &CachedEgress, estimate: Option<&Estimate>, isolated: Option<&crate::raw::MemberReceiver>,
    ) -> Result<bool> {
        let Some(SenderPlan { senders, local_slot, can_burst, role_hint }) = self.plan(estimate).await? else { return Ok(false); };
        let mode = n.settings.mode()?;
        let timing = RawMemberTiming::for_mode(mode);
        let mut result = Ok(false);
        let attempts = senders.len();
        for (attempt, sender) in senders.into_iter().enumerate() {
            let next = time::Instant::now() + timing.round;
            self.trace.attempt(attempt, if sender == local_slot { "burst" } else { "dial" });
            let _mimic_events = isolated.filter(|_| mode == "mimic").map(|receiver| raw_member::AttemptLog::new(
                &receiver.control, self.target.into(), &self.trace, attempt,
            ));
            let operation = async { if sender == local_slot {
                // The router may retain the previous member tuple even after the
                // local receiver and helper have been replaced. Use a distinct
                // STUN-bound sender port so the middle SYN allocates a new mapping.
                let fresh = if mode == "faketcp" {
                    self.trace.stage("prepare_fresh_sender");
                    Some(engine.faketcp_receiver(self.path.local.port())?.fresh_sender(engine).await?)
                } else { None };
                let mut recovery = if mode != "faketcp" && isolated.is_none() && let Some(observed) =
                    running.raw_sender_recovery.replacement(self.path, self.target.into()).await? {
                    self.trace.stage("prepare_fresh_sender");
                    let path = ObservedPath::new(observed.local, observed.mapped, observed.observer).context("无有效的恢复发送端映射")?;
                    let receiver = observed.recovery_receiver(engine, mode, self.target.into()).await?;
                    Some((path, observed, receiver))
                } else { None };
                let (replacement, receiver) = match &mut recovery {
                    Some((path, observed, receiver)) => (Some((*path, observed.tcp_observation())), Some(receiver)),
                    None => (None, None),
                };
                let (path, observation) = if let Some(mapping) = &fresh {
                    let mapped = mapping.mapped();
                    if mapped.ip() != IpAddr::V4(*self.path.mapped.ip()) { return Err(ExitChanged.into()); }
                    let path = ObservedPath::new(mapping.local, mapped, mapping.observer)
                        .context("FakeTCP 新发送端未取得公网映射")?;
                    (path, mapping.observation())
                } else { replacement.unwrap_or((self.path, self.observation)) };
                let control = isolated.map(|receiver| &receiver.control)
                    .or_else(|| receiver.as_ref().map(|receiver| &receiver.control)).cloned();
                if isolated.is_some() {
                    self.trace.stage("prepare_fresh_sender");
                }
                let _capture = (mode == "faketcp").then(|| wire::Watch::open(
                    self.components, path.local, *self.target.ip(),
                    wire::PeerPorts::Burst(self.target.port()), &self.trace, attempt,
                )).flatten();
                let punch = RawPunch { mode, path, peer: self.target.into(), client: false, fake: fresh.as_deref(),
                    control: control.as_ref(), member: true, trace: &self.trace, attempt, stop: self.stop };
                let result = StunLease::during(observation, path.addresses(), next,
                    |status| self.trace.stun_lease(status), async { Ok(()) }, |_| async {
                        let sample = async {
                            let registered = path.mapped.port();
                            let first = punch.candidates(engine, entry, estimate, registered).await;
                            if mode == "tcpraw" && (matches!(&first, Ok((_, false)))
                                || first.as_ref().is_err_and(|error| error.is::<MissingFirstAnchor>()))
                            {
                                self.trace.stage("resample_anchors");
                                return punch.candidates(engine, entry, estimate, registered).await;
                            }
                            first
                        };
                        let sampled = time::timeout(RAW_MEMBER_OFFER_WAIT, sample).await;
                        let ports = match sampled {
                            Ok(Ok((ports, true))) => ports,
                            Ok(Ok((_, false))) => { self.trace.stage("anchors_incomplete"); Vec::new() },
                            Ok(Err(error)) if error.is::<ExitChanged>() => return Err(error),
                            Ok(Err(error)) if error.is::<MissingSynReceipt>() => {
                                if isolated.is_none() {
                                    running.raw_sender_recovery.missing_receipt(self.target.into());
                                }
                                self.trace.stage("helper_receipt_missing");
                                self.trace.error(&error);
                                Vec::new()
                            }
                            Ok(Err(error)) => { self.trace.stage("anchors_failed"); self.trace.error(&error); Vec::new() },
                            Err(_) => { self.trace.stage("anchor_sample_timeout"); Vec::new() },
                        };
                        let sampled = !ports.is_empty();
                        self.trace.ports(attempt, &ports);
                        let offer = PredictionOffer { attempt: attempt as u8, ports };
                        time::timeout(timing.publish, self.signal(can_burst, role_hint, Some(offer), None)).await??;
                        self.trace.stage("offer_published");
                        if !sampled { return Ok(false); }
                        if let Some(receiver) = receiver {
                            loop {
                                if let Some((bridge, peer)) = receiver.bridges().into_iter().find_map(|bridge|
                                    receiver.peer(bridge).filter(|peer| peer.ip() == IpAddr::V4(*self.target.ip())).map(|peer| (bridge, peer)))
                                {
                                    let pipe = receiver.select(bridge, engine, &running.cancel).await?;
                                    let lifetime = pipe.cancel.clone().drop_guard();
                                    engine.tracker.spawn(engine.clone().serve(pipe, mode.to_owned(), peer, None));
                                    if wait_for_member_link(running, next, Some(peer)).await {
                                        lifetime.disarm();
                                        running.raw_sender_recovery.authenticated(self.target.into());
                                        return Ok(true);
                                    }
                                    return Ok(false);
                                }
                                receiver.wait_bridge().await;
                            }
                        }
                        // FakeTCP's burst worker is already the server for this round.
                        // A normal dial could replace it with a worker in another role.
                        if let Some(receiver) = isolated {
                            receiver.control.punch(self.target.into(), &running.member_greeting(n.profile.as_ref().unwrap())?).await?;
                            if mode == "mimic" && attempt + 1 == attempts {
                                return Ok(tokio::select! {
                                    result = wait_for_member_link(running, next, None) => result,
                                    _ = self.wait_for_mimic_retirement(can_burst, role_hint) => {
                                        self.trace.stage("peer_round_retired");
                                        false
                                    }
                                });
                            }
                        } else if mode != "faketcp" {
                            let _ = engine.dial_reserved(&n.id, self.target.into(), running).await;
                        }
                        Ok(wait_for_member_link(running, next, None).await)
                    }).await;
                if matches!(result, Ok(true)) && let Some(mapping) = fresh {
                    let endpoint = SocketAddr::V4(self.target);
                    let guard = running.peer.lock().unwrap().as_ref().and_then(|peer| {
                        peer.routes.values().find(|route| {
                            route.verified && route.endpoint == endpoint && !route.cancel.is_cancelled()
                        }).map(|route| route.cancel.clone())
                    });
                    if let Some(route) = guard {
                        engine.tracker.spawn(async move {
                            tokio::select! { _ = route.cancelled() => {}, _ = mapping.cancel.cancelled() => {} }
                            let _ = mapping.close().await;
                        });
                    }
                }
                result
            } else {
                if isolated.is_some() {
                    self.trace.stage("prepare_fresh_dialer");
                }
                self.trace.stage("await_candidates");
                let offer = async {
                    let ports = self.poll(can_burst, role_hint, timing.offer, Some(attempt), |r| r.offer.map(|o| o.ports)).await?;
                    if mode == "mimic" && ports.is_some() { self.trace.stage("offer_received"); }
                    Ok(ports)
                };
                StunLease::during(self.observation, self.path.addresses(), next,
                    |status| self.trace.stun_lease(status), offer, |ports| async {
                        let Some(ports) = ports else { self.trace.close("offer_timeout"); return Ok(false); };
                        if ports.is_empty() { self.trace.close("empty_offer"); return Ok(false); }
                        self.trace.ports(attempt, &ports);
                        self.trace.stage("candidate_connect");
                        self.dial_raw(engine, running, n, attempt, ports, next, timing.mesh, isolated, attempt + 1 == attempts).await
                    }).await
            }};
            match time::timeout_at(next, operation).await.unwrap_or_else(|_| {
                self.trace.close("round_deadline");
                Ok(false)
            }) {
                Ok(true) => return Ok(true),
                Err(error) if error.is::<ExitChanged>() || error.is::<StunLeaseLost>() => return Err(error),
                Err(error) => { self.trace.error(&error); result = Err(error); },
                Ok(false) => {},
            }
            if attempt + 1 < attempts {
                if wait_for_member_link(running, next, None).await { return Ok(true); }
            }
        }
        result
    }

    async fn wait_for_mimic_retirement(&self, can_burst: bool, role_hint: Option<PredictionRole>) {
        time::sleep(MIMIC_NO_PROGRESS).await;
        loop {
            if let Err(error) = self.signal(can_burst, role_hint, None, None).await
                && error.chain().any(|cause| {
                    let reason = cause.to_string();
                    reason.ends_with("端口预测轮次无效或过期") || reason.ends_with("端口预测的成员或出口已改变")
                })
            {
                return;
            }
            time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn dial_raw(&self, engine: &Arc<Engine>, running: &Arc<Running>, network: &crate::model::Network,
        attempt: usize, ports: Vec<u16>, round_deadline: time::Instant, mesh_wait: Duration,
        isolated: Option<&crate::raw::MemberReceiver>, final_attempt: bool,
    ) -> Result<bool> {
        use futures_util::StreamExt;

        let mode = network.settings.mode()?;
        let fake = (mode == "faketcp")
            .then(|| engine.faketcp_receiver(self.path.local.port())).transpose()?;
        let fake = fake.as_ref();
        let _capture = fake.and_then(|_| wire::Watch::open(
            self.components, self.path.local, *self.target.ip(),
            wire::PeerPorts::Candidates(&ports), &self.trace, attempt,
        ));
        let last_mimic_candidate = Mutex::new(None);
        let last_mimic_start = &last_mimic_candidate;
        let candidates = ports.into_iter().map(|port| SocketAddrV4::new(*self.target.ip(), port).into());
        let sweep = super::raw_candidate_attempts(candidates, |_, target| async move {
            if member_link_verified(running, Some(target)) { return true; }
            self.trace.socket(attempt, self.path.local.into(), target, "candidate_started", None);
            if mode == "mimic" && isolated.is_some() && final_attempt {
                *last_mimic_start.lock().unwrap() = Some(time::Instant::now());
            }
            let deadline = time::Instant::now() + super::RAW_CANDIDATE_HELPER_WAIT;
            let open = async {
                if let Some(mapping) = fake {
                    let pipe = mapping.member_candidate_pipe(target, &running.cancel).await?;
                    let guard = pipe.cancel.clone().drop_guard();
                    let server = engine.clone();
                    let id = network.id.clone();
                    engine.tracker.spawn(async move {
                        server.serve(pipe, "faketcp".into(), target, Some(id)).await;
                    });
                    return Ok(Some(guard));
                }
                if let Some(receiver) = isolated {
                    let control = &receiver.control;
                    // A peer's first SYN can establish this tuple before its candidate is scheduled.
                    // In that case still enqueue the member greeting, even if the probe is rejected.
                    if mode == "mimic" {
                        match control.probe(target, Duration::from_millis(750), Some(self.round)).await {
                            Ok(_) => self.trace.socket(attempt, self.path.local.into(), target, "syn_confirmed_by_helper", None),
                            Err(error) => {
                                let io = error.chain().find_map(|cause| cause.downcast_ref::<std::io::Error>());
                                self.trace.socket(attempt, self.path.local.into(), target, "syn_unconfirmed", io);
                            }
                        }
                    }
                    let greeting = running.member_greeting(network.profile.as_ref().unwrap())?;
                    control.punch(target, &greeting).await?;
                    return Ok(None);
                }
                engine.dial_reserved(&network.id, target, running).await.map(|()| None)
            };
            match time::timeout_at(deadline, open).await {
                Ok(Ok(guard)) => {
                    if guard.is_some() {
                        self.trace.socket(attempt, self.path.local.into(), target, "bridge_ready", None);
                    }
                    let deadline = (time::Instant::now() + mesh_wait).min(round_deadline);
                    let ready = wait_for_member_link(running, deadline, Some(target)).await;
                    if guard.is_some() {
                        let stage = if ready { "mesh_verified" } else { "mesh_deadline" };
                        self.trace.socket(attempt, self.path.local.into(), target, stage, None);
                    }
                    if ready && let Some(guard) = guard { guard.disarm(); }
                    ready
                }
                Ok(Err(error)) => {
                    let io = error.chain().find_map(|cause| cause.downcast_ref::<std::io::Error>());
                    self.trace.socket(attempt, self.path.local.into(), target, "candidate_failed", io);
                    false
                }
                Err(_) => {
                    self.trace.socket(attempt, self.path.local.into(), target, "deadline", None);
                    false
                }
            }
        });
        tokio::pin!(sweep);
        while let Some(ready) = sweep.next().await {
            if ready { return Ok(true); }
        }
        if mode == "mimic" {
            let started = *last_mimic_candidate.lock().unwrap();
            if let (Some(receiver), Some(last)) = (isolated, started) {
                let check = (last + MIMIC_NO_PROGRESS).min(round_deadline);
                if wait_for_member_link(running, check, None).await {
                    return Ok(true);
                }
                if !raw_member::mimic_handshake_progress(&receiver.control, IpAddr::V4(*self.target.ip()), self.trace.started_unix_ms()) {
                    self.trace.stage("mimic_candidates_exhausted");
                    return Ok(false);
                }
            }
            // A launched pipe can still authenticate after its candidate wait.
            return Ok(wait_for_member_link(running, round_deadline, None).await);
        }
        Ok(false)
    }

    async fn burst(&self, estimate: &Estimate, attempt: u8) -> Result<Option<TcpStream>> {
        let n = usize::from(attempt);
        let publish = |ports| async move {
            time::timeout(PUBLISH_WAIT, self.signal(true, estimate.role_hint(), Some(PredictionOffer { attempt, ports }), None)).await??;
            Ok::<_, anyhow::Error>(())
        };
        self.trace.stage("burst");
        let (burst, _watch) = match start_burst(self.path, self.target, false,
            Some((self.components.to_owned(), self.trace.clone(), n)), self.stop).await {
            Ok(burst) => burst,
            Err(error) => {
                if !self.stop.is_cancelled() {
                    let _ = publish(Vec::new()).await;
                }
                return Err(error);
            }
        };
        let local = SocketAddrV4::new(*self.path.local.ip(), burst.local_ports.1).into();
        let mut handoff = std::pin::pin!(Some(async {
            let result = async { handover(burst.middle.into_socket()?, OPEN_WAIT, self.stop).await }.await;
            self.trace.socket(n, local, self.target.into(),
                if result.is_ok() { "established" } else { "middle_failed" }, result.as_ref().err());
            result
        }));
        let mut middle = handoff.as_mut().as_pin_mut().expect("middle connection was prepared");
        let anchors = observe_anchors(burst.anchors, burst.local_ports, *self.path.mapped.ip(), self.stop);
        tokio::pin!(anchors);
        let mut connected = None;
        let observation = tokio::select! {
            biased;
            result = &mut middle => match result {
                Err(error) => {
                    self.trace.stage("middle_failed_before_offer");
                    // Empty offers are terminal for this attempt and wake the dialer.
                    let _ = publish(Vec::new()).await;
                    return Err(error.into());
                }
                Ok(stream) => { connected = Some(stream); anchors.await }
            },
            observation = &mut anchors => observation,
        };
        let mut failed_member_anchors = false;
        let ports = match observation {
            Ok(o) => {
                self.trace.anchors(n, o);
                if matches!(self.signal, Signal::Member { .. }) && o.p2.is_none() {
                    self.trace.stage("anchors_incomplete");
                    failed_member_anchors = true;
                    Vec::new()
                } else {
                    estimate.candidates(o)
                }
            }
            Err(e) if e.is::<ExitChanged>() => return Err(e),
            Err(e) => {
                self.trace.stage("anchors_failed");
                self.trace.error(&e);
                failed_member_anchors = matches!(self.signal, Signal::Member { .. });
                Vec::new()
            }
        };
        self.trace.ports(n, &ports);
        if let Some(stream) = connected {
            self.trace.stage(if publish(ports).await.is_ok() { "offer_published" } else { "offer_signal_failed" });
            return Ok(Some(stream));
        }
        // The anchors and socket may have become ready on the same scheduler tick.
        // Poll once more before committing an immutable offer to the coordinator.
        use futures_util::FutureExt;
        if let Some(result) = middle.as_mut().now_or_never() {
            match result {
                Ok(stream) => {
                    self.trace.stage(if publish(ports).await.is_ok() { "offer_published" } else { "offer_signal_failed" });
                    return Ok(Some(stream));
                }
                Err(error) => {
                    self.trace.stage("middle_failed_before_offer");
                    if failed_member_anchors {
                        self.trace.stage("middle_finished_with_failed_anchors");
                    }
                    let _ = publish(Vec::new()).await;
                    return Err(error.into());
                }
            }
        }
        // Once submission begins, its acknowledgement may race a refusal. Never
        // overwrite an in-flight offer, and always prefer the native socket error.
        finish_native_offer(handoff, failed_member_anchors, &self.trace, publish(ports)).await
    }

    async fn dial(&self, can_burst: bool, role_hint: Option<PredictionRole>, attempt: usize) -> Result<Option<TcpStream>> {
        self.trace.stage("await_candidates");
        let ready_by = time::Instant::now() + OFFER_WAIT;
        let offer = self.poll(can_burst, role_hint, OFFER_WAIT, Some(attempt), |r| r.offer.map(|o| o.ports));
        StunLease::during(
            self.observation,
            self.path.addresses(),
            ready_by,
            |status| self.trace.stun_lease(status),
            offer,
            |ports| self.dial_offer(attempt, ports),
        ).await
    }

    async fn dial_offer(
        &self, attempt: usize, ports: Option<Vec<u16>>,
    ) -> Result<Option<TcpStream>> {
        let Some(ports) = ports else {
            self.trace.close("offer_timeout");
            return Ok(None);
        };
        self.trace.ports(attempt, &ports);
        if ports.is_empty() {
            self.trace.close("empty_offer");
            return Ok(None);
        }
        self.trace.stage("candidate_connect");
        for &port in &ports {
            self.trace.socket(attempt, self.path.local.into(), SocketAddrV4::new(*self.target.ip(), port).into(), "listed", None);
        }
        let _watch = wire::Watch::open(
            self.components, self.path.local, *self.target.ip(),
            wire::PeerPorts::Candidates(&ports), &self.trace, attempt,
        );
        let trace = self.trace.clone();
        let stream = dial_candidates_observed(&ports, (*self.target.ip()).into(), self.path.local.into(),
            DialOptions { reuse_address: true, ..Default::default() }, self.stop,
            move |src, dst, stage, err| trace.socket(attempt, src, dst, stage, err)).await?;
        Ok(Some(stream))
    }
}

async fn finish_native_offer<T>(
    mut middle: std::pin::Pin<&mut Option<impl Future<Output = std::io::Result<T>>>>,
    failed_member_anchors: bool,
    trace: &Trace,
    publish: impl Future<Output = Result<()>>,
) -> Result<Option<T>> {
    let post = async {
        trace.stage(if publish.await.is_ok() { "offer_published" } else { "offer_signal_failed" });
    };
    if failed_member_anchors {
        middle.set(None);
        trace.stage("middle_abandoned_after_anchors");
        post.await;
        trace.close("anchors_failed");
        return Ok(None);
    }
    let (_, connected) = tokio::join!(biased; post, middle.as_mut().as_pin_mut().expect("middle connection was prepared"));
    Ok(Some(connected?))
}

impl Engine {
    pub(super) async fn prewarm_pair_prediction(&self, path: ObservedPath, stop: &CancellationToken) {
        let Ok(egress) = Egress::read(path).await else { return };
        let entry = self.tcp_prediction.entry(egress);
        let result = tokio::select! {
            _ = stop.cancelled() => return,
            _ = entry.retired.cancelled() => return,
            result = entry.estimate(path, stop, None) => result,
        };
        if result.is_err_and(|error| error.is::<ExitChanged>()) {
            self.tcp_prediction.retire(&entry);
        }
    }

    pub(super) async fn raw_pair_probe(
        self: &Arc<Self>,
        id: &str,
        peer: SocketAddr,
        client: &Client,
        state: &serde_json::Value,
        round: Uuid,
        observation: Option<discovery::TcpAddresses>,
        stop: &CancellationToken,
    ) -> Result<()> {
        let running = self.current(id).context("网络已删除")?;
        let n = running.config.read().unwrap().clone();
        let mode = n.settings.mode()?;
        ensure!(conwu_core::code::raw_tcp_mode(mode) && state["Mode"] == mode, "承载已改变");
        let agreed = ProbePlan::read(state, mode)?;
        let report = crate::assistance::candidate(state["HostEndpoint"].as_str().context("主机端点缺失")?)?;
        let for_listener = |local: SocketAddr, mapped: SocketAddr, observer| {
            (local.port() == n.settings.listen_port && mapped.ip() == report.ip()
                && agreed.as_ref().is_none_or(|plan| plan.observer == observer))
                .then(|| ObservedPath::new(local, mapped, observer))
                .flatten()
        };
        let path = if mode == "faketcp" {
            self.fake_mappings.read().unwrap().get(&n.settings.listen_port)
                .filter(|m| !m.cancel.is_cancelled())
                .and_then(|m| for_listener(m.local, m.observed_endpoint()?, m.observer))
        } else {
            (*running.observed_tcp.read().unwrap()).into_iter().chain(observation)
                .find_map(|p| for_listener(p.local, p.mapped, p.observer))
        };
        if agreed.is_some() && path.is_none() {
            if state["RawMultiCandidate"] == true {
                let log = RoundLog::new(Trace::new(round, "first_pair", "burst", mode), &self.events);
                log.trace.attempt(0, "burst");
                log.trace.stage("check_stun_path");
                log.trace.close("host_observation_changed");
            }
            anyhow::bail!("主机 TCP STUN 已改变，请重新生成配对码");
        }
        if state["RawMultiCandidate"] == true {
            let mut log = RoundLog::new(Trace::new(round, "first_pair", "burst", mode), &self.events);
            log.trace.attempt(0, "burst");
            log.trace.stage("plan_confirmed");
            log.trace.stage("warmup");
            if mode == "mimic" {
                log.trace.source(0, "mimic_helper");
                let control = self.raw_controls.lock().unwrap().get(&(mode.to_owned(), n.settings.listen_port)).cloned();
                if let Some(c) = control {
                    log.watch_mimic(&self.components, c.source, peer);
                    log.mimic = Some((c, peer, false));
                }
            }
            let trace = &log.trace;
            let prediction = match path {
                Some(path) => {
                    let mapping = (mode == "faketcp").then(|| self.fake_mappings.read().unwrap()
                        .get(&path.local.port()).cloned()).flatten();
                    let observation = mapping.as_ref().map_or(&running.tcp_observation, |mapping| mapping.observation());
                    StunLease::during(observation, path.addresses(), time::Instant::now() + Duration::from_secs(3),
                        |status| trace.stun_lease(status), async { Ok(()) }, |_| self.raw_host_candidates(RawPunch {
                            mode, path, peer, client: false, fake: None, control: None, member: false, trace, attempt: 0, stop,
                        }, report.port())).await
                }
                None => Err(anyhow::anyhow!("当前监听端口缺少同源 TCP STUN 观测")),
            };
            ensure!(!stop.is_cancelled(), "原始 TCP 预测已取消");
            let (ports, text) = match prediction {
                Ok((ports, tail)) => {
                    let anchors = if tail { "首尾锚点齐全" } else { "仅收到首锚点" };
                    let text = format!("{mode} 首次配对已排序 {} 个主机端口候选（{anchors}）", ports.len());
                    (ports, text)
                }
                Err(error) => {
                    trace.stage(if path.is_none() { "missing_stun_path" } else { "candidate_fallback" });
                    trace.error(&error);
                    let reason = crate::logging::redact(&format!("{error:#}"));
                    (Vec::new(), format!("{mode} 首次配对预测候选为 0，使用已登记的主机入口（{reason}）"))
                }
            };
            let _ = self.events.try_send(super::Event::Log {
                level: "INFO".into(),
                text,
            });
            let publish = client.publish_raw_candidates(state, round, &ports);
            trace.ports(0, &ports);
            trace.stage("publish_candidates");
            let published = if ports.is_empty() {
                let fallback = async {
                    if let Some((control, _, _)) = &log.mimic {
                        control.probe(peer, Duration::from_millis(750), Some(round)).await.map(drop)
                    } else {
                        self.punch_unpaired(id, peer, None).await
                    }
                };
                let (probe, published) = tokio::join!(fallback, publish);
                if let Err(error) = probe {
                    tracing::debug!(mode, reason = %crate::logging::redact(&error.to_string()), "原始 TCP 普通探测未完成");
                }
                published
            } else { publish.await };
            published.inspect_err(|e| { trace.error(e); trace.close("signal_failed"); })?;
            trace.stage("candidates_published");
            if mode == "mimic" {
                // The room poller cancels this token when a new round is scheduled.
                // Keep the observation open for the guest's ticket window and transit.
                tokio::select! {
                    _ = stop.cancelled() => {}
                    _ = time::sleep(crate::assistance::MIMIC_REPLY_WINDOW + Duration::from_millis(1500)) =>
                        trace.close("ticket_not_observed"),
                }
            } else {
                trace.close("offer_delivered");
            }
            return Ok(());
        }
        let sample = if let Some(path) = path {
            match self.raw_host_candidate(path, stop).await {
                Ok(sample) => sample,
                Err(error) => {
                    tracing::debug!(mode, reason = %crate::logging::redact(&error.to_string()), "原始 TCP 预测缺少有效观察，沿用登记入口");
                    None
                }
            }
        } else { None };
        let port = sample.as_ref().map_or(0, |(port, _)| *port);
        let _ = self.events.try_send(super::Event::Log {
            level: "INFO".into(),
            text: if port == 0 {
                format!("{mode} 首次配对预测未产生可信端口，本轮使用已登记的主机入口")
            } else {
                format!("{mode} 首次配对已选定主机预测端口")
            },
        });
        let ready = async {
            let mut reply = client.raw_pair_update(state, round, Some(port), false).await?;
            while reply["RawGuestReady"] != true {
                time::sleep(SIGNAL_POLL).await;
                reply = client.raw_pair_update(state, round, None, false).await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        let wait = if mode == "mimic" { 55 } else { 16 };
        time::timeout(Duration::from_secs(wait), ready).await.context("等待从机承载就绪超时")??;
        self.punch_unpaired(id, peer, None).await?;
        tracing::debug!(mode, %round, predicted = port != 0, "已执行原始 TCP 配对重试");
        drop(sample);
        Ok(())
    }

    async fn raw_host_candidates(
        &self,
        punch: RawPunch<'_>,
        registered: u16,
    ) -> Result<(Vec<u16>, bool)> {
        let RawPunch { path, stop, trace, .. } = punch;
        let entry = self.tcp_prediction.entry(Egress::read(path).await?);
        let sample = async {
            let estimate = entry.estimate(path, stop, Some(trace)).await?;
            let (ports, tail) = punch.candidates(self, &entry, estimate.as_ref(), registered).await?;
            ensure!(!ports.is_empty(), "{}", if estimate.is_none() {
                "TCP STUN 热身缺少足够的有效锚点样本"
            } else {
                "当前 TCP 端口分配规律未产生可信候选"
            });
            Ok((ports, tail))
        };
        let result = tokio::select! {
            _ = stop.cancelled() => anyhow::bail!("原始 TCP 预测已取消"),
            _ = entry.retired.cancelled() => anyhow::bail!("原始 TCP 出口已改变"),
            result = time::timeout(RAW_SAMPLE_WAIT, sample) => result.context("原始 TCP 预测阶段超时")?,
        };
        if result.as_ref().is_err_and(|e| e.is::<ExitChanged>()) {
            self.tcp_prediction.retire(&entry);
        }
        result
    }

    /// Raw carriers start their own TCP flow on the listener port. The kernel
    /// sockets used to train the estimator must never replace that flow.
    async fn raw_host_candidate(
        &self, path: ObservedPath, stop: &CancellationToken,
    ) -> Result<Option<(u16, TcpObservation)>> {
        let entry = self.tcp_prediction.entry(Egress::read(path).await?);
        let sample = async {
            if path.local == path.mapped { return Ok(None); }
            let estimate = entry.estimate(path, stop, None).await?;
            // Only the head observation is ordered with respect to the native SYN.
            // The helper's control acknowledgement alone cannot timestamp a tail anchor.
            let local = SocketAddrV4::new(*path.local.ip(), 0);
            let head = time::timeout(discovery::TCP_OBSERVER_ATTEMPT,
                discovery::observe_tcp_from(local.into(), path.observer.into())).await??;
            if head.mapped.ip() != *path.mapped.ip() { return Err(ExitChanged.into()); }
            if head.local.port() == head.mapped.port() && path.local.port() >= 1024 {
                let preserved = if path.local.port() == path.mapped.port() {
                    true
                } else {
                    let other = time::timeout(discovery::TCP_OBSERVER_ATTEMPT,
                        discovery::observe_tcp_from(local.into(), path.observer.into())).await;
                    match other {
                        Ok(Ok(other)) if other.mapped.ip() != head.mapped.ip() => return Err(ExitChanged.into()),
                        Ok(Ok(other)) => other.local.port() != head.local.port() && other.local.port() == other.mapped.port(),
                        _ => false,
                    }
                };
                if preserved { return Ok(Some((path.local.port(), head))); }
            }
            let Some(estimate) = estimate else { return Ok(None) };
            if !matches!(estimate.regime, NatRegime::Sequential { .. } | NatRegime::Strided { .. }) {
                return Ok(None);
            }
            let observation = MappingObservation {
                l1: head.local.port(), l_mid: path.local.port(), l2: head.local.port(),
                p1: head.mapped.port(), p2: None,
            };
            let candidate = estimate.candidates(observation).into_iter()
                .find(|&port| port >= 1024);
            Ok(candidate.map(|port| (port, head)))
        };
        let result: Result<_> = tokio::select! {
            _ = stop.cancelled() => Ok(None),
            _ = entry.retired.cancelled() => Ok(None),
            result = time::timeout(Duration::from_secs(11), sample) => result.unwrap_or(Ok(None)),
        };
        if result.as_ref().is_err_and(|e| e.is::<ExitChanged>()) { self.tcp_prediction.retire(&entry); }
        result
    }

    pub(super) async fn predict_room_path(
        &self,
        client: &Client,
        state: &serde_json::Value,
        owner: bool,
        path: ObservedPath,
        observation: &tokio::sync::Mutex<Option<TcpObservation>>,
        target: SocketAddr,
        round: Uuid,
        stop: &CancellationToken,
    ) -> Result<Option<TcpStream>> {
        let SocketAddr::V4(target) = target else { return Ok(None) };
        let trace = Trace::new(round, "first_pair", "member", state["Mode"].as_str().unwrap_or("tcp"));
        let _log = RoundLog::new(trace.clone(), &self.events);
        let probe = ProbePlan::read(state, state["Mode"].as_str().unwrap_or("tcp"))?;
        ensure!(probe.is_none_or(|plan| plan.observer == SocketAddr::V4(path.observer)), "TCP STUN 与配对探测配置不符");
        let egress = Egress::read(path).await.inspect_err(|error| {
            trace.error(error);
            trace.close("egress_failed");
        })?;
        let entry = self.tcp_prediction.entry(egress);
        let session = Session {
            trace: trace.clone(),
            components: &self.components,
            client,
            signal: Signal::Room { state, slot: if owner { 0 } else { 1 } },
            round,
            plan_hash: state["ProbeHash"].as_str().map(str::to_owned),
            path,
            observation,
            target,
            stop,
        };
        let result = tokio::select! {
            _ = stop.cancelled() => return Ok(None),
            _ = entry.retired.cancelled() => { trace.close("egress_changed"); return Ok(None); },
            result = async {
                trace.stage("warmup");
                session.run(entry.estimate(path, stop, Some(&trace)).await?).await
            } => result,
        };
        if result.as_ref().is_err_and(|error| error.is::<ExitChanged>()) {
            self.tcp_prediction.retire(&entry);
        }
        result.map(|stream| {
            if stream.is_some() {
                trace.stage("tcp_established");
                trace.close("socket_handoff");
            }
            stream
        }).inspect_err(|error| {
            trace.error(error);
            trace.close(if error.is::<StunLeaseLost>() {
                "stun_lease_lost"
            } else {
                "prediction_failed"
            });
        })
    }

    pub(super) async fn predict_member_path(
        self: &Arc<Self>,
        running: &Arc<Running>,
        client: &Client,
        path: ObservedPath,
        target: SocketAddr,
        trace: &Trace,
    ) -> Result<bool> {
        let network = running.config.read().unwrap().clone();
        let round = trace.round();
        let log = RoundLog::new(trace.clone(), &self.events);
        let SocketAddr::V4(target) = target else {
            trace.close("ipv6");
            return Ok(false);
        };
        let profile = network.profile.as_ref().context("TCP 预测成员身份缺失")?;
        let peer = remote_member(profile).context("TCP 预测对端成员已移除")?;
        if running.metrics.read().unwrap().connected
            || network.paused || !network.enabled || network.settings.existing_only()
            || network.settings.discovery_mode != "coordinator"
        {
            trace.close("connection_or_settings_changed");
            return Ok(false);
        }
        let mode = network.settings.mode()?;
        let fake = if mode == "faketcp" {
            Some(self.fake_mappings.read().unwrap().get(&path.local.port())
                .filter(|mapping| mapping.local == SocketAddr::V4(path.local) && !mapping.cancel.is_cancelled())
                .cloned().context("FakeTCP 同源接收器已变化")?)
        } else { None };
        trace.stage("check_egress");
        let egress = Egress::read(path).await.inspect_err(|e| { trace.error(e); trace.close("egress_failed"); })?;
        let entry = self.tcp_prediction.entry(egress);
        let stop = running.cancel.child_token();
        let _guard = stop.clone().drop_guard();
        let session = Session {
            trace: trace.clone(),
            components: &self.components,
            client,
            signal: Signal::Member { profile, peer: &peer, boot: running.boot },
            round,
            plan_hash: (network.settings.tcp_stun.len() == 1).then(|| ProbePlan::new(&profile.pair.mode, path.observer.into()).hash()).transpose()?,
            path,
            observation: fake.as_ref().map_or(&running.tcp_observation, |mapping| mapping.observation()),
            target,
            stop: &stop,
        };
        let operation = async {
            trace.stage("warmup");
            let estimate = entry.estimate(path, &stop, Some(&trace)).await?;
            if conwu_core::code::raw_tcp_mode(mode) {
                let connected = session.run_raw(self, running, &network, &entry, estimate.as_ref(), None).await?;
                if connected {
                    trace.stage("mesh_authenticated");
                    trace.close("success");
                } else {
                    trace.close(if trace.used_candidates() { "raw_reconnect_timeout" } else { "no_valid_candidates" });
                }
                return Ok(connected);
            }
            if let Some(stream) = session.run(estimate).await? {
                trace.stage("tcp_established");
                let endpoint = stream.peer_addr()?;
                self.serve_predicted_socket(running, &network, &peer, stream, Some(log)).await?;
                return Ok(wait_for_member_link(running, time::Instant::now() + Duration::from_secs(2), Some(endpoint)).await);
            }
            Ok(false)
        };
        let result = tokio::select! {
            _ = stop.cancelled() => return Ok(false),
            _ = entry.retired.cancelled() => { trace.close("egress_changed"); return Ok(false); },
            result = operation => result,
        };
        if result.as_ref().is_err_and(|error: &anyhow::Error| error.is::<ExitChanged>()) {
            self.tcp_prediction.retire(&entry);
        }
        result.inspect_err(|error| {
            trace.error(error);
            trace.close(if error.is::<StunLeaseLost>() { "stun_lease_lost" } else { "prediction_failed" });
        })
    }

    async fn serve_predicted_socket(
        self: &Arc<Self>,
        running: &Arc<Running>,
        network: &crate::model::Network,
        peer: &Member,
        stream: TcpStream,
        log: Option<RoundLog>,
    ) -> Result<()> {
        let current = running.config.read().unwrap().clone();
        ensure!(
            current.enabled
                && !current.paused
                && !current.settings.existing_only()
                && current.settings.discovery_mode == "coordinator"
                && current.settings.service == network.settings.service
                && current.settings.listen_port == network.settings.listen_port
                && current.profile.as_ref().and_then(remote_member).as_ref() == Some(peer),
            "TCP 预测期间网络设置已改变"
        );
        let profile = current.profile.as_ref().context("TCP 预测成员身份缺失")?;
        let mode = current.settings.mode()?.to_owned();
        let endpoint = stream.peer_addr()?;
        if let Some(l) = &log { l.trace.stage(if mode == "https" { "tls_handshake" } else { "tcp_transport" }); }
        let pipe = tokio::select! {
            _ = running.cancel.cancelled() => return Ok(()),
            result = transport::socket_role(&mode, stream, profile.pair.transport_key_pin.as_deref().unwrap_or(""), !current.created_here, &self.identity, &running.cancel) => result.inspect_err(|e| if let Some(l) = &log { l.trace.error(e); l.trace.close("transport_failed"); })?,
        };
        let engine = self.clone();
        let id = current.id.clone();
        if let Some(l) = &log { l.trace.stage("mesh_handoff"); l.trace.close("closed_before_mesh_auth"); }
        self.tracker.spawn(async move { engine.serve_inner(pipe, mode, endpoint, Some(id), None, log).await });
        Ok(())
    }
}

pub(super) fn watch_fallback(components: &std::path::Path, local: SocketAddr, peer: SocketAddr, ports: &[u16], trace: &Trace) -> Option<wire::Watch> {
    let (SocketAddr::V4(local), SocketAddr::V4(peer)) = (local, peer) else { return None };
    wire::Watch::open(components, local, *peer.ip(), wire::PeerPorts::Candidates(ports), trace, 0)
}

enum RawProbe {
    Fake(crate::native::ArmedSyn),
    Carrier(crate::raw::Control),
}

#[derive(Debug)]
struct MissingSynReceipt;

impl std::fmt::Display for MissingSynReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("双锚点已确认，但本轮 helper 未确认中间 SYN")
    }
}

impl std::error::Error for MissingSynReceipt {}

async fn submit_faketcp_burst<A>(
    first: impl FnOnce() -> A,
    middle: impl std::future::Future<Output = Result<u64>>,
    last: impl FnOnce() -> A,
) -> Result<(A, u64, A)> {
    let first = first();
    let middle = middle.await.context("未确认 FakeTCP 发出 TCP SYN")?;
    let last = last();
    Ok((first, middle, last))
}

#[derive(Clone, Copy)]
struct RawPunch<'a> {
    mode: &'a str,
    path: ObservedPath,
    peer: SocketAddr,
    client: bool,
    fake: Option<&'a crate::native_map::Mapping>,
    control: Option<&'a crate::raw::Control>,
    member: bool,
    trace: &'a Trace,
    attempt: usize,
    stop: &'a CancellationToken,
}

impl RawPunch<'_> {
    async fn candidates(&self, engine: &Engine, egress: &CachedEgress,
        estimate: Option<&Estimate>, registered: u16,
    ) -> Result<(Vec<u16>, bool)> {
        let Self { mode, path, peer, client, fake, trace, attempt, stop, .. } = *self;
        ensure!(discovery::local_route(peer)? == IpAddr::V4(*path.local.ip()),
            "对端与 TCP STUN 使用不同的本机出口");
        let probe = if mode == "faketcp" {
            let shared;
            let mapping = if let Some(mapping) = fake {
                mapping
            } else {
                shared = engine.faketcp_receiver(path.local.port())?;
                &shared
            };
            ensure!(mapping.local == SocketAddr::V4(path.local), "FakeTCP 同源接收器已改变");
            RawProbe::Fake(mapping.prepare_burst(peer, client).await?.arm_syn().await?)
        } else {
            let control = self.control.cloned().or_else(|| engine.raw_controls.lock().unwrap()
                .get(&(mode.to_owned(), path.local.port())).cloned())
                .filter(|control| control.source == SocketAddr::V4(path.local) && control.confirms_syn)
                .context("未取得支持 SYN 确认的同源承载")?;
            RawProbe::Carrier(control)
        };
        trace.stage("anchor_burst");
        let [first, last] = egress.reserve_raw_anchors(path.local).inspect_err(|_| trace.stage("adjacent_ports_unavailable"))?;
        let ports = (first.port(), path.local.port(), last.port());
        trace.local_ports(attempt, ports);
        ensure!(!stop.is_cancelled(), "原始 TCP 三连发已取消");
        let first = || first.connect(path.observer);
        let last = || last.connect(path.observer);
        let report_anchor = |port, result: &Result<SocketAddr>| {
            let source = SocketAddrV4::new(*path.local.ip(), port);
            let (stage, io) = match result {
                Ok(_) => ("anchor_binding_ok", None),
                Err(error) if error.is::<time::error::Elapsed>() => ("anchor_deadline", None),
                Err(error) => ("anchor_failed", error.chain().find_map(|e| e.downcast_ref::<std::io::Error>())),
            };
            trace.socket(attempt, source.into(), path.observer.into(), stage, io);
        };
        let (observation, timing) = match probe {
            RawProbe::Fake(syn) => {
                let (first, middle_us, last) = submit_faketcp_burst(first, syn.submit(), last).await?;
                let timing = BurstTiming { first_us: first.submitted_us, middle_us, last_us: last.submitted_us };
                trace.burst_timing(attempt, timing, None);
                ensure!(timing.first_us <= timing.middle_us && timing.middle_us <= timing.last_us,
                    "FakeTCP 三连发的提交时间顺序无效");
                (observe_anchor_pair(first, last, ports, *path.mapped.ip(), stop, report_anchor).await?, timing)
            }
            RawProbe::Carrier(control) => {
                let first = first();
                let wait = if self.member && mode == "tcpraw" { Duration::from_secs(2) } else { Duration::from_millis(750) };
                let round = (mode == "mimic").then(|| trace.round());
                let middle = control.probe(peer, wait, round);
                tokio::pin!(middle);
                let sent = tokio::select! {
                    biased;
                    result = &mut middle => Some(result),
                    _ = time::sleep(RAW_TAIL_DELAY) => None,
                };
                let last = last();
                let (first_us, last_us) = (first.submitted_us, last.submitted_us);
                let middle = async {
                    match sent { Some(result) => result, None => middle.await }
                        .context("未确认同源承载发出 TCP SYN")
                };
                let (observation, middle_us) = tokio::join!(
                    observe_anchor_pair(first, last, ports, *path.mapped.ip(), stop, report_anchor), middle,
                );
                let observation = observation?;
                trace.anchors(attempt, observation);
                let middle_us = if observation.p2.is_some() {
                    middle_us.context(MissingSynReceipt)?
                } else { middle_us? };
                (observation, BurstTiming { first_us, middle_us, last_us })
            }
        };
        let span = estimate.and_then(|e| bracket_stride_span(e.domain, observation, &e.regime));
        trace.anchors(attempt, observation);
        trace.burst_timing(attempt, timing, span);
        trace.socket(attempt, path.local.into(), peer, "syn_confirmed_by_helper", None);
        let ports = rank_raw_candidates(path, observation, estimate, registered, timing);
        Ok((ports, observation.p2.is_some()))
    }
}

fn rank_raw_candidates(
    path: ObservedPath,
    observation: MappingObservation,
    estimate: Option<&Estimate>,
    registered: u16,
    timing: BurstTiming,
) -> Vec<u16> {
    let preserve = path.local.port() == path.mapped.port()
        || observation.p1 == observation.l1 && observation.p2 == Some(observation.l2);
    let mut ports = Vec::new();
    let model = estimate.map(|estimate| estimate.ranked(observation, Some(timing))).unwrap_or_default();
    for port in preserve.then_some(path.local.port()).into_iter().chain(model) {
        if port >= 1024 && !ports.contains(&port) {
            ports.push(port);
        }
    }
    if !ports.is_empty() && registered >= 1024 && !ports.contains(&registered) {
        ports.truncate(crate::assistance::MAX_PORTS - 1);
        ports.push(registered);
    }
    ports.truncate(crate::assistance::MAX_PORTS);
    ports
}

#[cfg(test)]
mod tests;
