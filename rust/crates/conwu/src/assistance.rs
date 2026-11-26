//! Coordinator hint scheduling. Never carries business data or enrollment.
use anyhow::{Context, Result, ensure};
use conwu_core::{
    crypto as c,
    identity::{Member, Profile},
    unix_seconds,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

mod port_prediction;
pub(crate) use port_prediction::{MAX_PORTS, PredictionOffer, PredictionRole, PredictionUpdate, RoomPredictionReply};
pub(crate) const NATIVE_OFFER_WAIT: Duration = Duration::from_secs(4);
pub(crate) const NATIVE_OPEN_WAIT: Duration = Duration::from_millis(6500);
pub(crate) const NATIVE_ATTEMPT_WINDOW: Duration = Duration::from_secs(7);
pub(crate) const COORDINATED_FIRST_CONTACT: Duration = Duration::from_secs(3);
pub(crate) const MIMIC_OFFER_WINDOW: Duration = Duration::from_secs(34);
pub(crate) const RAW_OFFER_WAIT: Duration = Duration::from_secs(30);
pub(crate) const MIMIC_REPLY_WINDOW: Duration = Duration::from_secs(9);
pub(crate) const RAW_CANDIDATE_WAIT: Duration = Duration::from_millis(1400);

pub(crate) const PAIRING_RETRIES: u8 = 5;

pub(crate) async fn retry_pair_step<T, F>(
    stage: &str,
    transient: fn(&anyhow::Error) -> bool,
    mut run: impl FnMut(u8) -> F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let mut attempt = 0;
    loop {
        match run(attempt).await {
            Ok(result) => return Ok(result),
            Err(error) => {
                let reason = crate::logging::redact(&format!("{error:#}"));
                if attempt >= PAIRING_RETRIES || !transient(&error) {
                    return Err(error.context(format!("{stage}失败（第 {} 次尝试）：{reason}", attempt + 1)));
                }
                tracing::debug!(stage, attempt = attempt + 1, %reason, "配对步骤将重试");
                tokio::time::sleep(Duration::from_millis(250) * (1_u32 << attempt.min(2))).await;
                attempt += 1;
            }
        }
    }
}

#[derive(Debug)]
struct TemporarySignalStatus(reqwest::StatusCode);

impl std::fmt::Display for TemporarySignalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTPS 协调服务暂时无法处理请求（{}）", self.0)
    }
}
impl std::error::Error for TemporarySignalStatus {}

const RAW_ROUND_EXPIRED: &str = "原始 TCP 端口预测轮次已过期";

#[derive(Debug)]
pub(crate) struct RawRoundExpired;

impl std::fmt::Display for RawRoundExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(RAW_ROUND_EXPIRED)
    }
}
impl std::error::Error for RawRoundExpired {}

pub(crate) fn transient_signal(error: &anyhow::Error) -> bool {
    error.is::<TemporarySignalStatus>() || error.downcast_ref::<reqwest::Error>().is_some_and(|http| {
        !error.chain().any(|cause| cause.is::<rustls::Error>())
            && (http.is_connect() || http.is_timeout() || http.is_request() || http.is_body())
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ProbePlan {
    version: u8,
    mode: String,
    pub observer: SocketAddr,
    max_candidates: usize,
    offer_ms: u64,
    open_ms: u64,
    dial_ms: u64,
    attempt_ms: u64,
    first_contact_ms: u64,
    role_policy: String,
}

impl ProbePlan {
    pub(crate) fn new(mode: &str, observer: SocketAddr) -> Self {
        let (offer, open, dial, attempt, roles) = if conwu_core::code::stream_mode(mode) {
            let dial = conwu_core::nat_tcp_punch::handover::DialOptions::default().timeout;
            (NATIVE_OFFER_WAIT, NATIVE_OPEN_WAIT, dial, NATIVE_ATTEMPT_WINDOW, "strided-first")
        } else if mode == "mimic" {
            (RAW_OFFER_WAIT, MIMIC_REPLY_WINDOW, MIMIC_REPLY_WINDOW, MIMIC_OFFER_WINDOW, "host-burst")
        } else {
            (RAW_OFFER_WAIT, RAW_CANDIDATE_WAIT, RAW_CANDIDATE_WAIT, MIMIC_OFFER_WINDOW, "host-burst")
        };
        Self { version: 1, mode: mode.into(), observer, max_candidates: MAX_PORTS,
            offer_ms: offer.as_millis() as u64, open_ms: open.as_millis() as u64,
            dial_ms: dial.as_millis() as u64, attempt_ms: attempt.as_millis() as u64,
            first_contact_ms: COORDINATED_FIRST_CONTACT.as_millis() as u64, role_policy: roles.into() }
    }

    pub(crate) fn hash(&self) -> Result<String> {
        Ok(hex::encode(c::hash(&c::signed_json(&serde_json::to_value(self)?)?)))
    }

    pub(crate) fn read(state: &Value, mode: &str) -> Result<Option<Self>> {
        if state["ProbePlan"].is_null() {
            ensure!(state["ProbeHash"].is_null(), "协调探测计划缺失");
            return Ok(None);
        }
        let plan: Self = serde_json::from_value(state["ProbePlan"].clone())?;
        ensure!(candidate(&plan.observer.to_string())? == plan.observer, "STUN 观察器地址无效");
        ensure!(plan == Self::new(mode, plan.observer) && state["ProbeHash"] == plan.hash()?,
            "双方探测配置或版本不一致");
        Ok(Some(plan))
    }
}

const FIRST_CONTACT_LEAD: Duration = Duration::from_secs(1);
const LATE_TOLERANCE: Duration = Duration::from_secs(2);
const MEMBER_LEAD: Duration = Duration::from_secs(8);
const WAITING_MEMBER_LEAD: Duration = Duration::from_secs(2);
const MEMBER_WAIT: Duration = Duration::from_secs(4);
const MEMBER_POLL_GRACE: Duration = Duration::from_secs(6);
const MEMBER_TTL: Duration = Duration::from_secs(30);
// A scheduled TCP attempt can include discovery, warmup, and two candidate rounds.
const TCP_PREDICTION_TTL: Duration = Duration::from_secs(45);

pub enum Schedule {
    Waiting,
    Ready(uuid::Uuid, Duration),
    Expired(uuid::Uuid),
}
impl Schedule {
    pub fn read_for_host(state: &Value, round_trip: Duration, active: uuid::Uuid, started: Instant) -> Result<Self> {
        let schedule = Self::read(state, round_trip)?;
        // An older coordinator only advertises the scheduled start, even while
        // it still accepts native prediction messages for the current round.
        if let Self::Expired(round) = schedule
            && round == active && state["TcpPrediction"] == true
            && state["PredictionWindowMilliseconds"].is_null() && started.elapsed() < TCP_PREDICTION_TTL
        {
            return Ok(Self::Ready(round, Duration::ZERO));
        }
        Ok(schedule)
    }
    /// The server's relative delay is measured before its response travels
    /// back. Half the request RTT estimates that transit without wall clocks.
    pub fn read(state: &Value, round_trip: Duration) -> Result<Self> {
        let round = state["Round"]
            .as_str()
            .context("协调探测轮次缺失")?
            .parse::<uuid::Uuid>()?;
        if round.is_nil() {
            return Ok(Self::Waiting);
        }
        let delay = state["StartAfterMilliseconds"]
            .as_i64()
            .context("协调探测时间缺失")?;
        ensure!((-30000..=MEMBER_LEAD.as_millis() as i64).contains(&delay), "协调探测时间无效");
        let server_wait =
            Duration::from_millis(state["ServerWaitMilliseconds"].as_u64().unwrap_or(0));
        let transit = round_trip.saturating_sub(server_wait).as_millis().min(60000) as i64 / 2;
        let remaining = delay - transit;
        if remaining < -(LATE_TOLERANCE.as_millis() as i64) {
            if state["PredictionWindowMilliseconds"].as_u64().is_some_and(|window| {
                window <= TCP_PREDICTION_TTL.as_millis() as u64 && window > transit as u64
            }) {
                return Ok(Self::Ready(round, Duration::ZERO));
            }
            return Ok(Self::Expired(round));
        }
        Ok(Self::Ready(round, Duration::from_millis(remaining.max(0) as u64)))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MemberRequest {
    pub version: u8,
    pub request_id: uuid::Uuid,
    pub boot: uuid::Uuid,
    pub slot: u8,
    pub device: String,
    pub issued: i64,
    pub endpoint: String,
    pub signature: String,
    pub mode: String,
    pub ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prediction: Option<port_prediction::PredictionSignal>,
}
fn signed(network: &str, r: &MemberRequest) -> Result<Vec<u8>> {
    c::signed_json(
        &json!({"domain":"conwu-tcp-assist-v2","network":network,"Version":r.version,"RequestId":r.request_id,"Boot":r.boot,"Slot":r.slot,"Device":r.device,"Issued":r.issued,"Endpoint":r.endpoint,"Mode":r.mode,"Ready":r.ready}),
    )
}
impl MemberRequest {
    pub fn create(p: &Profile, boot: uuid::Uuid, endpoint: SocketAddr) -> Result<Self> {
        let mut r = Self {
            version: 1,
            request_id: uuid::Uuid::new_v4(),
            boot,
            slot: p.member.slot,
            device: p.member.device.clone(),
            issued: unix_seconds(),
            endpoint: endpoint.to_string(),
            signature: String::new(),
            mode: p.pair.mode.clone(),
            ready: true,
            prediction: None,
        };
        r.signature = c::sign(&p.signing_private, &signed(&p.pair.network, &r)?)?;
        Ok(r)
    }
    pub fn verify(&self, network: &str, member: &Member, source: IpAddr) -> Result<()> {
        ensure!(
            self.version == 1
                && !self.request_id.is_nil()
                && !self.boot.is_nil()
                && self.slot == member.slot
                && self.device == member.device
                && self.issued.abs_diff(unix_seconds()) <= 30
                && conwu_core::code::valid_mode(&self.mode)
                && self.mode != "udp",
            "协同请求无效或过期"
        );
        matches_source(&self.endpoint, source)?;
        ensure!(
            c::verify(
                &member.signing_key,
                &signed(network, self)?,
                &self.signature
            ),
            "协同身份签名无效"
        );
        if let Some(prediction) = &self.prediction {
            prediction.verify(network, self, member)?;
        }
        Ok(())
    }

    pub(crate) fn prediction_update(&self) -> Option<&PredictionUpdate> {
        self.prediction.as_ref()?.update.as_ref()
    }

    fn round_control(&self) -> Option<&port_prediction::RoundControl> {
        self.prediction.as_ref()?.round_control.as_ref()
    }
}
struct Participant {
    token: String,
    source: IpAddr,
    commitment: String,
    request: String,
    endpoint: String,
    ready: bool,
    prediction: bool,
    raw_round_sync: bool,
}
struct Room {
    owner: Participant,
    guest: Option<Participant>,
    withdrawn_guest: Option<Participant>,
    next_host_endpoint: Option<String>,
    raw_prediction_supported: bool,
    raw_prediction_requested: bool,
    raw_multi_supported: bool,
    rotate_mimic_endpoint: bool,
    raw_multi_requested: bool,
    raw_host_port: Option<u16>,
    raw_host_ports: Option<Vec<u16>>,
    raw_published: Option<Instant>,
    raw_guest_ready: bool,
    host_room: String,
    commitment: String,
    mode: String,
    probe: Option<ProbePlan>,
    probe_hash: Option<String>,
    create_digest: Option<[u8; 32]>,
    began: Instant,
    expires: i64,
    round: uuid::Uuid,
    start: Option<Instant>,
    attempts: u8,
    prediction: Option<port_prediction::RoomPrediction>,
}

impl Room {
    fn clear_round(&mut self) {
        self.round = uuid::Uuid::nil();
        self.start = None;
        self.prediction = None;
        self.raw_host_port = None;
        self.raw_host_ports = None;
        self.raw_published = None;
        self.raw_guest_ready = false;
    }

    fn predicts(&self) -> bool {
        conwu_core::code::stream_mode(&self.mode)
            && self.owner.prediction
            && self.guest.as_ref().is_some_and(|guest| guest.prediction)
    }

    fn stable_raw_round(&self) -> bool {
        self.raw_multi_requested && self.owner.raw_round_sync
            && self.guest.as_ref().is_some_and(|guest| guest.raw_round_sync)
    }

    fn prediction_window(&self) -> Option<Duration> {
        (self.predicts() || self.stable_raw_round()).then_some(TCP_PREDICTION_TTL)
    }
}
#[derive(Clone, Copy)]
struct MemberRound {
    round: uuid::Uuid,
    start: Instant,
    lead: Duration,
    prediction: bool,
    synchronized: bool,
}
enum MemberReply {
    Waiting,
    Refresh,
    Scheduled(MemberRound, String, uuid::Uuid),
}
impl MemberReply {
    fn json(self, mode: &str) -> Value {
        let (round, endpoint, delay, refresh, prediction, boot, window) = match self {
            Self::Waiting => (uuid::Uuid::nil(), String::new(), 0, false, false, None, None),
            Self::Refresh => (uuid::Uuid::nil(), String::new(), 0, true, false, None, None),
            Self::Scheduled(row, endpoint, boot) => {
                let delay = row.lead.as_millis() as i64 - row.start.elapsed().as_millis() as i64;
                let window = row.synchronized.then(|| TCP_PREDICTION_TTL.saturating_sub(row.start.elapsed()).as_millis() as u64);
                (row.round, endpoint, delay.max(-30000), false, row.prediction, Some(boot), window)
            }
        };
        json!({
            "Version": 1,
            "PeerEndpoint": endpoint,
            "Round": round,
            "StartAfterMilliseconds": delay,
            "Mode": mode,
            "Refresh": refresh,
            "TcpPrediction": prediction,
            "PeerBoot": boot,
            "PredictionWindowMilliseconds": window,
        })
    }
}
struct MemberReport {
    latest: MemberRequest,
    received: Instant,
    confirmed: bool,
    waiter: Option<oneshot::Sender<MemberReply>>,
    poll_timed_out: Option<Instant>,
    // Keep replay history across endpoint changes and the 30s readiness TTL.
    requests: HashMap<uuid::Uuid, i64>,
}
#[derive(Default)]
pub struct Assist {
    rooms: Mutex<HashMap<String, Room>>,
    members: Mutex<HashMap<(String, u8), MemberReport>>,
    rounds: Mutex<HashMap<String, MemberRound>>,
    predictions: Mutex<HashMap<String, port_prediction::RoundPrediction>>,
    rate: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}
fn secret() -> String {
    hex::encode_upper(c::random::<32>())
}
pub(crate) fn short_code(s: &str) -> bool {
    s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit())
}
fn commitment(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn candidate(s: &str) -> Result<SocketAddr> {
    let endpoint: SocketAddr = s.parse()?;
    ensure!(
        endpoint.is_ipv4()
            && endpoint.port() > 0
            && (crate::discovery::public(endpoint.ip()) || endpoint.ip().is_loopback()),
        "协同候选必须是公网 IPv4 地址"
    );
    Ok(endpoint)
}
fn matches_source(s: &str, source: IpAddr) -> Result<()> {
    ensure!(candidate(s)?.ip() == source, "候选与观察来源不符");
    Ok(())
}
impl Assist {
    pub fn limit(&self, source: IpAddr) -> Result<()> {
        let mut rate = self.rate.lock().unwrap();
        rate.retain(|_, v| v.0.elapsed() < Duration::from_secs(60));
        ensure!(
            rate.contains_key(&source) || rate.len() < 4096,
            "协同请求表已满"
        );
        let row = rate.entry(source).or_insert((Instant::now(), 0));
        if row.0.elapsed() > Duration::from_secs(10) {
            *row = (Instant::now(), 0)
        }
        row.1 += 1;
        ensure!(row.1 <= 100, "协同请求过于频繁");
        Ok(())
    }
    pub fn request(&self, action: &str, input: &Value, source: IpAddr) -> Result<Value> {
        self.limit(source)?;
        let text = |k: &str| {
            input
                .get(k)
                .or_else(|| {
                    let mut key = k.to_owned();
                    key[..1].make_ascii_lowercase();
                    input.get(&key)
                })
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let ready = input
            .get("Ready")
            .or_else(|| input.get("ready"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let prediction = input["TcpPrediction"] == true;
        let mut rooms = self.rooms.lock().unwrap();
        rooms.retain(|_, r| {
            r.expires > unix_seconds() && r.began.elapsed() < Duration::from_secs(300)
        });
        if matches!(action, "create" | "create-retry") {
            let endpoint = text("Endpoint");
            matches_source(&endpoint, source)?;
            let request = text("RequestId");
            ensure!((action == "create" && request.is_empty()) || conwu_core::valid_id(&request),
                "创建协调房间的请求标识无效");
            let create_digest = (!request.is_empty()).then(|| c::signed_json(input).map(|bytes| c::hash(&bytes))).transpose()?;
            if create_digest.is_some()
                && let Some((key, room)) = rooms.iter().find(|(_, room)| room.owner.request == request)
            {
                ensure!(room.owner.source == source && room.create_digest == create_digest,
                    "创建协调房间的请求与原申请不符");
                return Ok(room_state(key, room, &room.owner));
            }
            let mode = text("Mode");
            let host_room = text("HostRoom");
            let commitment = text("Commitment");
            ensure!(
                short_code(&host_room)
                    && self::commitment(&commitment)
                    && conwu_core::code::valid_mode(&mode)
                    && mode != "udp"
                    && rooms.len() < 128,
                "辅助会话无效或容量已满"
            );
            let probe = ProbePlan::read(input, &mode)?;
            ensure!(probe.as_ref().is_none_or(|plan| !plan.observer.ip().is_loopback() || source.is_loopback()),
                "公网配对不能指定本机 STUN 地址");
            let probe_hash = probe.as_ref().map(ProbePlan::hash).transpose()?;
            use rand::Rng;
            let room = loop {
                let c = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));
                if !rooms.contains_key(&c) {
                    break c;
                }
            };
            let row = Room {
                owner: Participant {
                    token: secret(),
                    source,
                    commitment: String::new(),
                    request,
                    endpoint,
                    ready,
                    prediction,
                    raw_round_sync: input["RawRoundSync"] == true,
                },
                guest: None,
                withdrawn_guest: None,
                next_host_endpoint: None,
                raw_prediction_supported: conwu_core::code::raw_tcp_mode(&mode) && input["RawHostPrediction"] == true,
                raw_prediction_requested: false,
                raw_multi_supported: input["RawMultiCandidate"] == true,
                rotate_mimic_endpoint: mode == "mimic" && input["MimicEndpointRotation"] == true,
                raw_multi_requested: false,
                raw_host_port: None,
                raw_host_ports: None,
                raw_published: None,
                raw_guest_ready: false,
                host_room,
                commitment,
                mode,
                probe,
                probe_hash,
                create_digest,
                began: Instant::now(),
                expires: unix_seconds() + 300,
                round: uuid::Uuid::nil(),
                start: None,
                attempts: 0,
                prediction: None,
            };
            let result = room_state(&room, &row, &row.owner);
            rooms.insert(room, row);
            return Ok(result);
        }
        let key = if matches!(action, "join" | "describe") {
            text("Code")
        } else {
            action.to_owned()
        };
        ensure!(short_code(&key), "辅助会话编号无效");
        let r = rooms.get_mut(&key).context("辅助会话已过期")?;
        if action == "describe" {
            ensure!(r.probe.is_some(), "此会话请使用主机复制的完整直连码");
            return Ok(json!({"Mode":r.mode,"Expires":r.expires}));
        }
        if action == "join" {
            let request = text("RequestId");
            let commitment = text("Commitment");
            ensure!(
                conwu_core::valid_id(&request)
                    && self::commitment(&commitment)
                    && text("Mode") == r.mode,
                "辅助申请无效"
            );
            if let Some(g) = &r.guest {
                ensure!(
                    g.source == source && g.request == request && g.commitment == commitment,
                    "辅助会话已有其他申请"
                );
            } else {
                r.raw_prediction_requested = r.raw_prediction_supported && input["RawHostPrediction"] == true;
                r.raw_multi_requested = r.raw_prediction_requested
                    && r.raw_multi_supported
                    && input["RawMultiCandidate"] == true;
                r.guest = Some(Participant {
                    token: secret(),
                    source,
                    commitment,
                    request,
                    endpoint: String::new(),
                    ready: false,
                    prediction,
                    raw_round_sync: input["RawRoundSync"] == true,
                });
            }
            return Ok(room_state(&key, r, r.guest.as_ref().unwrap()));
        }
        let token = text("Token");
        ensure!(token.len() == 64, "辅助令牌无效");
        if input["Withdraw"] == true && r.guest.is_none()
            && let Some(guest) = r.withdrawn_guest.as_ref()
                .filter(|guest| guest.source == source && c::eq(token.as_bytes(), guest.token.as_bytes()))
        {
            return Ok(room_state(&key, r, guest));
        }
        let owner = c::eq(token.as_bytes(), r.owner.token.as_bytes());
        let guest_present = r.guest.is_some();
        let ready = ready && (!owner || r.mode != "faketcp" || input["ReadyFor"].as_str().is_none_or(|endpoint| {
            !endpoint.is_empty() && r.guest.as_ref().is_some_and(|guest| guest.endpoint == endpoint)
        }));
        let p = if owner {
            &mut r.owner
        } else {
            r.guest
                .as_mut()
                .filter(|g| c::eq(token.as_bytes(), g.token.as_bytes()))
                .context("辅助令牌无效")?
        };
        ensure!(p.source == source, "辅助会话来源已变化");
        if input["Withdraw"] == true {
            ensure!(!owner, "只有申请方能撤回辅助申请");
            let guest = r.guest.take().unwrap();
            r.clear_round();
            r.attempts = 0;
            r.raw_prediction_requested = false;
            r.raw_multi_requested = false;
            if r.mode == "faketcp" {
                r.owner.ready = false;
                if let Some(endpoint) = r.next_host_endpoint.take() {
                    r.owner.endpoint = endpoint;
                }
            }
            let reply = room_state(&key, r, &guest);
            r.withdrawn_guest = Some(guest);
            return Ok(reply);
        }
        if let Some(raw_round) = input.get("RawPredictionRound") {
            ensure!(r.probe_hash.as_ref().is_none_or(|hash| input["ProbeHash"] == *hash),
                "原始 TCP 探测配置未确认");
            let round: uuid::Uuid = serde_json::from_value(raw_round.clone())?;
            let lifetime = if r.stable_raw_round() { TCP_PREDICTION_TTL } else { Duration::from_secs(65) };
            ensure!(r.raw_prediction_requested && r.start.is_some_and(|t| t.elapsed() < lifetime) && r.round == round,
                RawRoundExpired);
            let arm = input["RawGuestReady"] == true;
            if arm {
                ensure!(!owner && !r.raw_multi_requested && r.raw_host_port.is_some(), "原始 TCP 候选尚未就绪");
            }
            if let Some(value) = input.get("RawHostPorts") {
                let ports: Vec<u16> = serde_json::from_value(value.clone())?;
                ensure!(owner && r.raw_multi_requested && port_prediction::valid_ports(&ports),
                    "原始 TCP 多候选端口无效");
                ensure!(r.raw_host_ports.as_ref().is_none_or(|previous| *previous == ports),
                    "原始 TCP 多候选已提交");
                r.raw_host_ports = Some(ports);
                r.raw_published.get_or_insert_with(Instant::now);
            }
            if let Some(value) = input.get("RawHostPort") {
                let port: u16 = serde_json::from_value(value.clone())?;
                ensure!(owner && !r.raw_multi_requested && (port == 0 || port >= 1024), "原始 TCP 候选端口无效");
                ensure!(r.raw_host_port.is_none_or(|previous| previous == port), "原始 TCP 候选已提交");
                r.raw_host_port = Some(port);
            }
            if arm { r.raw_guest_ready = true; }
            return Ok(room_state(&key, r, if owner { &r.owner } else { r.guest.as_ref().unwrap() }));
        }
        if let Some(update) = input.get("PredictionUpdate") {
            let update: PredictionUpdate = serde_json::from_value(update.clone())?;
            ensure!(r.probe_hash.as_ref().is_none_or(|hash| update.plan_hash.as_ref() == Some(hash)),
                "TCP 探测配置未确认");
            ensure!(
                r.predicts()
                    && r.round == update.round
                    && r.start.is_some_and(|start| start.elapsed() < TCP_PREDICTION_TTL),
                "首次配对的端口预测轮次无效或过期"
            );
            let result = port_prediction::RoomPrediction::update(
                &mut r.prediction, if owner { 0 } else { 1 }, update,
            )?;
            let participant = if owner { &r.owner } else { r.guest.as_ref().unwrap() };
            let mut response = room_state(&key, r, participant);
            response["Prediction"] = json!(result);
            return Ok(response);
        }
        let retry = text("RetryRound");
        let retry = if retry.is_empty() {
            None
        } else {
            Some(retry.parse::<uuid::Uuid>().context("协调重试轮次无效")?)
        };
        let close = input
            .get("Close")
            .or_else(|| input.get("close"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if close {
            ensure!(owner, "只有主机能关闭会话");
            let result = room_state(&key, r, &r.owner);
            rooms.remove(&key);
            return Ok(result);
        }
        if !owner && ready {
            ensure!(r.probe_hash.as_ref().is_none_or(|hash| input["ProbeHash"] == *hash),
                "从机探测配置未确认，无法开始打洞");
        }
        let endpoint = text("Endpoint");
        let offered = text("NextHostEndpoint");
        if !offered.is_empty() {
            ensure!(owner && r.mode == "faketcp" && endpoint.is_empty(), "只有 FakeTCP 主机可以更新后续配对入口");
            matches_source(&offered, source)?;
            if guest_present {
                r.next_host_endpoint = (p.endpoint != offered).then_some(offered);
            } else {
                p.endpoint = offered;
            }
        }
        if !endpoint.is_empty() {
            matches_source(&endpoint, source)?;
            ensure!(
                p.endpoint.is_empty() || p.endpoint == endpoint,
                "辅助候选已改变，请重新生成直连码"
            );
            p.endpoint = endpoint;
        }
        p.ready = ready;
        // Only the current expired schedule can be replaced. Both peers may
        // report it concurrently; a delayed report must not replace a new one.
        let round_lifetime = r.prediction_window().unwrap_or(FIRST_CONTACT_LEAD + LATE_TOLERANCE);
        if retry == Some(r.round)
            && r.start.is_some_and(|t| t.elapsed() > round_lifetime)
        {
            ensure!(r.attempts <= PAIRING_RETRIES, "协调探测连续过期，请重新生成直连码");
            r.clear_round();
        }
        if let Some(value) = input.get("RetryMimicRound") {
            ensure!(!owner && ready && r.mode == "mimic" && r.stable_raw_round(),
                "此会话不支持从机请求 Mimic 新轮次");
            let failed: uuid::Uuid = serde_json::from_value(value.clone())?;
            // Retries of this request must not invalidate a newly scheduled round.
            if failed == r.round && r.start.is_some_and(|start| {
                r.raw_published.is_some_and(|published| published.elapsed() >= MIMIC_REPLY_WINDOW)
                    || start.elapsed() >= FIRST_CONTACT_LEAD + MIMIC_OFFER_WINDOW
            }) {
                ensure!(r.attempts <= PAIRING_RETRIES, "Mimic 协调探测已用完重试次数");
                if let Some(endpoint) = input.get("NextGuestEndpoint") {
                    ensure!(r.rotate_mimic_endpoint, "主机未声明支持更新 Mimic 从机端点");
                    let endpoint = endpoint.as_str().context("从机新映射无效")?;
                    matches_source(endpoint, source)?;
                    r.guest.as_mut().unwrap().endpoint = endpoint.to_owned();
                }
                r.clear_round();
            }
        }
        if r.start.is_none()
            && r.owner.ready
            && r.guest
                .as_ref()
                .is_some_and(|g| g.ready && !g.endpoint.is_empty())
        {
            r.round = uuid::Uuid::new_v4();
            r.start = Some(Instant::now());
            r.attempts += 1;
        }
        Ok(room_state(
            &key,
            r,
            if owner {
                &r.owner
            } else {
                r.guest.as_ref().unwrap()
            },
        ))
    }
    pub fn member(&self, network: &str, request: MemberRequest, peer: &Member) -> Result<Value> {
        let mode = request.mode.clone();
        Ok(self
            .report_member(network, request, peer, None)?
            .json(&mode))
    }
    pub async fn wait_member(
        &self,
        network: &str,
        request: MemberRequest,
        peer: &Member,
        cancel: &CancellationToken,
    ) -> Result<Value> {
        let began = Instant::now();
        let mode = request.mode.clone();
        let slot = request.slot;
        let request_id = request.request_id;
        let (send, mut receive) = oneshot::channel();
        let reply = match self.report_member(network, request, peer, Some(send))? {
            MemberReply::Waiting => tokio::select! {
                _ = cancel.cancelled() => anyhow::bail!("协调服务已停止"),
                reply = tokio::time::timeout(MEMBER_WAIT, &mut receive) => match reply {
                    Ok(reply) => reply.unwrap_or(MemberReply::Waiting),
                    Err(_) => {
                        self.member_poll_timed_out(network, slot, request_id);
                        MemberReply::Waiting
                    }
                }
            },
            reply => reply,
        };
        let mut reply = reply.json(&mode);
        reply["ServerWaitMilliseconds"] = json!(began.elapsed().as_millis() as u64);
        Ok(reply)
    }

    fn member_poll_timed_out(&self, network: &str, slot: u8, request_id: uuid::Uuid) {
        let mut members = self.members.lock().unwrap();
        if let Some(report) = members.get_mut(&(network.into(), slot))
            && report.latest.request_id == request_id && report.confirmed
            && report.waiter.take().is_some()
        {
            // A normal poll returned Waiting. Keep brief readiness for the
            // gap before its next request, including a fresh STUN recheck.
            report.poll_timed_out = Some(Instant::now());
        }
    }

    fn report_member(
        &self,
        network: &str,
        request: MemberRequest,
        peer: &Member,
        waiter: Option<oneshot::Sender<MemberReply>>,
    ) -> Result<MemberReply> {
        let now = Instant::now();
        let issued_now = unix_seconds();
        let ttl = MEMBER_TTL;
        let key = (network.to_owned(), request.slot);
        let peer_key = (network.to_owned(), peer.slot);
        let mut members = self.members.lock().unwrap();
        members.retain(|_, r| now.duration_since(r.received) <= ttl * 2);
        ensure!(
            members.len() < 8192 || members.contains_key(&key),
            "协同成员表已满"
        );
        let changed = members.get(&key).is_some_and(|r| {
            let old = &r.latest;
            old.device != request.device
                || old.boot != request.boot
                || old.endpoint != request.endpoint
                || old.ready != request.ready
                || old.mode != request.mode
                || old.prediction.is_some() != request.prediction.is_some()
                || old.round_control().is_some() != request.round_control().is_some()
                || now.duration_since(r.received) >= if old.round_control().is_some() { TCP_PREDICTION_TTL } else { ttl }
        });
        let current = members.entry(key.clone()).or_insert_with(|| MemberReport {
            latest: request.clone(),
            received: now,
            confirmed: false,
            waiter: None,
            poll_timed_out: None,
            requests: HashMap::new(),
        });
        current.requests.retain(|_, expires| *expires >= issued_now);
        ensure!(
            !current.requests.contains_key(&request.request_id),
            "重复的成员协调请求"
        );
        ensure!(current.requests.len() < 128, "成员协调请求过于频繁");
        ensure!(
            current.latest.device != request.device || request.issued >= current.latest.issued,
            "成员协调请求早于当前报告"
        );
        current
            .requests
            .insert(request.request_id, request.issued.saturating_add(30));
        current.confirmed = request.ready;
        current.received = now;
        current.latest = request;
        current.waiter = waiter;
        current.poll_timed_out = None;
        let mut rounds = self.rounds.lock().unwrap();
        let prior = rounds
            .get(network)
            .copied();
        let expired = prior.is_some_and(|r| now.duration_since(r.start) > if r.synchronized {
            TCP_PREDICTION_TTL
        } else {
            r.lead + LATE_TOLERANCE
        });
        rounds.retain(|_, r| {
            let lifetime = if r.prediction { TCP_PREDICTION_TTL } else { ttl };
            now.duration_since(r.start) < lifetime
        });
        let caller_ready = current.confirmed;
        let caller_waiting = current.waiter.as_ref().is_some_and(|waiter| !waiter.is_closed());
        let caller_endpoint = current.latest.endpoint.clone();
        let caller_boot = current.latest.boot;
        let caller_prediction = current.latest.prediction.is_some();
        let caller_synchronized = current.latest.round_control().is_some();
        let caller_finished = current.latest.round_control().and_then(|control| control.finished);
        let mode = current.latest.mode.clone();
        let remote = members.get_mut(&peer_key);
        if changed || expired && prior.is_some_and(|row| !row.synchronized) {
            rounds.remove(network);
            if let Some(remote) = remote {
                remote.confirmed = false;
                remote.poll_timed_out = None;
                if let Some(waiter) = remote.waiter.take() {
                    let _ = waiter.send(MemberReply::Refresh);
                }
            }
            return Ok(MemberReply::Waiting);
        }
        if expired {
            rounds.remove(network);
        }
        let Some(remote) = remote.filter(|r| {
            caller_ready
                && r.confirmed
                && r.latest.mode == mode
                && r.latest.device == peer.device
                && now.duration_since(r.received) < if r.latest.round_control().is_some() { TCP_PREDICTION_TTL } else { ttl }
        }) else {
            return Ok(MemberReply::Waiting);
        };
        if let Some(row) = rounds.get(network).filter(|row| row.synchronized) {
            let remote_finished = remote.latest.round_control().and_then(|control| control.finished);
            if remote_finished == Some(row.round) {
                // The caller is also asking for a schedule again. It may
                // have missed delivery of the old round and have no Finished
                // for it. Neither side can use that round any longer.
                rounds.remove(network);
            } else if caller_finished == Some(row.round) {
                return Ok(MemberReply::Waiting);
            }
        }
        let prior = rounds.get(network).copied();
        let synchronized = caller_synchronized && remote.latest.round_control().is_some();
        if prior.is_none() && synchronized {
            let remote_waiting = remote.waiter.as_ref().is_some_and(|waiter| !waiter.is_closed());
            let remote_returning = remote.poll_timed_out
                .is_some_and(|finished| now.duration_since(finished) < MEMBER_POLL_GRACE);
            // An abandoned poll cannot join a new round. A normal timeout
            // can bridge the gap between two consecutive requests.
            if !remote_waiting && !remote_returning
                && (caller_waiting || now.duration_since(remote.received) >= MEMBER_WAIT)
            {
                return Ok(MemberReply::Waiting);
            }
        }
        let mut row = prior.unwrap_or_else(|| MemberRound {
            round: uuid::Uuid::new_v4(),
            start: now,
            lead: if synchronized { Duration::ZERO } else { MEMBER_LEAD },
            prediction: caller_prediction && remote.latest.prediction.is_some(),
            synchronized,
        });
        if let Some(waiter) = remote.waiter.take() {
            let mut offered = row;
            if prior.is_none() && caller_waiting && !synchronized {
                offered.lead = WAITING_MEMBER_LEAD;
            }
            if waiter.send(MemberReply::Scheduled(offered, caller_endpoint, caller_boot)).is_ok() {
                row = offered;
            } else if prior.is_none() && synchronized && caller_waiting {
                return Ok(MemberReply::Waiting);
            }
        }
        let endpoint = remote.latest.endpoint.clone();
        let boot = remote.latest.boot;
        if prior.is_none() {
            remote.poll_timed_out = None;
            rounds.insert(network.into(), row);
        }
        members.get_mut(&key).unwrap().waiter = None;
        Ok(MemberReply::Scheduled(row, endpoint, boot))
    }
    pub fn status(&self) -> Value {
        let rooms = self.rooms.lock().unwrap();
        json!({"waiting":rooms.values().filter(|r|r.start.is_none()).count(),"scheduled":rooms.values().filter(|r|r.start.is_some()).count()})
    }
}
fn room_state(key: &str, r: &Room, p: &Participant) -> Value {
    let window = r.start.zip(r.prediction_window())
        .map(|(start, lifetime)| lifetime.saturating_sub(start.elapsed()).as_millis() as u64);
    json!({"Room":key,"Token":p.token,"Expires":r.expires,"HostRoom":r.host_room,"Commitment":r.commitment,"HostEndpoint":r.owner.endpoint,"GuestEndpoint":r.guest.as_ref().map(|g|g.endpoint.as_str()).unwrap_or(""),"Round":r.round,"StartAfterMilliseconds":r.start.map(|t|(FIRST_CONTACT_LEAD.as_millis() as i64-t.elapsed().as_millis() as i64).max(-30000)).unwrap_or(0),"PredictionWindowMilliseconds":window,"Mode":r.mode,"TcpPrediction":r.predicts(),
        "RawPredictionSupported":r.raw_prediction_supported,"RawHostPrediction":r.raw_prediction_requested,
        "RawMultiCandidate":r.raw_multi_requested,"RawHostPorts":r.raw_host_ports,
        "MimicRoundRetry":r.mode == "mimic" && r.stable_raw_round(),
        "MimicEndpointRotation":r.rotate_mimic_endpoint && r.stable_raw_round(),
        "RawHostPort":r.raw_host_port,"RawGuestReady":r.raw_guest_ready,"ProbePlan":r.probe,"ProbeHash":r.probe_hash,"ShortCode":r.probe.is_some()})
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_digit_coordinator_code_requires_matching_observer_plan_before_start() -> Result<()> {
        let service = Assist::default();
        let owner = "203.0.113.1".parse()?;
        let guest = "203.0.113.2".parse()?;
        for mode in ["faketcp", "phantun", "mimic", "tcpraw", "tcp", "https"] {
            let plan = ProbePlan::new(mode, "203.0.113.3:3479".parse()?);
            let hash = plan.hash()?;
            let host = service.request("create", &json!({"Endpoint":"203.0.113.1:44000",
                "HostRoom":"123456","Commitment":"A".repeat(64),"Mode":mode,"Ready":true,
                "ProbePlan":plan,"ProbeHash":hash}), owner)?;
            let room = host["Room"].as_str().unwrap();
            assert!(short_code(room) && host["ShortCode"] == true);
            let description = service.request("describe", &json!({"Code":room}), guest)?;
            assert_eq!(description["Mode"], mode);
            let join = service.request("join", &json!({"Code":room,"Mode":mode,
                "RequestId":conwu_core::id(),"Commitment":"B".repeat(64)}), guest)?;
            assert_eq!(ProbePlan::read(&join, mode)?, Some(plan));
            let invalid = json!({"Token":join["Token"],"Ready":true,"Endpoint":"203.0.113.2:45001","ProbeHash":"wrong"});
            assert!(service.request(room, &invalid, guest).is_err());
            let current = service.request(room, &json!({"Token":host["Token"],"Ready":true}), owner)?;
            assert_eq!(current["GuestEndpoint"], "");
            let ready = service.request(room, &json!({"Token":join["Token"],"Ready":true,
                "Endpoint":"203.0.113.2:45000","ProbeHash":hash}), guest)?;
            assert!(matches!(Schedule::read(&ready, Duration::ZERO)?, Schedule::Ready(_, _)));
        }
        Ok(())
    }
    #[tokio::test]
    async fn short_code_description_uses_the_public_response_shape() -> Result<()> {
        use axum::{Json, Router, extract::Path, routing::post};
        use std::sync::Arc;

        let service = Arc::new(Assist::default());
        let source: IpAddr = "127.0.0.1".parse()?;
        let plan = ProbePlan::new("tcp", "127.0.0.1:3478".parse()?);
        let host = service.request("create", &json!({
            "Endpoint":"127.0.0.1:44000","HostRoom":"123456","Commitment":"A".repeat(64),
            "Mode":"tcp","ProbeHash":plan.hash()?,"ProbePlan":plan
        }), source)?;
        let code = host["Room"].as_str().unwrap();
        let router = Router::new().route("/v1/punch-assist/{action}", post(
            move |Path(action): Path<String>, Json(input): Json<Value>| {
                let service = service.clone();
                async move { Json(service.request(&action, &input, source).unwrap()) }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = listener.local_addr()?;
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let client = Client {
            http: reqwest::Client::builder().no_proxy().build()?,
            base: format!("http://{endpoint}/").parse()?,
            endpoint,
        };
        let result = client.describe_pair(code).await;
        server.abort();
        assert_eq!(result?, "tcp");
        Ok(())
    }

    #[tokio::test]
    async fn create_retries_recover_the_room_after_a_lost_response() -> Result<()> {
        use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing::post};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

        let service = Arc::new(Assist::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let source: IpAddr = "127.0.0.1".parse()?;
        let endpoint = "127.0.0.1:44000";
        let router = Router::new().route("/v1/punch-assist/{action}", post({
            let service = service.clone();
            let calls = calls.clone();
            move |Path(action): Path<String>, Json(input): Json<Value>| {
                let service = service.clone();
                let calls = calls.clone();
                async move {
                    let attempt = calls.fetch_add(1, Ordering::SeqCst);
                    match service.request(&action, &input, source) {
                        Ok(_) if attempt < usize::from(PAIRING_RETRIES) => {
                            (StatusCode::BAD_GATEWAY, "upstream response lost").into_response()
                        }
                        Ok(reply) => Json(reply).into_response(),
                        Err(error) => (StatusCode::BAD_REQUEST, Json(json!({"error":error.to_string()}))).into_response(),
                    }
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let client = Client {
            http: reqwest::Client::builder().no_proxy().build()?,
            base: format!("http://{address}/").parse()?,
            endpoint: address,
        };
        let input = json!({"Endpoint":endpoint,"HostRoom":"123456","Commitment":"A".repeat(64),"Mode":"tcp"});
        let (restored, retries) = client.create_pair_room(input.clone()).await?;
        assert_eq!(retries, PAIRING_RETRIES);
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(PAIRING_RETRIES) + 1);
        {
            let rooms = service.rooms.lock().unwrap();
            assert_eq!(rooms.len(), 1);
            let room = &rooms[restored["Room"].as_str().unwrap()];
            assert_eq!(restored["Token"], room.owner.token);
        }
        let mut invalid = input;
        invalid["Mode"] = json!("udp");
        assert!(client.create_pair_room(invalid).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(PAIRING_RETRIES) + 2,
            "server validation errors must stop the retry");
        server.abort();
        Ok(())
    }

    #[test]
    fn repeated_create_cannot_change_the_request_or_its_source() -> Result<()> {
        let service = Assist::default();
        let owner = "203.0.113.1".parse()?;
        let other = "203.0.113.2".parse()?;
        let body = json!({"Endpoint":"203.0.113.1:44000","HostRoom":"123456","Commitment":"A".repeat(64),
            "RequestId":conwu_core::id(),"Mode":"https"});
        let stored = service.request("create", &body, owner)?;
        let same = service.request("create-retry", &body, owner)?;
        assert_eq!(stored["Room"], same["Room"]);
        assert_eq!(stored["Token"], same["Token"]);
        let mut changed = body;
        changed["Mode"] = json!("tcp");
        assert!(service.request("create-retry", &changed, owner).is_err());
        changed["Endpoint"] = json!("203.0.113.2:44000");
        assert!(service.request("create-retry", &changed, other).is_err());
        assert_eq!(service.rooms.lock().unwrap().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn coordinator_errors_keep_the_reason_and_the_response_size_limit() -> Result<()> {
        use axum::{Json, Router, http::StatusCode, routing::post};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = listener.local_addr()?;
        let router = Router::new()
            .route("/limit", post(|| async {
                (StatusCode::BAD_REQUEST, Json(json!({"error":"协调探测连续过期，请重新生成直连码"})))
            }))
            .route("/oversize", post(|| async {
                (StatusCode::BAD_REQUEST, Json(json!({"error":"x".repeat(9000)})))
            }));
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let client = Client {
            http: reqwest::Client::builder().no_proxy().build()?,
            base: format!("http://{endpoint}/").parse()?,
            endpoint,
        };
        let error = client.post("limit", &json!({}), None).await.unwrap_err();
        assert!(error.to_string().contains("请重新生成直连码"));
        let error = client.post("oversize", &json!({}), None).await.unwrap_err();
        assert!(error.to_string().contains("协同响应过大"));
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn raw_offer_poll_retries_signal_failure_but_returns_expired_round() -> Result<()> {
        use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing::post};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

        let service = Arc::new(Assist::default());
        let source: IpAddr = "127.0.0.1".parse()?;
        let owner = service.request("create", &json!({
            "Endpoint":"127.0.0.1:44000", "HostRoom":"123456", "Commitment":"A".repeat(64),
            "Mode":"mimic", "Ready":true, "RawHostPrediction":true, "RawMultiCandidate":true
        }), source)?;
        let room = owner["Room"].as_str().unwrap();
        let guest = service.request("join", &json!({
            "Code":room, "RequestId":conwu_core::id(), "Commitment":"B".repeat(64),
            "Mode":"mimic", "RawHostPrediction":true, "RawMultiCandidate":true
        }), source)?;
        let state = service.request(room, &json!({
            "Token":guest["Token"], "Endpoint":"127.0.0.1:44010", "Ready":true
        }), source)?;
        let round: uuid::Uuid = serde_json::from_value(state["Round"].clone())?;
        assert!(!round.is_nil());
        service.request(room, &json!({
            "Token":owner["Token"], "RawPredictionRound":round, "RawHostPorts":[44002,44003]
        }), source)?;

        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route("/v1/punch-assist/{action}", post({
            let calls = calls.clone();
            move |Path(action): Path<String>, Json(input): Json<Value>| {
                let calls = calls.clone();
                let service = service.clone();
                async move {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        return StatusCode::BAD_GATEWAY.into_response();
                    }
                    match service.request(&action, &input, source) {
                        Ok(reply) => Json(reply).into_response(),
                        Err(error) => (StatusCode::BAD_REQUEST, Json(json!({"error":error.to_string()}))).into_response(),
                    }
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = listener.local_addr()?;
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let client = Client {
            http: reqwest::Client::builder().no_proxy().build()?,
            base: format!("http://{endpoint}/").parse()?,
            endpoint,
        };
        let ports: Vec<_> = client.raw_pair_candidates(&state, round).await?
            .into_iter().map(|addr| addr.port()).collect();
        assert_eq!(ports, [44002, 44003]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let error = client.raw_pair_candidates(&state, uuid::Uuid::new_v4()).await.unwrap_err();
        assert!(error.is::<RawRoundExpired>());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        server.abort();
        Ok(())
    }

    #[test]
    fn schedules_account_for_response_transit_and_reject_expired_or_invalid_rounds() -> Result<()> {
        let round = uuid::Uuid::new_v4();
        let state = |round: uuid::Uuid, delay: i64| {
            json!({"Round":round,"StartAfterMilliseconds":delay})
        };
        assert!(matches!(Schedule::read(&state(uuid::Uuid::nil(), 0), Duration::ZERO)?, Schedule::Waiting));
        assert!(matches!(Schedule::read(&state(round, 1000), Duration::from_millis(400))?, Schedule::Ready(id, delay) if id == round && delay == Duration::from_millis(800)));
        assert!(matches!(Schedule::read(&state(round, -1900), Duration::from_millis(400))?, Schedule::Expired(id) if id == round));
        assert!(matches!(Schedule::read(&state(round, -2000), Duration::ZERO)?, Schedule::Ready(_, delay) if delay.is_zero()));
        assert!(Schedule::read(&state(round, 8001), Duration::ZERO).is_err());
        assert!(Schedule::read(&json!({"Round":"invalid","StartAfterMilliseconds":0}), Duration::ZERO).is_err());
        assert!(Schedule::read(&json!({"Round":round}), Duration::ZERO).is_err());
        Ok(())
    }

    #[test]
    fn mimic_late_guest_keeps_the_round_then_resynchronizes_on_expiry() -> Result<()> {
        let service = Assist::default();
        let a = "203.0.113.1".parse()?;
        let b = "203.0.113.2".parse()?;
        let owner = service.request("create", &json!({"Mode":"mimic","HostRoom":"123456",
            "Endpoint":"203.0.113.1:41000","Commitment":"A".repeat(64),"Ready":true,
            "RawHostPrediction":true,"RawMultiCandidate":true,"RawRoundSync":true}), a)?;
        let room = owner["Room"].as_str().unwrap();
        let guest = service.request("join", &json!({"Code":room,"Mode":"mimic",
            "RequestId":conwu_core::id(),"Commitment":"B".repeat(64),
            "RawHostPrediction":true,"RawMultiCandidate":true,"RawRoundSync":true}), b)?;
        let ready = |round: &Value| json!({"Token":guest["Token"],"Endpoint":"203.0.113.2:42000",
            "Ready":true,"RetryRound":round});
        let first = service.request(room, &ready(&json!(uuid::Uuid::nil())), b)?;
        let first_id: uuid::Uuid = serde_json::from_value(first["Round"].clone())?;
        let age = |elapsed| service.rooms.lock().unwrap().get_mut(room).unwrap().start = Some(Instant::now() - elapsed);
        age(Duration::from_secs(5));
        let late = service.request(room, &ready(&first["Round"]), b)?;
        assert!(matches!(Schedule::read(&late, Duration::from_millis(100))?, Schedule::Ready(round, delay)
            if round == first_id && delay.is_zero()));
        let candidate = |round: &Value| json!({"Token":owner["Token"],"RawPredictionRound":round,
            "RawHostPorts":[41002,41003]});
        assert_eq!(service.request(room, &candidate(&first["Round"]), a)?["RawHostPorts"], json!([41002,41003]));

        age(TCP_PREDICTION_TTL + Duration::from_secs(1));
        assert!(service.request(room, &candidate(&first["Round"]), a).unwrap_err().is::<RawRoundExpired>());
        let fresh = service.request(room, &ready(&first["Round"]), b)?;
        assert_ne!(fresh["Round"], first["Round"]);
        assert!(fresh["RawHostPorts"].is_null());
        let host = service.request(room, &json!({"Token":owner["Token"],"Ready":true,
            "RetryRound":first["Round"]}), a)?;
        assert_eq!(host["Round"], fresh["Round"]);
        service.request(room, &candidate(&host["Round"]), a)?;
        let received = service.request(room, &json!({"Token":guest["Token"],"RawPredictionRound":fresh["Round"]}), b)?;
        assert_eq!(received["RawHostPorts"], json!([41002,41003]));
        Ok(())
    }

    #[test]
    fn mimic_guest_retries_after_the_ticket_window_without_leaving_the_room() -> Result<()> {
        let service = Assist::default();
        let a = "203.0.113.1".parse()?;
        let b = "203.0.113.2".parse()?;
        let host = service.request("create", &json!({"Mode":"mimic","HostRoom":"123456",
            "Endpoint":"203.0.113.1:41000","Commitment":"A".repeat(64),"Ready":true,
            "RawHostPrediction":true,"RawMultiCandidate":true,"RawRoundSync":true,"MimicEndpointRotation":true}), a)?;
        let room = host["Room"].as_str().unwrap();
        let guest = service.request("join", &json!({"Code":room,"Mode":"mimic",
            "RequestId":conwu_core::id(),"Commitment":"B".repeat(64),
            "RawHostPrediction":true,"RawMultiCandidate":true,"RawRoundSync":true}), b)?;
        let first = service.request(room, &json!({"Token":guest["Token"],"Ready":true,
            "Endpoint":"203.0.113.2:42000"}), b)?;
        let offer = json!({"Token":host["Token"],"RawPredictionRound":first["Round"],
            "RawHostPorts":[41002,41003]});
        let retry = json!({"Token":guest["Token"],"RetryMimicRound":first["Round"],"Ready":true});
        service.request(room, &offer, a)?;
        assert_eq!(service.request(room, &retry, b)?["Round"], first["Round"]);
        service.rooms.lock().unwrap().get_mut(room).unwrap().raw_published =
            Some(Instant::now() - MIMIC_REPLY_WINDOW);
        let next = service.request(room, &retry, b)?;
        assert_ne!(next["Round"], first["Round"]);
        assert_eq!(next["GuestEndpoint"], first["GuestEndpoint"]);
        assert_eq!(next["Token"], guest["Token"]);
        assert!(next["RawHostPorts"].is_null());
        assert!(service.request(room, &offer, a).unwrap_err().is::<RawRoundExpired>());
        assert_eq!(service.request(room, &retry, b)?["Round"], next["Round"]);
        assert_eq!(service.request(room, &json!({"Token":host["Token"],"Ready":true}), a)?["Round"], next["Round"]);
        let rotate = |round: &Value, addr: &str| json!({"Token":guest["Token"],"RetryMimicRound":round,
            "Ready":true,"NextGuestEndpoint":addr});
        let move_port = rotate(&next["Round"], "203.0.113.2:42001");
        assert_eq!(service.request(room, &move_port, b)?["GuestEndpoint"], next["GuestEndpoint"]);
        service.rooms.lock().unwrap().get_mut(room).unwrap().raw_published = Some(Instant::now() - MIMIC_REPLY_WINDOW);
        assert!(service.request(room, &rotate(&next["Round"], "203.0.113.3:42001"), b).is_err());
        let updated = service.request(room, &move_port, b)?;
        assert_ne!(updated["Round"], next["Round"]);
        assert_eq!(updated["GuestEndpoint"], "203.0.113.2:42001");
        assert_eq!(updated["Token"], guest["Token"]);
        assert!(updated["RawHostPorts"].is_null());
        let replay = service.request(room, &rotate(&next["Round"], "203.0.113.2:42002"), b)?;
        assert_eq!(replay["Round"], updated["Round"]);
        assert_eq!(replay["GuestEndpoint"], updated["GuestEndpoint"]);
        assert_eq!(service.request(room, &json!({"Token":host["Token"],"Ready":true}), a)?["GuestEndpoint"], updated["GuestEndpoint"]);
        Ok(())
    }
    #[test]
    fn expired_first_contact_rounds_resynchronize_with_a_bound_and_preserve_bindings() -> Result<()> {
        for mode in ["faketcp", "phantun", "mimic", "tcpraw", "tcp", "https"] {
            let service = Assist::default();
            let a = "203.0.113.1".parse()?;
            let b = "203.0.113.2".parse()?;
            let room = service.request("create", &json!({"Endpoint":"203.0.113.1:44000","HostRoom":"123456","Commitment":"A".repeat(64),"Mode":mode}), a)?;
            let key = room["Room"].as_str().unwrap();
            let guest = service.request("join", &json!({"Code":key,"RequestId":conwu_core::id(),"Commitment":"B".repeat(64),"Mode":mode}), b)?;
            let input = |round: &Value| json!({"Token":guest["Token"],"Endpoint":"203.0.113.2:44001","RetryRound":round});
            let mut current = service.request(key, &input(&json!(uuid::Uuid::nil())), b)?;
            let original = current.clone();
            let early = service.request(key, &input(&current["Round"]), b)?;
            assert_eq!(early["Round"], current["Round"], "未过期的轮次不能被替换");
            for _ in 0..PAIRING_RETRIES {
                service.rooms.lock().unwrap().get_mut(key).unwrap().start = Some(Instant::now() - Duration::from_secs(4));
                let old = current["Round"].clone();
                assert!(service.request(key, &input(&old), a).is_err(), "令牌持有者的来源必须继续匹配");
                current = service.request(key, &input(&old), b)?;
                assert_ne!(current["Round"], old);
                for field in ["Room", "Token", "HostRoom", "Commitment", "HostEndpoint", "GuestEndpoint", "Mode"] {
                    assert_eq!(current[field], original[field], "重新调度不能改变绑定：{field}");
                }
                // The other participant can report the old round after a new
                // one was scheduled. That replay must not consume a retry.
                let owner = service.request(key, &json!({"Token":room["Token"],"RetryRound":old}), a)?;
                assert_eq!(owner["Round"], current["Round"]);
            }
            service.rooms.lock().unwrap().get_mut(key).unwrap().start = Some(Instant::now() - Duration::from_secs(4));
            assert!(service.request(key, &input(&current["Round"]), b).is_err(), "重同步必须有明确上限");
            assert_eq!(service.rooms.lock().unwrap()[key].attempts, PAIRING_RETRIES + 1);
        }
        Ok(())
    }
    #[test]
    fn first_contact_is_source_bound_and_member_rounds_cover_all_carriers() -> Result<()> {
        for mode in ["faketcp", "phantun", "mimic", "tcpraw", "tcp", "https"] {
            let service = Assist::default();
            let a = "203.0.113.1".parse()?;
            let b = "203.0.113.2".parse()?;
            let room=service.request("create",&json!({"Endpoint":"203.0.113.1:44000","HostRoom":"123456","Commitment":"A".repeat(64),"Mode":mode,"Ready":true}),a)?;
            let guest=service.request("join",&json!({"Code":room["Room"],"RequestId":conwu_core::id(),"Commitment":"B".repeat(64),"Mode":mode}),b)?;
            let key = room["Room"].as_str().unwrap();
            assert!(service.request(key,&json!({"Token":guest["Token"],"Endpoint":"203.0.113.9:44001","Ready":true}),b).is_err());
            let scheduled = service.request(
                key,
                &json!({"Token":guest["Token"],"Endpoint":"203.0.113.2:44001","Ready":true}),
                b,
            )?;
            assert_ne!(scheduled["Round"], uuid::Uuid::nil().to_string());
            let mut owner = Profile::create(mode)?;
            let peer = Profile::import(&owner.issue(None)?.export()?)?;
            let request =
                MemberRequest::create(&owner, uuid::Uuid::new_v4(), "203.0.113.1:44000".parse()?)?;
            request.verify(&owner.pair.network, &owner.member, a)?;
            assert!(
                request
                    .verify(&owner.pair.network, &owner.member, b)
                    .is_err()
            );
            let mut forged = request.clone();
            forged.mode = "udp".into();
            assert!(
                forged
                    .verify(&owner.pair.network, &owner.member, a)
                    .is_err()
            );
            service.member(&owner.pair.network, request.clone(), &peer.member)?;
            let reply = service.member(
                &owner.pair.network,
                MemberRequest::create(&peer, uuid::Uuid::new_v4(), "203.0.113.2:44001".parse()?)?,
                &owner.member,
            )?;
            let matched = service.member(&owner.pair.network,
                MemberRequest::create(&owner, request.boot, request.endpoint.parse()?)?, &peer.member)?;
            assert_eq!(reply["Round"], matched["Round"]);
            assert_eq!(reply["PeerEndpoint"], "203.0.113.1:44000");
            assert_eq!(matched["PeerEndpoint"], "203.0.113.2:44001");
            assert!(matched["StartAfterMilliseconds"].as_i64().unwrap() <= MEMBER_LEAD.as_millis() as i64);
        }
        Ok(())
    }

    #[test]
    fn raw_port_retry_is_scoped_to_one_guest_round_and_carrier() -> Result<()> {
        for mode in ["faketcp", "phantun", "mimic", "tcpraw", "tcp", "https"] {
            let service = Assist::default();
            let owner_ip = "203.0.113.1".parse()?;
            let guest_ip = "203.0.113.2".parse()?;
            let owner = service.request("create",&json!({"Mode":mode,"HostRoom":"123456",
                "Endpoint":"203.0.113.1:41000","Commitment":"A".repeat(64),
                "RawHostPrediction":true,"RawMultiCandidate":true}),owner_ip)?;
            let room = owner["Room"].as_str().unwrap();
            let join = |upgrade| service.request("join",&json!({"Code":room,"Mode":mode,
                "RequestId":conwu_core::id(),"Commitment":"B".repeat(64),"RawHostPrediction":upgrade}),guest_ip);
            let first = join(false)?;
            assert_eq!(first["RawHostPrediction"], false);
            service.request(room,&json!({"Token":first["Token"],"Withdraw":true}),guest_ip)?;
            let next = join(true)?;
            let enabled = conwu_core::code::raw_tcp_mode(mode);
            assert_eq!(next["RawHostPrediction"], enabled);
            assert_eq!(next["RawMultiCandidate"], false);
            let guest_addr = "203.0.113.2:42003";
            service.request(room,&json!({"Token":next["Token"],"Endpoint":guest_addr,"Ready":true}),guest_ip)?;
            let schedule = service.request(room,&json!({"Token":owner["Token"],"ReadyFor":guest_addr,"Ready":true}),owner_ip)?;
            let publish = |port| service.request(room,&json!({"Token":owner["Token"],
                "RawPredictionRound":schedule["Round"],"RawHostPort":port}),owner_ip);
            if !enabled { assert!(publish(41003).is_err()); continue; }
            assert!(publish(80).is_err());
            assert!(service.request(room,&json!({"Token":owner["Token"],"RawPredictionRound":uuid::Uuid::new_v4(),"RawHostPort":41003}), owner_ip).is_err());
            assert!(service.request(room,&json!({"Token":next["Token"],"RawPredictionRound":schedule["Round"],"RawHostPort":41003}), guest_ip).is_err());
            assert_eq!(publish(41003)?["RawHostPort"],41003);
            assert!(publish(41004).is_err());
            let ready = service.request(room,&json!({"Token":next["Token"],"RawPredictionRound":schedule["Round"],"RawGuestReady":true}),guest_ip)?;
            assert_eq!(ready["RawGuestReady"],true);
            assert_eq!(ready["HostEndpoint"],"203.0.113.1:41000");
            service.request(room,&json!({"Token":next["Token"],"Withdraw":true}),guest_ip)?;
            assert!(publish(41003).is_err());
            let fresh = join(false)?;
            assert_eq!(fresh["RawGuestReady"],false);
            assert!(fresh["RawHostPort"].is_null());
            service.request(room, &json!({"Token":fresh["Token"],"Withdraw":true}), guest_ip)?;

            let multi = service.request("join", &json!({"Code":room,"Mode":mode,
                "RequestId":conwu_core::id(),"Commitment":"B".repeat(64),"RawHostPrediction":true,
                "RawMultiCandidate":true}), guest_ip)?;
            assert_eq!(multi["RawMultiCandidate"], true);
            service.request(room, &json!({"Token":multi["Token"],"Endpoint":guest_addr,"Ready":true}), guest_ip)?;
            let schedule = service.request(room, &json!({"Token":owner["Token"],"ReadyFor":guest_addr,"Ready":true}), owner_ip)?;
            let offer = |token: &Value, round: &Value, ports: &[u16], source| {
                service.request(room, &json!({"Token":token,"RawPredictionRound":round,
                    "RawHostPorts":ports}), source)
            };
            let ports = [41004, 41001, 41002];
            for invalid in [vec![443], vec![41001, 41001], (41000..41017).collect()] {
                assert!(offer(&owner["Token"], &schedule["Round"], &invalid, owner_ip).is_err());
            }
            assert!(offer(&multi["Token"], &schedule["Round"], &ports, guest_ip).is_err());
            assert!(offer(&owner["Token"], &json!(uuid::Uuid::new_v4()), &ports, owner_ip).is_err());
            assert!(offer(&owner["Token"], &schedule["Round"], &ports, guest_ip).is_err());
            assert_eq!(offer(&owner["Token"], &schedule["Round"], &ports, owner_ip)?["RawHostPorts"], json!(ports));
            assert!(offer(&owner["Token"], &schedule["Round"], &[41003], owner_ip).is_err());
            let received = service.request(room, &json!({"Token":multi["Token"],
                "RawPredictionRound":schedule["Round"]}), guest_ip)?;
            assert_eq!(received["RawHostPorts"], json!(ports));
            assert_eq!(received["HostEndpoint"], "203.0.113.1:41000");
            service.request(room, &json!({"Token":multi["Token"],"Withdraw":true}), guest_ip)?;
            assert!(offer(&owner["Token"], &schedule["Round"], &ports, owner_ip).is_err());
        }
        Ok(())
    }

    #[test]
    fn faketcp_invite_refreshes_the_host_port_between_guests() -> Result<()> {
        let service = Assist::default();
        let owner_ip = "203.0.113.1".parse()?;
        let guest_ip = "203.0.113.2".parse()?;
        let owner = service.request("create", &json!({
            "Endpoint":"203.0.113.1:41000","HostRoom":"123456","Commitment":"A".repeat(64),"Mode":"faketcp","Ready":false
        }), owner_ip)?;
        let room = owner["Room"].as_str().unwrap();
        let offer = |endpoint: &str| service.request(room, &json!({"Token":owner["Token"],"NextHostEndpoint":endpoint}), owner_ip);
        let join = || service.request("join", &json!({
            "Code":room,"RequestId":conwu_core::id(),"Commitment":"B".repeat(64),"Mode":"faketcp"
        }), guest_ip);
        assert!(offer("203.0.113.2:41001").is_err());
        assert_eq!(offer("203.0.113.1:41001")?["HostEndpoint"], "203.0.113.1:41001");
        let guest = join()?;
        assert_eq!(guest["HostEndpoint"], "203.0.113.1:41001");
        assert!(service.request(room, &json!({"Token":guest["Token"],"NextHostEndpoint":"203.0.113.2:41000"}), guest_ip).is_err());
        assert_eq!(offer("203.0.113.1:41002")?["HostEndpoint"], guest["HostEndpoint"]);
        service.request(room, &json!({"Token":guest["Token"],"Withdraw":true}), guest_ip)?;
        assert_eq!(join()?["HostEndpoint"], "203.0.113.1:41002");
        Ok(())
    }

    #[test]
    fn withdrawing_a_guest_allows_a_fresh_attempt_with_the_same_code() -> Result<()> {
        for mode in ["mimic", "faketcp", "tcp"] {
            let service = Assist::default();
            let owner_ip = "203.0.113.1".parse()?;
            let guest_ip = "203.0.113.2".parse()?;
            let owner = service.request("create", &json!({
                "Endpoint": "203.0.113.1:44000", "HostRoom": "123456",
                "Commitment": "A".repeat(64), "Mode": mode, "Ready": mode != "faketcp",
                "TcpPrediction": true,
            }), owner_ip)?;
            let room = owner["Room"].as_str().unwrap();
            let invite = |commitment: &str| json!({
                "Code": room, "RequestId": conwu_core::id(),
                "Commitment": commitment.repeat(64), "Mode": mode, "TcpPrediction": true,
            });
            let advertise = |guest: &Value, endpoint: &str| {
                service.request(room, &json!({"Token": guest["Token"], "Endpoint": endpoint}), guest_ip)
            };
            let prepare = |endpoint: &str| {
                service.request(room, &json!({"Token": owner["Token"], "ReadyFor": endpoint}), owner_ip)
            };
            let first_endpoint = "203.0.113.2:44001";
            let first = service.request("join", &invite("B"), guest_ip)?;
            advertise(&first, first_endpoint)?;
            let scheduled = prepare(first_endpoint)?;
            let waiting = json!(uuid::Uuid::nil());
            assert_ne!(scheduled["Round"], waiting);
            let retry = invite("C");
            assert!(service.request("join", &retry, guest_ip).is_err());
            let withdraw = json!({"Token": first["Token"], "Withdraw": true});
            assert!(service.request(room, &withdraw, owner_ip).is_err());
            assert!(service.request(room, &json!({"Token": owner["Token"], "Withdraw": true}), owner_ip).is_err());
            let cleared = service.request(room, &withdraw, guest_ip)?;
            assert_eq!(service.request(room, &withdraw, guest_ip)?, cleared);
            assert_eq!(cleared["Round"], waiting);
            assert_eq!(cleared["GuestEndpoint"], "");
            assert_eq!(cleared["HostRoom"], owner["HostRoom"]);

            let second = service.request("join", &retry, guest_ip)?;
            assert_ne!(second["Token"], first["Token"]);
            let second_endpoint = "203.0.113.2:44002";
            advertise(&second, second_endpoint)?;
            if mode == "faketcp" {
                assert_eq!(prepare(first_endpoint)?["Round"], waiting);
            }
            let next = prepare(second_endpoint)?;
            assert_eq!(next["GuestEndpoint"], second_endpoint);
            assert_ne!(next["Round"], waiting);
            assert_ne!(next["Round"], scheduled["Round"]);
            assert!(service.request(room, &withdraw, guest_ip).is_err());
            assert_eq!(advertise(&second, second_endpoint)?["Round"], next["Round"]);
        }
        Ok(())
    }

    #[test]
    fn native_first_pair_accepts_delayed_roles_until_the_prediction_deadline() -> Result<()> {
        for mode in ["tcp", "https"] {
            let service = Assist::default();
            let (a, b) = ("203.0.113.1".parse()?, "203.0.113.2".parse()?);
            let host = service.request("create", &json!({"Endpoint":"203.0.113.1:44000","HostRoom":"123456",
                "Commitment":"A".repeat(64),"Mode":mode,"TcpPrediction":true}), a)?;
            let key = host["Room"].as_str().unwrap();
            let guest = service.request("join", &json!({"Code":key,"RequestId":conwu_core::id(),
                "Commitment":"B".repeat(64),"Mode":mode,"TcpPrediction":true}), b)?;
            let state = service.request(key, &json!({"Token":guest["Token"],"Endpoint":"203.0.113.2:44001"}), b)?;
            let round = serde_json::from_value(state["Round"].clone())?;
            let started = Instant::now() - Duration::from_secs(10);
            service.rooms.lock().unwrap().get_mut(key).unwrap().start = Some(started);
            let retry = json!({"Token":host["Token"],"RetryRound":round});
            let mut late = service.request(key, &retry, a)?;
            assert!(matches!(Schedule::read(&late, Duration::from_millis(200))?,
                Schedule::Ready(id, delay) if id == round && delay.is_zero()));
            late["PredictionWindowMilliseconds"] = Value::Null;
            assert!(matches!(Schedule::read_for_host(&late, Duration::ZERO, round, started)?, Schedule::Ready(id, _) if id == round));
            assert!(matches!(Schedule::read_for_host(&late, Duration::ZERO, uuid::Uuid::nil(), started)?, Schedule::Expired(_)));
            let expired = Instant::now() - TCP_PREDICTION_TTL - Duration::from_secs(1);
            assert!(matches!(Schedule::read_for_host(&late, Duration::ZERO, round, expired)?, Schedule::Expired(_)));
            for (participant, address, can_burst) in [(&host, a, true), (&guest, b, false)] {
                let update = PredictionUpdate { round, can_burst, ..Default::default() };
                assert_eq!(service.request(key, &json!({"Token":participant["Token"],"PredictionUpdate":update}), address)?["Round"], state["Round"]);
            }
            service.rooms.lock().unwrap().get_mut(key).unwrap().start = Some(expired);
            let next = service.request(key, &retry, a)?;
            assert_ne!(next["Round"], state["Round"]);
            assert_eq!(service.request(key, &retry, a)?["Round"], next["Round"]);
        }
        Ok(())
    }

    #[test]
    fn first_contact_prediction_shares_only_the_current_room_offer() -> Result<()> {
        let service = Assist::default();
        let a = "203.0.113.1".parse()?;
        let b = "203.0.113.2".parse()?;
        let owner = service.request("create", &json!({
            "Endpoint":"203.0.113.1:44000","HostRoom":"123456",
            "Commitment":"A".repeat(64),"Mode":"tcp","TcpPrediction":true
        }), a)?;
        assert_eq!(owner["TcpPrediction"], false);
        let guest = service.request("join", &json!({
            "Code":owner["Room"],"RequestId":conwu_core::id(),
            "Commitment":"B".repeat(64),"Mode":"tcp","TcpPrediction":true
        }), b)?;
        let room = owner["Room"].as_str().unwrap();
        let ready = service.request(room, &json!({
            "Token":guest["Token"],"Endpoint":"203.0.113.2:44001"
        }), b)?;
        let round = ready["Round"].as_str().unwrap().parse()?;
        let status = |participant: &Value, round, can_burst, offer| json!({
            "Token":participant["Token"],
            "PredictionUpdate":PredictionUpdate { round, can_burst, offer, ..Default::default() }
        });
        service.request(room, &status(&owner, round, true, None), a)?;
        let plan = service.request(room, &status(&guest, round, false, None), b)?;
        assert_eq!(plan["Prediction"]["Senders"], json!([0, 0]));
        let offer = PredictionOffer { attempt: 0, ports: vec![44321, 44322] };
        let publish = status(&owner, round, true, Some(offer));
        assert!(service.request(room, &publish, b).is_err());
        assert!(service.request(room, &status(&guest, uuid::Uuid::new_v4(), false, None), b).is_err());
        assert_eq!(service.request(room, &publish, a)?["Prediction"]["Offers"], json!([null, null]));
        let result = service.request(room, &status(&guest, round, false, None), b)?;
        assert_eq!(result["Prediction"]["Offers"][0]["Ports"], json!([44321, 44322]));
        Ok(())
    }

    #[test]
    fn reconnect_rounds_renew_after_expiry_without_requiring_new_boots_or_endpoints() -> Result<()>
    {
        let service = Assist::default();
        let mut owner = Profile::create("tcp")?;
        let peer = Profile::import(&owner.issue(None)?.export()?)?;
        let a = MemberRequest::create(&owner, uuid::Uuid::new_v4(), "203.0.113.1:44000".parse()?)?;
        let b = MemberRequest::create(&peer, uuid::Uuid::new_v4(), "203.0.113.2:44001".parse()?)?;
        let poll =
            |p: &Profile, r: &MemberRequest| MemberRequest::create(p, r.boot, r.endpoint.parse()?);
        service.member(&owner.pair.network, a.clone(), &peer.member)?;
        let first = service.member(&owner.pair.network, b.clone(), &owner.member)?;
        service
            .rounds
            .lock()
            .unwrap()
            .get_mut(&owner.pair.network)
            .unwrap()
            .start = Instant::now() - MEMBER_LEAD - LATE_TOLERANCE - Duration::from_secs(1);
        let waiting = service.member(&owner.pair.network, poll(&owner, &a)?, &peer.member)?;
        assert_eq!(waiting["Round"], uuid::Uuid::nil().to_string());
        let matched = service.member(&owner.pair.network, poll(&peer, &b)?, &owner.member)?;
        let next = service.member(&owner.pair.network, poll(&owner, &a)?, &peer.member)?;
        assert_ne!(next["Round"], first["Round"]);
        assert_eq!(next["Round"], matched["Round"]);
        assert_eq!(next["PeerEndpoint"], "203.0.113.2:44001");
        assert!(
            matches!(Schedule::read(&next, Duration::ZERO)?, Schedule::Ready(_, after) if after > Duration::from_secs(7))
        );
        Ok(())
    }

    #[test]
    fn waiting_members_get_the_same_short_round() -> Result<()> {
        let service = Assist::default();
        let mut owner = Profile::create("tcp")?;
        let peer = Profile::import(&owner.issue(None)?.export()?)?;
        let network = &owner.pair.network;
        let a = "203.0.113.1:44000".parse()?;
        let b = "203.0.113.2:44001".parse()?;
        let (owner_send, mut owner_receive) = oneshot::channel();
        let (peer_send, _peer_receive) = oneshot::channel();
        let first = service.report_member(
            network,
            MemberRequest::create(&owner, uuid::Uuid::new_v4(), a)?,
            &peer.member,
            Some(owner_send),
        )?;
        assert!(matches!(first, MemberReply::Waiting));
        let second = service.report_member(
            network,
            MemberRequest::create(&peer, uuid::Uuid::new_v4(), b)?,
            &owner.member,
            Some(peer_send),
        )?;
        let MemberReply::Scheduled(first, endpoint_b, _) = owner_receive.try_recv()? else {
            anyhow::bail!("first member must receive the scheduled round");
        };
        let MemberReply::Scheduled(second, endpoint_a, boot_a) = second else {
            anyhow::bail!("second member must receive the scheduled round");
        };
        assert_eq!(first.round, second.round);
        assert_eq!(first.start, second.start);
        assert_eq!(first.lead, WAITING_MEMBER_LEAD);
        assert_eq!(second.lead, WAITING_MEMBER_LEAD);
        assert_eq!(endpoint_a, a.to_string());
        assert_eq!(endpoint_b, b.to_string());
        let mut reply = MemberReply::Scheduled(second, endpoint_a, boot_a).json("tcp");
        reply["StartAfterMilliseconds"] = json!(2000);
        reply["ServerWaitMilliseconds"] = json!(3200);
        assert!(matches!(Schedule::read(&reply, Duration::from_millis(3600))?,
            Schedule::Ready(round, after) if round == second.round && after == Duration::from_millis(1800)));
        Ok(())
    }

    #[test]
    fn synchronized_retry_requires_the_peer_and_releases_both_after_cooldown() -> Result<()> {
        let service = Assist::default();
        let mut owner = Profile::create("https")?;
        let peer = Profile::import(&owner.issue(None)?.export()?)?;
        let network = &owner.pair.network;
        let a_boot = uuid::Uuid::new_v4();
        let b_boot = uuid::Uuid::new_v4();
        let report = |p: &Profile, boot, endpoint: &str, finished| -> Result<MemberRequest> {
            let mut request = MemberRequest::create(p, boot, endpoint.parse()?)?;
            request.synchronize_prediction(p, finished)?;
            Ok(request)
        };
        let a = |finished| report(&owner, a_boot, "203.0.113.1:44000", finished);
        let b = |finished| report(&peer, b_boot, "203.0.113.2:45000", finished);

        let (abandoned, receiver) = oneshot::channel();
        service.report_member(network, a(None)?, &peer.member, Some(abandoned))?;
        drop(receiver);
        let (b_send, mut b_receive) = oneshot::channel();
        assert!(matches!(service.report_member(network, b(None)?, &owner.member, Some(b_send))?, MemberReply::Waiting));
        let (a_send, _a_receive) = oneshot::channel();
        let MemberReply::Scheduled(first, _, _) = service.report_member(network, a(None)?, &peer.member, Some(a_send))?
            else { anyhow::bail!("双方在线后未发放轮次") };
        assert!(matches!(b_receive.try_recv()?, MemberReply::Scheduled(row, ..) if row.round == first.round && row.prediction));

        let (a_send, mut a_receive) = oneshot::channel();
        assert!(matches!(service.report_member(network, a(Some(first.round))?, &peer.member, Some(a_send))?, MemberReply::Waiting));
        let (b_send, _b_receive) = oneshot::channel();
        let MemberReply::Scheduled(retry, _, _) = service.report_member(network, b(Some(first.round))?, &owner.member, Some(b_send))?
            else { anyhow::bail!("冷却结束后未发放新轮次") };
        assert_ne!(retry.round, first.round);
        assert!(matches!(a_receive.try_recv()?, MemberReply::Scheduled(row, ..) if row.round == retry.round));
        Ok(())
    }

    #[test]
    fn synchronized_reconnect_reschedules_after_a_missed_reply_without_waiting_for_ttl() -> Result<()> {
        let service = Assist::default();
        let mut owner = Profile::create("phantun")?;
        let peer = Profile::import(&owner.issue(None)?.export()?)?;
        let network = &owner.pair.network;
        let owner_boot = uuid::Uuid::new_v4();
        let peer_boot = uuid::Uuid::new_v4();
        let report = |p: &Profile, boot, endpoint: &str, finished| -> Result<MemberRequest> {
            let mut request = MemberRequest::create(p, boot, endpoint.parse()?)?;
            request.synchronize_prediction(p, finished)?;
            Ok(request)
        };
        let a = |finished| report(&owner, owner_boot, "203.0.113.1:44000", finished);
        let b = || report(&peer, peer_boot, "203.0.113.2:45000", None);
        let mut finished = None;
        for _ in 0..5 {
            let (send, _receive) = oneshot::channel();
            let waiting = a(finished)?;
            let request_id = waiting.request_id;
            assert!(matches!(service.report_member(network, waiting, &peer.member, Some(send))?, MemberReply::Waiting));
            // The first request completes normally just before its peer
            // arrives. No two live long polls overlap in these rounds.
            service.member_poll_timed_out(network, owner.member.slot, request_id);
            let (send, _receive) = oneshot::channel();
            let MemberReply::Scheduled(new, ..) = service.report_member(network, b()?, &owner.member, Some(send))?
                else { anyhow::bail!("等待者错过轮次后未快速生成新轮次"); };
            assert_ne!(Some(new.round), finished);
            let attach = service.member(network, a(finished)?, &peer.member)?;
            assert_eq!(attach["Round"], new.round.to_string());
            finished = Some(new.round);
            // Peer B reports no Finished, as it would after a lost
            // schedule. Member A must be able to request a fresh round.
        }
        Ok(())
    }

    #[tokio::test]
    async fn coordinator_releases_the_waiting_member_when_peer_reports_ready() -> Result<()> {
        let service = Assist::default();
        let stop = CancellationToken::new();
        let mut owner = Profile::create("tcp")?;
        let peer = Profile::import(&owner.issue(None)?.export()?)?;
        let network = &owner.pair.network;
        let owner_request = MemberRequest::create(
            &owner, uuid::Uuid::new_v4(), "203.0.113.1:44000".parse()?,
        )?;
        let peer_request = MemberRequest::create(
            &peer, uuid::Uuid::new_v4(), "203.0.113.2:44001".parse()?,
        )?;
        let (a, b) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                service.wait_member(network, owner_request, &peer.member, &stop),
                service.wait_member(network, peer_request, &owner.member, &stop),
            )
        }).await.context("both members must be released before a poll times out")?;
        let (a, b) = (a?, b?);
        assert_eq!(a["Round"], b["Round"]);
        assert_ne!(a["Round"], uuid::Uuid::nil().to_string());
        for reply in [a, b] {
            let delay = reply["StartAfterMilliseconds"].as_i64().unwrap();
            assert!((1..=2000).contains(&delay));
            assert!(reply["ServerWaitMilliseconds"].is_u64());
        }
        Ok(())
    }

    #[test]
    fn a_missing_waiter_retains_the_legacy_lead() -> Result<()> {
        for cancelled in [false, true] {
            let service = Assist::default();
            let mut owner = Profile::create("tcp")?;
            let peer = Profile::import(&owner.issue(None)?.export()?)?;
            let network = &owner.pair.network;
            let a = MemberRequest::create(
                &owner, uuid::Uuid::new_v4(), "203.0.113.1:44000".parse()?,
            )?;
            let b = MemberRequest::create(
                &peer, uuid::Uuid::new_v4(), "203.0.113.2:44001".parse()?,
            )?;
            let (owner_send, owner_receive) = oneshot::channel();
            service.report_member(network, a, &peer.member, Some(owner_send))?;
            let (peer_send, _peer_receive) = oneshot::channel();
            let waiter = if cancelled {
                drop(owner_receive);
                Some(peer_send)
            } else {
                None
            };
            let reply = service.report_member(network, b, &owner.member, waiter)?;
            assert!(matches!(reply, MemberReply::Scheduled(row, ..) if row.lead == MEMBER_LEAD));
        }
        Ok(())
    }

    #[test]
    fn restart_invalidates_a_waiting_report_and_requests_fresh_readiness() -> Result<()> {
        let service = Assist::default();
        let mut owner = Profile::create("tcp")?;
        let peer = Profile::import(&owner.issue(None)?.export()?)?;
        let network = &owner.pair.network;
        let owner_boot = uuid::Uuid::new_v4();
        let a = "203.0.113.1:44000".parse()?;
        let b = "203.0.113.2:44001".parse()?;
        let mut old = MemberRequest::create(&peer, uuid::Uuid::new_v4(), b)?;
        old.ready = false;
        service.member(network, old, &owner.member)?;
        let (send, mut receive) = oneshot::channel();
        let result = service.report_member(network,
            MemberRequest::create(&owner, owner_boot, a)?, &peer.member, Some(send))?;
        assert!(matches!(result, MemberReply::Waiting));
        let (peer_send, mut peer_receive) = oneshot::channel();
        let result = service.report_member(network,
            MemberRequest::create(&peer, uuid::Uuid::new_v4(), b)?, &owner.member, Some(peer_send))?;
        assert!(matches!(result, MemberReply::Waiting));
        assert!(matches!(receive.try_recv()?, MemberReply::Refresh));
        let (send, _receive) = oneshot::channel();
        let result = service.report_member(network,
            MemberRequest::create(&owner, owner_boot, a)?, &peer.member, Some(send))?;
        let reply = peer_receive.try_recv()?;
        assert!(matches!((result, reply), (MemberReply::Scheduled(a, ..), MemberReply::Scheduled(b, ..))
            if a.round == b.round && a.lead == WAITING_MEMBER_LEAD));
        Ok(())
    }

    #[test]
    fn member_change_needs_another_report_from_the_current_peer() -> Result<()> {
        let service = Assist::default();
        let mut owner = Profile::create("tcp")?;
        let peer = Profile::import(&owner.issue(None)?.export()?)?;
        let network = &owner.pair.network;
        let a = "203.0.113.1:41000".parse()?;
        let b = "203.0.113.2:42000".parse()?;
        let boot = uuid::Uuid::new_v4();
        let poll_b = || MemberRequest::create(&peer, boot, b);
        let poll_a = |boot, endpoint| MemberRequest::create(&owner, boot, endpoint);
        let empty = uuid::Uuid::nil().to_string();
        service.member(network, poll_a(boot, a)?, &peer.member)?;
        let old_b = poll_b()?;
        let mut previous = service.member(network, old_b.clone(), &owner.member)?["Round"].clone();
        let next_boot = uuid::Uuid::new_v4();
        for endpoint in [a, "203.0.113.1:41001".parse()?] {
            let changed = service.member(network, poll_a(next_boot, endpoint)?, &peer.member)?;
            assert_eq!(changed["Round"], empty);
            assert_eq!(changed["PeerEndpoint"], "");
            assert!(
                service
                    .member(network, old_b.clone(), &owner.member)
                    .is_err()
            );
            assert_eq!(
                service.member(network, poll_a(next_boot, endpoint)?, &peer.member)?["Round"],
                empty
            );
            let fresh = service.member(network, poll_b()?, &owner.member)?;
            assert_ne!(fresh["Round"], empty);
            assert_ne!(fresh["Round"], previous);
            assert_eq!(fresh["PeerEndpoint"], endpoint.to_string());
            assert_eq!(
                service.member(network, poll_a(next_boot, endpoint)?, &peer.member)?["Round"],
                fresh["Round"]
            );
            previous = fresh["Round"].clone();
        }
        Ok(())
    }
}

pub struct InviteLocator {
    service: String,
    pin: String,
    client: tokio::sync::OnceCell<Client>,
}
impl InviteLocator {
    pub fn new(service: &str, pin: &str) -> Result<Self> {
        crate::discovery::validate_service(service)?;
        let service = url::Url::parse(service)?;
        ensure!(service.scheme() == "https", "协调直连码需要 HTTPS 地址");
        ensure!(
            pin.is_empty() || pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit()),
            "协调服务器证书指纹无效"
        );
        Ok(Self { service: service.to_string(), pin: pin.into(), client: Default::default() })
    }
    pub fn parse(locator: &str) -> Result<Self> {
        let (service, pin) = locator.trim().split_once('#').unwrap_or((locator.trim(), ""));
        Self::new(service, pin)
    }
    pub fn share_code(&self, code: &str) -> String {
        if self.pin.is_empty() {
            format!("{code}@{}", self.service)
        } else {
            format!("{code}@{}#{}", self.service, self.pin)
        }
    }
    pub async fn connect(&self) -> Result<Client> {
        Ok(self.client.get_or_try_init(|| Client::open_resolved(&self.service, &self.pin, false, true))
            .await?.clone())
    }
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: url::Url,
    pub endpoint: SocketAddr,
}
impl Client {
    pub async fn open(service: &str, pin: &str, bootstrap: bool) -> Result<Self> {
        Self::open_resolved(service, pin, bootstrap, false).await
    }
    async fn open_resolved(service: &str, pin: &str, bootstrap: bool, public_only: bool) -> Result<Self> {
        crate::discovery::validate_service(service)?;
        let mut base = url::Url::parse(service)?;
        if !base.path().ends_with('/') {
            base.set_path(&(base.path().to_owned() + "/"));
        }
        let host = base.host_str().context("协调域名缺失")?;
        let port = base.port_or_known_default().unwrap();
        let usable = |ip: &IpAddr| ip.is_ipv4() && (!public_only || crate::discovery::public(*ip));
        let addresses = crate::dns::with_recent_ip(crate::dns::EndpointKind::Coordinator, host, port, async {
            Ok(crate::dns::addresses(host).await?.into_iter().filter(usable).collect())
        }).await?
            .into_iter()
            .filter(usable)
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();
        let endpoint = *addresses.first().context(if public_only {
            "辅助直连码需要公网 IPv4 协调节点"
        } else {
            "协调辅助需要 IPv4"
        })?;
        let http =
            crate::transport::pinned_http_bootstrap(pin, bootstrap, Some((host, &addresses)))?;
        Ok(Self {
            http,
            base,
            endpoint,
        })
    }
    pub async fn post(&self, path: &str, input: &Value, auth: Option<&str>) -> Result<Value> {
        use futures_util::StreamExt;
        let mut request = self.http.post(self.base.join(path)?).json(input);
        if let Some(auth) = auth {
            request = request.bearer_auth(auth);
        }
        let response = request.send().await.map_err(reqwest::Error::without_url)?;
        let status = response.status();
        let remote = response.remote_addr();
        if status == reqwest::StatusCode::REQUEST_TIMEOUT || status.is_server_error() {
            return Err(TemporarySignalStatus(status).into());
        }
        ensure!(
            response.content_length().is_none_or(|s| s <= 8192),
            "协同响应过大"
        );
        let mut stream = response.bytes_stream();
        let mut bytes = vec![];
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.map_err(reqwest::Error::without_url)?);
            ensure!(bytes.len() <= 8192, "协同响应过大");
        }
        let result: Value = conwu_core::parse_rest(&bytes)?;
        if status.is_success() {
            crate::dns::remember_coordinator(&self.base, remote);
        }
        if status == reqwest::StatusCode::BAD_REQUEST
            && input.get("RawPredictionRound").is_some()
            && result["Error"] == RAW_ROUND_EXPIRED
        {
            return Err(RawRoundExpired.into());
        }
        ensure!(
            status.is_success(),
            "协调辅助请求失败（{status}）：{}",
            crate::logging::redact(result["Error"].as_str().unwrap_or("协调节点未接受请求"))
        );
        Ok(result)
    }
    pub async fn room(&self, action: &str, input: &Value) -> Result<Value> {
        let result = self
            .post(&format!("v1/punch-assist/{action}"), input, None)
            .await?;
        ensure!(
            short_code(result["Room"].as_str().unwrap_or(""))
                && short_code(result["HostRoom"].as_str().unwrap_or(""))
                && result["Token"]
                    .as_str()
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                && self::commitment(result["Commitment"].as_str().unwrap_or("")),
            "辅助会话绑定无效"
        );
        let expires = result["Expires"].as_i64().unwrap_or(0);
        ensure!(
            expires > unix_seconds() && expires <= unix_seconds() + 305,
            "辅助会话已过期"
        );
        let host = candidate(result["HostEndpoint"].as_str().context("主机候选缺失")?)?;
        let guest = result["GuestEndpoint"].as_str().unwrap_or("");
        if !self.endpoint.ip().is_loopback() {
            ensure!(
                crate::discovery::public(host.ip())
                    && (guest.is_empty() || crate::discovery::public(candidate(guest)?.ip())),
                "对外协调不能指示探测内网地址"
            );
        }
        Ok(result)
    }

    pub(crate) async fn create_pair_room(&self, mut input: Value) -> Result<(Value, u8)> {
        input["RequestId"] = json!(conwu_core::id());
        // A coordinator without retry support rejects create-retry. Retrying
        // create there after a lost response could allocate a duplicate room.
        let input = &input;
        retry_pair_step("创建协调配对房间", transient_signal, |attempt| async move {
            Ok((self.room(if attempt == 0 { "create" } else { "create-retry" }, input).await?, attempt))
        }).await
    }

    pub(crate) async fn join_pair_room(&self, input: &Value) -> Result<(Value, u8)> {
        retry_pair_step("提交协调配对申请", transient_signal, |attempt| async move {
            Ok((self.room("join", input).await?, attempt))
        }).await
    }

    pub(crate) async fn describe_pair(&self, code: &str) -> Result<String> {
        ensure!(short_code(code), "协调配对码应为六位数字");
        let input = json!({"Code":code});
        let result = retry_pair_step("查询协调配对码", transient_signal, |_| {
            self.post("v1/punch-assist/describe", &input, None)
        }).await?;
        let now = unix_seconds();
        ensure!(result["Expires"].as_i64().is_some_and(|expires| expires > now && expires <= now + 305),
            "辅助会话已过期");
        let mode = result["Mode"].as_str()
            .filter(|mode| conwu_core::code::stream_mode(mode) || conwu_core::code::raw_tcp_mode(mode))
            .context("协调服务器未返回有效的配对协议")?;
        Ok(mode.into())
    }
    pub(crate) async fn raw_pair_update(
        &self, state: &Value, round: uuid::Uuid, port: Option<u16>, guest_ready: bool,
    ) -> Result<Value> {
        let mut input = json!({"Token":state["Token"],"RawPredictionRound":round,"ProbeHash":state["ProbeHash"]});
        if let Some(port) = port { input["RawHostPort"] = json!(port); }
        if guest_ready { input["RawGuestReady"] = json!(true); }
        self.raw_pair_exchange(state, round, &input).await
    }

    async fn raw_pair_exchange(&self, state: &Value, round: uuid::Uuid, input: &Value) -> Result<Value> {
        let room = state["Room"].as_str().context("缺少配对房间")?;
        let reply = retry_pair_step("同步原始 TCP 候选", transient_signal, |_| self.room(room, input)).await?;
        ensure!(["Room","Token","HostRoom","Commitment","Mode","HostEndpoint","GuestEndpoint","RawMultiCandidate","ProbePlan","ProbeHash"]
                .iter().all(|key| reply[*key] == state[*key]), "原始 TCP 预测与本轮配对不符");
        ensure!(reply["RawHostPrediction"] == true && reply["Round"] == round.to_string(), RawRoundExpired);
        Ok(reply)
    }

    pub(crate) async fn publish_raw_candidates(
        &self, state: &Value, round: uuid::Uuid, ports: &[u16],
    ) -> Result<()> {
        let input = json!({"Token":state["Token"],"RawPredictionRound":round,"RawHostPorts":ports,"ProbeHash":state["ProbeHash"]});
        self.raw_pair_exchange(state, round, &input).await?;
        Ok(())
    }

    pub(crate) async fn retry_mimic_round(
        &self, state: &Value, previous: uuid::Uuid, endpoint: Option<SocketAddr>, stop: &CancellationToken,
    ) -> Result<(uuid::Uuid, Value)> {
        let room = state["Room"].as_str().context("缺少配对房间")?;
        let mut input = json!({"Token":state["Token"],"Ready":true,"ProbeHash":state["ProbeHash"],
            "RetryMimicRound":previous});
        if let Some(endpoint) = endpoint { input["NextGuestEndpoint"] = json!(endpoint); }
        let negotiate = async {
            loop {
                let sent = Instant::now();
                match self.room(room, &input).await {
                    Ok(next) => {
                        ensure!(["Room","Token","HostRoom","Commitment","Mode","HostEndpoint",
                            "RawMultiCandidate","ProbePlan","ProbeHash"]
                            .iter().all(|key| next[*key] == state[*key]), "Mimic 新轮次配对绑定已改变");
                        if let Schedule::Ready(round, delay) = Schedule::read(&next, sent.elapsed())?
                            && round != previous
                        {
                            let expected = endpoint.map_or_else(|| state["GuestEndpoint"].clone(), |addr| json!(addr));
                            ensure!(next["GuestEndpoint"] == expected, "协调器未确认本轮从机 STUN 映射");
                            tokio::time::sleep(delay).await;
                            return Ok((round, next));
                        }
                    }
                    Err(error) if transient_signal(&error) => {}
                    Err(error) => return Err(error),
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        };
        tokio::select! {
            _ = stop.cancelled() => anyhow::bail!("加入已取消"),
            result = tokio::time::timeout(Duration::from_secs(6), negotiate) =>
                result.context("等待协调器切换 Mimic 配对轮次超时")?,
        }
    }

    pub(crate) async fn raw_pair_candidates(&self, state: &Value, round: uuid::Uuid) -> Result<Vec<SocketAddr>> {
        let host = candidate(state["HostEndpoint"].as_str().context("缺少主机端点")?)?;
        tokio::time::timeout(RAW_OFFER_WAIT, async {
            loop {
                let reply = self.raw_pair_update(state, round, None, false).await?;
                if !reply["RawHostPorts"].is_null() {
                    let ports: Vec<u16> = serde_json::from_value(reply["RawHostPorts"].clone())?;
                    ensure!(port_prediction::valid_ports(&ports), "主机返回的候选端口无效");
                    if ports.is_empty() {
                        return Ok(vec![host]);
                    }
                    return Ok(ports.into_iter().map(|port| SocketAddr::new(host.ip(), port)).collect());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }).await.context("等待主机的原始 TCP 多候选超时")?
    }

    pub(crate) async fn raw_pair_target(&self, state: &Value, round: uuid::Uuid) -> Result<SocketAddr> {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let reply = self.raw_pair_update(state, round, None, false).await?;
                if !reply["RawHostPort"].is_null() {
                    let port: u16 = serde_json::from_value(reply["RawHostPort"].clone())?;
                    ensure!(port == 0 || port >= 1024, "主机返回的候选端口无效");
                    let mut host = candidate(state["HostEndpoint"].as_str().context("缺少主机端点")?)?;
                    if port != 0 { host.set_port(port); }
                    return Ok(host);
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }).await.context("等待主机的原始 TCP 端口预测超时")?
    }
    pub async fn member(
        &self,
        p: &Profile,
        boot: uuid::Uuid,
        endpoint: SocketAddr,
        wait: bool,
        prediction: bool,
        finished: Option<uuid::Uuid>,
    ) -> Result<(Value, Duration)> {
        let query = if wait { "?wait=1" } else { "" };
        let path = format!("v3/mesh/{}/tcp-assist{query}", p.pair.network);
        let auth = hex::encode_upper(p.pair.key("discovery-auth"));
        let submit = async |prediction: bool| {
            let mut request = MemberRequest::create(p, boot, endpoint)?;
            if prediction {
                request.synchronize_prediction(p, finished)?;
            }
            let request = serde_json::to_value(request)?;
            let sent = Instant::now();
            let result = self.post(&path, &request, Some(&auth)).await;
            let elapsed = sent.elapsed();
            match &result {
                Ok(state) => tracing::debug!(
                    round = ?state["Round"], peer = ?state["PeerEndpoint"],
                    delay_ms = ?state["StartAfterMilliseconds"],
                    wait_ms = ?state["ServerWaitMilliseconds"], "成员协调调度回应"
                ),
                Err(error) => tracing::debug!(reason = %crate::logging::redact(&error.to_string()), "成员协调请求失败"),
            }
            Ok::<_, anyhow::Error>((result?, elapsed))
        };
        let (response, prediction) = match submit(prediction).await {
            Err(error) if prediction && conwu_core::code::raw_tcp_mode(&p.pair.mode)
                && error.to_string().ends_with("端口预测需要系统 TCP 承载") => (submit(false).await?, false),
            result => (result?, prediction),
        };
        if response.0["Refresh"] == true {
            return submit(prediction).await;
        }
        Ok(response)
    }
}
