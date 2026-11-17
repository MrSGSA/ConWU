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
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};

const FIRST_CONTACT_LEAD: Duration = Duration::from_secs(1);
const LATE_TOLERANCE: Duration = Duration::from_secs(2);
const MAX_FIRST_CONTACT_ROUNDS: u8 = 3;
const MEMBER_LEAD: Duration = Duration::from_secs(8);

pub enum Schedule {
    Waiting,
    Ready(uuid::Uuid, Duration),
    Expired(uuid::Uuid),
}
impl Schedule {
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
        let transit = round_trip.as_millis().min(60000) as i64 / 2;
        let remaining = delay - transit;
        if remaining < -(LATE_TOLERANCE.as_millis() as i64) {
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
                && (self.issued - unix_seconds()).abs() <= 30
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
        Ok(())
    }
}
struct Participant {
    token: String,
    source: IpAddr,
    commitment: String,
    request: String,
    endpoint: String,
    ready: bool,
}
struct Room {
    owner: Participant,
    guest: Option<Participant>,
    host_room: String,
    commitment: String,
    mode: String,
    began: Instant,
    expires: i64,
    round: uuid::Uuid,
    start: Option<Instant>,
    attempts: u8,
}
struct MemberRound {
    peer: String,
    round: uuid::Uuid,
    start: Instant,
    bindings: String,
}
#[derive(Default)]
pub struct Assist {
    rooms: Mutex<HashMap<String, Room>>,
    members: Mutex<HashMap<(String, u8), (MemberRequest, Instant)>>,
    rounds: Mutex<HashMap<String, MemberRound>>,
    rate: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}
fn secret() -> String {
    hex::encode_upper(c::random::<32>())
}
fn code(s: &str) -> bool {
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
        let mut rooms = self.rooms.lock().unwrap();
        rooms.retain(|_, r| {
            r.expires > unix_seconds() && r.began.elapsed() < Duration::from_secs(300)
        });
        if action == "create" {
            let endpoint = text("Endpoint");
            matches_source(&endpoint, source)?;
            let mode = text("Mode");
            let host_room = text("HostRoom");
            let commitment = text("Commitment");
            ensure!(
                code(&host_room)
                    && self::commitment(&commitment)
                    && conwu_core::code::valid_mode(&mode)
                    && mode != "udp"
                    && rooms.len() < 128,
                "辅助会话无效或容量已满"
            );
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
                    request: String::new(),
                    endpoint,
                    ready,
                },
                guest: None,
                host_room,
                commitment,
                mode,
                began: Instant::now(),
                expires: unix_seconds() + 300,
                round: uuid::Uuid::nil(),
                start: None,
                attempts: 0,
            };
            let result = room_state(&room, &row, &row.owner);
            rooms.insert(room, row);
            return Ok(result);
        }
        let key = if action == "join" {
            text("Code")
        } else {
            action.to_owned()
        };
        ensure!(code(&key), "辅助会话编号无效");
        let r = rooms.get_mut(&key).context("辅助会话已过期")?;
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
                r.guest = Some(Participant {
                    token: secret(),
                    source,
                    commitment,
                    request,
                    endpoint: String::new(),
                    ready: false,
                });
            }
            return Ok(room_state(&key, r, r.guest.as_ref().unwrap()));
        }
        let token = text("Token");
        ensure!(token.len() == 64, "辅助令牌无效");
        let owner = c::eq(token.as_bytes(), r.owner.token.as_bytes());
        let p = if owner {
            &mut r.owner
        } else {
            r.guest
                .as_mut()
                .filter(|g| c::eq(token.as_bytes(), g.token.as_bytes()))
                .context("辅助令牌无效")?
        };
        ensure!(p.source == source, "辅助会话来源已变化");
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
        let endpoint = text("Endpoint");
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
        if retry == Some(r.round)
            && r.start.is_some_and(|t| t.elapsed() > FIRST_CONTACT_LEAD + LATE_TOLERANCE)
        {
            ensure!(r.attempts < MAX_FIRST_CONTACT_ROUNDS, "协调探测连续过期，请重新生成直连码");
            r.start = None;
            r.round = uuid::Uuid::nil();
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
    pub fn member(&self, network: &str, request: MemberRequest, peer_slot: u8) -> Result<Value> {
        let mut members = self.members.lock().unwrap();
        members.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(30));
        ensure!(
            members.len() < 8192 || members.contains_key(&(network.into(), request.slot)),
            "协同成员表已满"
        );
        let peer = members
            .get(&(network.into(), peer_slot))
            .map(|(r, _)| r.clone());
        members.insert(
            (network.into(), request.slot),
            (request.clone(), Instant::now()),
        );
        let Some(peer) = peer.filter(|p| p.mode == request.mode && p.ready && request.ready) else {
            return Ok(
                json!({"Version":1,"PeerEndpoint":"","Round":uuid::Uuid::nil(),"StartAfterMilliseconds":0,"Mode":request.mode}),
            );
        };
        let bindings = if request.slot < peer.slot {
            format!(
                "{}/{}/{}/{}",
                request.boot, request.endpoint, peer.boot, peer.endpoint
            )
        } else {
            format!(
                "{}/{}/{}/{}",
                peer.boot, peer.endpoint, request.boot, request.endpoint
            )
        };
        let mut rounds = self.rounds.lock().unwrap();
        rounds.retain(|_, r| r.start.elapsed() < Duration::from_secs(30));
        let row = rounds.entry(network.into()).or_insert_with(|| MemberRound {
            peer: String::new(),
            round: uuid::Uuid::new_v4(),
            start: Instant::now(),
            bindings: bindings.clone(),
        });
        if row.bindings != bindings || row.start.elapsed() > MEMBER_LEAD + LATE_TOLERANCE {
            *row = MemberRound {
                peer: String::new(),
                round: uuid::Uuid::new_v4(),
                start: Instant::now(),
                bindings,
            };
        }
        row.peer = peer.endpoint;
        Ok(
            json!({"Version":1,"PeerEndpoint":row.peer,"Round":row.round,"StartAfterMilliseconds":(MEMBER_LEAD.as_millis() as i64-row.start.elapsed().as_millis() as i64).max(-30000),"Mode":request.mode}),
        )
    }
    pub fn status(&self) -> Value {
        let rooms = self.rooms.lock().unwrap();
        json!({"waiting":rooms.values().filter(|r|r.start.is_none()).count(),"scheduled":rooms.values().filter(|r|r.start.is_some()).count()})
    }
}
fn room_state(key: &str, r: &Room, p: &Participant) -> Value {
    json!({"Room":key,"Token":p.token,"Expires":r.expires,"HostRoom":r.host_room,"Commitment":r.commitment,"HostEndpoint":r.owner.endpoint,"GuestEndpoint":r.guest.as_ref().map(|g|g.endpoint.as_str()).unwrap_or(""),"Round":r.round,"StartAfterMilliseconds":r.start.map(|t|(FIRST_CONTACT_LEAD.as_millis() as i64-t.elapsed().as_millis() as i64).max(-30000)).unwrap_or(0),"Mode":r.mode})
}
#[cfg(test)]
mod tests {
    use super::*;
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
            for _ in 1..MAX_FIRST_CONTACT_ROUNDS {
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
            assert_eq!(service.rooms.lock().unwrap()[key].attempts, MAX_FIRST_CONTACT_ROUNDS);
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
            service.member(&owner.pair.network, request.clone(), peer.member.slot)?;
            let reply = service.member(
                &owner.pair.network,
                MemberRequest::create(&peer, uuid::Uuid::new_v4(), "203.0.113.2:44001".parse()?)?,
                owner.member.slot,
            )?;
            let matched = service.member(&owner.pair.network, request, peer.member.slot)?;
            assert_eq!(reply["Round"], matched["Round"]);
            assert_eq!(reply["PeerEndpoint"], "203.0.113.1:44000");
            assert_eq!(matched["PeerEndpoint"], "203.0.113.2:44001");
            assert!(matched["StartAfterMilliseconds"].as_i64().unwrap() <= MEMBER_LEAD.as_millis() as i64);
        }
        Ok(())
    }

    #[test]
    fn reconnect_rounds_renew_after_expiry_without_requiring_new_boots_or_endpoints() -> Result<()> {
        let service = Assist::default();
        let mut owner = Profile::create("tcp")?;
        let peer = Profile::import(&owner.issue(None)?.export()?)?;
        let a = MemberRequest::create(&owner, uuid::Uuid::new_v4(), "203.0.113.1:44000".parse()?)?;
        let b = MemberRequest::create(&peer, uuid::Uuid::new_v4(), "203.0.113.2:44001".parse()?)?;
        service.member(&owner.pair.network, a.clone(), b.slot)?;
        let first = service.member(&owner.pair.network, b.clone(), a.slot)?;
        service.rounds.lock().unwrap().get_mut(&owner.pair.network).unwrap().start =
            Instant::now() - MEMBER_LEAD - LATE_TOLERANCE - Duration::from_secs(1);
        let next = service.member(&owner.pair.network, a.clone(), b.slot)?;
        let matched = service.member(&owner.pair.network, b, a.slot)?;
        assert_ne!(next["Round"], first["Round"]);
        assert_eq!(next["Round"], matched["Round"]);
        assert_eq!(next["PeerEndpoint"], "203.0.113.2:44001");
        assert!(matches!(Schedule::read(&next, Duration::ZERO)?, Schedule::Ready(_, after) if after > Duration::from_secs(7)));
        Ok(())
    }
}

pub struct Client {
    http: reqwest::Client,
    base: url::Url,
    pub endpoint: SocketAddr,
}
impl Client {
    pub async fn open(service: &str, pin: &str, bootstrap: bool) -> Result<Self> {
        crate::discovery::validate_service(service)?;
        let mut base = url::Url::parse(service)?;
        if !base.path().ends_with('/') {
            base.set_path(&(base.path().to_owned() + "/"));
        }
        let host = base.host_str().context("协调域名缺失")?;
        let addresses = crate::dns::addresses(host)
            .await?
            .into_iter()
            .filter(IpAddr::is_ipv4)
            .map(|ip| SocketAddr::new(ip, base.port_or_known_default().unwrap()))
            .collect::<Vec<_>>();
        let endpoint = *addresses.first().context("协调辅助需要 IPv4")?;
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
        let response = request.send().await?;
        let status = response.status();
        ensure!(
            response.content_length().is_none_or(|s| s <= 8192),
            "协同响应过大"
        );
        let mut stream = response.bytes_stream();
        let mut bytes = vec![];
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?);
            ensure!(bytes.len() <= 8192, "协同响应过大");
        }
        let result: Value = conwu_core::parse_rest(&bytes)?;
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
            code(result["Room"].as_str().unwrap_or(""))
                && code(result["HostRoom"].as_str().unwrap_or(""))
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
    pub async fn member(
        &self,
        p: &Profile,
        boot: uuid::Uuid,
        endpoint: SocketAddr,
    ) -> Result<Value> {
        let request = MemberRequest::create(p, boot, endpoint)?;
        let result = self.post(
            &format!("v3/mesh/{}/tcp-assist", p.pair.network),
            &serde_json::to_value(request)?,
            Some(&hex::encode_upper(p.pair.key("discovery-auth"))),
        )
        .await;
        match &result {
            Ok(state) => tracing::debug!(
                round = ?state["Round"], peer = ?state["PeerEndpoint"],
                delay_ms = ?state["StartAfterMilliseconds"], "成员协调调度回应"
            ),
            Err(error) => tracing::debug!(reason = %crate::logging::redact(&error.to_string()), "成员协调请求失败"),
        }
        result
    }
}
