use crate::backend::App;
use anyhow::{Context, Result, ensure};
use axum::{
    Extension, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use conwu_core::{
    crypto as c,
    identity::{self, Directory},
    metadata::{Envelope, Snapshot},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
#[derive(Clone, serde::Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct WatchRequest {
    pub slot: u8,
    pub device: String,
    pub boot_id: uuid::Uuid,
    pub request_id: uuid::Uuid,
    pub server_epoch: uuid::Uuid,
    pub after: i64,
    pub expires: i64,
    pub signature: String,
}
impl WatchRequest {
    fn signed(&self, network: &str) -> Result<Vec<u8>> {
        c::signed_json(
            &json!({"domain":"streamlink-mesh-watch-v1","network":network,"Slot":self.slot,"Device":self.device,"BootId":self.boot_id,"RequestId":self.request_id,"ServerEpoch":self.server_epoch,"After":self.after,"Expires":self.expires}),
        )
    }
    pub(crate) fn create(
        profile: &conwu_core::identity::Profile,
        boot: uuid::Uuid,
        epoch: uuid::Uuid,
        after: i64,
    ) -> Result<Self> {
        let mut r = Self {
            slot: profile.member.slot,
            device: profile.member.device.clone(),
            boot_id: boot,
            request_id: uuid::Uuid::new_v4(),
            server_epoch: epoch,
            after,
            expires: conwu_core::unix_seconds() + 40,
            signature: String::new(),
        };
        r.signature = c::sign(&profile.signing_private, &r.signed(&profile.pair.network)?)?;
        Ok(r)
    }
    fn verify(&self, network: &str, member: &identity::Member) -> Result<()> {
        let now = conwu_core::unix_seconds();
        ensure!(
            self.slot == member.slot
                && self.device == member.device
                && !self.boot_id.is_nil()
                && !self.request_id.is_nil()
                && self.after >= 0
                && self.expires > now
                && self.expires <= now + 45
                && self.signature.len() < 256
                && c::verify(&member.signing_key, &self.signed(network)?, &self.signature),
            "协调等待身份签名无效"
        );
        Ok(())
    }
}
#[derive(Clone, serde::Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Change {
    pub cursor: i64,
    pub kind: String,
    pub slot: u8,
    pub target_slot: u8,
}
#[derive(serde::Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct WatchResponse {
    pub server_epoch: uuid::Uuid,
    pub cursor: i64,
    pub reset: bool,
    pub changes: Vec<Change>,
    pub snapshot: Snapshot,
}
struct Account {
    waiting: bool,
    requests: HashMap<uuid::Uuid, i64>,
    tokens: f64,
    tick: Instant,
}
impl Default for Account {
    fn default() -> Self {
        Self {
            waiting: false,
            requests: HashMap::new(),
            tokens: 8.,
            tick: Instant::now(),
        }
    }
}
#[derive(Default)]
struct Feed {
    cursor: i64,
    changes: std::collections::VecDeque<Change>,
    accounts: HashMap<u8, Account>,
}
impl Registry {
    fn changed(&self, network: &str, kind: &str, slot: u8, target_slot: u8) {
        let mut feeds = self.feeds.lock().unwrap();
        let feed = feeds.entry(network.into()).or_default();
        feed.cursor += 1;
        feed.changes.push_back(Change {
            cursor: feed.cursor,
            kind: kind.into(),
            slot,
            target_slot,
        });
        while feed.changes.len() > 128 {
            feed.changes.pop_front();
        }
        drop(feeds);
        self.changes.notify_waiters();
    }
    fn snapshot(&self, network: &str, slot: u8, boot: uuid::Uuid) -> Result<Snapshot> {
        let rows = self.registrations.lock().unwrap();
        let r = rows.get(network).context("网络未注册")?;
        let nodes = self
            .nodes
            .lock()
            .unwrap()
            .iter()
            .filter(|(key, (e, t))| {
                key.starts_with(&format!("{network}/"))
                    && t.elapsed() < Duration::from_secs(180)
                    && r.directory
                        .members
                        .iter()
                        .any(|m| m.slot == e.slot && m.device == e.device)
            })
            .map(|(_, (e, _))| e.clone())
            .collect();
        let traversal = self
            .traversal
            .lock()
            .unwrap()
            .get_mut(network)
            .map(|i| {
                i.snapshot()
                    .into_iter()
                    .filter(|m| {
                        m.to_slot == slot
                            && m.to_boot == boot
                            && r.directory
                                .members
                                .iter()
                                .any(|p| p.slot == m.from_slot && p.device == m.from_device)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Snapshot {
            directory: r.directory.clone(),
            nodes,
            traversal,
            capabilities: conwu_core::metadata::DiscoveryCapabilities {
                traversal_version: 1,
                tcp_peer_reflexive: 1,
                ..Default::default()
            },
        })
    }
}
struct WaitGuard {
    registry: Arc<Registry>,
    network: String,
    slot: u8,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl Drop for WaitGuard {
    fn drop(&mut self) {
        if let Some(a) = self
            .registry
            .feeds
            .lock()
            .unwrap()
            .get_mut(&self.network)
            .and_then(|f| f.accounts.get_mut(&self.slot))
        {
            a.waiting = false;
        }
    }
}
async fn signed_watch(
    State(r): State<Arc<Registry>>,
    Path(network): Path<String>,
    request: Request,
) -> Response {
    let result=async{
        let auth=authenticate(&r,&request,&network)?;let input:WatchRequest=body(request).await?;
        let member={let rows=r.registrations.lock().unwrap();let Some(row)=rows.get(&network)else{return Ok(StatusCode::PRECONDITION_FAILED.into_response())};
            if !c::eq(auth.as_bytes(),row.auth.as_bytes()){return Ok(StatusCode::UNAUTHORIZED.into_response());}
            let Some(member)=row.directory.members.iter().find(|m|m.slot==input.slot)else{return Ok(StatusCode::FORBIDDEN.into_response())};member.clone()};
        if input.verify(&network,&member).is_err(){return Ok(StatusCode::FORBIDDEN.into_response());}
        let permit=match r.waiters.clone().try_acquire_owned(){Ok(p)=>p,Err(_)=>return Ok(StatusCode::SERVICE_UNAVAILABLE.into_response())};
        {
            let mut feeds=r.feeds.lock().unwrap();let feed=feeds.entry(network.clone()).or_default();let a=feed.accounts.entry(input.slot).or_default();
            a.tokens=(a.tokens+a.tick.elapsed().as_secs_f64()*0.8).min(8.);a.tick=Instant::now();
            a.requests.retain(|_,expires|*expires>conwu_core::unix_seconds());
            if a.waiting||a.requests.contains_key(&input.request_id){return Ok(StatusCode::CONFLICT.into_response());}
            if a.tokens<1.||a.requests.len()>=128{return Ok(StatusCode::TOO_MANY_REQUESTS.into_response());}
            a.tokens-=1.;a.requests.insert(input.request_id,input.expires);a.waiting=true;
        }
        let _guard=WaitGuard{registry:r.clone(),network:network.clone(),slot:input.slot,_permit:permit};
        let deadline=tokio::time::Instant::now()+Duration::from_secs(25.min((input.expires-conwu_core::unix_seconds()).max(0)as u64));
        loop{
            let notified=r.changes.notified();tokio::pin!(notified);notified.as_mut().enable();
            if !r.registrations.lock().unwrap().get(&network).is_some_and(|row|row.directory.members.contains(&member)){return Ok(StatusCode::FORBIDDEN.into_response());}
            let(cursor,reset,changes)={let feeds=r.feeds.lock().unwrap();let feed=feeds.get(&network).unwrap();let reset=input.server_epoch!=r.epoch||input.after>feed.cursor||feed.changes.front().is_some_and(|c|input.after<c.cursor-1);
                let changes=feed.changes.iter().filter(|c|c.cursor>input.after&&(if c.target_slot!=0{c.target_slot==input.slot}else{c.slot==0||c.slot!=input.slot})).cloned().collect::<Vec<_>>();(feed.cursor,reset,changes)};
            if reset||!changes.is_empty()||tokio::time::Instant::now()>=deadline{return Ok(axum::Json(WatchResponse{server_epoch:r.epoch,cursor,reset,changes,snapshot:r.snapshot(&network,input.slot,input.boot_id)?}).into_response());}
            tokio::select!{_=r.app.engine.cancel.cancelled()=>return Ok(StatusCode::SERVICE_UNAVAILABLE.into_response()),_=tokio::time::sleep_until(deadline)=>{},_=notified=>{}}
        }
    }.await;
    result.unwrap_or_else(|e: anyhow::Error| reply(Err(e)))
}

use crate::coordination_store::Registration;
struct Registry {
    trust_cloudflare: bool,
    epoch: uuid::Uuid,
    feeds: Mutex<HashMap<String, Feed>>,
    waiters: Arc<tokio::sync::Semaphore>,
    traversal: Mutex<HashMap<String, conwu_core::traversal::Inbox>>,
    names: Mutex<HashMap<String, String>>,
    assist: crate::assistance::Assist,
    changes: tokio::sync::Notify,
    app: Arc<App>,
    registrations: Mutex<BTreeMap<String, Registration>>,
    nodes: Mutex<HashMap<String, (Envelope, Instant)>>,
    rate: Mutex<HashMap<String, (Instant, u32)>>,
}
struct Running {
    certificate_pin: String,
    cancel: CancellationToken,
    settings: Value,
    registry: std::sync::Weak<Registry>,
    finished: CancellationToken,
    external: Arc<std::sync::RwLock<Value>>,
    probe_changed: Arc<tokio::sync::Notify>,
    certificate_expires: Option<i64>,
}
static RUNNING: OnceLock<Mutex<Option<Running>>> = OnceLock::new();
fn running() -> &'static Mutex<Option<Running>> {
    RUNNING.get_or_init(|| Mutex::new(None))
}
pub fn status() -> Value {
    let r = running().lock().unwrap();
    if let Some(r) = r.as_ref() {
        let clients = r.registry.upgrade().map(|registry| {
            let nodes=registry.nodes.lock().unwrap();let names=registry.names.lock().unwrap();let mut devices:BTreeMap<String,Value>=BTreeMap::new();
            for (key,(e,t)) in nodes.iter().filter(|(_,(_,t))|t.elapsed()<Duration::from_secs(180)) {
                let row=devices.entry(e.device.clone()).or_insert_with(||json!({"deviceId":e.device,"name":names.get(key).cloned().unwrap_or_else(||format!("设备 {}",&e.device[..8])),"phase":"自主打洞协调","networks":0,"lastSeen":0}));
                row["networks"]=json!(row["networks"].as_u64().unwrap_or(0)+1);
                row["lastSeen"]=json!(row["lastSeen"].as_i64().unwrap_or(0).max((conwu_core::unix_seconds()-t.elapsed().as_secs() as i64)*1000));
            }devices.into_values().take(128).collect::<Vec<_>>()
        }).unwrap_or_default();
        let active = !r.cancel.is_cancelled() && !r.finished.is_cancelled();
        let state = if !active {
            "已停止，等待恢复"
        } else if r
            .certificate_expires
            .is_some_and(|t| t <= conwu_core::unix_seconds())
        {
            "运行中；监听证书已过期，请更换证书"
        } else if r
            .certificate_expires
            .is_some_and(|t| t <= conwu_core::unix_seconds() + 7 * 86400)
        {
            "运行中；监听证书将在7天内过期"
        } else {
            "运行中"
        };
        json!({"enabled":true,"running":active,"state":state,"addresses":[r.settings["listenUrl"]],"certificatePin":r.certificate_pin,"certificateExpires":r.certificate_expires.map(crate::coordination_store::timestamp),"external":r.external.read().unwrap().clone(),"clients":clients,"punchAssist":r.registry.upgrade().map(|r|r.assist.status())})
    } else {
        json!({"enabled":false,"running":false,"state":"未开启","addresses":[],"clients":[]})
    }
}
pub fn validate(settings: &Value) -> Result<()> {
    if settings.is_null() {
        return Ok(());
    }
    if let Some(text) = settings["publicUrl"].as_str().filter(|s| !s.is_empty()) {
        crate::discovery::validate_service(text)?;
        let endpoint = url::Url::parse(text)?;
        ensure!(endpoint.scheme() == "https", "外部协调地址必须使用HTTPS");
    }
    if let Some(pin) = settings["publicCertificatePin"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        ensure!(
            pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit()),
            "外部证书SHA-256指纹无效"
        );
    }
    let url = url::Url::parse(
        settings["listenUrl"]
            .as_str()
            .unwrap_or("http://127.0.0.1:47822"),
    )?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "本机协调监听格式无效"
    );
    let ip = url
        .host_str()
        .context("缺少监听 IP")?
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()?;
    ensure!(
        url.port().is_some_and(|p| p >= 1024),
        "协调端口范围为1024–65535"
    );
    ensure!(
        url.scheme() == "https" || ip.is_loopback(),
        "公网协调监听需使用证书，或通过本机反向代理提供 HTTPS"
    );
    if settings["enabled"] == true && url.scheme() == "https" {
        let manual = settings["certificateFile"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
            || settings["certificateKeyFile"]
                .as_str()
                .is_some_and(|s| !s.is_empty());
        if manual {
            for key in ["certificateFile", "certificateKeyFile"] {
                let path = settings[key].as_str().context("缺少证书或私钥")?;
                ensure!(
                    std::path::Path::new(path).is_absolute()
                        && std::path::Path::new(path).is_file(),
                    "证书与私钥必须为本机文件"
                );
            }
        }
    }
    Ok(())
}
fn listener_settings(settings: &Value) -> Value {
    let mut value = settings.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("publicUrl");
        object.remove("publicCertificatePin");
    }
    value
}
fn diagnostic(code: &str, detail: &str, reachable: bool) -> Value {
    json!({"code":code,"detail":detail,"reachable":reachable,"checkedAt":crate::coordination_store::timestamp(conwu_core::unix_seconds())})
}
fn expiry(bytes: &[u8]) -> Option<i64> {
    x509_parser::parse_x509_certificate(bytes)
        .ok()
        .map(|(_, c)| c.validity().not_after.timestamp())
}
async fn probe(url: &str, pin: &str, instance: &str) -> Value {
    if url.is_empty() {
        return diagnostic(
            "unconfigured",
            "尚未设置外部HTTPS地址，未检查外部访问路径",
            false,
        );
    }
    let check = async {
        let mut endpoint = url::Url::parse(url)?.join("health")?;
        let challenge = conwu_core::id();
        endpoint
            .query_pairs_mut()
            .append_pair("challenge", &challenge);
        let response = crate::transport::pinned_http_bootstrap(pin, false, None)?
            .get(endpoint)
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "外部HTTPS返回HTTP {}，请检查代理转发和访问限制",
            response.status().as_u16()
        );
        use futures_util::StreamExt;
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?);
            ensure!(bytes.len() <= 16384, "协调响应超过16KiB");
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            value["meshProtocol"] == 4 && value["meshTraversal"] == 1 && value["relay"] == false,
            "地址已响应，但未提供兼容的ConWU协调能力"
        );
        ensure!(
            value["instanceId"] == instance && value["challenge"] == challenge,
            "HTTPS响应属于其他协调实例或缓存，请检查代理源站和缓存规则"
        );
        Ok::<_, anyhow::Error>(())
    };
    match tokio::time::timeout(Duration::from_secs(8), check).await {
        Ok(Ok(())) => diagnostic(
            "reachable",
            "已通过外部HTTPS地址确认当前协调实例；对端网络的可达性仍需在对端检查",
            true,
        ),
        Ok(Err(error)) => diagnostic(
            "probe-error",
            &format!("协调地址检查未完成：{error}"),
            false,
        ),
        Err(_) => diagnostic(
            "timeout",
            "外部协调HTTPS在8秒内未响应，请检查监听、端口和代理状态",
            false,
        ),
    }
}
pub async fn configure(app: Arc<App>, settings: Value) -> Result<()> {
    validate(&settings)?;
    {
        let mut running = running().lock().unwrap();
        if let Some(prior) = running.as_mut() {
            if !prior.cancel.is_cancelled()
                && !prior.finished.is_cancelled()
                && listener_settings(&prior.settings) == listener_settings(&settings)
            {
                if prior.settings != settings {
                    prior.settings = settings.clone();
                    *prior.external.write().unwrap() =
                        diagnostic("checking", "正在检查外部HTTPS地址", false);
                    prior.probe_changed.notify_one();
                }
                return Ok(());
            }
        }
    }
    let prior = running().lock().unwrap().take();
    if let Some(prior) = prior {
        prior.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(10), prior.finished.cancelled())
            .await
            .context("旧协调监听尚未退出")?;
    }
    if settings["enabled"] != true {
        return Ok(());
    }
    let url = url::Url::parse(settings["listenUrl"].as_str().unwrap())?;
    let address: SocketAddr =
        format!("{}:{}", url.host_str().unwrap(), url.port().unwrap()).parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    ensure!(
        !app.store.checked_file("coordinator-restore.json")?.exists(),
        "协调恢复未完成，请显式重新恢复完整备份"
    );
    let path = app.store.root.join("coordinator.json");
    let registrations = if path.exists() {
        let bytes = std::fs::read(path)?;
        ensure!(bytes.len() <= 8 * 1024 * 1024, "协调数据过大");
        let registrations = crate::coordination_store::decode(&bytes)?;
        for (network, r) in &registrations {
            identity::validate_directory(&r.directory, network, &r.directory.owner_key, 0)?;
            ensure!(
                identity::network_id(&r.directory.owner_key)? == *network,
                "协调目录根身份无效"
            );
        }
        registrations
    } else {
        BTreeMap::new()
    };
    let registry = Arc::new(Registry {
        trust_cloudflare: settings["trustCloudflare"] == true,
        epoch: uuid::Uuid::new_v4(),
        feeds: Mutex::new(HashMap::new()),
        waiters: Arc::new(tokio::sync::Semaphore::new(64)),
        traversal: Mutex::new(HashMap::new()),
        names: Mutex::new(HashMap::new()),
        assist: crate::assistance::Assist::default(),
        changes: tokio::sync::Notify::new(),
        app: app.clone(),
        registrations: Mutex::new(registrations),
        nodes: Mutex::new(HashMap::new()),
        rate: Mutex::new(HashMap::new()),
    });
    let instance = registry.epoch.simple().to_string();
    let health_instance = instance.clone();
    let router = Router::new()
        .route(
            "/health",
            get(move |Query(query): Query<HashMap<String,String>>| { let instance=health_instance.clone(); async move {
                let challenge = query.get("challenge").filter(|s| s.len()==32 && s.bytes().all(|b|b.is_ascii_hexdigit())).cloned().unwrap_or_default();
                let mut reply = axum::Json(
                    json!({"ok":true,"mesh":true,"pairwise":true,"version":crate::model::VERSION,"meshProtocol":4,"pairNetworks":1,"nodeIdentity":1,"integratedCoordinator":1,"meshWatch":1,"meshTraversal":1,"punchAssist":1,"punchTcpStun":1,"punchModes":["faketcp","phantun","mimic","tcpraw","tcp","https"],"tcpAssist":1,"traversal":1,"nativeAbi":1,"relay":false,"instanceId":instance,"challenge":challenge}),
                ).into_response();
                reply.headers_mut().insert("Cache-Control", "no-store".parse().unwrap());
                reply
            }}),
        )
        .route("/v3/mesh/{network}/directory", put(directory))
        .route("/v3/mesh/{network}/nodes/{slot}", put(publish))
        .route("/v3/mesh/{network}", get(read))
        .route("/v3/mesh/{network}/watch", get(watch).post(signed_watch))
        .route("/v3/mesh/{network}/tcp-assist", post(member_assist))
        .route("/v3/mesh/{network}/traversal",post(publish_traversal))
        .route("/v1/punch-assist/{action}", post(first_assist))
        .layer(DefaultBodyLimit::max(65536))
        .with_state(registry.clone())
        .merge(crate::web::remote_router(app.clone())?);
    let stop = app.engine.cancel.child_token();
    let mut certificate_pin = String::new();
    let mut certificate_expires = None;
    let tls = if url.scheme() == "https" {
        if settings["certificateFile"]
            .as_str()
            .is_none_or(|s| s.is_empty())
        {
            certificate_pin = app.engine.identity.certificate_pin.clone();
            if let Ok(bytes) = std::fs::read(app.store.checked_file("stream-certificate.der")?) {
                certificate_expires = expiry(&bytes);
            }
            Some(app.engine.identity.server.clone())
        } else {
            let certificate = std::fs::read(settings["certificateFile"].as_str().unwrap())?;
            let key = std::fs::read(settings["certificateKeyFile"].as_str().unwrap())?;
            let certificates = rustls_pemfile::certs(&mut certificate.as_slice())
                .collect::<std::io::Result<Vec<_>>>()?;
            certificate_pin =
                hex::encode_upper(c::hash(certificates.first().context("证书为空")?.as_ref()));
            certificate_expires = expiry(certificates[0].as_ref());
            let key = rustls_pemfile::private_key(&mut key.as_slice())?.context("证书私钥为空")?;
            Some(Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certificates, key)?,
            ))
        }
    } else {
        None
    };
    let finished = CancellationToken::new();
    let external = Arc::new(std::sync::RwLock::new(diagnostic(
        "checking",
        "正在检查外部HTTPS地址",
        false,
    )));
    let changed = Arc::new(tokio::sync::Notify::new());
    *running().lock().unwrap() = Some(Running {
        cancel: stop.clone(),
        settings: settings.clone(),
        registry: Arc::downgrade(&registry),
        certificate_pin,
        certificate_expires,
        finished: finished.clone(),
        external: external.clone(),
        probe_changed: changed.clone(),
    });
    let probe_stop = stop.clone();
    app.engine.tracker.spawn(async move {
        loop {
            let settings = running().lock().unwrap().as_ref().map(|r| r.settings.clone()).unwrap_or_default();
            let result = tokio::select! { _=probe_stop.cancelled()=>break,
                r=probe(settings["publicUrl"].as_str().unwrap_or(""), settings["publicCertificatePin"].as_str().unwrap_or(""), &instance)=>r };
            *external.write().unwrap() = result;
            tokio::select! { _=probe_stop.cancelled()=>break, _=changed.notified()=>{}, _=tokio::time::sleep(Duration::from_secs(60))=>{} }
        }
    });
    app.engine.tracker.spawn(async move {
        let connections = tokio_util::task::TaskTracker::new();
        let gate=Arc::new(tokio::sync::Semaphore::new(128));
        loop {
            let (mut socket,remote)=tokio::select!{_=stop.cancelled()=>break,r=listener.accept()=>match r{Ok(r)=>r,Err(_)=>break}};
            let Ok(permit)=gate.clone().try_acquire_owned() else {continue};
            let tls=tls.clone();let stop=stop.clone();let router=router.clone().layer(Extension(remote));
            connections.spawn(async move {
                let _permit=permit;
                if is_stun(&socket).await {let _=stun_server(&mut socket,remote,&stop).await;return;}
                if let Some(tls)=tls {
                    let handshake=tokio::time::timeout(Duration::from_secs(6),tokio_rustls::TlsAcceptor::from(tls).accept(socket));
                    let stream=tokio::select!{_=stop.cancelled()=>return,r=handshake=>match r{Ok(Ok(s))=>s,_=>return}};
                    serve_http(stream,router,stop).await;
                }else{serve_http(socket,router,stop).await;}
            });
        }
        drop(listener);
        connections.close();
        connections.wait().await;
        finished.cancel();
    });
    app.log("INFO", "Rust 本机协调服务已启动");
    Ok(())
}
fn authenticate(registry: &Registry, request: &Request, network: &str) -> Result<String> {
    ensure!(conwu_core::valid_id(network), "网络编号无效");
    let auth = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .context("缺少协调授权")?;
    let value = auth.strip_prefix("Bearer ").context("协调授权无效")?;
    ensure!(
        value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit()),
        "协调授权格式无效"
    );
    let hash = hex::encode_upper(c::hash(auth.as_bytes()));
    let mut rate = registry.rate.lock().unwrap();
    ensure!(
        rate.contains_key(network) || rate.len() < 4096,
        "协调请求表已满"
    );
    let rate = rate.entry(network.into()).or_insert((Instant::now(), 0));
    if rate.0.elapsed() > Duration::from_secs(10) {
        *rate = (Instant::now(), 0);
    }
    rate.1 += 1;
    ensure!(rate.1 <= 100, "协调请求过于频繁");
    Ok(hash)
}
async fn body<T: serde::de::DeserializeOwned>(request: Request) -> Result<T> {
    let bytes = axum::body::to_bytes(request.into_body(), 65536).await?;
    Ok(conwu_core::parse_rest(&bytes)?)
}
async fn directory(
    State(r): State<Arc<Registry>>,
    Path(network): Path<String>,
    request: Request,
) -> Response {
    reply(
        async move {
            let auth = authenticate(&r, &request, &network)?;
            let directory: Directory = body(request).await?;
            identity::validate_directory(&directory, &network, &directory.owner_key, 0)?;
            ensure!(
                identity::network_id(&directory.owner_key)? == network,
                "网络根身份无效"
            );
            let mut registrations = r.registrations.lock().unwrap();
            if let Some(prior) = registrations.get(&network) {
                ensure!(
                    c::eq(auth.as_bytes(), prior.auth.as_bytes()),
                    "协调授权不符"
                );
                conwu_core::metadata::successor(&directory, &prior.directory)?;
                if directory.revision == prior.directory.revision {
                    return Ok(json!({"ok":true}));
                }
            }
            ensure!(
                registrations.contains_key(&network) || registrations.len() < 4096,
                "协调网络表已满"
            );
            let mut next = registrations.clone();
            next.insert(network.clone(), Registration { auth, directory });
            r.app
                .store
                .write("coordinator.json", &serde_json::to_vec(&next)?, true)?;
            *registrations = next;
            r.changed(&network, "directory", 0, 0);
            r.changes.notify_waiters();
            Ok(json!({"ok":true}))
        }
        .await,
    )
}
async fn publish(
    State(r): State<Arc<Registry>>,
    Path((network, slot)): Path<(String, u8)>,
    request: Request,
) -> Response {
    reply(
        async move {
            let auth = authenticate(&r, &request, &network)?;
            let name = request
                .headers()
                .get("X-ConWU-Device-Name")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| c::unb64(s).ok())
                .and_then(|b| String::from_utf8(b).ok())
                .filter(|s| c::check_name(s).is_ok());
            let envelope: Envelope = body(request).await?;
            let registrations = r.registrations.lock().unwrap();
            let registration = registrations.get(&network).context("网络未注册")?;
            ensure!(
                c::eq(auth.as_bytes(), registration.auth.as_bytes()),
                "协调授权不符"
            );
            let member = registration
                .directory
                .members
                .iter()
                .find(|m| m.slot == slot)
                .context("成员未授权")?;
            envelope.validate(&network, member)?;
            let mut nodes = r.nodes.lock().unwrap();
            nodes.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(180));
            let key = format!("{network}/{slot}");
            if let Some((prior, _)) = nodes.get(&key) {
                ensure!(
                    envelope.revision > prior.revision
                        || envelope.revision == prior.revision && envelope.data == prior.data,
                    "公告回退或冲突"
                );
            }
            if let Some(name) = name {
                r.names.lock().unwrap().insert(key.clone(), name);
            }
            nodes.insert(key, (envelope, Instant::now()));
            r.changed(&network, "announcement", slot, 0);
            r.changes.notify_waiters();
            Ok(json!({"ok":true}))
        }
        .await,
    )
}
async fn read(
    State(r): State<Arc<Registry>>,
    Path(network): Path<String>,
    request: Request,
) -> Response {
    reply(
        async move {
            let auth = authenticate(&r, &request, &network)?;
            let registrations = r.registrations.lock().unwrap();
            let registration = registrations.get(&network).context("网络未注册")?;
            ensure!(
                c::eq(auth.as_bytes(), registration.auth.as_bytes()),
                "协调授权不符"
            );
            let nodes = r
                .nodes
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, (_, t))| {
                    key.starts_with(&format!("{network}/"))
                        && t.elapsed() < Duration::from_secs(180)
                })
                .filter(|(_, (e, _))| {
                    registration
                        .directory
                        .members
                        .iter()
                        .any(|m| m.slot == e.slot && m.device == e.device)
                })
                .map(|(_, (e, _))| e.clone())
                .collect();
            Ok(json!(Snapshot {
                capabilities: conwu_core::metadata::DiscoveryCapabilities {
                    traversal_version: 1,
                    tcp_peer_reflexive: 1,
                    ..Default::default()
                },
                directory: registration.directory.clone(),
                nodes,
                traversal: r
                    .traversal
                    .lock()
                    .unwrap()
                    .get_mut(&network)
                    .map(|i| i.snapshot())
                    .unwrap_or_default(),
            }))
        }
        .await,
    )
}
fn reply(result: Result<Value>) -> Response {
    match result {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error":e.to_string()})),
        )
            .into_response(),
    }
}
async fn watch(
    State(r): State<Arc<Registry>>,
    Path(network): Path<String>,
    request: Request,
) -> Response {
    let accepted = (|| -> Result<()> {
        let auth = authenticate(&r, &request, &network)?;
        let registrations = r.registrations.lock().unwrap();
        let row = registrations.get(&network).context("网络未注册")?;
        ensure!(c::eq(auth.as_bytes(), row.auth.as_bytes()), "协调授权不符");
        Ok(())
    })();
    if let Err(e) = accepted {
        return reply(Err(e));
    }
    tokio::select! { _=r.app.engine.cancel.cancelled()=>return StatusCode::SERVICE_UNAVAILABLE.into_response(), _=tokio::time::sleep(Duration::from_secs(20))=>{}, _=r.changes.notified()=>{} }
    read(State(r), Path(network), request).await
}
async fn first_assist(
    State(r): State<Arc<Registry>>,
    Path(action): Path<String>,
    Extension(remote): Extension<SocketAddr>,
    request: Request,
) -> Response {
    reply(
        async {
            let source = client_source(r.trust_cloudflare, &request, remote);
            let input: Value = body(request).await?;
            r.assist.request(&action, &input, source)
        }
        .await,
    )
}
async fn publish_traversal(
    State(r): State<Arc<Registry>>,
    Path(network): Path<String>,
    request: Request,
) -> Response {
    reply(
        async {
            let auth = authenticate(&r, &request, &network)?;
            #[derive(Deserialize)]
            #[serde(rename_all = "PascalCase")]
            struct Batch {
                messages: Vec<conwu_core::traversal::Message>,
            }
            let batch: Batch = body(request).await?;
            let registrations = r.registrations.lock().unwrap();
            let registration = registrations.get(&network).context("网络未注册")?;
            ensure!(
                c::eq(auth.as_bytes(), registration.auth.as_bytes())
                    && !registration.directory.closed,
                "协调授权不符或网络已关闭"
            );
            let mut boxes = r.traversal.lock().unwrap();
            ensure!(
                boxes.len() < 4096 || boxes.contains_key(&network),
                "打洞邮箱数量已满"
            );
            boxes.entry(network).or_default().insert(
                &registration.directory.network,
                &registration.directory,
                batch.messages,
            )?;
            r.changed(&registration.directory.network, "traversal", 0, 0);
            r.changes.notify_waiters();
            Ok(json!({"ok":true}))
        }
        .await,
    )
}
async fn member_assist(
    State(r): State<Arc<Registry>>,
    Path(network): Path<String>,
    Extension(remote): Extension<SocketAddr>,
    request: Request,
) -> Response {
    reply(
        async {
            let source = client_source(r.trust_cloudflare, &request, remote);
            let wait = request.uri().query() == Some("wait=1");
            let auth = authenticate(&r, &request, &network)?;
            let input: crate::assistance::MemberRequest = body(request).await?;
            let (_permit, member, peer) = {
                let registrations = r.registrations.lock().unwrap();
                let registration = registrations.get(&network).context("网络未注册")?;
                ensure!(
                    c::eq(auth.as_bytes(), registration.auth.as_bytes()),
                    "协调授权不符"
                );
                let member = registration
                    .directory
                    .members
                    .iter()
                    .find(|m| m.slot == input.slot)
                    .context("协同成员未授权")?;
                input.verify(&network, member, source)?;
                let peer = registration
                    .directory
                    .members
                    .iter()
                    .find(|m| m.slot != input.slot)
                    .context("尚无对机成员")?;
                let permit = wait.then(|| r.waiters.clone().try_acquire_owned().ok()).flatten();
                let Some(permit) = permit else {
                    return r.assist.member(&network, input, peer);
                };
                (permit, member.clone(), peer.clone())
            };
            let result = r.assist.wait_member(&network, input, &peer, &r.app.engine.cancel).await?;
            let registrations = r.registrations.lock().unwrap();
            let registration = registrations.get(&network).context("网络未注册")?;
            ensure!(
                c::eq(auth.as_bytes(), registration.auth.as_bytes())
                    && registration.directory.members.contains(&member)
                    && registration.directory.members.contains(&peer),
                "协同成员授权已改变"
            );
            Ok(result)
        }
        .await,
    )
}
fn client_source(trust: bool, request: &Request, remote: SocketAddr) -> std::net::IpAddr {
    if trust && remote.ip().is_loopback() {
        if let Some(ip) = request
            .headers()
            .get("CF-Connecting-IP")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<std::net::IpAddr>().ok())
            .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
        {
            return ip;
        }
    }
    remote.ip()
}
#[test]
fn forwarded_address_requires_explicit_trust_and_a_loopback_proxy() {
    let request = Request::builder()
        .header("CF-Connecting-IP", "198.51.100.4")
        .body(axum::body::Body::empty())
        .unwrap();
    let local = "127.0.0.1:12345".parse().unwrap();
    let external = "203.0.113.9:12345".parse().unwrap();
    assert_eq!(
        client_source(true, &request, local),
        "198.51.100.4".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(client_source(false, &request, local), local.ip());
    assert_eq!(client_source(true, &request, external), external.ip());
}
async fn serve_http<S>(stream: S, router: Router, stop: CancellationToken)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper_util::service::TowerToHyperService::new(router);
    let builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let connection = builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
    tokio::select! {_=stop.cancelled()=>{},_=connection=>{}}
}
async fn is_stun(socket: &tokio::net::TcpStream) -> bool {
    tokio::time::timeout(Duration::from_millis(750), async {
        let mut prefix = [0; 8];
        loop {
            let n = socket.peek(&mut prefix).await?;
            if n == 0 || prefix[0] != 0 {
                return Ok::<_, std::io::Error>(false);
            }
            if n >= 8 {
                return Ok(prefix[..2] == [0, 1] && prefix[4..8] == [0x21, 0x12, 0xa4, 0x42]);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .is_ok_and(|r| r.unwrap_or(false))
}
async fn stun_server(
    socket: &mut tokio::net::TcpStream,
    remote: SocketAddr,
    stop: &CancellationToken,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let mut request = [0u8; 20];
        tokio::select! {_=stop.cancelled()=>return Ok(()),r=tokio::time::timeout(Duration::from_secs(75),socket.read_exact(&mut request))=>{r??;}}
        let size = u16::from_be_bytes(request[2..4].try_into()?) as usize;
        ensure!(
            request[..2] == [0, 1]
                && request[4..8] == [0x21, 0x12, 0xa4, 0x42]
                && size <= 4096
                && size % 4 == 0,
            "STUN 请求无效"
        );
        if size > 0 {
            let mut skip = vec![0; size];
            tokio::time::timeout(Duration::from_secs(2), socket.read_exact(&mut skip)).await??;
        }
        let mut response = request.to_vec();
        response[..2].copy_from_slice(&[1, 1]);
        let ip = match remote.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        response[2..4].copy_from_slice(&((ip.len() + 8) as u16).to_be_bytes());
        response.extend_from_slice(&0x20u16.to_be_bytes());
        response.extend_from_slice(&((ip.len() + 4) as u16).to_be_bytes());
        response.extend_from_slice(&[0, if remote.is_ipv4() { 1 } else { 2 }]);
        response.extend_from_slice(&(remote.port() ^ 0x2112).to_be_bytes());
        response.extend(ip.iter().enumerate().map(|(i, b)| *b ^ request[4 + i]));
        tokio::time::timeout(Duration::from_secs(2), socket.write_all(&response)).await??;
    }
}

pub async fn exchange(
    settings: &crate::model::Settings,
    profile: &conwu_core::identity::Profile,
    envelope: &Envelope,
    name: &str,
) -> Result<Snapshot> {
    let mut base = url::Url::parse(&settings.service)?;
    ensure!(
        (base.scheme() == "https"
            || base.scheme() == "http"
                && base
                    .host_str()
                    .is_some_and(|h| h == "127.0.0.1" || h == "localhost"))
            && base.username().is_empty()
            && base.password().is_none()
            && base.query().is_none()
            && base.fragment().is_none(),
        "发现协调地址应为 HTTPS 地址"
    );
    if !base.path().ends_with('/') {
        base.set_path(&(base.path().to_owned() + "/"));
    }
    let client = crate::transport::pinned_http(&settings.certificate_pin)?;
    let auth = hex::encode_upper(profile.pair.key("discovery-auth"));
    let network = &profile.pair.network;
    client
        .put(base.join(&format!("v3/mesh/{network}/directory"))?)
        .bearer_auth(&auth)
        .json(profile.directory.as_ref().context("缺少目录")?)
        .send()
        .await?
        .error_for_status()?;
    client
        .put(base.join(&format!("v3/mesh/{network}/nodes/{}", profile.member.slot))?)
        .bearer_auth(&auth)
        .header("X-ConWU-Device-Name", c::b64(name.as_bytes()))
        .json(envelope)
        .send()
        .await?
        .error_for_status()?;
    let response = client
        .get(base.join(&format!("v3/mesh/{network}"))?)
        .bearer_auth(&auth)
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        response.content_length().is_none_or(|n| n <= 65536),
        "协调快照过大"
    );
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut bytes = vec![];
    while let Some(chunk) = stream.next().await {
        bytes.extend_from_slice(&chunk?);
        ensure!(bytes.len() <= 65536, "协调快照过大");
    }
    let snapshot: Snapshot = conwu_core::parse_rest(&bytes)?;
    ensure!(snapshot.nodes.len() <= 8, "协调成员数超过限制");
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coordinator_health_binds_origin_and_listener_restart_releases_port() -> Result<()> {
        let app = crate::tests::app().await?;
        let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = reservation.local_addr()?.port();
        drop(reservation);
        let address = format!("https://127.0.0.1:{port}/");
        let mut settings = json!({"enabled":true,"listenUrl":address,"trustCloudflare":false});
        configure(app.clone(), settings.clone()).await?;
        let pin = status()["certificatePin"].as_str().unwrap().to_owned();
        let http = crate::transport::pinned_http(&pin)?;
        let before: Value = http
            .get(format!("{address}health?challenge={}", "a".repeat(32)))
            .send()
            .await?
            .json()
            .await?;
        ensure!(
            before["relay"] == false && before["challenge"] == "a".repeat(32),
            "须与原版健康检查兼容且应答本次挑战"
        );
        let instance = before["instanceId"].as_str().unwrap();
        ensure!(
            probe(&address, &pin, instance).await["reachable"] == true,
            "HTTPS须确认当前源站"
        );
        ensure!(
            probe(&address, &pin, &conwu_core::id()).await["reachable"] == false,
            "错误实例必须拒绝"
        );
        settings["publicUrl"] = json!(address);
        settings["publicCertificatePin"] = json!(pin);
        configure(app.clone(), settings.clone()).await?;
        let after: Value = http
            .get(format!("{address}health"))
            .send()
            .await?
            .json()
            .await?;
        ensure!(
            after["instanceId"] == before["instanceId"],
            "只改外部地址不得重启监听或丢失会话"
        );
        settings["trustCloudflare"] = json!(true);
        configure(app.clone(), settings.clone()).await?;
        settings["enabled"] = json!(false);
        configure(app.clone(), settings).await?;
        let _released =
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        app.engine.shutdown().await?;
        Ok(())
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coordinator_stun_and_cross_network_snapshot_boundary() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let stop = CancellationToken::new();
        let cancel = stop.clone();
        let task = tokio::spawn(async move {
            let (mut socket, remote) = listener.accept().await?;
            ensure!(is_stun(&socket).await, "观察器应识别 STUN");
            stun_server(&mut socket, remote, &cancel).await
        });
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        let source = stream.local_addr()?;
        for _ in 0..3 {
            ensure!(
                crate::discovery::stun_tcp(&mut stream).await? == source,
                "STUN 应反射实际四元组"
            );
        }
        stop.cancel();
        task.await??;
        let app = crate::tests::app().await?;
        let node = c::new_private()?;
        let profiles = [
            conwu_core::identity::Profile::create_for_device("tcp", &node, None)?,
            conwu_core::identity::Profile::create_for_device("tcp", &node, None)?,
        ];
        let token = "A".repeat(64);
        let hash = hex::encode_upper(c::hash(format!("Bearer {token}").as_bytes()));
        let mut registrations = BTreeMap::new();
        let mut nodes = HashMap::new();
        for p in &profiles {
            registrations.insert(
                p.pair.network.clone(),
                Registration {
                    auth: hash.clone(),
                    directory: p.directory.clone().unwrap(),
                },
            );
            let announcement = conwu_core::metadata::Announcement {
                slot: p.member.slot,
                device: p.member.device.clone(),
                revision: conwu_core::unix_seconds() * 1000,
                expires: conwu_core::unix_seconds() + 120,
                endpoint: "203.0.113.1:44000".into(),
                name: "共同设备".into(),
                traversal: None,
                pkarr_source: None,
                existing_endpoints: None,
                existing_entry_only: false,
                connection_paused: false,
            };
            nodes.insert(
                format!("{}/{}", p.pair.network, p.member.slot),
                (Envelope::seal(p, &announcement)?, Instant::now()),
            );
        }
        let registry = Arc::new(Registry {
            trust_cloudflare: false,
            epoch: uuid::Uuid::new_v4(),
            feeds: Mutex::new(HashMap::new()),
            waiters: Arc::new(tokio::sync::Semaphore::new(64)),
            app: app.clone(),
            names: Mutex::new(HashMap::new()),
            assist: crate::assistance::Assist::default(),
            changes: tokio::sync::Notify::new(),
            registrations: Mutex::new(registrations),
            nodes: Mutex::new(nodes),
            rate: Mutex::new(HashMap::new()),
            traversal: Mutex::new(HashMap::new()),
        });
        let request = Request::builder()
            .uri("/")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())?;
        let response = read(
            State(registry.clone()),
            Path(profiles[0].pair.network.clone()),
            request,
        )
        .await;
        ensure!(response.status() == StatusCode::OK, "协调请求应通过认证");
        let snapshot: Snapshot =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await?)?;
        ensure!(
            snapshot.nodes.len() == 1 && snapshot.directory.network == profiles[0].pair.network,
            "同设备的其他网络公告不能混入当前网络"
        );
        snapshot.nodes[0].open(&profiles[0], &profiles[0].member)?;
        let watch_body = |input: &WatchRequest| -> Result<Request> {
            Ok(Request::builder()
                .uri("/")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::from(serde_json::to_vec(input)?))?)
        };
        let input = WatchRequest::create(&profiles[0], uuid::Uuid::new_v4(), uuid::Uuid::nil(), 0)?;
        let first = signed_watch(
            State(registry.clone()),
            Path(profiles[0].pair.network.clone()),
            watch_body(&input)?,
        )
        .await;
        ensure!(
            first.status() == StatusCode::OK,
            "签名等待首次应返回完整快照"
        );
        let first: WatchResponse =
            serde_json::from_slice(&axum::body::to_bytes(first.into_body(), 196608).await?)?;
        ensure!(
            first.reset && first.snapshot.capabilities.traversal_version == 1,
            "等待需声明真实受管协议能力"
        );
        let replay = signed_watch(
            State(registry.clone()),
            Path(profiles[0].pair.network.clone()),
            watch_body(&input)?,
        )
        .await;
        ensure!(
            replay.status() == StatusCode::CONFLICT,
            "相同等待请求不能反复占用资源"
        );
        let mut forged = WatchRequest::create(
            &profiles[0],
            input.boot_id,
            first.server_epoch,
            first.cursor,
        )?;
        forged.signature = "invalid".into();
        ensure!(
            signed_watch(
                State(registry.clone()),
                Path(profiles[0].pair.network.clone()),
                watch_body(&forged)?
            )
            .await
            .status()
                == StatusCode::FORBIDDEN,
            "网络Bearer不能冒充成员签名"
        );
        let next = WatchRequest::create(
            &profiles[0],
            input.boot_id,
            first.server_epoch,
            first.cursor,
        )?;
        let state = registry.clone();
        let network = profiles[0].pair.network.clone();
        let request = watch_body(&next)?;
        let waiter =
            tokio::spawn(async move { signed_watch(State(state), Path(network), request).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if registry
                    .feeds
                    .lock()
                    .unwrap()
                    .get(&profiles[0].pair.network)
                    .and_then(|f| f.accounts.get(&profiles[0].member.slot))
                    .is_some_and(|a| a.waiting)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let duplicate = WatchRequest::create(
            &profiles[0],
            input.boot_id,
            first.server_epoch,
            first.cursor,
        )?;
        ensure!(
            signed_watch(
                State(registry.clone()),
                Path(profiles[0].pair.network.clone()),
                watch_body(&duplicate)?
            )
            .await
            .status()
                == StatusCode::CONFLICT,
            "同一成员仅保持一个等待"
        );
        registry.changed(
            &profiles[0].pair.network,
            "traversal",
            0,
            profiles[0].member.slot,
        );
        let awake = tokio::time::timeout(Duration::from_secs(2), waiter).await??;
        let awake: WatchResponse =
            serde_json::from_slice(&axum::body::to_bytes(awake.into_body(), 196608).await?)?;
        ensure!(
            !awake.reset && awake.cursor > first.cursor && awake.changes.len() == 1,
            "受管消息必须立即唤醒正确成员"
        );
        app.engine.shutdown().await?;
        Ok(())
    }
}
