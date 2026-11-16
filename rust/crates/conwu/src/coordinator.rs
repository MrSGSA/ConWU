use crate::backend::App;
use anyhow::{Context, Result, ensure};
use axum::{
    Extension, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use conwu_core::{
    crypto as c,
    identity::{self, Directory},
    metadata::{Envelope, Snapshot},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Serialize, Deserialize)]
struct Registration {
    auth: String,
    directory: Directory,
}
struct Registry {
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
        json!({"enabled":true,"running":!r.cancel.is_cancelled(),"state":"运行中","addresses":[r.settings["listenUrl"]],"certificatePin":r.certificate_pin,"clients":clients,"punchAssist":r.registry.upgrade().map(|r|r.assist.status())})
    } else {
        json!({"enabled":false,"running":false,"state":"未开启","addresses":[],"clients":[]})
    }
}
pub fn validate(settings: &Value) -> Result<()> {
    if settings.is_null() {
        return Ok(());
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
pub async fn configure(app: Arc<App>, settings: Value) -> Result<()> {
    validate(&settings)?;
    if let Some(prior) = running().lock().unwrap().as_ref() {
        if prior.settings == settings && !prior.cancel.is_cancelled() {
            return Ok(());
        }
    }
    if let Some(prior) = running().lock().unwrap().take() {
        prior.cancel.cancel();
    }
    if settings["enabled"] != true {
        return Ok(());
    }
    let url = url::Url::parse(settings["listenUrl"].as_str().unwrap())?;
    let address: SocketAddr =
        format!("{}:{}", url.host_str().unwrap(), url.port().unwrap()).parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let path = app.store.root.join("coordinator.json");
    let registrations = if path.exists() {
        let bytes = std::fs::read(path)?;
        ensure!(bytes.len() <= 8 * 1024 * 1024, "协调数据过大");
        let registrations: BTreeMap<String, Registration> = serde_json::from_slice(&bytes)?;
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
        names: Mutex::new(HashMap::new()),
        assist: crate::assistance::Assist::default(),
        changes: tokio::sync::Notify::new(),
        app: app.clone(),
        registrations: Mutex::new(registrations),
        nodes: Mutex::new(HashMap::new()),
        rate: Mutex::new(HashMap::new()),
    });
    let router = Router::new()
        .route(
            "/health",
            get(|| async {
                axum::Json(
                    json!({"ok":true,"mesh":true,"pairwise":true,"version":"rust-experiment","punchAssist":1,"punchTcpStun":1,"punchModes":["faketcp","phantun","mimic","tcpraw","tcp","https"],"tcpAssist":1}),
                )
            }),
        )
        .route("/v3/mesh/{network}/directory", put(directory))
        .route("/v3/mesh/{network}/nodes/{slot}", put(publish))
        .route("/v3/mesh/{network}", get(read))
        .route("/v3/mesh/{network}/watch", get(watch))
        .route("/v3/mesh/{network}/tcp-assist", post(member_assist))
        .route("/v1/punch-assist/{action}", post(first_assist))
        .layer(DefaultBodyLimit::max(65536))
        .with_state(registry.clone());
    let stop = app.engine.cancel.child_token();
    let mut certificate_pin = String::new();
    let tls = if url.scheme() == "https" {
        if settings["certificateFile"]
            .as_str()
            .is_none_or(|s| s.is_empty())
        {
            certificate_pin = app.engine.identity.certificate_pin.clone();
            Some(app.engine.identity.server.clone())
        } else {
            let certificate = std::fs::read(settings["certificateFile"].as_str().unwrap())?;
            let key = std::fs::read(settings["certificateKeyFile"].as_str().unwrap())?;
            let certificates = rustls_pemfile::certs(&mut certificate.as_slice())
                .collect::<std::io::Result<Vec<_>>>()?;
            certificate_pin =
                hex::encode_upper(c::hash(certificates.first().context("证书为空")?.as_ref()));
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
    *running().lock().unwrap() = Some(Running {
        cancel: stop.clone(),
        settings: settings.clone(),
        registry: Arc::downgrade(&registry),
        certificate_pin,
    });
    let tracker = app.engine.tracker.clone();
    app.engine.tracker.spawn(async move {
        let gate=Arc::new(tokio::sync::Semaphore::new(128));
        loop {
            let (mut socket,remote)=tokio::select!{_=stop.cancelled()=>break,r=listener.accept()=>match r{Ok(r)=>r,Err(_)=>break}};
            let Ok(permit)=gate.clone().try_acquire_owned() else {continue};
            let tls=tls.clone();let stop=stop.clone();let router=router.clone().layer(Extension(remote));
            tracker.spawn(async move {
                let _permit=permit;
                if is_stun(&socket).await {let _=stun_server(&mut socket,remote,&stop).await;return;}
                if let Some(tls)=tls {
                    let handshake=tokio::time::timeout(Duration::from_secs(6),tokio_rustls::TlsAcceptor::from(tls).accept(socket));
                    let stream=tokio::select!{_=stop.cancelled()=>return,r=handshake=>match r{Ok(Ok(s))=>s,_=>return}};
                    serve_http(stream,router,stop).await;
                }else{serve_http(socket,router,stop).await;}
            });
        }
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
            }
            ensure!(
                registrations.contains_key(&network) || registrations.len() < 4096,
                "协调网络表已满"
            );
            let mut next = registrations.clone();
            next.insert(network, Registration { auth, directory });
            r.app
                .store
                .write("coordinator.json", &serde_json::to_vec(&next)?, true)?;
            *registrations = next;
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
                directory: registration.directory.clone(),
                nodes
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
            let input: Value = body(request).await?;
            r.assist.request(&action, &input, remote.ip())
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
            let auth = authenticate(&r, &request, &network)?;
            let input: crate::assistance::MemberRequest = body(request).await?;
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
            input.verify(&network, member, remote.ip())?;
            let peer = registration
                .directory
                .members
                .iter()
                .find(|m| m.slot != input.slot)
                .context("尚无对机成员")?;
            r.assist.member(&network, input, peer.slot)
        }
        .await,
    )
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
            app: app.clone(),
            names: Mutex::new(HashMap::new()),
            assist: crate::assistance::Assist::default(),
            changes: tokio::sync::Notify::new(),
            registrations: Mutex::new(registrations),
            nodes: Mutex::new(nodes),
            rate: Mutex::new(HashMap::new()),
        });
        let request = Request::builder()
            .uri("/")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())?;
        let response = read(
            State(registry),
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
        app.engine.shutdown().await;
        Ok(())
    }
}
