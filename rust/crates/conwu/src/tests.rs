use super::*;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

fn project() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}
pub(crate) async fn app() -> Result<Arc<backend::App>> {
    let root = project().join("out/lab").join(conwu_core::id());
    open_app(root).await
}
async fn open_app(root: std::path::PathBuf) -> Result<Arc<backend::App>> {
    let store = Arc::new(store::Store::open(&root)?);
    let (app, events) = backend::App::open(store, root.join("components"), true)?;
    let actor = app.clone();
    app.engine.tracker.spawn(async move {
        actor.events(events).await;
    });
    app.start_departures();
    Ok(app)
}
async fn cmd(app: &Arc<backend::App>, mut body: Value) -> Result<Value> {
    let id = uuid::Uuid::new_v4().to_string();
    body["operationId"] = json!(id);
    app.submit(body)?;
    let result = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let result = app.reply("", Some(&id));
            if result["operation"]["completed"] == true {
                return result;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    ensure!(
        result["operation"]["error"].as_str() == Some(""),
        "操作失败：{}",
        result["operation"]["error"]
    );
    Ok(result)
}
async fn wait<F: Fn() -> bool>(label: &str, condition: F) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("等待{label}超时"))
}
fn local_ip() -> Result<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0")?;
    s.connect("192.0.2.1:9")?;
    Ok(s.local_addr()?.ip())
}
fn port() -> u16 {
    std::net::TcpListener::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn packet(from: Ipv4Addr, to: Ipv4Addr, marker: u8) -> Vec<u8> {
    let mut p = vec![marker; 1028];
    p[0] = 0x45;
    p[1] = 0;
    p[2..4].copy_from_slice(&(1028u16).to_be_bytes());
    p[4..8].fill(0);
    p[8] = 64;
    p[9] = 17;
    p[10..12].fill(0);
    p[12..16].copy_from_slice(&from.octets());
    p[16..20].copy_from_slice(&to.octets());
    p[20..22].copy_from_slice(&(42000u16).to_be_bytes());
    p[22..24].copy_from_slice(&(42001u16).to_be_bytes());
    p[24..26].copy_from_slice(&(1008u16).to_be_bytes());
    p[26..28].fill(0);
    let mut sum: u32 = p[..20]
        .chunks_exact(2)
        .map(|w| u16::from_be_bytes([w[0], w[1]]) as u32)
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    assert!(conwu_core::link::valid_packet(&p));
    p
}
async fn create(app: &Arc<backend::App>, name: &str, mode: &str, flows: bool) -> Result<String> {
    let listen = port();
    let source = port();
    let mut settings = model::Settings::default();
    settings.path_selection = format!("{mode}-only");
    settings.stream_flow_lanes = flows;
    settings.connection_source = "existing".into();
    settings.discovery_mode = "existing".into();
    settings.listen_port = listen;
    settings.source_port = source;
    settings.existing_entries = vec![model::Entry {
        peer_slot: 0,
        source: SocketAddr::new(local_ip()?, listen).to_string(),
    }];
    let result=cmd(app,json!({"method":"configuration","configuration":{"action":"save","id":"","name":name,"expectedRevision":0,"settings":settings}})).await?;
    let cid = result["configurationId"].as_str().unwrap();
    cmd(app,json!({"method":"network","network":{"action":"create-direct","name":name,"configurationId":cid,"mode":mode}})).await?;
    let id = app.db.read().unwrap().selected_network_id.clone();
    Ok(id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn desktop_pairing_and_packets_over_tcp_and_https() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    for (mode, lanes) in [
        ("tcp", false),
        ("https", false),
        ("tcp", true),
        ("https", true),
    ] {
        let mut host = app().await?;
        let mut guest = app().await?;
        let hid = create(&host, "独立主网络", mode, lanes).await?;
        let second = create(&host, "另一条网络", mode, false).await?;
        ensure!(hid != second, "网络必须独立");
        cmd(&host,json!({"method":"network","networkId":hid,"network":{"action":"invite-compact","expectedNetwork":hid}})).await?;
        let pair = host.engine.pairing(&hid);
        let code = pair["code"].as_str().unwrap().to_string();
        ensure!(
            host.engine.pairing(&second).is_null(),
            "生成直连码不得作用于另一网络"
        );
        cmd(&guest,json!({"method":"network","network":{"action":"join-compact","code":code,"name":"申请"}})).await?;
        let gid = guest.db.read().unwrap().selected_network_id.clone();
        wait("申请与揭示", || {
            host.engine.pairing(&hid)["verification"]
                .as_str()
                .is_some_and(|s| s.len() == 6)
        })
        .await?;
        let pair = host.engine.pairing(&hid);
        ensure!(
            pair["verification"] == guest.engine.pairing(&gid)["verification"],
            "双方 SAS 必须一致"
        );
        cmd(&host,json!({"method":"network","networkId":hid,"network":{"action":"approve","candidate":pair["candidate"],"verification":pair["verification"]}})).await?;
        wait("获批身份落盘", || {
            guest
                .db
                .read()
                .unwrap()
                .networks
                .iter()
                .any(|n| n.id == gid && n.profile.is_some())
        })
        .await?;
        wait("双向路径验证", || {
            host.engine
                .current(&hid)
                .is_some_and(|r| r.metrics.read().unwrap().connected)
                && guest
                    .engine
                    .current(&gid)
                    .is_some_and(|r| r.metrics.read().unwrap().connected)
        })
        .await?;
        if lanes {
            wait("三连接分流", || {
                [(&host, &hid), (&guest, &gid)].iter().all(|(app, id)| {
                    app.engine.current(id).is_some_and(|r| {
                        r.metrics.read().unwrap().stream_flows["splitActive"] == true
                    })
                })
            })
            .await?;
        }
        let h = host.engine.current(&hid).unwrap();
        let g = guest.engine.current(&gid).unwrap();
        let hip = h
            .config
            .read()
            .unwrap()
            .profile
            .as_ref()
            .unwrap()
            .local_ip()?;
        let gip = g
            .config
            .read()
            .unwrap()
            .profile
            .as_ref()
            .unwrap()
            .local_ip()?;
        for marker in 1..=32 {
            h.memory
                .as_ref()
                .unwrap()
                .inject(packet(hip, gip, marker))?;
            g.memory
                .as_ref()
                .unwrap()
                .inject(packet(gip, hip, marker))?;
        }
        wait("双向业务包", || {
            h.metrics.read().unwrap().received >= 32 * 1028
                && g.metrics.read().unwrap().received >= 32 * 1028
        })
        .await?;
        ensure!(
            h.memory.as_ref().unwrap().drain().len() == 32
                && g.memory.as_ref().unwrap().drain().len() == 32,
            "数据报必须完整"
        );
        g.memory.as_ref().unwrap().inject(packet(hip, hip, 99))?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        ensure!(
            h.memory.as_ref().unwrap().drain().is_empty(),
            "伪造虚拟源地址必须拒绝"
        );
        if lanes {
            let group = host
                .engine
                .flow_groups
                .lock()
                .unwrap()
                .values()
                .find(|g| g.network == hid)
                .cloned()
                .context("分流连接未找到")?;
            group.interrupt_lane(2);
            wait("辅助连接退出", || {
                group.status()["connections"]
                    .as_u64()
                    .is_some_and(|n| n < 3)
            })
            .await?;
            tokio::time::sleep(Duration::from_millis(150)).await;
            let mut audio = packet(hip, gip, 123);
            audio[20..22].copy_from_slice(&48000u16.to_be_bytes());
            audio[22..24].copy_from_slice(&48000u16.to_be_bytes());
            h.memory.as_ref().unwrap().inject(audio.clone())?;
            wait("音频回到主连接", || {
                g.metrics.read().unwrap().received >= 33 * 1028
            })
            .await?;
            ensure!(
                g.memory.as_ref().unwrap().drain() == vec![audio],
                "辅助退出后数据仍应送达"
            );
        }
        drop(h);
        drop(g);
        let hroot = host.store.root.clone();
        let groot = guest.store.root.clone();
        let identity = guest.db.read().unwrap().node_private.clone();
        host.engine.shutdown().await;
        guest.engine.shutdown().await;
        drop(host);
        drop(guest);
        host = open_app(hroot).await?;
        guest = open_app(groot).await?;
        host.boot().await;
        guest.boot().await;
        ensure!(
            guest.db.read().unwrap().node_private == identity,
            "重启应保留设备私钥"
        );
        wait("双后台重启复连", || {
            [&host, &guest].iter().all(|a| {
                a.engine
                    .current(if Arc::ptr_eq(a, &host) { &hid } else { &gid })
                    .is_some_and(|r| r.metrics.read().unwrap().connected)
            })
        })
        .await?;
        let h = host.engine.current(&hid).unwrap();
        let g = guest.engine.current(&gid).unwrap();
        cmd(
            &guest,
            json!({"method":"network","networkId":gid,"network":{"action":"disconnect"}}),
        )
        .await?;
        g.memory.as_ref().unwrap().inject(packet(gip, hip, 42))?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        ensure!(
            h.memory.as_ref().unwrap().drain().is_empty(),
            "断开时必须停止业务转发"
        );
        ensure!(
            guest
                .db
                .read()
                .unwrap()
                .networks
                .iter()
                .any(|n| n.id == gid && n.profile.is_some()),
            "断开保留成员记录"
        );
        cmd(
            &guest,
            json!({"method":"network","networkId":gid,"network":{"action":"reconnect"}}),
        )
        .await?;
        g.memory.as_ref().unwrap().inject(packet(gip, hip, 43))?;
        wait("恢复转发", || {
            h.metrics.read().unwrap().received >= 1028
        })
        .await?;
        cmd(&guest,json!({"method":"network","networkId":gid,"network":{"action":"leave","confirmReplace":true}})).await?;
        ensure!(
            !guest
                .db
                .read()
                .unwrap()
                .networks
                .iter()
                .any(|n| n.id == gid),
            "退出必须删除本机记录"
        );
        wait("主机收到退出通知", || {
            host.db
                .read()
                .unwrap()
                .networks
                .iter()
                .find(|n| n.id == hid)
                .unwrap()
                .profile
                .as_ref()
                .unwrap()
                .directory
                .as_ref()
                .unwrap()
                .members
                .len()
                == 1
        })
        .await?;
        ensure!(
            host.db
                .read()
                .unwrap()
                .networks
                .iter()
                .find(|n| n.id == hid)
                .unwrap()
                .profile
                .as_ref()
                .unwrap()
                .directory
                .as_ref()
                .unwrap()
                .members
                .len()
                == 1,
            "主机必须收到签名退出并删除从机"
        );
        host.engine.shutdown().await;
        guest.engine.shutdown().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_session_and_csrf_boundary() -> Result<()> {
    let app = app().await?;
    let (panel, task) = web::Panel::start(app.clone(), 0).await?;
    let client = reqwest::Client::new();
    let url = &panel.origin;
    ensure!(
        client
            .get(format!("{url}/api/status"))
            .send()
            .await?
            .status()
            == 401,
        "未登录必须拒绝"
    );
    let link = panel.link();
    let ticket = link.rsplit_once('#').unwrap().1;
    let response = client
        .post(format!("{url}/api/session"))
        .header("Origin", url)
        .json(&json!({"ticket":ticket}))
        .send()
        .await?;
    let cookie = response.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let session: Value = response.json().await?;
    ensure!(session["csrf"].is_string(), "面板票据需生成 CSRF");
    let again = client
        .post(format!("{url}/api/session"))
        .header("Origin", url)
        .json(&json!({"ticket":ticket}))
        .send()
        .await?;
    ensure!(again.status() == 401, "票据必须单次使用");
    let body = json!({"method":"patch","operationId":uuid::Uuid::new_v4().to_string(),"patch":{"deviceName":"Rust 实验"}});
    let denied = client
        .post(format!("{url}/api/command"))
        .header("Origin", url)
        .header("Cookie", &cookie)
        .json(&body)
        .send()
        .await?;
    ensure!(denied.status() == 403, "缺少 CSRF 必须拒绝");
    let status: Value = client
        .get(format!("{url}/api/status"))
        .header("Cookie", &cookie)
        .send()
        .await?
        .json()
        .await?;
    ensure!(status["ok"] == true, "合法会话可读状态");
    let mut accepted = Vec::new();
    for _ in 0..2 {
        let response = client
            .post(format!("{url}/api/command"))
            .header("Origin", url)
            .header("Cookie", &cookie)
            .header("x-streamlink-csrf", session["csrf"].as_str().unwrap())
            .json(&body)
            .send()
            .await?;
        ensure!(response.status().is_success(), "同一请求重试必须允许");
        accepted.push(response.json::<Value>().await?);
    }
    ensure!(
        accepted[0]["operation"]["id"] == accepted[1]["operation"]["id"],
        "重试须复用同一操作"
    );
    let mut changed = body.clone();
    changed["patch"]["deviceName"] = json!("另一条操作");
    let conflict = client
        .post(format!("{url}/api/command"))
        .header("Origin", url)
        .header("Cookie", &cookie)
        .header("x-streamlink-csrf", session["csrf"].as_str().unwrap())
        .json(&changed)
        .send()
        .await?;
    ensure!(!conflict.status().is_success(), "同一编号不能改写操作内容");
    let then = Instant::now();
    let spoof = client
        .get(format!("{url}/api/status"))
        .header("Host", "evil.test")
        .header("Cookie", &cookie)
        .send()
        .await?;
    ensure!(
        spoof.status() == 400 && then.elapsed() < Duration::from_secs(1),
        "重绑定 Host 必须拒绝"
    );
    app.engine.shutdown().await;
    task.await??;
    Ok(())
}

#[test]
fn malformed_inputs_do_not_become_endpoints() {
    assert!(conwu_core::code::DirectCode::import("0000-0000-0000-0000").is_err());
    assert!(
        model::Settings {
            listen_port: 40000,
            source_port: 40000,
            ..Default::default()
        }
        .validate()
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_port_reverse_tcp_and_tls_roles() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    for mode in ["tcp", "https"] {
        let host = app().await?;
        let listening = transport::listener(0, false).await?;
        let source = transport::listener(0, false).await?;
        let port = source.local_addr()?.port();
        let destination = SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            listening.local_addr()?.port(),
        );
        let stop = tokio_util::sync::CancellationToken::new();
        let incoming = async {
            let (socket, remote) = listening.accept().await?;
            ensure!(remote.port() == port, "出站必须复用映射源端口");
            transport::client_socket(mode, socket, &host.engine.identity.pin, false, &stop).await
        };
        let outgoing = transport::connect_role(
            mode,
            destination,
            "",
            port,
            false,
            &host.engine.identity,
            &stop,
        );
        let (mut peer, mut server) = tokio::try_join!(incoming, outgoing)?;
        server.tx.send(vec![37; 1028]).await?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(2), peer.rx.recv()).await?
                == Some(vec![37; 1028]),
            "反向建立的传输应正确收发"
        );
        peer.tx.send(vec![53; 1028]).await?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(2), server.rx.recv()).await?
                == Some(vec![53; 1028]),
            "反向传输应双向可用"
        );
        stop.cancel();
        host.engine.shutdown().await;
    }
    Ok(())
}
#[test]
fn legacy_import_is_read_only_and_does_not_start_networks() -> Result<()> {
    let base = project().join("out/lab").join(conwu_core::id());
    let legacy = store::Store::open(&base.join("legacy"))?;
    let output = store::Store::open(&base.join("rust"))?;
    let node = conwu_core::crypto::new_private()?;
    let p = conwu_core::identity::Profile::create_for_device("tcp", &node, None)?;
    let mut settings = model::Settings::default();
    settings.path_selection = "tcp-only".into();
    let value = json!({"DeviceName":"迁移实验","NodeSigningPrivate":node,"Mesh":p,"SavedNetworkSettings":settings,"Enabled":true,"AutoStart":false,"ExistingEntries":[],"SecretNeverExpose":"do not copy"});
    let bytes = serde_json::to_vec(&value)?;
    #[cfg(windows)]
    let bytes = store::dpapi(&bytes, true, b"StreamLink-profile-v2")?;
    let name = if cfg!(windows) {
        "profile.dpapi"
    } else {
        "profile.json"
    };
    legacy.write(name, &bytes, false)?;
    let report = migration::import(&legacy.root, &output)?;
    ensure!(
        report["networks"] == 1 && report["sourceModified"] == false && report["started"] == false,
        "迁移只应产生独立资料"
    );
    ensure!(
        std::fs::read(legacy.root.join(name))? == bytes,
        "导入不能修改源配置"
    );
    let db = output.load()?;
    ensure!(
        db.node_private == node && db.networks[0].profile.as_ref().unwrap().member == p.member,
        "迁移应保留网络身份"
    );
    ensure!(
        !serde_json::to_string(&db)?.contains("do not copy"),
        "旧配置中的额外私密字段不得进入 UI 设置"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changing_and_removing_listener_releases_owned_ports() -> Result<()> {
    let app = app().await?;
    let id = create(&app, "监听切换实验", "tcp", false).await?;
    let mut network = app
        .db
        .read()
        .unwrap()
        .networks
        .iter()
        .find(|n| n.id == id)
        .unwrap()
        .clone();
    let old = network.settings.listen_port;
    let new = port();
    network.settings.listen_port = new;
    app.engine.install(network.clone()).await?;
    let released = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, old))?;
    ensure!(
        std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, new)).is_err(),
        "新监听应仍占用本机端口"
    );
    app.engine.remove(&id).await?;
    let removed = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, new))?;
    drop((released, removed));
    app.engine.shutdown().await;
    Ok(())
}

#[test]
fn certificates_and_verified_download_survive_reopening() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let root = project().join("out/lab").join(conwu_core::id());
    let store = store::Store::open(&root)?;
    let first = transport::TlsIdentity::load(&store)?;
    let updates = store.root.join("updates");
    std::fs::create_dir(&updates)?;
    let package = updates.join("conwu-rust-test.msi");
    std::fs::write(&package, b"isolated local fixture")?;
    store.write_secret("update-ready.private.json", &serde_json::to_vec(&json!({"package":package,"sha256":updater::hash_file(&package)?,"version":"fixture","ticket":"AB".repeat(32)}))?, false)?;
    drop(store);
    let store = store::Store::open(&root)?;
    let second = transport::TlsIdentity::load(&store)?;
    ensure!(
        first.pin == second.pin && first.certificate_pin == second.certificate_pin,
        "普通重启必须保留公钥和整证书 pin"
    );
    ensure!(
        updates::restore(&store)?["state"] == "Ready",
        "重启应恢复已校验的下载"
    );
    std::fs::write(&package, b"changed")?;
    ensure!(
        updates::restore(&store).is_err(),
        "不能信任已被改写的安装包"
    );
    Ok(())
}

#[test]
fn update_cleanup_cannot_escape_the_owned_directory() -> Result<()> {
    let base = project().join("out/lab").join(conwu_core::id());
    let store = store::Store::open(&base.join("owned"))?;
    let outside = base.join("outside");
    std::fs::create_dir(&outside)?;
    let sentinel = outside.join("keep");
    std::fs::write(&sentinel, b"keep")?;
    ensure!(
        updater::safe_remove(&store.root.join("..").join("outside"), &store.root).is_err(),
        "上级路径必须拒绝"
    );
    ensure!(
        updater::safe_remove(&store.root, &store.root).is_err(),
        "不能删除数据根目录"
    );
    #[cfg(target_os = "linux")]
    {
        let link = store.root.join("linked");
        std::os::unix::fs::symlink(&outside, &link)?;
        ensure!(
            updater::safe_remove(&link, &store.root).is_err(),
            "符号链接不能引导清理越界"
        );
    }
    ensure!(std::fs::read(sentinel)? == b"keep", "边界外文件须原样保留");
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "development oracle required; creates only isolated PFX fixture"]
fn legacy_https_pfx_import_preserves_approved_identity() -> Result<()> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let oracle = std::env::var("CONWU_DOTNET_ORACLE")?;
    let mut process = Command::new("dotnet")
        .arg(oracle)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    process
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"op\":\"tls-fixture\"}\n")?;
    let output = process.wait_with_output()?;
    ensure!(output.status.success(), "开发对照程序未生成 fixture");
    let reply: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(reply["ok"] == true, "PFX fixture 未创建");
    let fixture = &reply["result"];
    let base = project().join("out/lab").join(conwu_core::id());
    let legacy = store::Store::open(&base.join("legacy"))?;
    let target = store::Store::open(&base.join("rust"))?;
    let node = conwu_core::crypto::new_private()?;
    let mut profile = conwu_core::identity::Profile::create_for_device("https", &node, None)?;
    profile.pair.transport_key_pin = Some(
        fixture["pin"]
            .as_str()
            .context("fixture pin missing")?
            .into(),
    );
    let settings = model::Settings {
        path_selection: "https-only".into(),
        ..Default::default()
    };
    let bytes = serde_json::to_vec(
        &json!({"DeviceName":"TLS 迁移实验","NodeSigningPrivate":node,"Mesh":profile,"SavedNetworkSettings":settings,"Enabled":true}),
    )?;
    let bytes = store::dpapi(&bytes, true, b"StreamLink-profile-v2")?;
    legacy.write("profile.dpapi", &bytes, false)?;
    let protected = store::dpapi(
        &serde_json::to_vec(&fixture["pfx"])?,
        true,
        b"ConWU-private-document-v1",
    )?;
    legacy.write("stream-tls.protected", &protected, false)?;
    migration::import(&legacy.root, &target)?;
    let restored = transport::TlsIdentity::load(&target)?;
    ensure!(
        restored.pin == fixture["pin"],
        "导入应保留已批准的 TLS SPKI"
    );
    ensure!(
        std::fs::read(legacy.root.join("stream-tls.protected"))? == protected,
        "导入不能改写旧 PFX"
    );
    Ok(())
}
