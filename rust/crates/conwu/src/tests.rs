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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_carrier_failure_is_reported_without_falling_into_stun() -> Result<()> {
    let guest = app().await?;
    let code = conwu_core::code::DirectCode {
        endpoint: "192.0.2.23:443".parse()?,
        mode: "mimic".into(),
        room: "012345".into(),
        punch: true,
        coordinator: false,
    };
    cmd(&guest, json!({"method":"network","network":{
        "action":"join-compact","code":code.issue()?,"name":"本机组件故障验收"
    }})).await?;
    let id = guest.db.read().unwrap().selected_network_id.clone();
    tokio::time::timeout(Duration::from_secs(6), async {
        while guest.engine.pairing(&id)["active"] != false {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }).await.context("本机组件失败被错误地转入外部发现或打洞等待")?;
    let pairing = guest.engine.pairing(&id);
    let error = pairing["error"].as_str().context("本机组件失败未保留原因")?;
    ensure!(error.contains("本机 mimic 承载组件未就绪"), "本机故障被误报成主机不可达：{error}");
    ensure!(guest.status("")["logEntries"].as_array().unwrap().iter().any(|row| {
        row["text"].as_str().is_some_and(|s| s.contains("申请加入 本机组件故障验收 失败"))
    }), "加入失败没有记录到统一日志");
    ensure!(!guest.db.read().unwrap().networks.iter().any(|n| n.profile.is_some()), "失败的申请取得了成员身份");
    cmd(&guest, json!({"method":"network","networkId":id,"network":{
        "action":"leave","confirmReplace":true
    }})).await?;
    {
        let db = guest.db.read().unwrap();
        ensure!(db.networks.is_empty() && db.selected_network_id.is_empty(), "未批准申请应能直接移除");
        ensure!(db.departures.is_empty(), "未取得身份的申请不能生成离网通知");
    }
    guest.engine.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entry_admission_keeps_sas_and_cli_uses_local_secret() -> Result<()> {
    let host = app().await?;
    let guest = app().await?;
    let hid = create(&host, "入口申请", "tcp", false).await?;
    let entry = host
        .db
        .read()
        .unwrap()
        .networks
        .iter()
        .find(|n| n.id == hid)
        .unwrap()
        .settings
        .existing_entries[0]
        .source
        .clone();
    ensure!(host.engine.pairing(&hid).is_null(), "无需预先生成临时房间");
    cmd(
        &guest,
        json!({"method":"network","network":{"action":"join-entry","entry":entry,"mode":"tcp"}}),
    )
    .await?;
    let gid = guest.db.read().unwrap().selected_network_id.clone();
    wait("入口 SAS", || {
        host.engine.pairing(&hid)["verification"]
            .as_str()
            .is_some_and(|s| s.len() == 6)
    })
    .await?;
    let pairing = host.engine.pairing(&hid);
    ensure!(pairing["pending"] == true && pairing["phase"] == "Pending", "审批前应进入待处理状态");
    ensure!(
        pairing["verification"] == guest.engine.pairing(&gid)["verification"],
        "入口申请也须绑定 SAS"
    );
    ensure!(
        guest
            .db
            .read()
            .unwrap()
            .networks
            .iter()
            .find(|n| n.id == gid)
            .unwrap()
            .profile
            .is_none(),
        "不能在审批前入网"
    );
    cmd(&host,json!({"method":"network","networkId":hid,"network":{"action":"approve","verification":pairing["verification"],"candidate":pairing["candidate"]}})).await?;
    ensure!(host.engine.pairing(&hid)["pending"] == false, "批准后须立即退出待审批状态");
    wait("入口批准", || {
        guest
            .db
            .read()
            .unwrap()
            .networks
            .iter()
            .any(|n| n.id == gid && n.profile.is_some())
    })
    .await?;
    wait("批准配置交付确认", || host.engine.pairing(&hid)["delivered"] == true).await?;
    let completed = host.engine.pairing(&hid);
    ensure!(completed["active"] == false && completed["phase"] == "Completed", "交付后应收尾，且不影响内部重试房间");
    let (panel, web) = web::Panel::start(host.clone(), 0).await?;
    host.store.write(
        "panel.private.json",
        &serde_json::to_vec(&json!({"origin":panel.origin,"secret":panel.bootstrap}))?,
        false,
    )?;
    let client = cli::Client::open(&host.store.root)?;
    ensure!(
        client.call(json!({"method":"status"})).await?["status"]["networks"]
            .as_array()
            .unwrap()
            .len()
            == 1,
        "CLI 应看到原网络"
    );
    client
        .mutate(json!({"method":"patch","patch":{"deviceName":"CLI 测试"}}))
        .await?;
    ensure!(
        host.db.read().unwrap().device_name == "CLI 测试",
        "CLI 操作应落盘"
    );
    host.engine.shutdown().await?;
    guest.engine.shutdown().await?;
    web.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_pairing_is_terminal_while_the_reply_room_is_retained() -> Result<()> {
    let host = app().await?;
    let guest = app().await?;
    let hid = create(&host, "拒绝申请隔离验收", "tcp", false).await?;
    cmd(&host,json!({"method":"network","networkId":hid,"network":{"action":"invite-compact"}})).await?;
    let code = host.engine.pairing(&hid)["code"].clone();
    cmd(&guest,json!({"method":"network","network":{"action":"join-compact","code":code}})).await?;
    let gid = guest.db.read().unwrap().selected_network_id.clone();
    wait("拒绝前揭示", || host.engine.pairing(&hid)["verification"].as_str().is_some_and(|v|v.len()==6)).await?;
    let pending = host.engine.pairing(&hid);
    ensure!(cmd(&host,json!({"method":"network","networkId":hid,"network":{"action":"reject","candidate":"stale"}})).await.is_err(), "旧页面不能拒绝新申请");
    ensure!(host.engine.pairing(&hid)["pending"] == true, "迟到操作不能改变当前申请");
    cmd(&host,json!({"method":"network","networkId":hid,"network":{"action":"reject","candidate":pending["candidate"]}})).await?;
    let rejected = host.engine.pairing(&hid);
    ensure!(rejected["active"] == false && rejected["pending"] == false && rejected["phase"] == "Rejected", "拒绝后不能继续显示待办");
    ensure!(host.engine.rooms.lock().unwrap().contains_key(&hid), "保留房间以便从机获取拒绝结果");
    wait("从机收到拒绝", || guest.engine.pairing(&gid)["active"] == false).await?;
    ensure!(guest.db.read().unwrap().networks.iter().all(|n|n.profile.is_none()), "拒绝不能交付成员身份");
    host.engine.shutdown().await?;
    guest.engine.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_receipts_refresh_after_start_and_acknowledge_only_the_matching_result() -> Result<()> {
    let app = app().await?;
    store::write_update_record(&app.store.root,&json!({"state":"Installing","version":"fixture"}))?;
    *app.local_update.write().unwrap()=updates::restore(&app.store)?;
    let before = app.status("")["localUpdate"].clone();
    store::write_update_record(&app.store.root,&json!({"state":"Installed","version":"fixture","attempt":"first"}))?;
    let installed = app.status("")["localUpdate"].clone();
    ensure!(installed["state"]=="Installed" && installed["receiptId"]!=before["receiptId"], "运行中的后台应读到更新 worker 的最终结果");
    ensure!(updates::dismiss(&app,before["receiptId"].as_str().unwrap()).is_err(), "迟到确认不能清除新结果");
    cmd(&app,json!({"method":"update-dismiss","localUpdate":{"receiptId":installed["receiptId"]}})).await?;
    ensure!(app.status("")["localUpdate"]["acknowledged"]==true, "结果应可确认关闭");
    ensure!(updates::restore(&app.store)?["acknowledged"]==true && app.store.root.join("last-update.json").is_file(), "确认必须跨重启保留，且不删除历史记录");
    store::write_update_record(&app.store.root,&json!({"state":"Installed","version":"fixture","attempt":"second"}))?;
    ensure!(app.status("")["localUpdate"]["acknowledged"]==false, "同版本的下一次安装必须有独立确认");
    *app.local_update.write().unwrap()=json!({"state":"Ready","version":"future","ticket":"fixture"});
    ensure!(updates::dismiss(&app,installed["receiptId"].as_str().unwrap()).is_err(), "旧结果不能关闭下一更新任务");
    ensure!(app.status("")["localUpdate"]["state"]=="Ready", "磁盘旧结果不能覆盖新下载任务");
    app.engine.shutdown().await?;
    Ok(())
}

#[test]
fn coordination_snapshots_preserve_revocations_and_reject_corruption() -> Result<()> {
    let root = project().join("out/lab").join(conwu_core::id());
    let store = store::Store::open(&root)?;
    let mut owner = conwu_core::identity::Profile::create("tcp")?;
    let former = owner.issue(None)?.member;
    owner.remove_peer(former.slot)?;
    let registry = std::collections::BTreeMap::from([(
        owner.pair.network.clone(),
        coordination_store::Registration {
            auth: "AB".repeat(32),
            directory: owner.directory.clone().unwrap(),
        },
    )]);
    let bytes = serde_json::to_vec(&registry)?;
    store.write("coordinator.json", &bytes, false)?;
    let backup = root.join("test.slcoord");
    coordination_store::backup(&store, &backup, true)?;
    coordination_store::inspect(&backup)?;
    ensure!(
        coordination_store::restore(&store, &backup, false).is_err(),
        "恢复必须明确确认"
    );
    let result = coordination_store::restore(&store, &backup, true)?;
    ensure!(
        std::path::Path::new(result["previousSnapshot"].as_str().unwrap()).is_file(),
        "完整保存回退点"
    );
    let restored = coordination_store::decode(&std::fs::read(root.join("coordinator.json"))?)?;
    let directory = &restored[&owner.pair.network].directory;
    ensure!(
        directory.next_slot == owner.directory.as_ref().unwrap().next_slot
            && !directory.members.contains(&former),
        "撤销记录及槽位高水位不能回退"
    );
    let mut invalid = bytes.clone();
    let value = serde_json::from_slice::<Value>(&invalid)?;
    let mut records = value.clone();
    records[&owner.pair.network]["Directory"]["Signature"] = json!("invalid");
    invalid = serde_json::to_vec(&records)?;
    ensure!(
        coordination_store::decode(&invalid).is_err(),
        "伪造成员目录不能导入"
    );
    let entry = serde_json::to_string(&registry[&owner.pair.network])?;
    let duplicate = format!(
        "{{\"{}\":{},\"{}\":{}}}",
        owner.pair.network, entry, owner.pair.network, entry
    );
    ensure!(
        coordination_store::decode(duplicate.as_bytes()).is_err(),
        "重复网络ID不能覆盖高水位"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_admin_login_origin_csrf_and_local_command_boundary() -> Result<()> {
    // DrvFS cannot enforce Unix mode bits. Only this permissions fixture uses
    // a native Linux filesystem; no production credential is copied there.
    #[cfg(unix)]
    let app = open_app(
        std::env::temp_dir()
            .join(format!("conwu-rust-permissions-{}", conwu_core::id())),
    )
    .await?;
    #[cfg(windows)]
    let app = app().await?;
    let password = "ConWU isolated test password";
    let config = remote_admin::Config::create("https://control.example/", password)?;
    ensure!(
        config.verify(password) && !config.verify("wrong"),
        "兼容PBKDF2密码验证"
    );
    ensure!(
        remote_admin::Config::create("https://control.example/path", password).is_err(),
        "不能静默忽略管理来源路径"
    );
    app.store
        .write("remote-admin.json", &serde_json::to_vec(&config)?, false)?;
    let router = web::remote_router(app.clone())?
        .layer(axum::Extension("198.51.100.1:50000".parse::<SocketAddr>()?));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let cancel = app.engine.cancel.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(cancel.cancelled_owned())
            .await
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let headers = || {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert("Host", "control.example".parse().unwrap());
        h.insert("Origin", "https://control.example".parse().unwrap());
        h
    };
    ensure!(
        client
            .get(format!("{origin}/admin/"))
            .headers(headers())
            .send()
            .await?
            .status()
            == 303,
        "未登录跳转登录"
    );
    ensure!(
        client
            .post(format!("{origin}/admin/api/login"))
            .headers(headers())
            .json(&json!({"password":"wrong"}))
            .send()
            .await?
            .status()
            == 401,
        "错误密码不能登录"
    );
    let logged = client
        .post(format!("{origin}/admin/api/login"))
        .headers(headers())
        .json(&json!({"password":password}))
        .send()
        .await?;
    ensure!(logged.status() == 200, "正确密码应可登录");
    let cookie = logged
        .headers()
        .get("set-cookie")
        .context("缺少会话Cookie")?
        .to_str()?
        .to_owned();
    ensure!(
        cookie.contains("Secure") && cookie.contains("Path=/admin/"),
        "远程会话需独立安全Cookie"
    );
    let session: Value = logged.json().await?;
    let mut auth = headers();
    auth.insert("Cookie", cookie.split(';').next().unwrap().parse()?);
    ensure!(
        client
            .get(format!("{origin}/admin/api/status"))
            .headers(auth.clone())
            .send()
            .await?
            .status()
            == 200,
        "登录后可查询"
    );
    ensure!(client.post(format!("{origin}/admin/api/command")).headers(auth.clone()).json(&json!({"method":"patch","operationId":uuid::Uuid::new_v4(),"patch":{"deviceName":"untrusted"}})).send().await?.status()==403,"远程操作也必须带CSRF");
    ensure!(
        client
            .post(format!("{origin}/admin/api/local"))
            .headers(auth.clone())
            .json(&json!({"secret":"","command":{"method":"status"}}))
            .send()
            .await?
            .status()
            != 200,
        "远程管理不能访问本地CLI权限"
    );
    auth.insert(
        "X-StreamLink-CSRF",
        session["csrf"].as_str().unwrap().parse()?,
    );
    ensure!(
        client
            .post(format!("{origin}/admin/api/logout"))
            .headers(auth.clone())
            .json(&json!({}))
            .send()
            .await?
            .status()
            == 204,
        "退出应撤销会话"
    );
    ensure!(
        client
            .get(format!("{origin}/admin/api/status"))
            .headers(auth)
            .send()
            .await?
            .status()
            == 401,
        "退出后不可继续查询"
    );
    app.engine.shutdown().await?;
    server.await??;
    Ok(())
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
        {
            let db = guest.db.read().unwrap();
            let settings = &db.networks.iter().find(|n| n.id == gid).unwrap().settings;
            ensure!(
                (20000..30000).contains(&settings.listen_port)
                    && (20000..30000).contains(&settings.source_port)
                    && settings.listen_port != settings.source_port,
                "自动分配的持久端口应避开系统默认临时端口池且互不冲突"
            );
        }
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
        wait("首个心跳延迟", || {
            [&h, &g]
                .iter()
                .all(|r| r.metrics.read().unwrap().rtt.is_some())
        })
        .await?;
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(800)).await;
            ensure!(
                [&h, &g]
                    .iter()
                    .all(|r| r.metrics.read().unwrap().rtt.is_some_and(|ms| ms < 750.0)),
                "本地 RTT 不应累计同一心跳 nonce 的等待秒数"
            );
        }
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
        host.engine.shutdown().await?;
        guest.engine.shutdown().await?;
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
        host.engine.shutdown().await?;
        guest.engine.shutdown().await?;
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
    app.engine.shutdown().await?;
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
async fn coordinated_stream_keeps_the_observed_ip_and_port_across_target_routes() -> Result<()> {
    rustls::crypto::ring::default_provider().install_default().ok();
    let host = app().await?;
    for mode in ["tcp", "https"] {
        let reflector = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let retained = transport::tcp_open_from(reflector.local_addr()?, "127.0.0.2:0".parse()?).await?;
        let local = retained.local_addr()?;
        let (_reflection, reflected_source) = reflector.accept().await?;
        ensure!(reflected_source == local, "观察连接必须保留实际源地址");
        let listening = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let destination = listening.local_addr()?;
        ensure!(discovery::local_route(destination)? != local.ip(), "夹具必须覆盖观察源与目标默认选路不同的情况");
        let stop = tokio_util::sync::CancellationToken::new();
        let incoming = async {
            let (socket, source) = listening.accept().await?;
            ensure!(source == local, "协调探测必须同时复用观察时的源 IP 和端口");
            transport::client_socket(mode, socket, &host.engine.identity.pin, false, &stop).await
        };
        let outgoing = transport::connect_role_from(mode, destination, "", local, false, &host.engine.identity, &stop);
        let (mut peer, mut server) = tokio::try_join!(incoming, outgoing)?;
        server.tx.send(vec![37; 1028]).await?;
        ensure!(tokio::time::timeout(Duration::from_secs(2), peer.rx.recv()).await? == Some(vec![37; 1028]), "同源反向建连必须交付完整报文");
        peer.tx.send(vec![53; 1028]).await?;
        ensure!(tokio::time::timeout(Duration::from_secs(2), server.rx.recv()).await? == Some(vec![53; 1028]), "同源通道必须双向可用");
        stop.cancel();
    }
    host.engine.shutdown().await?;
    Ok(())
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
        host.engine.shutdown().await?;
    }
    Ok(())
}
#[test]
fn legacy_import_is_read_only_and_does_not_start_networks() -> Result<()> {
    let base = project().join("out/lab").join(conwu_core::id());
    let legacy = store::Store::open(&base.join("legacy"))?;
    let output = store::Store::open(&base.join("rust"))?;
    // Deleted network tombstones are not active networks and must not consume
    // the migration limit. They do not need a readable old private profile.
    std::fs::create_dir(legacy.root.join("networks"))?;
    for _ in 0..40 {
        let folder = legacy.root.join("networks").join(conwu_core::id());
        std::fs::create_dir(&folder)?;
        std::fs::write(folder.join("network-info.json"), br#"{"Removed":true}"#)?;
    }
    let node = conwu_core::crypto::new_private()?;
    let p = conwu_core::identity::Profile::create_for_device("tcp", &node, None)?;
    let mut settings = model::Settings::default();
    settings.path_selection = "tcp-only".into();
    ensure!(settings.tcp_stun.len() > 80, "应包含原版完整默认STUN列表");
    settings.existing_entries = vec![model::Entry {
        peer_slot: 0,
        source: "txt://migration.example".into(),
    }];
    let adapter_scope = conwu_core::id();
    let value = json!({"DeviceName":"迁移实验","AdapterScope":adapter_scope,"NodeSigningPrivate":node,"Mesh":p,"SavedNetworkSettings":settings,"Enabled":true,"AutoStart":false,"ExistingEntries":[],"SecretNeverExpose":"do not copy"});
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
    #[cfg(windows)]
    ensure!(
        db.networks[0]
            .legacy_adapter
            .as_ref()
            .is_some_and(|a| a.owner == adapter_scope
                && a.network == p.pair.network
                && a.slot == p.member.slot),
        "迁移应保留原网卡作用域，支持原版回退"
    );
    ensure!(
        db.node_private == node && db.networks[0].profile.as_ref().unwrap().member == p.member,
        "迁移应保留网络身份"
    );
    ensure!(
        db.networks[0].settings.tcp_stun == settings.tcp_stun,
        "导入不可截断原版STUN列表"
    );
    ensure!(
        db.networks[0].settings.existing_entries == settings.existing_entries,
        "迁移应保留订阅配置，不可被旧运行时入口覆盖"
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
    app.engine.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removal_cancels_pending_discovery_commit_before_reusing_port() -> Result<()> {
    let root = project().join("out/lab").join(conwu_core::id());
    let store = Arc::new(store::Store::open(&root)?);
    // Deliberately do not start the event actor: a UI operation may hold its
    // transaction while waiting for the network it is removing to stop.
    let (app, mut events) = backend::App::open(store, root.join("components"), true)?;
    let listen = port();
    let mut settings = model::Settings::default();
    settings.path_selection = "tcp-only".into();
    settings.listen_port = listen;
    settings.source_port = port();
    settings.tcp_stun.clear();
    settings.pkarr_gateways.clear();
    settings
        .extra
        .insert("disableGatewayMapping".into(), json!(true));
    settings.existing_entries.push(model::Entry {
        peer_slot: 0,
        source: SocketAddr::new(local_ip()?, listen).to_string(),
    });
    let network = model::Network {
        legacy_adapter: None,
        id: conwu_core::id(),
        name: "取消发现提交".into(),
        configuration_id: conwu_core::id(),
        settings,
        profile: Some(conwu_core::identity::Profile::create("tcp")?),
        enabled: true,
        paused: false,
        created_here: true,
        created_at: conwu_core::unix_seconds(),
        approved_settings: None,
        peer_name: String::new(),
        pkarr_seed: conwu_core::crypto::b64([17u8; 32]),
        pkarr_sequence: 0,
        peer_pkarr: String::new(),
        bootstrap: vec![],
        creation_operation: String::new(),
        creation_digest: String::new(),
    };
    app.engine.install(network.clone()).await?;
    let pending = tokio::time::timeout(Duration::from_secs(3), events.recv())
        .await?
        .context("未收到发现序号预留")?;
    ensure!(
        matches!(&pending, runtime::Event::Discovery { .. }),
        "应等待发现提交回执"
    );
    // Keep the unacknowledged reply alive throughout removal.
    tokio::time::timeout(Duration::from_secs(3), app.engine.remove(&network.id)).await??;
    ensure!(
        app.engine.current(&network.id).is_none(),
        "取消后不得留下运行代次"
    );
    let released = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, listen))?;
    drop(released);
    drop(pending);
    app.engine.install(network.clone()).await?;
    tokio::time::timeout(Duration::from_secs(3), app.engine.remove(&network.id)).await??;
    app.engine.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_refresh_keeps_first_stun_reply_and_reobserves_a_closed_stream() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let app = app().await?;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let servers = [listener.local_addr()?.to_string()];
    let source = port();
    let reflector = tokio::spawn(async move {
        for external in [49152u16, 49153] {
            let (mut socket, peer) = listener.accept().await?;
            ensure!(peer.port() == source, "重新观察须保留接收端口");
            let mut request = [0u8; 20];
            socket.read_exact(&mut request).await?;
            let mut reply = request.to_vec();
            reply[..4].copy_from_slice(&[1, 1, 0, 12]);
            reply.extend_from_slice(&[0, 1, 0, 8, 0, 1]);
            reply.extend_from_slice(&external.to_be_bytes());
            reply.extend_from_slice(&[203, 0, 113, 7]);
            socket.write_all(&reply).await?;
            socket.shutdown().await?;
        }
        Ok::<_, anyhow::Error>(())
    });
    let first =
        discovery::refresh_or_observe_tcp(None, source, &servers, &app.engine, "tcp").await?;
    assert_eq!(first.mapped.port(), 49152);
    let next = discovery::refresh_or_observe_tcp(Some(first), source, &servers, &app.engine, "tcp")
        .await?;
    assert_eq!(next.mapped.port(), 49153);
    reflector.await??;
    app.engine.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stun_failures_rotate_into_the_rest_of_the_saved_catalogue() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let app = app().await?;
    let unavailable = port();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server = listener.local_addr()?;
    let reply = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = [0u8; 20];
        stream.read_exact(&mut request).await?;
        let mut response = request.to_vec();
        response[..4].copy_from_slice(&[1, 1, 0, 12]);
        response.extend_from_slice(&[0, 1, 0, 8, 0, 1, 0xC0, 0x00, 203, 0, 113, 1]);
        stream.write_all(&response).await?;
        Ok::<_, anyhow::Error>(())
    });
    let mut servers = vec![format!("127.0.0.1:{unavailable}"); 8];
    servers.push(server.to_string());
    let source = port();
    ensure!(
        discovery::observe_tcp(source, &servers, &app.engine, "tcp")
            .await
            .is_err(),
        "首轮只能使用有界的前八项"
    );
    let observed = discovery::observe_tcp(source, &servers, &app.engine, "tcp").await?;
    ensure!(
        observed.observer == server && observed.mapped == "203.0.113.1:49152".parse()?,
        "下一轮应使用列表后部服务器且校验STUN回复"
    );
    reply.await??;
    app.engine.shutdown().await?;
    Ok(())
}

#[test]
fn certificates_and_verified_download_survive_reopening() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let root = project().join("out/lab").join(conwu_core::id());
    let store = store::Store::open(&root)?;
    store::write_update_record(
        &store.root,
        &json!({"state":"Installed","version":"previous-fixture"}),
    )?;
    ensure!(
        serde_json::from_slice::<Value>(&std::fs::read(store.root.join("last-update.json"))?)?["state"]
            == "Installed",
        "更新结束记录应能在新后台持有数据锁时写入"
    );
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
