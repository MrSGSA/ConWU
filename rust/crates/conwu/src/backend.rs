use crate::{
    discovery,
    model::{Configuration, Database, Network, Settings, VERSION},
    pkarr,
    runtime::{self, Engine, Event},
    store::Store,
    transport::TlsIdentity,
};
use anyhow::{Context, Result, ensure};
use conwu_core::{code::DirectCode, crypto as c, identity::Profile, unix_seconds};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, RwLock},
};
use tokio::sync::mpsc;

const MAX_CONFIGURATIONS: usize = 64;

struct Command {
    body: Value,
    id: String,
}
pub struct App {
    pub store: Arc<Store>,
    pub db: RwLock<Database>,
    pub engine: Arc<Engine>,
    commands: mpsc::Sender<Command>,
    operations: Mutex<BTreeMap<String, Value>>,
    logs: crate::logging::Journal,
    entry_resolutions: RwLock<Value>,
    pub update: RwLock<Value>,
    pub local_update: RwLock<Value>,
    pub desktop: RwLock<Value>,
    pub update_busy: std::sync::atomic::AtomicBool,
    transaction: tokio::sync::Mutex<()>,
}
impl App {
    pub fn open(
        store: Arc<Store>,
        components: std::path::PathBuf,
        memory: bool,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Event>)> {
        let db = store.load()?;
        ensure!(
            db.schema == 1 && db.networks.len() <= 32,
            "配置版本或容量无效"
        );
        c::valid_public(&c::public(&db.node_private)?)?;
        for n in &db.networks {
            n.settings.validate()?;
            if let Some(p) = &n.profile {
                p.validate()?;
            }
        }
        let tls = TlsIdentity::load(&store)?;
        let pkarr = pkarr::Client::open(store.clone())?;
        let (events, receiver) = mpsc::channel(128);
        let engine = Engine::new(store.clone(), tls, events, components, memory, pkarr);
        *engine.device_name.write().unwrap() = db.device_name.clone();
        *engine.node_private.write().unwrap() = db.node_private.clone();
        let (commands, queue) = mpsc::channel(64);
        let logs = crate::logging::Journal::open(&store)?;
        let local_update = crate::updates::restore(&store).unwrap_or_else(|e|
            json!({"supported":true,"state":"Error","canInstall":false,"message":format!("本地更新记录未恢复：{e}")}));
        let app = Arc::new(Self {
            store,
            db: RwLock::new(db),
            engine,
            commands,
            operations: Mutex::new(BTreeMap::new()),
            logs,
            entry_resolutions: RwLock::new(json!([])),
            update: RwLock::new(
                json!({"currentVersion":VERSION,"platform":std::env::consts::OS,"state":"NotChecked","message":if cfg!(feature="production"){"尚未检查更新"}else{"Rust 实验分支"},"updateAvailable":false}),
            ),
            local_update: RwLock::new(local_update),
            desktop: RwLock::new(
                json!({"serviceRegistered":false,"serviceState":if memory{"隔离测试后台"}else{"前台实验后台"},"autoStart":false}),
            ),
            update_busy: std::sync::atomic::AtomicBool::new(false),
            transaction: tokio::sync::Mutex::new(()),
        });
        let actor = app.clone();
        app.engine.tracker.spawn(async move {
            actor.actor(queue).await;
        });
        Ok((app, receiver))
    }
    pub fn log(&self, level: &str, text: &str) {
        let configured = self.db.read().unwrap().log_level.clone();
        let rank = |s: &str| match s.to_ascii_lowercase().as_str() {
            "off" => 5,
            "error" => 4,
            "warn" => 3,
            "info" => 2,
            _ => 1,
        };
        if rank(level) >= rank(&configured) {
            self.logs.push(level, text);
        }
    }
    pub fn commit(&self, next: Database) -> Result<()> {
        // A pending join reserves its configuration slot. Open older stores
        // that already exceed the limit, and allow edits or cleanup there.
        let slots = next.configuration_slots();
        ensure!(
            slots <= MAX_CONFIGURATIONS || slots <= self.db.read().unwrap().configuration_slots(),
            "设置数量超过限制，请移除不用的设置或加入申请"
        );
        validate_bindings(&next)?;
        self.store.save(&next)?;
        *self.engine.device_name.write().unwrap() = next.device_name.clone();
        *self.db.write().unwrap() = next;
        Ok(())
    }
    pub fn submit(&self, body: Value) -> Result<Value> {
        let id = body["operationId"]
            .as_str()
            .context("缺少操作编号")?
            .to_string();
        uuid::Uuid::parse_str(&id)?;
        ensure!(body["method"].is_string(), "操作方法无效");
        let digest = hex::encode(c::hash(serde_json::to_vec(&body)?));
        let existing = {
            self.db
                .read()
                .unwrap()
                .networks
                .iter()
                .find(|n| n.creation_operation == id)
                .cloned()
        };
        if let Some(n) = existing {
            ensure!(
                n.creation_digest == digest,
                "此操作编号已用于另一个创建或加入请求"
            );
            return Ok(
                json!({"ok":true,"api":1,"operation":{"id":id,"completed":true,"phase":"已完成","error":"","networkId":n.id},"status":self.status(&n.id)}),
            );
        }
        let mut operations = self.operations.lock().unwrap();
        if let Some(prior) = operations.get(&id) {
            ensure!(prior["_digest"] == digest, "操作编号已用于其他请求");
            return Ok(
                json!({"ok":true,"api":1,"operation":public_operation(prior),"status":self.status(body["networkId"].as_str().unwrap_or(""))}),
            );
        }
        if operations.len() >= 512 {
            let completed = operations
                .iter()
                .filter(|(_, v)| v["completed"] == true)
                .take(128)
                .map(|(k, _)| k.clone())
                .collect::<Vec<_>>();
            for k in completed {
                operations.remove(&k);
            }
        }
        ensure!(operations.len() < 512, "操作队列已满");
        let op = json!({"id":id,"completed":false,"phase":"处理操作","error":"","_digest":digest});
        operations.insert(id.clone(), op.clone());
        if let Err(e) = self.commands.try_send(Command {
            body: body.clone(),
            id: id.clone(),
        }) {
            operations.remove(&id);
            return Err(e.into());
        }
        drop(operations);
        Ok(
            json!({"ok":true,"api":1,"operation":public_operation(&op),"status":self.status(body["networkId"].as_str().unwrap_or(""))}),
        )
    }
    pub fn reply(&self, network: &str, operation: Option<&str>) -> Value {
        // Read completion before taking the state snapshot. Otherwise a long
        // command may finish between the two reads and return "completed"
        // together with its pre-change status (e.g. the interim direct code
        // before the coordinator code replaces it).
        let snapshot = operation.and_then(|id| self.operations.lock().unwrap().get(id).cloned());
        let mut result = json!({"ok":true,"api":1,"error":"","status":self.status(network)});
        if let Some(op) = snapshot {
            result["operation"] = public_operation(&op);
            if let Some(c) = op.get("configurationId") {
                result["configurationId"] = c.clone();
            }
        }
        result
    }
    pub fn status(&self, selected: &str) -> Value {
        let db = self.db.read().unwrap().clone();
        let mut rows = vec![];
        let mut aggregate = vec![];
        let mut sent = 0;
        let mut received = 0;
        let mut connected = 0;
        for n in &db.networks {
            let s = self.network_status(n, &db);
            sent += s["peers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["sentBytes"].as_u64().unwrap_or(0))
                .sum::<u64>();
            received += s["peers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["receivedBytes"].as_u64().unwrap_or(0))
                .sum::<u64>();
            if s["directPeers"].as_u64().unwrap_or(0) > 0 {
                connected += 1;
            }
            for p in s["peers"].as_array().unwrap() {
                aggregate.push(json!({"networkId":n.id,"deviceId":p["deviceId"],"role":if n.created_here{"从机"}else{"主机"},"peer":p,"connectedSince":p["connectedSince"]}));
            }
            rows.push(json!({"id":n.id,"name":n.name,"enabled":n.enabled,"configurationId":n.configuration_id,"appliedConfigurationRevision":db.configurations.iter().find(|c|c.id==n.configuration_id).map_or(0,|c|c.revision),"status":s}));
        }
        let selected = if selected.is_empty() {
            &db.selected_network_id
        } else {
            selected
        };
        let selection = rows.iter().find(|r| r["id"] == selected);
        let mut out = selection
            .map(|r| r["status"].clone())
            .unwrap_or_else(|| base_status(&db));
        let mut device = serde_json::to_value(Settings::default()).unwrap();
        if let (Some(target), Some(extra)) =
            (device.as_object_mut(), db.device_settings.as_object())
        {
            target.extend(extra.clone());
        }
        out["workspaceVersion"] = json!(1);
        out["selectedNetworkId"] = json!(selection.map_or("", |_| selected));
        out["networks"] = json!(rows);
        out["deviceSettings"] = device;
        out["networkDefaults"] = serde_json::to_value(Settings::default()).unwrap();
        out["deviceSettingsRevision"] = json!(revision(&db.device_settings));
        out["configurations"]=json!(db.configurations.iter().map(|c|json!({"id":c.id,"name":c.name,"revision":c.revision,"settings":c.settings,"networks":db.networks.iter().filter(|n|n.configuration_id==c.id).map(|n|{
            let applied=!n.enabled||self.engine.current(&n.id).is_some_and(|r|r.config.read().unwrap().settings==n.settings);
            json!({"id":n.id,"name":n.name,"enabled":n.enabled,"state":if applied{"applied"}else{"pending"},"error":if applied{""}else{"已保存，尚未成功应用；请重试"}})
        }).collect::<Vec<_>>()})).collect::<Vec<_>>());
        let network_count = db.networks.iter().filter(|n| n.profile.is_some()).count();
        out["aggregate"] = json!({"networkCount":network_count,"connectedNetworks":connected,"connectingNetworks":network_count-connected,"offlineNetworks":0,"totalDevices":aggregate.len(),"sentBytes":sent,"receivedBytes":received,"peers":aggregate});
        out["logs"] = json!([]);
        out["logEntries"] = json!(self.logs.rows());
        out["entryResolutions"] = self.entry_resolutions.read().unwrap().clone();
        out["update"] = self.update.read().unwrap().clone();
        out["localUpdate"] = crate::updates::status(self);
        out["desktop"] = self.desktop.read().unwrap().clone();
        out["coordinator"] = crate::coordinator::status();
        out["uuTakeover"] = crate::uu::status(self);
        out["nativeTransport"] = json!(
            self.engine
                .fake_mappings
                .read()
                .unwrap()
                .values()
                .map(|m| m.status())
                .collect::<Vec<_>>()
        );
        out
    }
    fn network_status(&self, n: &Network, db: &Database) -> Value {
        let mut out = base_status(db);
        let revoked = n.is_revoked();
        out["networkCreatedHere"] = json!(n.created_here);
        out["networkRevoked"] = json!(revoked);
        out["networkEstablishedAt"] = json!(n.created_at);
        out["networkEnabled"] = json!(n.enabled && !n.paused);
        out["networkPaused"] = json!(n.paused);
        out["settings"] = json!(n.settings);
        out["settingsRevision"] = json!(revision(&json!(n.settings)));
        out["pairing"] = if revoked { Value::Null } else { self.engine.pairing(&n.id) };
        out["receivedNetworkSettings"] = n.approved_settings.clone().unwrap_or(Value::Null);
        if revoked {
            out["state"] = json!("主机已撤回本机授权");
        }
        if let Some(p) = &n.profile {
            let running = self.engine.current(&n.id);
            let metrics = running
                .as_ref()
                .map(|r| r.metrics.read().unwrap().clone())
                .unwrap_or_default();
            let peer = runtime::remote_member(p);
            let live = metrics.connected && !n.paused && n.enabled && !metrics.peer_paused;
            out["networkId"] = json!(p.pair.network);
            out["virtualIp"] = json!(p.local_ip().unwrap().to_string());
            out["isOwner"] = json!(!p.owner_private.is_empty());
            out["canManageNetwork"] = out["isOwner"].clone();
            out["networkDirect"] = json!(p.pair.direct);
            out["totalPeers"] = json!(usize::from(peer.is_some()));
            out["directPeers"] = json!(usize::from(live));
            out["state"] = json!(if metrics.error.is_empty() {
                metrics.phase.clone()
            } else {
                metrics.error.clone()
            });
            out["pkarr"] = metrics.pkarr.clone();
            let phase = if n.paused || metrics.peer_paused {
                "Paused"
            } else if live {
                "Connected"
            } else {
                "WaitingPeer"
            };
            let connection = json!({"phase":phase,"detail":metrics.phase,"elapsedMs":if live{(unix_seconds()-metrics.since)*1000}else{0},"failureCode":metrics.error});
            out["connection"] = connection.clone();
            out["entryPreparation"] = json!({"state":if metrics.local_endpoints.is_empty(){"Preparing"}else{"Ready"},"detail":if metrics.local_endpoints.is_empty(){"等待入口候选"}else{"本机入口已准备"},"endpoint":metrics.local_endpoints.first().cloned().unwrap_or_default(),"receiverReady":running.is_some()});
            out["managedTraversal"] = metrics.managed.clone();
            out["adapter"] = json!({"ready":running.is_some(),"provider":metrics.adapter,"state":if running.is_some(){"Ready"}else{"Stopped"}});
            out["routeWarnings"] = json!(metrics.route_warnings);
            if let Some(peer) = peer {
                out["peers"] = json!([{"slot":peer.slot,"name":if n.peer_name.is_empty(){"对端"}else{&n.peer_name},"deviceId":peer.device,"virtualIp":runtime::member_ip(p,&peer).unwrap().to_string(),"connected":live,"degraded":false,"rttMs":metrics.rtt,"phase":phase,"connection":connection,"actualTransport":p.pair.mode,"traversalMethod":if n.settings.existing_only(){"ExistingEntry"}else{"Autonomous"},"sentBytes":metrics.sent,"receivedBytes":metrics.received,"droppedPackets":metrics.dropped,"connectedSince":metrics.since,"outerTarget":metrics.endpoint,"outerSource":"Rust","entryDirection":"Direct","quality":"Unknown","streamFlows":metrics.stream_flows}]);
            }
        }
        out
    }
    async fn actor(self: Arc<Self>, mut queue: mpsc::Receiver<Command>) {
        while let Some(command) =
            tokio::select! {_=self.engine.cancel.cancelled()=>None,c=queue.recv()=>c}
        {
            let background = matches!(
                command.body["method"].as_str(),
                Some(
                    "update-check"
                        | "check-update"
                        | "update-download"
                        | "update-install"
                        | "local-update"
                )
            ) || command.body["method"] == "network"
                && matches!(
                    command.body["network"]["action"].as_str(),
                    Some("resolve-entries" | "invite" | "invite-compact" | "pair-poll")
                );
            if background {
                let app = self.clone();
                self.engine.tracker.spawn(async move {
                    app.run_command(command, false).await;
                });
            } else {
                self.run_command(command, true).await;
            }
        }
    }
    async fn run_command(self: &Arc<Self>, command: Command, serialized: bool) {
        let _transaction = if serialized {
            Some(self.transaction.lock().await)
        } else {
            None
        };
        let selected = command.body["networkId"].as_str().unwrap_or("").to_string();
        let method = command.body["method"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let result = self.execute(&command.body).await;
        let (error, extra) = match result {
            Ok(extra) => (String::new(), extra),
            Err(e) => {
                self.log("ERROR", &format!("{method} 未完成：{e}"));
                (e.to_string(), Value::Null)
            }
        };
        let mut op = json!({"id":command.id,"completed":true,"phase":if error.is_empty(){"已完成"}else{"未完成"},"error":error,"networkId":selected});
        if let Some(c) = extra.get("configurationId") {
            op["configurationId"] = c.clone();
        }
        if !extra.is_null() {
            op["result"] = extra;
        }
        let mut operations = self.operations.lock().unwrap();
        op["_digest"] = operations
            .get(&command.id)
            .map(|o| o["_digest"].clone())
            .unwrap_or(Value::Null);
        operations.insert(command.id, op);
    }
    pub async fn boot(self: &Arc<Self>) {
        let settings = self.db.read().unwrap().device_settings.clone();
        if settings["coordinator"]["enabled"] == true {
            if let Err(error) =
                crate::coordinator::configure(self.clone(), settings["coordinator"].clone()).await
            {
                self.log("ERROR", &format!("本机协调服务启动失败：{error}"));
            }
        }
        let networks = self.db.read().unwrap().networks.clone();
        for n in networks {
            if n.enabled && n.profile.is_some() {
                if let Err(e) = self.engine.install(n.clone()).await {
                    self.log("ERROR", &format!("{} 启动失败：{e}", n.name));
                }
            }
        }
    }
    pub fn supervise(self: &Arc<Self>) {
        let app = self.clone();
        self.engine.tracker.spawn(async move{
            loop{
                tokio::select!{_=app.engine.cancel.cancelled()=>break,_=tokio::time::sleep(std::time::Duration::from_secs(10))=>{}}
                let ids=app.db.read().unwrap().networks.iter().filter(|n|n.enabled&&n.profile.is_some()&&app.engine.current(&n.id).is_none_or(|r|r.cancel.is_cancelled())).map(|n|n.id.clone()).collect::<Vec<_>>();
                for id in ids{
                    let Ok(_transaction)=app.transaction.try_lock()else{continue};
                    let network=app.db.read().unwrap().networks.iter().find(|n|n.id==id&&n.enabled&&n.profile.is_some()).cloned();
                    if let Some(network)=network{if let Err(error)=app.engine.install(network).await{app.log("WARN",&format!("网络启动将在后台重试：{error}"));}}
                }
                let Ok(_transaction)=app.transaction.try_lock()else{continue};
                let settings=app.db.read().unwrap().device_settings["coordinator"].clone();
                if settings["enabled"]==true&&crate::coordinator::status()["running"]!=true{if let Err(error)=crate::coordinator::configure(app.clone(),settings).await{app.log("WARN",&format!("协调监听将在后台重试：{error}"));}}
            }
        });
    }
    pub async fn events(self: Arc<Self>, mut events: mpsc::Receiver<Event>) {
        while let Some(event) =
            tokio::select! {_=self.engine.cancel.cancelled()=>None,e=events.recv()=>e}
        {
            let _transaction = self.transaction.lock().await;
            match event {
                Event::DepartureDelivered { id } => {
                    let mut next = self.db.read().unwrap().clone();
                    next.departures.retain(|d| d.id != id);
                    if let Err(e) = self.commit(next) {
                        self.log("WARN", &format!("退出回执保存暂未完成：{e}"));
                    }
                }
                Event::Joined {
                    id,
                    profile,
                    settings,
                    approved,
                    peer_name,
                    bootstrap,
                    reply,
                } => {
                    let result = (|| -> Result<Network> {
                        let mut next = self.db.read().unwrap().clone();
                        let n = next
                            .networks
                            .iter_mut()
                            .find(|n| n.id == id)
                            .context("申请已取消")?;
                        ensure!(n.is_join_request(), "加入申请已结束");
                        if next.configurations.iter().any(|c| c.id == n.configuration_id) {
                            n.configuration_id = conwu_core::id();
                        }
                        n.name = approved["NetworkName"].as_str().unwrap_or(&n.name).into();
                        if settings.discovery_mode == "pkarr" && !settings.existing_only() {
                            n.peer_pkarr = approved["PkarrSource"].as_str().unwrap_or("").into();
                        }
                        n.pkarr_seed = c::b64(pkarr::member_seed(&profile)?);
                        n.profile = Some(profile);
                        let mut settings = settings;
                        settings.listen_port = n.settings.listen_port;
                        settings.source_port = n.settings.source_port;
                        n.settings = settings.clone();
                        n.approved_settings = Some(approved);
                        n.peer_name = peer_name;
                        n.bootstrap = vec![bootstrap.to_string()];
                        n.enabled = true;
                        n.paused = false;
                        let n = n.clone();
                        next.configurations.push(Configuration {
                            id: n.configuration_id.clone(),
                            name: n.name.clone(),
                            revision: 1,
                            settings: n.settings.clone(),
                        });
                        self.commit(next)?;
                        Ok(n)
                    })();
                    match result {
                        Ok(n) => {
                            self.log("INFO", &format!("已加入网络 {}", n.name));
                            let app = self.clone();
                            self.engine.tracker.spawn(async move {
                                let _transaction = app.transaction.lock().await;
                                if app.engine.cancel.is_cancelled() {
                                    return;
                                }
                                let current = app
                                    .db
                                    .read()
                                    .unwrap()
                                    .networks
                                    .iter()
                                    .find(|network| network.id == n.id && network.enabled)
                                    .cloned();
                                let Some(n) = current else {
                                    return;
                                };
                                if let Err(e) = app.engine.install(n).await {
                                    tracing::error!("加入后的虚拟网卡启动失败：{e}");
                                }
                            });
                            let _ = reply.send(Ok(()));
                        }
                        Err(e) => {
                            let _ = reply.send(Err(e));
                        }
                    }
                }
                Event::GuestState { id, state } => {
                    let name = self.db.read().unwrap().networks.iter()
                        .find(|n| n.id == id && n.is_join_request())
                        .map(|n| n.name.clone());
                    let Some(name) = name else { continue };
                    if state["active"] == false {
                        if let Some(error) = state["error"].as_str().filter(|s| !s.is_empty()) {
                            self.log("WARN", &format!("申请加入 {name} 失败：{error}"));
                        }
                    }
                    self.engine.guest_states.write().unwrap().insert(id, state);
                }
                Event::Discovery {
                    id,
                    sequence,
                    reply,
                } => {
                    let result = (|| -> Result<()> {
                        let mut next = self.db.read().unwrap().clone();
                        let n = next
                            .networks
                            .iter_mut()
                            .find(|n| n.id == id)
                            .context("网络已移除")?;
                        ensure!(sequence > n.pkarr_sequence, "发现序号回退");
                        n.pkarr_sequence = sequence;
                        self.commit(next)
                    })();
                    let _ = reply.send(result);
                }
                Event::Snapshot { id, snapshot } => {
                    if let Err(e) = self.accept_snapshot(&id, snapshot).await {
                        tracing::debug!("同步拒绝：{e}");
                    }
                }
                Event::Departure {
                    network,
                    notice,
                    reply,
                } => {
                    let result = self.accept_departure(&network, notice).await;
                    let _ = reply.send(result);
                }
                Event::Log { level, text } => self.log(&level, &text),
            }
        }
    }
    async fn execute(self: &Arc<Self>, body: &Value) -> Result<Value> {
        let id = body["networkId"].as_str().unwrap_or("");
        match body["method"].as_str().unwrap_or("") {
            "cancel" => Ok(json!({"cancelled":false,"message":"后台查询已完成或已由当前请求替代"})),
            #[cfg(feature = "lab-api")]
            "lab-inject" => {
                ensure!(self.engine.memory, "实验接口仅允许内存网卡");
                let r = self.engine.current(id).context("网络未启动")?;
                let packet = c::unb64(body["packet"].as_str().context("缺少实验包")?)?;
                r.memory.as_ref().context("不是实验网卡")?.inject(packet)?;
                Ok(Value::Null)
            }
            #[cfg(feature = "lab-api")]
            "lab-read" => {
                ensure!(self.engine.memory, "实验接口仅允许内存网卡");
                let r = self.engine.current(id).context("网络未启动")?;
                Ok(
                    json!({"packets":r.memory.as_ref().context("不是实验网卡")?.drain().into_iter().map(c::b64).collect::<Vec<_>>()}),
                )
            }
            "configuration" => self.configuration(id, &body["configuration"]).await,
            "coordinator-maintenance" => {
                ensure!(
                    crate::coordinator::status()["running"] != true,
                    "请先关闭本机协调角色再备份或恢复"
                );
                let input = &body["maintenance"];
                let path = std::path::Path::new(input["path"].as_str().context("缺少备份路径")?);
                match input["action"].as_str() {
                    Some("backup") => crate::coordination_store::backup(&self.store, path, true),
                    Some("restore") => crate::coordination_store::restore(
                        &self.store,
                        path,
                        input["confirmRollback"] == true,
                    ),
                    _ => anyhow::bail!("未知协调维护操作"),
                }
            }
            "network" => {
                let mut action = body["network"].clone();
                ensure!(action.is_object(), "网络操作无效");
                action["_operationId"] = body["operationId"].clone();
                action["_digest"] = json!(hex::encode(c::hash(serde_json::to_vec(body)?)));
                self.network(id, &action).await
            }
            "save-settings" => {
                let action = &body["settingsBatch"]["device"];
                self.save_device(action).await?;
                Ok(Value::Null)
            }
            "patch" => {
                let mut next = self.db.read().unwrap().clone();
                let patch = &body["patch"];
                if let Some(name) = patch["deviceName"].as_str() {
                    c::check_name(name)?;
                    ensure!(
                        patch["expectedDeviceName"]
                            .as_str()
                            .is_none_or(|s| s == next.device_name),
                        "设备名已被修改，请刷新"
                    );
                    next.device_name = name.into();
                }
                if let Some(level) = patch["logLevel"].as_str() {
                    ensure!(
                        ["info", "warn", "error", "debug", "off"].contains(&level),
                        "日志等级无效"
                    );
                    next.log_level = level.into();
                }
                self.commit(next)?;
                Ok(Value::Null)
            }
            "start" => self.network(id, &json!({"action":"reconnect"})).await,
            "check-update" | "update-check" => {
                *self.update.write().unwrap() =
                    crate::updates::check(body["update"]["source"].as_str().unwrap_or("github"))
                        .await?;
                Ok(Value::Null)
            }
            "local-update" | "update-download" | "update-install" => {
                let mut action = body["localUpdate"].clone();
                if action.is_null() {
                    action = json!({});
                }
                if body["method"] == "update-install" {
                    action["action"] = json!("install");
                }
                crate::updates::command(self, action).await
            }
            "update-dismiss" => crate::updates::dismiss(self, body["localUpdate"]["receiptId"].as_str().unwrap_or("")),
            "uu-takeover" => crate::uu::configure(self, body["uuTakeover"].clone()).await,
            "register-service" => {
                crate::platform::install(self).await?;
                Ok(Value::Null)
            }
            _ => anyhow::bail!("未知后台操作"),
        }
    }
    fn find(&self, id: &str) -> Result<Network> {
        self.db
            .read()
            .unwrap()
            .networks
            .iter()
            .find(|n| n.id == id)
            .cloned()
            .context("请选择目标网络")
    }
    async fn save_device(self: &Arc<Self>, action: &Value) -> Result<()> {
        let mut next = self.db.read().unwrap().clone();
        if let Some(expected) = action
            .get("expectedDeviceRevision")
            .or_else(|| action.get("expectedRevision"))
            .unwrap_or(&Value::Null)
            .as_str()
            .filter(|s| !s.is_empty())
        {
            ensure!(
                expected == revision(&next.device_settings),
                "设备设置已改变，请刷新"
            );
        }
        if let Some(patch) = action.get("patch") {
            if let Some(name) = patch["deviceName"].as_str() {
                ensure!(
                    patch["expectedDeviceName"]
                        .as_str()
                        .is_none_or(|v| v == next.device_name),
                    "设备名已改变，请刷新后保存"
                );
                c::check_name(name)?;
                next.device_name = name.into();
            }
            if let Some(level) = patch["logLevel"].as_str() {
                ensure!(
                    patch["expectedLogLevel"]
                        .as_str()
                        .is_none_or(|v| v == next.log_level),
                    "日志等级已改变，请刷新后保存"
                );
                ensure!(
                    ["info", "warn", "error", "debug", "off"].contains(&level),
                    "日志等级无效"
                );
                next.log_level = level.into();
            }
        }
        if let Some(coordinator) = action["settings"].get("coordinator") {
            crate::coordinator::validate(coordinator)?;
            next.device_settings["coordinator"] = coordinator.clone();
        }
        if let Some(auto) = action["autoStart"].as_bool() {
            ensure!(
                action["expectedAutoStart"].as_bool().is_none_or(
                    |v| v == next.device_settings["autoStart"].as_bool().unwrap_or(false)
                ),
                "开机启动设置已改变，请刷新"
            );
            // Re-saving Windows preferences also repairs a stale tray Run entry.
            if cfg!(windows) || auto != next.device_settings["autoStart"].as_bool().unwrap_or(false) {
                crate::platform::configure_startup(self, auto).await?;
            }
            next.device_settings["autoStart"] = json!(auto);
        }
        self.commit(next.clone())?;
        crate::coordinator::configure(self.clone(), next.device_settings["coordinator"].clone())
            .await?;
        Ok(())
    }
    async fn configuration(self: &Arc<Self>, network_id: &str, action: &Value) -> Result<Value> {
        let mut next = self.db.read().unwrap().clone();
        let id = action["id"].as_str().unwrap_or("");
        let name = action["name"].as_str().unwrap_or("网络设置");
        c::check_name(name)?;
        let index = next.configurations.iter().position(|c| c.id == id);
        if let Some(i) = index {
            ensure!(
                action["expectedRevision"].as_u64() == Some(next.configurations[i].revision),
                "此网络设置已变化，请刷新"
            );
        }
        let mut changed = vec![];
        let kind = action["action"].as_str().unwrap_or("");
        let out = match kind {
            "save" | "copy" => {
                let settings: Settings = if kind == "copy" {
                    let original = &next.configurations[index.context("找不到要复制的设置")?];
                    match action.get("settings") {
                        Some(value) => serde_json::from_value(value.clone())?,
                        None => original.settings.clone(),
                    }
                } else {
                    serde_json::from_value(action["settings"].clone())?
                };
                settings.validate()?;
                let id = if let Some(i) = index.filter(|_| kind == "save") {
                    ensure!(
                        next.networks
                            .iter()
                            .filter(|n| n.configuration_id == id)
                            .count()
                            <= 1,
                        "请为当前网络复制独立设置"
                    );
                    let c = &mut next.configurations[i];
                    c.name = name.into();
                    c.settings = settings.clone();
                    c.revision += 1;
                    c.id.clone()
                } else {
                    let id = conwu_core::id();
                    next.configurations.push(Configuration {
                        id: id.clone(),
                        name: name.into(),
                        revision: 1,
                        settings: settings.clone(),
                    });
                    id
                };
                for n in next
                    .networks
                    .iter_mut()
                    .filter(|n| n.configuration_id == id)
                {
                    if let Some(p) = &n.profile {
                        ensure!(
                            p.pair.mode == settings.mode()?,
                            "已有网络的身份固定连接协议，请新建网络切换协议"
                        );
                    }
                    n.settings = settings.clone();
                    changed.push(n.clone());
                }
                id
            }
            "assign" => {
                let c = next
                    .configurations
                    .get(index.context("设置不存在")?)
                    .unwrap()
                    .clone();
                ensure!(
                    !next
                        .networks
                        .iter()
                        .any(|n| n.id != network_id && n.configuration_id == id),
                    "每条网络必须使用独立设置"
                );
                let n = next
                    .networks
                    .iter_mut()
                    .find(|n| n.id == network_id)
                    .context("网络不存在")?;
                if let Some(p) = &n.profile {
                    ensure!(p.pair.mode == c.settings.mode()?, "协议与网络身份不符");
                }
                n.configuration_id = id.into();
                n.settings = c.settings;
                changed.push(n.clone());
                id.into()
            }
            "delete" => {
                let i = index.context("设置不存在")?;
                ensure!(
                    !next.networks.iter().any(|n| n.configuration_id == id),
                    "设置仍被网络使用"
                );
                next.configurations.remove(i);
                String::new()
            }
            "apply" => {
                index.context("设置不存在")?;
                changed = next
                    .networks
                    .iter()
                    .filter(|n| n.configuration_id == id)
                    .cloned()
                    .collect();
                id.into()
            }
            _ => anyhow::bail!("未知设置操作"),
        };
        self.commit(next)?;
        for n in changed {
            if n.enabled {
                self.engine.install(n).await?;
            }
        }
        Ok(json!({"configurationId":out}))
    }
    async fn network(self: &Arc<Self>, id: &str, action: &Value) -> Result<Value> {
        let kind = action["action"].as_str().context("缺少网络操作")?;
        if matches!(kind, "create-direct" | "create") {
            let mut next = self.db.read().unwrap().clone();
            ensure!(next.networks.len() < 32, "最多支持32条实验网络");
            let name = action["name"].as_str().unwrap_or("新网络");
            c::check_name(name)?;
            let cid = action["configurationId"]
                .as_str()
                .context("缺少独立网络设置")?;
            let mut settings = next
                .configurations
                .iter()
                .find(|c| c.id == cid)
                .context("请先保存网络设置")?
                .settings
                .clone();
            ensure!(
                !next.networks.iter().any(|n| n.configuration_id == cid),
                "请为新网络保存独立设置"
            );
            settings.validate()?;
            let requested = action["requestedVirtualIp"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let mut attempts = 0;
            let mut profile = loop {
                let candidate = Profile::create_for_device(
                    settings.mode()?,
                    &next.node_private,
                    requested.clone(),
                )?;
                let subnet = candidate.local_ip()?.octets();
                let conflict = next
                    .networks
                    .iter()
                    .filter_map(|n| n.profile.as_ref())
                    .any(|p| p.local_ip().is_ok_and(|ip| ip.octets()[..3] == subnet[..3]));
                if !conflict {
                    break candidate;
                }
                attempts += 1;
                ensure!(
                    requested.is_none() && attempts < 128,
                    "虚拟网段已被另一条网络占用，请选择不同网段"
                );
            };
            if profile.pair.mode == "https" {
                profile.pair.transport_key_pin = Some(self.engine.identity.pin.clone());
            }
            // New networks get their own listener. Legacy compatible listeners
            // can still be shared, but implicit sharing makes changes ambiguous.
            while next.networks.iter().any(|n| {
                n.settings.listen_port == settings.listen_port
                    || n.settings.source_port == settings.listen_port
            }) {
                settings.listen_port = settings
                    .listen_port
                    .checked_add(2)
                    .context("没有空闲监听端口")?;
            }
            while settings.source_port == settings.listen_port
                || next.networks.iter().any(|n| {
                    n.settings.source_port == settings.source_port
                        || n.settings.listen_port == settings.source_port
                })
            {
                settings.source_port = settings
                    .source_port
                    .checked_add(2)
                    .context("没有空闲的本机源端口")?;
            }
            if let Some(configuration) = next
                .configurations
                .iter_mut()
                .find(|configuration| configuration.id == cid)
            {
                if configuration.settings != settings {
                    configuration.settings = settings.clone();
                    configuration.revision += 1;
                }
            }
            let n = Network {
                legacy_adapter: None,
                creation_operation: action["_operationId"].as_str().unwrap_or("").into(),
                creation_digest: action["_digest"].as_str().unwrap_or("").into(),
                id: profile.pair.network.clone(),
                name: name.into(),
                configuration_id: cid.into(),
                settings,
                profile: Some(profile),
                enabled: true,
                paused: false,
                created_here: true,
                created_at: unix_seconds(),
                approved_settings: None,
                peer_name: String::new(),
                pkarr_seed: c::b64(c::random::<32>()),
                pkarr_sequence: 0,
                peer_pkarr: String::new(),
                bootstrap: vec![],
            };
            let new_id = n.id.clone();
            next.selected_network_id = new_id.clone();
            next.networks.push(n.clone());
            validate_bindings(&next)?;
            self.engine.install(n).await?;
            if let Err(error) = self.commit(next) {
                if let Err(cleanup) = self.engine.remove(&new_id).await {
                    self.log("WARN", &format!("未保存的网络资源仍在释放：{cleanup}"));
                }
                return Err(error);
            }
            self.log("INFO", &format!("已创建网络 {name}"));
            return Ok(Value::Null);
        }
        if matches!(kind, "join-compact" | "join-entry") {
            let codes = if kind == "join-entry" {
                let mode = action["mode"].as_str().unwrap_or("faketcp");
                ensure!(
                    conwu_core::code::valid_mode(mode) && mode != "udp",
                    "请选择当前六种协议"
                );
                let entry = crate::model::Entry {
                    peer_slot: 0,
                    source: action["entry"].as_str().context("请填写目标入口")?.into(),
                };
                let endpoints = discovery::resolve(
                    &[entry],
                    mode,
                    &self.engine.pkarr,
                    &Settings::default().pkarr_gateways,
                )
                .await;
                ensure!(!endpoints.is_empty(), "没有从目标入口取得可用地址");
                endpoints
                    .into_iter()
                    .take(8)
                    .map(|endpoint| DirectCode {
                        endpoint,
                        mode: mode.into(),
                        room: conwu_core::pairing::ENTRY_LOCATOR.into(),
                        punch: false,
                        coordinator: false,
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![DirectCode::import(
                    action["code"].as_str().context("请填写直连码")?,
                )?]
            };
            let code = &codes[0];
            ensure!(
                code.mode != "udp",
                "此版本不再接入直接 UDP 网络，请使用当前六种协议的直连码"
            );
            let mut next = self.db.read().unwrap().clone();
            ensure!(next.networks.len() < 32, "网络数量超过限制");
            let id = conwu_core::id();
            let cid = conwu_core::id();
            let mut settings = Settings::default();
            settings.path_selection = format!("{}-only", code.mode);
            let mut reserved = next
                .networks
                .iter()
                .flat_map(|n| [n.settings.listen_port, n.settings.source_port])
                .collect::<Vec<_>>();
            settings.listen_port = free_port(&reserved)?;
            reserved.push(settings.listen_port);
            settings.source_port = free_port(&reserved)?;
            let requested = action["requestedVirtualIp"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let n = Network {
                legacy_adapter: None,
                creation_operation: action["_operationId"].as_str().unwrap_or("").into(),
                creation_digest: action["_digest"].as_str().unwrap_or("").into(),
                id: id.clone(),
                name: action["name"].as_str().unwrap_or("申请中的网络").into(),
                configuration_id: cid,
                settings,
                profile: None,
                enabled: true,
                paused: false,
                created_here: false,
                created_at: unix_seconds(),
                approved_settings: None,
                peer_name: String::new(),
                pkarr_seed: String::new(),
                pkarr_sequence: 0,
                peer_pkarr: String::new(),
                bootstrap: vec![code.endpoint.to_string()],
            };
            next.networks.push(n);
            next.selected_network_id = id.clone();
            let name = next.device_name.clone();
            let node = next.node_private.clone();
            let retained = next.rejoin_credentials.last().cloned();
            self.commit(next)?;
            self.engine
                .start_guest(id, codes, name, node, requested, retained);
            return Ok(Value::Null);
        }
        if kind == "resolve-entries" {
            let settings: Settings = serde_json::from_value(action["settings"].clone())?;
            settings.validate()?;
            let rows = discovery::detailed(
                &settings.existing_entries,
                settings.mode()?,
                &self.engine.pkarr,
                &settings.pkarr_gateways,
            )
            .await;
            self.log(
                "INFO",
                &format!(
                    "入口解析完成，{} / {} 个来源成功",
                    rows.iter().filter(|r| r["error"] == "").count(),
                    rows.len()
                ),
            );
            *self.entry_resolutions.write().unwrap() = json!(rows);
            return Ok(Value::Null);
        }
        let n = self.find(id)?;
        if let Some(expected) = action["expectedNetwork"].as_str().filter(|s| !s.is_empty()) {
            ensure!(
                n.profile
                    .as_ref()
                    .is_some_and(|p| p.pair.network == expected),
                "操作目标网络已变化"
            );
        }
        match kind {
            "rename-network" => {
                let name = action["name"].as_str().context("缺少网络名称")?;
                c::check_name(name)?;
                let mut next = self.db.read().unwrap().clone();
                let n = next.networks.iter_mut().find(|n| n.id == id).unwrap();
                n.name = name.into();
                let updated = n.clone();
                self.commit(next)?;
                if self.engine.current(id).is_some() {
                    self.engine.install(updated).await?;
                }
            }
            "invite-compact" | "invite" => {
                let local = n
                    .settings
                    .existing_entries
                    .iter()
                    .filter(|e| e.peer_slot == 0)
                    .cloned()
                    .collect::<Vec<_>>();
                let mut endpoints = if local.is_empty() {
                    self.engine
                        .current(id)
                        .map(|r| {
                            r.metrics
                                .read()
                                .unwrap()
                                .local_endpoints
                                .iter()
                                .filter_map(|s| s.parse().ok())
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    discovery::resolve(
                        &local,
                        n.settings.mode()?,
                        &self.engine.pkarr,
                        &n.settings.pkarr_gateways,
                    )
                    .await
                };
                if !n.settings.manual_endpoint.is_empty() {
                    endpoints = discovery::endpoint(&n.settings.manual_endpoint).await?;
                }
                let family = action["entryFamily"].as_str().unwrap_or("");
                ensure!(matches!(family, "" | "ipv4" | "ipv6"), "直连码地址族无效");
                endpoints.retain(|e| {
                    conwu_core::code::valid_endpoint(e)
                        && (e.is_ipv4()
                            || conwu_core::code::stream_mode(n.settings.mode().unwrap()))
                        && (family.is_empty()
                            || if family == "ipv4" {
                                e.is_ipv4()
                            } else {
                                e.is_ipv6()
                            })
                });
                endpoints.sort_by_key(|e| e.is_ipv6());
                let candidate = endpoints
                    .first()
                    .copied()
                    .context("尚未取得所选地址族的本机入口，请等待打洞或检查入口订阅")?;
                let (name, node) = {
                    let db = self.db.read().unwrap();
                    (db.device_name.clone(), db.node_private.clone())
                };
                self.engine.create_code(id, candidate, &name, &node)?;
                if !n.settings.existing_only()
                    && n.settings.discovery_mode == "coordinator"
                    && !n.settings.service.is_empty()
                {
                    self.engine.assist_code(id, candidate).await?;
                }
            }
            "pair-poll" => {}
            "approve" => {
                let updated = {
                    let mut next = self.db.read().unwrap().clone();
                    let history = next.rejoin_history.get(id).cloned().unwrap_or_default();
                    let n = next.networks.iter_mut().find(|n| n.id == id).unwrap();
                    let profile = n.profile.as_mut().context("网络身份缺失")?;
                    let mut rooms = self.engine.rooms.lock().unwrap();
                    let (host, _) = rooms.get_mut(id).context("配对会话已结束")?;
                    ensure!(
                        action["candidate"].as_str() == Some(&host.state.candidate),
                        "申请已变化"
                    );
                    let mut trial = host.clone();
                    trial.rejoin_history = history;
                    let mut approved = n.settings.approved(
                        profile,
                        &n.name,
                        &n.settings
                            .existing_entries
                            .iter()
                            .filter(|e| e.peer_slot == 0)
                            .cloned()
                            .collect::<Vec<_>>(),
                    );
                    let source = pkarr::source(c::unb64(&n.pkarr_seed)?.as_slice().try_into()?);
                    approved["PkarrSource"] = json!(source);
                    let entries =
                        if n.settings.discovery_mode == "pkarr" && !n.settings.existing_only() {
                            vec![json!({"PeerSlot":profile.member.slot,"Source":source})]
                        } else {
                            vec![]
                        };
                    trial.approve(
                        profile,
                        action["verification"].as_str().unwrap_or(""),
                        &entries,
                        Some(approved),
                    )?;
                    n.peer_name = host.state.guest_name.clone();
                    let updated = n.clone();
                    next.rejoin_history
                        .insert(id.into(), trial.rejoin_history.clone());
                    self.store.save(&next)?;
                    *self.db.write().unwrap() = next;
                    *host = trial;
                    updated
                };
                self.engine.install(updated).await?;
                self.log("INFO", "已批准对端加入，正在交付网络配置");
            }
            "reject" => {
                let mut rooms = self.engine.rooms.lock().unwrap();
                let host = &mut rooms.get_mut(id).context("没有待处理申请")?.0;
                ensure!(
                    action["candidate"].as_str() == Some(&host.state.candidate)
                        && !host.state.candidate.is_empty()
                        && host.ticket.expires > unix_seconds()
                        && host.state.outcome.is_empty(),
                    "申请已变化或已处理"
                );
                host.reject()?;
            }
            "pair-cancel" => {
                if n.is_join_request() {
                    let mut next = self.db.read().unwrap().clone();
                    next.remove_network(&n);
                    self.commit(next)?;
                }
                self.engine.cancel_guest(id);
                self.engine.rooms.lock().unwrap().remove(id);
            }
            "disconnect" | "pause-network" | "reconnect" => {
                ensure!(n.profile.is_some(), "当前记录没有可用的网络授权");
                let mut next = self.db.read().unwrap().clone();
                let n = next.networks.iter_mut().find(|n| n.id == id).unwrap();
                n.paused = kind != "reconnect";
                n.enabled = true;
                let n = n.clone();
                self.commit(next)?;
                self.engine.install(n).await?;
            }
            "leave" | "delete-network" | "forget-network" | "remove-network" => {
                ensure!(action["confirmReplace"] == true, "请确认退出并删除网络");
                let retired = if kind == "delete-network" {
                    let mut retired = n.profile.clone().context("网络身份缺失")?;
                    ensure!(!retired.owner_private.is_empty(), "仅主机能删除整个网络");
                    let peers = retired
                        .directory
                        .as_ref()
                        .unwrap()
                        .members
                        .iter()
                        .filter(|m| m.slot != retired.member.slot)
                        .map(|m| m.slot)
                        .collect::<Vec<_>>();
                    for slot in peers {
                        retired.remove_peer(slot)?;
                    }
                    Some(retired)
                } else {
                    None
                };
                if kind == "leave" {
                    ensure!(
                        n.profile
                            .as_ref()
                            .is_none_or(|p| p.owner_private.is_empty()),
                        "主机请使用删除网络，或断开连接以保留网络"
                    );
                }
                let notice = if kind == "leave" {
                    // An unapproved request has no member identity and cannot
                    // sign a departure. Removing it only cancels local pairing.
                    n.profile.as_ref().map(conwu_core::departure::Notice::create).transpose()?
                } else {
                    None
                };
                let mut next = self.db.read().unwrap().clone();
                if let Some(notice) = notice {
                    ensure!(
                        next.departures.len() < 64,
                        "退出通知队列已满，请先恢复与主机的连接"
                    );
                    let p = n.profile.as_ref().unwrap();
                    if let Some(credential) = conwu_core::rejoin::Credential::retain(p) {
                        next.rejoin_credentials
                            .retain(|c| c.network != credential.network);
                        next.rejoin_credentials.push(credential);
                        if next.rejoin_credentials.len() > 32 {
                            next.rejoin_credentials.remove(0);
                        }
                    }
                    let mut entries = n
                        .settings
                        .existing_entries
                        .iter()
                        .filter(|e| e.peer_slot < 0)
                        .cloned()
                        .collect::<Vec<_>>();
                    if !n.settings.existing_only() && !n.peer_pkarr.is_empty() {
                        entries.push(crate::model::Entry {
                            peer_slot: -1,
                            source: n.peer_pkarr.clone(),
                        });
                    }
                    next.departures.push(crate::model::PendingDeparture {
                        id: conwu_core::id(),
                        notice,
                        owner_key: p.owner_key.clone(),
                        mode: p.pair.mode.clone(),
                        pin: p.pair.transport_key_pin.clone().unwrap_or_default(),
                        entries,
                        bootstrap: n.bootstrap.clone(),
                        pkarr_gateways: n.settings.pkarr_gateways.clone(),
                    });
                }
                next.remove_network(&n);
                self.commit(next)?;
                if let Some(retired) = retired {
                    let directory = retired.directory.as_ref().unwrap();
                    if let Err(error) = self.engine.notify_directory(id, directory.clone()).await {
                        self.log("WARN", &format!("未能通知对机网络已移除：{error}"));
                    }
                    if n.settings.discovery_mode == "coordinator" && !n.settings.service.is_empty() {
                        let publish = async {
                            crate::transport::pinned_http(&n.settings.certificate_pin)?
                                .put(url::Url::parse(&n.settings.service)?.join(&format!(
                                    "v3/mesh/{}/directory", retired.pair.network
                                ))?)
                                .bearer_auth(hex::encode_upper(retired.pair.key("discovery-auth")))
                                .json(directory)
                                .send()
                                .await?
                                .error_for_status()?;
                            Ok::<_, anyhow::Error>(())
                        };
                        if !matches!(
                            tokio::time::timeout(std::time::Duration::from_secs(1), publish).await,
                            Ok(Ok(()))
                        ) {
                            self.log("WARN", "发现服务尚未确认网络清理，本机已删除网络");
                        }
                    }
                }
                self.engine.remove(id).await?;
                self.log("INFO", &format!("已移除网络 {}", n.name));
            }
            "revoke" => {
                let slot = u8::try_from(action["peerSlot"].as_u64().context("请选择成员")?)
                    .context("成员槽位无效")?;
                let mut next = self.db.read().unwrap().clone();
                let n = next.networks.iter_mut().find(|n| n.id == id).unwrap();
                let profile = n.profile.as_mut().context("身份不存在")?;
                profile.remove_peer(slot)?;
                let directory = profile.directory.clone().context("成员目录缺失")?;
                n.peer_pkarr.clear();
                n.peer_name.clear();
                n.settings.existing_entries.retain(|e| e.peer_slot >= 0);
                let n = n.clone();
                if let Some(history) = next.rejoin_history.get_mut(id) {
                    history.retain(|h| h.current_slot != slot);
                }
                self.commit(next)?;
                if let Err(error) = self.engine.notify_directory(id, directory).await {
                    self.log("WARN", &format!("未能通知对机授权已撤回：{error}"));
                }
                self.engine.install(n).await?;
            }
            "refresh-pkarr" => {
                self.engine.refresh_discovery(id)?;
            }
            _ => anyhow::bail!("此网络操作未迁移：{kind}"),
        }
        Ok(Value::Null)
    }
    async fn accept_snapshot(
        self: &Arc<Self>,
        id: &str,
        snapshot: conwu_core::metadata::Snapshot,
    ) -> Result<()> {
        let mut next = self.db.read().unwrap().clone();
        let n = next
            .networks
            .iter_mut()
            .find(|n| n.id == id)
            .context("网络已移除")?;
        let profile = n.profile.as_ref().context("身份缺失")?;
        let directory = profile.directory.as_ref().context("目录缺失")?;
        conwu_core::metadata::successor(&snapshot.directory, directory)?;
        if !snapshot.directory.members.contains(&profile.member) {
            n.profile = None;
            n.enabled = false;
            self.commit(next)?;
            self.engine.remove(id).await?;
            self.log("WARN", "主机已撤回本机授权，停止该网络");
            return Ok(());
        }
        let mut changed = snapshot.directory.revision > directory.revision;
        let mut paused = None;
        for envelope in snapshot.nodes.into_iter().take(8) {
            let Some(member) = snapshot
                .directory
                .members
                .iter()
                .find(|m| m.slot == envelope.slot && m.slot != profile.member.slot)
            else {
                continue;
            };
            let announcement = envelope.open(profile, member)?;
            let prior = n
                .settings
                .extra
                .get("peerMetadataRevision")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if envelope.revision <= prior {
                continue;
            }
            if let Some(source) = announcement.pkarr_source {
                pkarr::decode_key(
                    source
                        .strip_prefix("pkarr://")
                        .context("对机 PKARR 来源无效")?,
                )?;
                ensure!(
                    n.peer_pkarr.is_empty() || n.peer_pkarr == source,
                    "对机发现身份改变，需要重新配对"
                );
                if !n.settings.existing_only() {
                    n.peer_pkarr = source;
                }
            }
            if n.settings.discovery_mode == "coordinator" && !n.settings.existing_only() {
                let mut endpoints = announcement.existing_endpoints.unwrap_or_default();
                if !announcement.endpoint.is_empty() && !endpoints.contains(&announcement.endpoint)
                {
                    endpoints.push(announcement.endpoint);
                }
                n.settings
                    .extra
                    .insert("coordinatorEndpoints".into(), json!(endpoints));
            }
            n.peer_name = announcement.name;
            paused = Some(announcement.connection_paused);
            n.settings
                .extra
                .insert("peerMetadataRevision".into(), json!(envelope.revision));
            changed = true;
        }
        if changed {
            n.profile.as_mut().unwrap().directory = Some(snapshot.directory);
            let n = n.clone();
            self.commit(next)?;
            self.engine.install(n).await?;
            if let (Some(r), Some(paused)) = (self.engine.current(id), paused) {
                r.metrics.write().unwrap().peer_paused = paused;
            }
        }
        Ok(())
    }
    async fn accept_departure(self: &Arc<Self>, network: &str, notice: Value) -> Result<Value> {
        let notice: conwu_core::departure::Notice = serde_json::from_value(notice)?;
        let mut next = self.db.read().unwrap().clone();
        let n = next
            .networks
            .iter_mut()
            .find(|n| {
                n.profile
                    .as_ref()
                    .is_some_and(|p| p.pair.network == network && !p.owner_private.is_empty())
            })
            .context("主机网络不存在")?;
        let p = n.profile.as_mut().unwrap();
        notice.validate(&p.owner_key)?;
        ensure!(notice.network == network, "退出网络不符");
        if let Some(current) = p
            .directory
            .as_ref()
            .unwrap()
            .members
            .iter()
            .find(|m| m.slot == notice.member.slot)
        {
            ensure!(*current == notice.member, "成员身份已改变");
            p.remove_peer(notice.member.slot)?;
        }
        let receipt = conwu_core::departure::Receipt::create(p, &notice)?;
        n.peer_name.clear();
        n.peer_pkarr.clear();
        n.settings.existing_entries.retain(|e| e.peer_slot >= 0);
        let n = n.clone();
        self.commit(next)?;
        self.engine.install(n).await?;
        Ok(json!(receipt))
    }
    pub fn start_departures(self: &Arc<Self>) {
        let app = self.clone();
        self.engine.tracker.spawn(async move{loop{let pending=app.db.read().unwrap().departures.clone();for notice in pending{if app.engine.cancel.is_cancelled(){return}let delivered=tokio::select!{_=app.engine.cancel.cancelled()=>return,r=app.send_departure(&notice)=>r};if delivered.is_ok(){let _=app.engine.events.send(Event::DepartureDelivered{id:notice.id}).await;}}tokio::select!{_=app.engine.cancel.cancelled()=>break,_=tokio::time::sleep(std::time::Duration::from_secs(2))=>{}}}});
    }
    async fn send_departure(&self, n: &crate::model::PendingDeparture) -> Result<()> {
        let targets = if n.entries.is_empty() {
            n.bootstrap.iter().filter_map(|s| s.parse().ok()).collect()
        } else {
            discovery::resolve(&n.entries, &n.mode, &self.engine.pkarr, &n.pkarr_gateways).await
        };
        for endpoint in targets {
            let token = self.engine.cancel.child_token();
            let result = if conwu_core::code::stream_mode(&n.mode) {
                crate::transport::connect(&n.mode, endpoint, &n.pin, false, &token).await
            } else {
                crate::raw::connect_ref(&self.engine, &n.mode, endpoint, 0, &token).await
            };
            if let Ok(mut pipe) = result {
                let request = conwu_core::pairing::Request {
                    id: conwu_core::id(),
                    method: "member-leave".into(),
                    target_network: n.notice.network.clone(),
                    departure: Some(json!(n.notice)),
                    ..Default::default()
                };
                pipe.tx.send(conwu_core::pairing::encode(&request)?).await?;
                if let Ok(Some(response)) =
                    tokio::time::timeout(std::time::Duration::from_secs(3), pipe.rx.recv()).await
                {
                    let v: Value = conwu_core::pairing::decode(&response)?;
                    let receipt: conwu_core::departure::Receipt =
                        serde_json::from_value(v["Departure"].clone())?;
                    receipt.validate(&n.owner_key, &n.notice)?;
                    return Ok(());
                }
            }
        }
        anyhow::bail!("主机暂未确认退出，将保留签名通知并重试")
    }
}
fn base_status(db: &Database) -> Value {
    json!({"version":VERSION,"deviceName":db.device_name,"virtualIp":"","state":"等待创建或加入网络","serviceReady":true,"networkEnabled":false,"directPeers":0,"totalPeers":0,"peers":[],"logLevel":db.log_level,"settingsPatchVersion":1,"networkId":"","isOwner":false,"canManageNetwork":false,"networkDirect":true,"networkPaused":false,"settings":Settings::default(),"logs":[],"logEntries":[],"platform":std::env::consts::OS,"personalFeatureEdition":true,"entryResolutions":[],"inactiveEntrySlots":[]})
}
fn public_operation(value: &Value) -> Value {
    let mut v = value.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("_digest");
    }
    v
}
pub fn revision(v: &Value) -> String {
    hex::encode(c::hash(serde_json::to_vec(v).unwrap()))
}
fn validate_bindings(db: &Database) -> Result<()> {
    let active = db
        .networks
        .iter()
        .filter(|n| n.enabled && n.profile.is_some())
        .collect::<Vec<_>>();
    for (i, a) in active.iter().enumerate() {
        for b in active.iter().skip(i + 1) {
            ensure!(
                a.settings.source_port != b.settings.source_port
                    && a.settings.source_port != b.settings.listen_port
                    && b.settings.source_port != a.settings.listen_port,
                "两条网络的源端口冲突，请为本机设置独立端口"
            );
            if a.settings.listen_port == b.settings.listen_port {
                ensure!(
                    a.settings.mode()? == b.settings.mode()?,
                    "同一个端口不能监听不同协议"
                );
                if a.settings.mode()? == "https" {
                    ensure!(
                        a.created_here == b.created_here
                            && (a.created_here
                                || a.profile.as_ref().unwrap().pair.transport_key_pin
                                    == b.profile.as_ref().unwrap().pair.transport_key_pin),
                        "HTTPS 不同主机身份需要独立监听端口"
                    );
                }
                if !conwu_core::code::stream_mode(a.settings.mode()?) {
                    ensure!(
                        a.settings.existing_only() == b.settings.existing_only()
                            && a.settings.tcp_stun == b.settings.tcp_stun
                            && a.settings.service == b.settings.service,
                        "不同原始承载发现配置需要独立监听端口"
                    );
                }
            }
            let ai = a.profile.as_ref().unwrap().local_ip()?.octets();
            let bi = b.profile.as_ref().unwrap().local_ip()?.octets();
            ensure!(
                ai[..3] != bi[..3],
                "两条网络的虚拟网段重叠，请选择不同的虚拟网段"
            );
        }
    }
    Ok(())
}
fn free_port(reserved: &[u16]) -> Result<u16> {
    use rand::Rng;
    // A persisted listener must not come from Windows' ephemeral client pool:
    // UI/HTTPS connections can otherwise take that port before boot binds it.
    for _ in 0..256 {
        let port = rand::thread_rng().gen_range(20000..30000);
        if reserved.contains(&port) {
            continue;
        }
        if let Ok(tcp) = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)) {
            if let Ok(udp) = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)) {
                drop((tcp, udp));
                return Ok(port);
            }
        }
    }
    anyhow::bail!("未找到可用于网络的独立监听端口")
}
