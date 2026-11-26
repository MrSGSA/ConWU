use std::time::{Duration, Instant};

#[cfg(windows)]
mod firewall;
#[cfg(windows)]
pub(crate) mod companion;
#[cfg(windows)]
mod display;
#[cfg(windows)]
pub(crate) mod moonlight;
#[cfg(windows)]
mod process;
#[cfg(windows)]
pub(crate) mod sunshine;

#[cfg(windows)]
pub(crate) fn cover_file_name(record: &str) -> String {
    format!("projection-cover-{}.bin", hex::encode(conwu_core::crypto::hash(record.as_bytes())))
}

pub(crate) const SUNSHINE_PORT: u16 = 48289;

#[cfg(windows)]
fn component(root: &std::path::Path, relative: &str) -> Option<std::path::PathBuf> {
    let path = crate::store::Store::resolve_root(&root.join(relative)).ok()?;
    if !path.is_file() {
        return None;
    }
    crate::platform::filesystem_argument(&path)
        .ok()
        .map(Into::into)
}

#[cfg(windows)]
pub(crate) fn state_dir(
    data: &std::path::Path,
    engine: &str,
    instance: &str,
) -> anyhow::Result<std::path::PathBuf> {
    use anyhow::Context;
    use conwu_core::crypto::hash;
    use std::{fs, path::PathBuf};

    let local = std::env::var_os("LOCALAPPDATA").context("本机用户配置目录不可用")?;
    let key = hex::encode(&hash(data.as_os_str().as_encoded_bytes())[..12]);
    let root = PathBuf::from(local).join("ConWU/Projection").join(key);
    let root = crate::store::Store::resolve_root(&root)?;
    fs::create_dir_all(&root)?;
    crate::store::private_directory(&root)?;
    let path = crate::store::Store::resolve_root(&root.join(engine).join(instance))?;
    fs::create_dir_all(&path)?;
    Ok(crate::platform::filesystem_argument(&path)?.into())
}

#[cfg(windows)]
fn write_state(
    directory: &std::path::Path,
    name: &str,
    bytes: &[u8],
) -> anyhow::Result<std::path::PathBuf> {
    use std::{fs, io::Write};

    let path = directory.join(name);
    if fs::symlink_metadata(&path).is_ok() {
        crate::store::reject_link(&path)?;
        if fs::read(&path)? == bytes {
            return Ok(path);
        }
    }
    let temp = directory.join(format!("{name}.{}.tmp", conwu_core::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if path.exists() {
            crate::store::replace_windows(&temp, &path)
        } else {
            fs::rename(&temp, &path).map_err(Into::into)
        }
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result.map(|()| path)
}

#[cfg(windows)]
pub(crate) struct ProjectionRoute {
    pub carrier: String,
    pub remote_port: u16,
    pub sunshine_port: u16,
    pub companion_port: u16,
    pub interface: u32,
    pub video_datagrams: bool,
}

#[cfg(windows)]
pub(crate) fn supports_video_datagrams(mode: &str) -> bool {
    conwu_core::code::valid_mode(mode) && !conwu_core::code::stream_mode(mode)
}

const VALID_FOR: Duration = Duration::from_secs(4);

pub enum Endpoint {
    Legacy(u16),
    Sunshine(u16),
    Companion(u16),
}

#[derive(Default)]
pub struct Listener {
    bound: Option<(u16, Instant)>,
}

impl Listener {
    pub fn port(&self, configured: u16) -> u16 {
        self.bound
            .filter(|(port, observed)| *port == configured && observed.elapsed() < VALID_FOR)
            .map_or(0, |(port, _)| port)
    }

    pub fn live_port(&self) -> u16 {
        self.bound
            .filter(|(_, observed)| observed.elapsed() < VALID_FOR)
            .map_or(0, |(port, _)| port)
    }

    #[cfg(windows)]
    pub fn report(&mut self, port: Option<u16>) {
        self.bound = port.map(|port| (port, Instant::now()));
    }
}

pub fn announce(endpoint: Endpoint) -> [u8; 6] {
    let (mut frame, port) = match endpoint {
        Endpoint::Legacy(port) => (*b"PRJ1\0\0", port),
        Endpoint::Sunshine(port) => (*b"PRJ2\0\0", port),
        Endpoint::Companion(port) => (*b"PRJ3\0\0", port),
    };
    frame[4..].copy_from_slice(&port.to_be_bytes());
    frame
}

pub fn parse(frame: &[u8]) -> Option<Endpoint> {
    if frame.len() != 6 {
        return None;
    }
    let port = u16::from_be_bytes(frame[4..].try_into().unwrap());
    match &frame[..4] {
        b"PRJ1" if port == 0 || port >= 1024 => Some(Endpoint::Legacy(port)),
        b"PRJ2" if port == 0 || (1029..=65514).contains(&port) => Some(Endpoint::Sunshine(port)),
        b"PRJ3" if port == 0 || port >= 1024 => Some(Endpoint::Companion(port)),
        _ => None,
    }
}

pub struct Advertisement {
    port: u16,
    epoch: [u8; 16],
    sequence: u64,
    seen: Instant,
}

impl Advertisement {
    pub fn receive(previous: &mut Option<Self>, port: u16, header: &[u8]) {
        // The caller has authenticated the SLM4 frame for the live peer.
        let epoch = header[8..24].try_into().unwrap();
        let sequence = u64::from_be_bytes(header[40..48].try_into().unwrap());
        if previous
            .as_ref()
            .is_none_or(|old| old.epoch != epoch || old.sequence < sequence)
        {
            *previous = Some(Self {
                port,
                epoch,
                sequence,
                seen: Instant::now(),
            });
        }
    }

    #[cfg(windows)]
    pub fn port(&self, epoch: Option<[u8; 16]>) -> u16 {
        if epoch == Some(self.epoch) && self.seen.elapsed() < VALID_FOR {
            self.port
        } else {
            0
        }
    }
}

#[cfg(windows)]
mod desktop {
    use std::{
        collections::BTreeMap,
        net::Ipv4Addr,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use anyhow::{Context, Result, ensure};
    use conwu_core::crypto;
    use serde::Serialize;
    use serde_json::{Value, json};
    use tokio::sync::oneshot;

    use crate::{backend::App, model::Network, runtime};

    use super::*;

    const COMPONENT: &str = "ConWU-Projection.exe";
    const SUNSHINE: &str = "projection/sunshine/sunshine.exe";
    const EMBEDDED_MOONLIGHT: &str = "projection/moonlight/ConWU-Moonlight.exe";
    const DESKTOP: &str = "ConWU-Desktop.exe";
    const DESKTOP_ACTIVE: Duration = Duration::from_secs(5);
    const LAUNCH_WINDOW: Duration = Duration::from_secs(6);

    #[derive(Default)]
    pub struct Launcher(Mutex<Desktop>);

    #[derive(Default)]
    struct Desktop {
        seen: Option<Instant>,
        pending: Option<Launch>,
        open_desktop: Option<Instant>,
        moonlight: moonlight::Report,
        hosts: BTreeMap<String, sunshine::Status>,
        stop_moonlight: bool,
        pending_file: Option<(companion::Job, Instant)>,
        files: Vec<companion::Progress>,
        stop_files: Vec<String>,
        file_queries: BTreeMap<String, PendingQuery>,
        previews: BTreeMap<String, PreviewState>,
    }

    struct PreviewState {
        device: String,
        generation: String,
        next: Option<Instant>,
        revision: u64,
    }

    struct PendingQuery {
        query: Option<companion::browser::Query>,
        result: oneshot::Sender<companion::browser::QueryResult>,
    }

    struct Launch {
        target: moonlight::Target,
        video: crate::model::ProjectionVideo,
        requested: Instant,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Access {
        record: String,
        network: String,
        device: String,
        local: Ipv4Addr,
        remote: Ipv4Addr,
        port: u16,
        remote_port: u16,
        interface: u32,
        video_datagrams: bool,
        authorization: [u8; 32],
    }

    impl App {
        pub(crate) fn projection_component(&self) -> Option<PathBuf> {
            component(&self.engine.components, COMPONENT)
        }

        pub(crate) fn projection_engines(&self) -> Option<(PathBuf, PathBuf)> {
            Some((
                component(&self.engine.components, SUNSHINE)?,
                component(&self.engine.components, EMBEDDED_MOONLIGHT)?,
            ))
        }

        pub(crate) fn projection_embedded(&self) -> bool {
            self.projection_engines().is_some()
                && component(&self.engine.components, DESKTOP).is_some()
        }

        fn sunshine_binding(network: &Network) -> Option<sunshine::Binding> {
            let profile = network.profile.as_ref()?;
            let peer = runtime::remote_member(profile)?;
            Some(sunshine::Binding {
                record: network.id.clone(),
                network: profile.pair.network.clone(),
                local: profile.local_ip().ok()?,
                remote: runtime::member_ip(profile, &peer).ok()?,
            })
        }

        pub(crate) fn projection_status(&self, network: &Network) -> Value {
            let running = self.engine.current(&network.id);
            let remote = running
                .as_ref()
                .and_then(|running| running.projection_route(network));
            let (local, sunshine) =
                remote
                    .as_ref()
                    .and(running.as_ref())
                    .map_or((0, 0), |running| {
                        (
                            running
                                .projection_listener
                                .lock()
                                .unwrap()
                                .port(network.projection.port),
                            running
                                .projection_sunshine
                                .lock()
                                .unwrap()
                                .port(SUNSHINE_PORT),
                        )
                    });
            let desktop = self.projection.0.lock().unwrap();
            let host = desktop.hosts.get(&network.id).filter(|_| {
                desktop
                    .seen
                    .is_some_and(|seen| seen.elapsed() < DESKTOP_ACTIVE)
                    && remote.is_some()
            });
            json!({
                "authorized": network.projection.allowed,
                "coverRevision": desktop.previews.get(&network.id).filter(|p| p.revision != 0)
                    .map(|p| format!("{}-{}", p.generation, p.revision)),
                "port": network.projection.port,
                "localPort": local,
                "remotePort": remote.as_ref().map_or(0, |route| route.remote_port),
                "localSunshinePort": sunshine,
                "remoteSunshinePort": remote.as_ref().map_or(0, |route| route.sunshine_port),
                "carrier": remote.as_ref().map(|route| route.carrier.as_str()),
                "hostMessage": host.and_then(|status| status.message.as_ref()),
                "video": network.projection.video,
                "files": network.projection.files,
                "fileBrowser": network.projection.file_browser,
                "clipboard": network.projection.clipboard,
                "companionReady": remote.is_some_and(|route| route.companion_port != 0),
            })
        }

        fn companion_route(network: &Network, remote_port: u16) -> Result<companion::Route> {
            let profile = network.profile.as_ref().context("Projection 网络身份已变化")?;
            let peer = runtime::remote_member(profile).context("Projection 成员已变化")?;
            let key = profile.shared_key(&peer)?;
            Ok(companion::Route {
                port: remote_port,
                binding: companion::Binding {
                    record: network.id.clone(),
                    local: profile.local_ip()?,
                    remote: runtime::member_ip(profile, &peer)?,
                    key: *crypto::hkdf(&*key, profile.pair.network.as_bytes(), b"ConWU Projection companion v1"),
                    files: network.projection.files,
                    file_browser: network.projection.file_browser,
                    clipboard: network.projection.clipboard,
                },
            })
        }

        fn projection_access(&self) -> Result<Value> {
            let db = self.db.read().unwrap();
            let mut access = Vec::new();
            for network in &db.networks {
                let Some(route) = self
                    .engine
                    .current(&network.id)
                    .and_then(|running| running.projection_route(network))
                else {
                    continue;
                };
                let profile = network.profile.as_ref().context("远控网络身份已变化")?;
                let peer = runtime::remote_member(profile).context("远控成员已变化")?;
                let shared = profile.shared_key(&peer)?;
                access.push(Access {
                    record: network.id.clone(),
                    network: profile.pair.network.clone(),
                    device: peer.device.clone(),
                    local: profile.local_ip()?,
                    remote: runtime::member_ip(profile, &peer)?,
                    port: network.projection.port,
                    remote_port: route.remote_port,
                    interface: route.interface,
                    video_datagrams: route.video_datagrams,
                    authorization: *crypto::hkdf(
                        &*shared,
                        profile.pair.network.as_bytes(),
                        b"ConWU Projection TLS authorization v1",
                    ),
                });
            }
            Ok(json!({"ok":true,"access":access}))
        }

        pub(crate) fn start_projection_firewall(self: &Arc<Self>) {
            let app = self.clone();
            let cancel = app.engine.cancel.clone();
            self.engine.tracker.spawn(async move {
                let namespace =
                    hex::encode(&crypto::hash(app.store.root.as_os_str().as_encoded_bytes())[..12]);
                let mut rules = firewall::Rules::default();
                let mut tick = tokio::time::interval(Duration::from_secs(2));
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break,
                        _ = tick.tick() => {}
                    }
                    let desired = app.projection_firewall_scopes(&namespace);
                    if !rules.is_current(&desired) {
                        let update = tokio::task::spawn_blocking(move || {
                            rules.apply(desired);
                            rules
                        })
                        .await;
                        let Ok(updated) = update else { return };
                        rules = updated;
                    }
                }
                if !rules.is_current(&BTreeMap::new()) {
                    let _ = tokio::task::spawn_blocking(move || rules.apply(BTreeMap::new())).await;
                }
            });
        }

        fn projection_firewall_scopes(&self, namespace: &str) -> BTreeMap<String, firewall::Scope> {
            let (program, bundled) = if let Some((sunshine, _)) = self.projection_engines() {
                (sunshine, true)
            } else if let Some(legacy) = self.projection_component() {
                (legacy, false)
            } else {
                return BTreeMap::new();
            };
            let db = self.db.read().unwrap();
            let paths = db.networks.iter().filter_map(|network| {
                let running = self.engine.current(&network.id)?;
                let route = running.projection_route(network)?;
                let profile = network.profile.as_ref()?;
                let peer = runtime::remote_member(profile)?;
                let scope = firewall::Scope {
                    program: program.clone(),
                    interface: firewall::interface_alias(route.interface)?,
                    local: profile.local_ip().ok()?,
                    remote: runtime::member_ip(profile, &peer).ok()?,
                    ports: vec![network.projection.port],
                    udp: false,
                    block: false,
                };
                let name = format!("ConWU Projection {namespace} {}", network.id);
                let companion = running.projection_companion.lock().unwrap().live_port();
                Some((name, scope, route.video_datagrams, companion))
            });
            let mut scopes = BTreeMap::new();
            let tray = std::env::current_exe().ok().map(crate::platform::windows_launcher);
            for (name, scope, udp_video, companion) in paths {
                if bundled {
                    if let Some(tray) = tray.as_ref().filter(|_| companion != 0) {
                        scopes.insert(format!("{name} Companion TCP"), firewall::Scope {
                            program: tray.clone(),
                            ports: vec![companion],
                            ..scope.clone()
                        });
                    }
                    scopes.insert(
                        format!("{name} Sunshine TCP"),
                        firewall::Scope {
                            ports: sunshine::TCP.to_vec(),
                            ..scope.clone()
                        },
                    );
                    scopes.insert(
                        format!("{name} Sunshine UDP"),
                        firewall::Scope {
                            ports: sunshine::UDP.to_vec(),
                            udp: true,
                            ..scope.clone()
                        },
                    );
                    scopes.insert(
                        format!("{name} Sunshine Admin"),
                        firewall::Scope {
                            ports: vec![sunshine::PANEL],
                            block: true,
                            ..scope
                        },
                    );
                } else {
                    if udp_video {
                        scopes.insert(
                            format!("{name} UDP"),
                            firewall::Scope {
                                udp: true,
                                ..scope.clone()
                            },
                        );
                    }
                    scopes.insert(name, scope);
                }
            }
            scopes
        }

        fn moonlight_target(&self, network: &Network, device: &str) -> Option<moonlight::Target> {
            let running = self.engine.current(&network.id)?;
            let route = running.projection_route(network)?;
            if route.sunshine_port == 0 {
                return None;
            }
            let profile = network.profile.as_ref()?;
            let peer = runtime::remote_member(profile)?;
            if peer.device != device {
                return None;
            }
            Some(moonlight::Target {
                record: network.id.clone(),
                carrier: route.carrier,
                device: peer.device.clone(),
                local: profile.local_ip().ok()?,
                remote: runtime::member_ip(profile, &peer).ok()?,
                interface: route.interface,
                port: route.sunshine_port,
            })
        }

        fn moonlight_allowed(&self, target: &moonlight::Target) -> bool {
            self.db
                .read()
                .unwrap()
                .networks
                .iter()
                .find(|n| n.id == target.record)
                .and_then(|network| self.moonlight_target(network, &target.device))
                .as_ref()
                == Some(target)
        }

        pub(crate) fn projection_moonlight_status(&self) -> Value {
            let desktop = self.projection.0.lock().unwrap();
            let online = desktop
                .seen
                .is_some_and(|seen| seen.elapsed() < DESKTOP_ACTIVE);
            let running = online
                .then_some(desktop.moonlight.target.as_ref())
                .flatten();
            let starting = desktop
                .pending
                .as_ref()
                .filter(|item| item.requested.elapsed() < LAUNCH_WINDOW)
                .map(|item| &item.target);
            json!({"available":online && desktop.moonlight.available,
                "networkId":running.or(starting).map(|target| &target.record),
                "opened":running.is_some() && matches!(desktop.moonlight.stage, moonlight::Stage::Playing),
                "stopping":running.is_some() && (desktop.stop_moonlight || matches!(desktop.moonlight.stage, moonlight::Stage::Stopping)),
                "error":desktop.moonlight.error})
        }

        pub(crate) fn projection_file_status(&self) -> Vec<companion::Progress> {
            let desktop = self.projection.0.lock().unwrap();
            if desktop.seen.is_some_and(|seen| seen.elapsed() < DESKTOP_ACTIVE) {
                desktop.files.clone()
            } else {
                Vec::new()
            }
        }

        fn projection_tool_route(&self, record: &str, device: &str, needs_files: bool) -> Result<companion::Route> {
            ensure!(self.projection_engines().is_some(), "当前安装缺少 Projection 组件");
            let db = self.db.read().unwrap();
            let network = db.networks.iter().find(|network| network.id == record).context("网络不存在")?;
            ensure!(!needs_files || network.projection.files, "请先在 Projection 设置中启用文件传输");
            let profile = network.profile.as_ref().context("网络未配对")?;
            ensure!(runtime::remote_member(profile).is_some_and(|peer| peer.device == device), "设备已变化，请刷新设备列表");
            let port = self.engine.current(record).and_then(|running| running.projection_route(network))
                .map(|route| route.companion_port).filter(|&port| port != 0).context("等待对机 Projection 就绪")?;
            Self::companion_route(network, port)
        }

        pub(crate) async fn projection_bitrate(&self, input: &Value) -> Result<Value> {
            use crate::model::{ProjectionResolution, ProjectionVideo};
            let video: ProjectionVideo = serde_json::from_value(input["video"].clone())?;
            video.validate()?;
            let (width, height) = match video.resolution_mode {
                ProjectionResolution::Custom => (video.width, video.height),
                ProjectionResolution::Local => {
                    let display: display::DisplayMode = serde_json::from_value(input["display"].clone())?;
                    display.stream_size()?
                }
                ProjectionResolution::Peer => {
                    let record = input["networkId"].as_str().context("请选择网络")?;
                    let device = input["deviceId"].as_str().context("请选择设备")?;
                    companion::display(&self.projection_tool_route(record, device, false)?).await?.stream_size()?
                }
            };
            Ok(json!({"width":width,"height":height,"kbps":video.bitrate_kbps(width,height)}))
        }

        pub(crate) async fn projection_tool_query(&self, input: Value, files: bool) -> Result<Value> {
            use companion::browser::{Action, Query};

            let record = input["networkId"].as_str().context("请选择网络")?;
            let device = input["deviceId"].as_str().context("请选择设备")?;
            let action: Action = serde_json::from_value(input["request"].clone())?;
            let device_action = matches!(&action, Action::Preview);
            ensure!(files != device_action, "操作类型不符");
            let route = self.projection_tool_route(record, device, files)?;
            if let Action::Copy { paths, .. } = &action {
                ensure!((1..=64).contains(&paths.len()), "每次可传输 1–64 个文件");
            }
            let query = Query { id: conwu_core::id(), route, action };
            ensure!(serde_json::to_vec(&query)?.len() <= 64 * 1024, "文件请求过大");
            let (result, receiver) = oneshot::channel();
            {
                let mut desktop = self.projection.0.lock().unwrap();
                ensure!(desktop.seen.is_some_and(|seen| seen.elapsed() < DESKTOP_ACTIVE), "请先启动本机 ConWU 托盘");
                desktop.file_queries.retain(|_, item| !item.result.is_closed());
                ensure!(desktop.file_queries.len() < 4, "设备操作较多，请稍后重试");
                desktop.file_queries.insert(query.id.clone(), PendingQuery { query: Some(query), result });
            }
            let reply = tokio::time::timeout(Duration::from_secs(16), receiver).await
                .context("等待对机操作响应超时")??;
            if let Some(error) = reply.error {
                anyhow::bail!("{error}");
            }
            Ok(reply.value.unwrap_or(Value::Null))
        }

        fn schedule_previews(self: &Arc<Self>, connected: &BTreeMap<String, String>, stopped: Option<&str>, playing: Option<&str>) {
            let mut desktop = self.projection.0.lock().unwrap();
            desktop.previews.retain(|id, p| connected.get(id) == Some(&p.device));
            for (id, device) in connected {
                let p = desktop.previews.entry(id.clone()).or_insert_with(|| PreviewState {
                    device: device.clone(), generation: conwu_core::id(), next: Some(Instant::now()), revision: 0,
                });
                if stopped == Some(id) {
                    p.generation = conwu_core::id();
                    p.revision = 0;
                    p.next = Some(Instant::now());
                }
                if playing == Some(id) || !p.next.is_some_and(|next| next <= Instant::now()) { continue; }
                p.next = None;
                let (app, id, device, generation) = (self.clone(), id.clone(), device.clone(), p.generation.clone());
                tokio::spawn(async move {
                    let input = json!({"networkId":id,"deviceId":device,"request":{"action":"preview"}});
                    let reply = app.projection_tool_query(input.clone(), false).await;
                    let _tx = app.transaction.lock().await;
                    let file = app.cover_file(&input);
                    let route = app.projection_tool_route(&id, &device, false);
                    let mut desktop = app.projection.0.lock().unwrap();
                    let Some(p) = desktop.previews.get_mut(&id).filter(|p| p.generation == generation) else { return };
                    let saved = reply.and_then(|value| {
                        route?;
                        ensure!(value["image"].as_str().is_some_and(|s| s.len() <= 96 * 1024 &&
                            (s.starts_with("Qk") || s.starts_with("/9j/"))), "桌面缩略图无效");
                        app.store.write_secret(&file?, &serde_json::to_vec(&json!({"device":device,"preview":value}))?, false)
                    });
                    if saved.is_ok() { p.revision += 1; }
                    else { p.next = Some(Instant::now() + Duration::from_secs(30)); }
                });
            }
        }

        fn cover_file(&self, input: &Value) -> Result<String> {
            let db = self.db.read().unwrap();
            let target = db.networks.iter().find(|n| Some(n.id.as_str()) == input["networkId"].as_str())
                .context("请选择已配对的设备")?;
            let profile = target.profile.as_ref().filter(|p| p.pair.direct).context("网络尚未配对")?;
            ensure!(target.projection.allowed && runtime::remote_member(profile).is_some_and(|p|
                Some(p.device.as_str()) == input["deviceId"].as_str()), "设备配对或授权已变化");
            Ok(super::cover_file_name(&target.id))
        }

        pub(crate) fn projection_cached_cover(&self, input: &Value) -> Result<Value> {
            let file = self.cover_file(input)?;
            self.projection_tool_route(input["networkId"].as_str().context("网络无效")?,
                input["deviceId"].as_str().context("设备无效")?, false)?;
            if !self.store.checked_file(&file)?.exists() { return Ok(Value::Null); }
            let data: Value = serde_json::from_slice(&self.store.read_secret(&file)?)?;
            Ok(if data["device"] == input["deviceId"] {
                data["preview"]["image"].as_str().map(|image| json!({"image":image})).unwrap_or(Value::Null)
            } else { Value::Null })
        }

        pub(crate) fn request_projection_files(&self, record: &str, device: &str) -> Result<Value> {
            self.projection_tool_route(record, device, true)?;
            let mut desktop = self.projection.0.lock().unwrap();
            ensure!(desktop.seen.is_some_and(|seen| seen.elapsed() < DESKTOP_ACTIVE), "请先启动本机 ConWU 托盘");
            ensure!(!desktop.files.iter().any(|progress| progress.active) && desktop.pending_file.is_none(),
                "已有 Projection 文件操作正在进行");
            let job = companion::Job { record: record.into(), id: conwu_core::id() };
            desktop.files.insert(0, companion::Progress::choosing(job.clone()));
            desktop.pending_file = Some((job, Instant::now()));
            Ok(Value::Null)
        }

        pub(crate) fn cancel_projection_files(&self, job: &str) -> Result<Value> {
            let mut desktop = self.projection.0.lock().unwrap();
            ensure!(desktop.files.iter().any(|progress| progress.active && progress.job.id == job),
                "文件传输已结束");
            if desktop.pending_file.as_ref().is_some_and(|(item, _)| item.id == job) {
                desktop.pending_file = None;
                desktop.files.retain(|item| item.job.id != job);
            } else {
                if !desktop.stop_files.iter().any(|id| id == job) {
                    desktop.stop_files.push(job.into());
                }
            }
            Ok(Value::Null)
        }

        pub(crate) fn open_projection_desktop(&self) -> Result<Value> {
            ensure!(self.projection_embedded(), "当前安装缺少支持同窗播放的 Projection 组件");
            let mut desktop = self.projection.0.lock().unwrap();
            ensure!(
                desktop
                    .seen
                    .is_some_and(|seen| seen.elapsed() < DESKTOP_ACTIVE),
                "请先启动本机 ConWU 托盘"
            );
            desktop.open_desktop = Some(Instant::now());
            Ok(Value::Null)
        }

        pub(crate) fn stop_projection_moonlight(&self, record: &str) -> Result<Value> {
            let mut desktop = self.projection.0.lock().unwrap();
            if desktop
                .pending
                .as_ref()
                .is_some_and(|item| item.target.record == record)
            {
                desktop.pending = None;
            } else {
                ensure!(
                    desktop
                        .moonlight
                        .target
                        .as_ref()
                        .is_some_and(|target| target.record == record),
                    "此设备没有由 ConWU 发起的 Moonlight 会话"
                );
                desktop.stop_moonlight = true;
            }
            Ok(Value::Null)
        }

        pub(crate) fn request_projection(
            &self,
            record: &str,
            device: &str,
            embedded: bool,
        ) -> Result<Value> {
            ensure!(embedded, "请在 ConWU 桌面窗口内启动 Projection");
            ensure!(self.projection_embedded(), "当前安装缺少支持同窗播放的 Projection 组件");
            let db = self.db.read().unwrap();
            let network = db
                .networks
                .iter()
                .find(|network| network.id == record)
                .context("网络不存在")?;
            let target = self
                .moonlight_target(network, device)
                .context("等待对端随包 Sunshine 就绪，并检查直连与远控授权")?;
            ensure!(self.engine.current(record).and_then(|running| running.projection_route(network))
                .is_some_and(|route| route.companion_port != 0), "等待对端 Projection 自动连接组件就绪");
            let mut desktop = self.projection.0.lock().unwrap();
            ensure!(
                desktop
                    .seen
                    .is_some_and(|seen| seen.elapsed() < DESKTOP_ACTIVE),
                "请先启动当前用户的 ConWU 托盘"
            );
            ensure!(
                desktop.moonlight.target.is_none(),
                "请先结束当前 Projection 串流"
            );
            ensure!(
                desktop
                    .pending
                    .as_ref()
                    .is_none_or(|launch| launch.requested.elapsed() >= LAUNCH_WINDOW),
                "已有远控连接正在启动"
            );
            ensure!(desktop.moonlight.available, "正在准备 Projection 播放组件，请稍候");
            desktop.moonlight.error = None;
            desktop.pending = Some(Launch {
                target,
                video: network.projection.video,
                requested: Instant::now(),
            });
            Ok(Value::Null)
        }

        pub(crate) fn projection_local(self: &Arc<Self>, input: &Value) -> Result<Value> {
            match input["method"].as_str().unwrap_or("") {
                "projection-access" => self.projection_access(),
                "projection-listeners" => {
                    let ports: BTreeMap<String, u16> =
                        serde_json::from_value(input["ports"].clone())?;
                    ensure!(ports.len() <= 32, "Projection 监听记录过多");
                    for n in &self.db.read().unwrap().networks {
                        if let Some(running) = self.engine.current(&n.id) {
                            let port = ports.get(&n.id).copied().filter(|port| {
                                *port == n.projection.port && running.projection_route(n).is_some()
                            });
                            running.projection_listener.lock().unwrap().report(port);
                        }
                    }
                    Ok(json!({"ok":true}))
                }
                "projection-desktop" => {
                    let executable = self.projection_component();
                    let engines = self.projection_engines();
                    let reports: Vec<sunshine::Report> = if input["sunshine"].is_null() {
                        Vec::new()
                    } else {
                        serde_json::from_value(input["sunshine"].clone())?
                    };
                    let companion_reports: Vec<companion::Report> = input.get("companions")
                        .map(|reports| serde_json::from_value(reports.clone()))
                        .transpose()?.unwrap_or_default();
                    let (listen, bindings, hosts, companions, connected) = {
                        let db = self.db.read().unwrap();
                        let mut listen = false;
                        let mut bindings = Vec::new();
                        let mut hosts = BTreeMap::new();
                        let mut companions = Vec::new();
                        let mut connected = BTreeMap::new();
                        for network in &db.networks {
                            let Some(running) = self.engine.current(&network.id) else {
                                continue;
                            };
                            let route = running.projection_route(network);
                            let routed = route.is_some();
                            listen |= engines.is_none() && executable.is_some() && routed;
                            let binding = (engines.is_some() && routed)
                                .then(|| Self::sunshine_binding(network))
                                .flatten();
                            let mut ready = None;
                            if let Some(binding) = binding {
                                if let Some(report) =
                                    reports.iter().find(|report| report.binding == binding)
                                {
                                    ready = report.status.ready.then_some(SUNSHINE_PORT);
                                    hosts.insert(network.id.clone(), report.status.clone());
                                }
                                bindings.push(binding);
                            }
                            running.projection_sunshine.lock().unwrap().report(ready);
                            let mut companion_port = None;
                            if let Some(route) = route.filter(|_| engines.is_some()) {
                                let companion = Self::companion_route(network, route.companion_port)?;
                                companion_port = companion_reports.iter().find(|report| {
                                    report.record == companion.binding.record
                                        && report.local == companion.binding.local
                                        && report.remote == companion.binding.remote
                                        && report.port >= 1024
                                }).map(|report| report.port);
                                if companion.port != 0 && let Some(peer) = network.profile.as_ref().and_then(runtime::remote_member) {
                                    connected.insert(network.id.clone(), peer.device);
                                }
                                companions.push(companion);
                            }
                            running.projection_companion.lock().unwrap().report(companion_port);
                        }
                        (listen, bindings, hosts, companions, connected)
                    };
                    let report: moonlight::Report = if input["moonlight"].is_null() {
                        Default::default()
                    } else {
                        serde_json::from_value(input["moonlight"].clone())?
                    };
                    let revoked = report
                        .target
                        .as_ref()
                        .is_some_and(|target| !self.moonlight_allowed(target));
                    let files: Vec<companion::Progress> = input.get("files")
                        .map(|files| serde_json::from_value(files.clone())).transpose()?.unwrap_or_default();
                    let results: Vec<companion::browser::QueryResult> = input.get("fileResults")
                        .map(|value| serde_json::from_value(value.clone())).transpose()?.unwrap_or_default();
                    ensure!(files.len() <= 25 && results.len() <= 2, "文件状态报告过大");
                    let playing = report.target.as_ref().map(|t| t.record.clone());
                    let (launch, stop_moonlight, open_desktop, send_file, stop_files, file_queries, stopped) = {
                        let mut desktop = self.projection.0.lock().unwrap();
                        desktop.files = files;
                        for result in results {
                            if let Some(item) = desktop.file_queries.remove(&result.id) {
                                let _ = item.result.send(result);
                            }
                        }
                        desktop.file_queries.retain(|_, item| !item.result.is_closed());
                        let file_queries = desktop.file_queries.values_mut().filter_map(|item| item.query.take()).collect::<Vec<_>>();
                        let send_file = desktop.pending_file.take()
                            .filter(|(_, queued)| queued.elapsed() < LAUNCH_WINDOW)
                            .map(|(job, _)| job);
                        let stop_files = std::mem::take(&mut desktop.stop_files);
                        desktop.seen = Some(Instant::now());
                        let stopped = desktop.moonlight.target.as_ref().filter(|t| Some(&t.record) != playing.as_ref())
                            .map(|t| t.record.clone());
                        desktop.moonlight = report;
                        desktop.hosts = hosts;
                        desktop.stop_moonlight = desktop.moonlight.target.is_some()
                            && (desktop.stop_moonlight || revoked);
                        let launch = if desktop.moonlight.target.is_some() {
                            None
                        } else {
                            desktop
                                .pending
                                .take()
                                .filter(|launch| launch.requested.elapsed() < LAUNCH_WINDOW)
                        };
                        if let Some(launch) = &launch {
                            desktop.moonlight.target = Some(launch.target.clone());
                        }
                        let open_desktop = desktop.open_desktop.take()
                            .is_some_and(|requested| requested.elapsed() < LAUNCH_WINDOW);
                        (launch, desktop.stop_moonlight, open_desktop, send_file, stop_files, file_queries, stopped)
                    };
                    self.schedule_previews(&connected, stopped.as_deref(), playing.as_deref());
                    let launch = launch.filter(|item| self.moonlight_allowed(&item.target))
                        .map(|item| json!({"moonlight":item.target,"video":item.video}));
                    Ok(json!({
                        "ok":true,"executable":executable,"listen":listen,"launch":launch,"stopMoonlight":stop_moonlight,
                        "sunshineExecutable":engines.as_ref().map(|(path, _)| path),
                        "moonlightExecutable":engines.as_ref().map(|(_, path)| path),
                        "desktopExecutable":component(&self.engine.components, DESKTOP),
                        "bindings":bindings,"openDesktop":open_desktop,
                        "companions":companions,"sendFile":send_file,"stopFiles":stop_files,"fileQueries":file_queries,
                    }))
                }
                _ => anyhow::bail!("未知 Projection 本机请求"),
            }
        }
    }
}

#[cfg(windows)]
pub use desktop::Launcher;

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn video_datagrams_follow_packet_carriers() {
        for mode in ["faketcp", "phantun", "mimic", "tcpraw", "udp"] {
            assert!(supports_video_datagrams(mode), "{mode}");
        }
        for mode in ["tcp", "https", "unknown"] {
            assert!(!supports_video_datagrams(mode), "{mode}");
        }
    }

    #[test]
    fn withdrawal_cannot_be_overwritten_by_an_older_announcement() {
        let mut frame = [0; 48];
        frame[8..24].fill(1);
        let epoch = Some([1; 16]);
        let mut advertisement = None;
        frame[40..].copy_from_slice(&9u64.to_be_bytes());
        Advertisement::receive(&mut advertisement, 0, &frame);
        frame[40..].copy_from_slice(&8u64.to_be_bytes());
        Advertisement::receive(&mut advertisement, 46424, &frame);
        assert_eq!(advertisement.as_ref().unwrap().port(epoch), 0);
        frame[40..].copy_from_slice(&10u64.to_be_bytes());
        Advertisement::receive(&mut advertisement, 46425, &frame);
        assert_eq!(advertisement.as_ref().unwrap().port(epoch), 46425);
        assert_eq!(advertisement.as_ref().unwrap().port(Some([2; 16])), 0);
    }

    #[test]
    fn only_a_recent_binding_for_the_configured_port_is_advertised() {
        let mut listener = Listener::default();
        listener.report(Some(46424));
        assert_eq!(listener.port(46424), 46424);
        assert_eq!(listener.port(46425), 0);
        listener.bound.as_mut().unwrap().1 -= VALID_FOR;
        assert_eq!(listener.port(46424), 0);
        assert!(matches!(
            parse(&announce(Endpoint::Legacy(46425))),
            Some(Endpoint::Legacy(46425))
        ));
        assert!(matches!(
            parse(&announce(Endpoint::Sunshine(SUNSHINE_PORT))),
            Some(Endpoint::Sunshine(SUNSHINE_PORT))
        ));
        assert!(parse(&announce(Endpoint::Legacy(100))).is_none());
        assert!(parse(&announce(Endpoint::Sunshine(u16::MAX))).is_none());
    }
}
