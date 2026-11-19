use crate::backend::{App, revision};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
#[cfg(any(windows, test))]
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;
use std::{
    collections::{BTreeMap, HashSet},
    net::Ipv4Addr,
    sync::{Arc, Mutex, OnceLock},
};

#[cfg(windows)]
mod identity;
mod sockets;
use sockets::{Flow, SocketOwners};
const MIN_TRAFFIC_BYTES_PER_SECOND: u64 = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConnectedPath {
    local_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    boot: uuid::Uuid,
    since: i64,
    endpoint: String,
}

#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
struct RuleInputs {
    pids: Vec<u32>,
    addresses: Vec<Ipv4Addr>,
}

#[cfg(any(windows, test))]
impl RuleInputs {
    fn new(pids: Vec<u32>, paths: &BTreeMap<String, ConnectedPath>) -> Self {
        let mut addresses = paths.values().map(|path| path.local_ip).collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        Self { pids, addresses }
    }
}

#[derive(Default)]
struct Counters {
    sent: u64,
    received: u64,
    buckets: BTreeMap<i64, u64>,
    confirmed: bool,
}
impl Counters {
    #[cfg(any(windows, test))]
    fn reset_confirmation(&mut self) {
        self.buckets.clear();
        self.confirmed = false;
    }

    fn record(&mut self, size: u64, outbound: bool, now: i64) {
        if outbound {
            self.sent += size;
        } else {
            self.received += size;
        }
        self.buckets.retain(|k, _| *k >= now - 5 && *k <= now + 1);
        let previous = self.buckets.get(&(now - 1)).copied().unwrap_or(0);
        let current = self.buckets.entry(now).or_default();
        *current += size;
        self.confirmed |=
            *current >= MIN_TRAFFIC_BYTES_PER_SECOND && previous >= MIN_TRAFFIC_BYTES_PER_SECOND;
    }
}
#[derive(Default)]
struct State {
    active: bool,
    pids: Vec<u32>,
    error: String,
    observation_error: String,
    networks: BTreeMap<String, Counters>,
    owners: Option<SocketOwners>,
    eligible: BTreeMap<String, ConnectedPath>,
    route_pending: Vec<String>,
    generation: u64,
}
impl State {
    #[cfg(any(windows, test))]
    fn reset_rules(&mut self) {
        self.active = false;
        self.owners = None;
        self.observation_error.clear();
        self.eligible.clear();
        for c in self.networks.values_mut() {
            c.reset_confirmation();
        }
    }
    #[cfg(any(windows, test))]
    fn sync_paths(&mut self, paths: BTreeMap<String, ConnectedPath>) {
        for (id, counters) in &mut self.networks {
            if self.eligible.get(id) != paths.get(id) {
                counters.reset_confirmation();
            }
        }
        self.eligible = paths;
    }
    #[cfg(any(windows, test))]
    fn lose_observation(&mut self, reason: String) {
        self.owners = None;
        self.observation_error = reason;
        for counters in self.networks.values_mut() {
            counters.buckets.clear();
        }
    }
    fn traffic(&mut self, valid: &HashSet<String>, now: i64) -> Value {
        self.networks.retain(|id, _| valid.contains(id));
        let (mut sent, mut received, mut observed, mut confirmed) = (0, 0, false, false);
        let rows = self.networks.iter_mut().map(|(id,c)| {
            sent += c.sent; received += c.received;
            let a = c.buckets.get(&(now-1)).copied().unwrap_or(0);
            let b = c.buckets.get(&(now-2)).copied().unwrap_or(0);
            let current = self.active && self.error.is_empty() && self.owners.is_some()
                && self.eligible.contains_key(id);
            let live = current && a >= MIN_TRAFFIC_BYTES_PER_SECOND && b >= MIN_TRAFFIC_BYTES_PER_SECOND;
            observed |= live;
            confirmed |= current && c.confirmed;
            json!({"id":id,"trafficObserved":live,"sessionConfirmed":current&&c.confirmed,
                "sentBytes":c.sent,"receivedBytes":c.received,"bytesPerSecond":if current{(a+b)/2}else{0}})
        }).collect::<Vec<_>>();
        json!({"networks":rows,"sentBytes":sent,"receivedBytes":received,"trafficObserved":observed,"sessionConfirmed":confirmed})
    }
}
static STATE: OnceLock<Mutex<State>> = OnceLock::new();
fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| Mutex::new(State::default()))
}
pub fn status(app: &App) -> Value {
    let db = app.db.read().unwrap();
    let settings = db.device_settings["uuTakeover"].clone();
    let valid = db
        .networks
        .iter()
        .filter(|n| n.profile.is_some())
        .map(|n| n.id.clone())
        .collect();
    let mut s = state().lock().unwrap();
    let traffic = s.traffic(&valid, conwu_core::unix_seconds());
    let (phase, message) = if !cfg!(windows) {
        ("Unsupported", "本平台暂不支持 UU 选路接管")
    } else if settings["enabled"] != true {
        ("Disabled", "接管未开启")
    } else if !s.error.is_empty() {
        ("Error", s.error.as_str())
    } else if s.active && !s.observation_error.is_empty() {
        (
            "ObservationUnavailable",
            "规则已就绪，暂时无法确认 UU 流量归属",
        )
    } else if s.active {
        if traffic["trafficObserved"] == true {
            ("Transmitting", "已检测到 UU 持续经由 ConWU 传输")
        } else if traffic["sessionConfirmed"] == true {
            ("Idle", "本轮规则已检测到 UU 流量，当前流量较低")
        } else {
            ("Ready", "选路规则已就绪；重新连接 UU 会话后确认实际流量")
        }
    } else if s.eligible.is_empty() {
        if s.route_pending.is_empty() {
            ("WaitingNetwork", "等待 ConWU 网络直连")
        } else {
            ("WaitingRoute", "等待 Windows 路由指向对应的 ConWU 网卡")
        }
    } else if s.pids.is_empty() {
        ("WaitingUu", "等待 UU 启动")
    } else {
        ("Applying", "正在恢复 UU 选路规则")
    };
    json!({"supported":cfg!(windows),"settings":settings,"revision":revision(&settings),"state":phase,
        "message":message,"rulesActive":s.active,"processes":s.pids,"sessionId":s.generation,
        "observationAvailable":s.owners.is_some(),"routePending":s.route_pending,
        "confirmationScope":"currentRules","trafficObserved":traffic["trafficObserved"],
        "sessionConfirmed":traffic["sessionConfirmed"],"networks":traffic["networks"],
        "sentBytes":traffic["sentBytes"],"receivedBytes":traffic["receivedBytes"]})
}
pub async fn configure(app: &App, action: Value) -> Result<Value> {
    ensure!(cfg!(windows), "UU 远程接管目前支持 Windows");
    let mut next = app.db.read().unwrap().clone();
    let settings = json!({"enabled":action["settings"]["enabled"].as_bool().unwrap_or(false),"automatic":true});
    if let Some(expected) = action["expectedRevision"].as_str() {
        ensure!(
            expected == revision(&next.device_settings["uuTakeover"]),
            "UU 设置已改变，请刷新"
        );
    }
    next.device_settings["uuTakeover"] = settings;
    app.commit(next)?;
    Ok(Value::Null)
}
pub fn observe(id: &str, p: &[u8], outbound: bool) {
    let Some(flow) = Flow::from_packet(p, outbound) else {
        return;
    };
    let mut s = state().lock().unwrap();
    let addresses_match = s
        .eligible
        .get(id)
        .is_some_and(|path| path.local_ip == *flow.local.ip() && path.peer_ip == *flow.peer.ip());
    if !s.active || !addresses_match || !s.owners.as_ref().is_some_and(|o| o.contains(&flow)) {
        return;
    }
    s.networks.entry(id.into()).or_default().record(
        p.len() as u64,
        outbound,
        conwu_core::unix_seconds(),
    );
}

#[cfg(windows)]
fn connected_paths(app: &App) -> (BTreeMap<String, ConnectedPath>, Vec<String>) {
    let enabled_networks = {
        let db = app.db.read().unwrap();
        if db.device_settings["uuTakeover"]["enabled"] != true {
            return (BTreeMap::new(), vec![]);
        }
        db.networks
            .iter()
            .filter_map(|n| {
                let profile = n.profile.as_ref()?;
                let peer = crate::runtime::remote_member(profile)?;
                let local_ip = profile.local_ip().ok()?;
                let peer_ip = crate::runtime::member_ip(profile, &peer).ok()?;
                (n.enabled && !n.paused).then(|| (n.id.clone(), local_ip, peer_ip))
            })
            .collect::<Vec<_>>()
    };
    let mut paths = BTreeMap::new();
    let mut pending = vec![];
    for (id, local_ip, peer_ip) in enabled_networks {
        let Some(running) = app.engine.current(&id) else {
            continue;
        };
        let path = {
            let metrics = running.metrics.read().unwrap();
            (metrics.connected && !metrics.peer_paused).then(|| ConnectedPath {
                local_ip,
                peer_ip,
                boot: running.boot,
                since: metrics.since,
                endpoint: metrics.endpoint.clone(),
            })
        };
        if let Some(path) = path {
            if running.routes_to_peer(local_ip, peer_ip) {
                paths.insert(id, path);
            } else {
                pending.push(id);
            }
        }
    }
    (paths, pending)
}

#[cfg(windows)]
pub fn start(app: Arc<App>) {
    let tracker = app.engine.tracker.clone();
    tracker.spawn(async move {
        let mut gate: Option<Gate> = None;
        let scanner = Arc::new(Mutex::new(identity::Scanner::default()));
        let mut rules = None;
        let mut retry_at = Instant::now();
        let mut failures = 0u32;
        loop {
            if app.engine.cancel.is_cancelled() { break; }
            let (paths, route_pending) = connected_paths(&app);
            let result = if paths.is_empty() {
                *scanner.lock().unwrap() = identity::Scanner::default();
                Ok(vec![])
            } else {
                let scanner = scanner.clone();
                tokio::task::spawn_blocking(move || scanner.lock().unwrap().poll())
                    .await.unwrap_or_else(|error| Err(error.into()))
            };
            match result {
                Ok(processes) => {
                    let next = RuleInputs::new(processes.iter().map(|p| p.pid).collect(), &paths);
                    let changed = rules.as_ref() != Some(&next);
                    {
                        let mut s = state().lock().unwrap();
                        if changed {
                            s.reset_rules();
                            s.error.clear();
                            s.pids = next.pids.clone();
                        }
                        // An outer route change only invalidates that network's evidence.
                        s.sync_paths(paths);
                        s.route_pending = route_pending;
                    }
                    if changed {
                        gate.take();
                        failures = 0;
                        retry_at = Instant::now();
                    }
                    if !next.pids.is_empty() && gate.is_none() && Instant::now() >= retry_at {
                        match Gate::open(&app.engine.components, &next.addresses, &processes) {
                            Ok(g) => {
                                gate = Some(g);
                                let mut s = state().lock().unwrap();
                                s.active = true; s.error.clear(); s.generation += 1;
                            }
                            Err(error) => {
                                state().lock().unwrap().error = error.to_string();
                                failures = failures.saturating_add(1);
                                retry_at = Instant::now() + retry_delay(failures);
                            }
                        }
                    }
                    if gate.is_some() {
                        let snapshot = owners(&next.pids);
                        let mut s = state().lock().unwrap();
                        match snapshot {
                            Ok(owners) => {
                                failures = 0;
                                s.owners = Some(owners);
                                s.observation_error.clear();
                            }
                            Err(error) => s.lose_observation(error.to_string()),
                        }
                    }
                    rules = Some(next);
                }
                Err(error) => {
                    gate.take();
                    rules = None;
                    let mut s = state().lock().unwrap();
                    s.reset_rules(); s.pids.clear(); s.error = error.to_string();
                    s.route_pending = route_pending;
                }
            }
            tokio::select! { _=app.engine.cancel.cancelled()=>break, _=tokio::time::sleep(Duration::from_millis(500))=>{} }
        }
        drop(gate);
        let mut s = state().lock().unwrap(); s.reset_rules(); s.pids.clear(); s.error.clear();
    });
}
#[cfg(not(windows))]
pub fn start(_: Arc<App>) {}

#[cfg(any(windows, test))]
fn retry_delay(failures: u32) -> Duration {
    Duration::from_millis((500u64 << failures.min(5)).min(15000))
}
#[cfg(windows)]
use windows::{Gate, owners};
#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        ffi::{CString, c_void},
        path::Path,
    };
    type Open = unsafe extern "C" fn(*const i8, i32, i16, u64) -> *mut c_void;
    type Close = unsafe extern "C" fn(*mut c_void) -> i32;
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetExtendedTcpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            kind: i32,
            reserved: u32,
        ) -> u32;
        fn GetExtendedUdpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            kind: i32,
            reserved: u32,
        ) -> u32;
    }
    pub struct Gate {
        _library: libloading::Library,
        handle: *mut c_void,
        close: Close,
        _processes: Vec<identity::Process>,
    }
    // Only the polling owner opens/closes these handles. OS handle lifetime is
    // pinned throughout rule ownership; no pointer references Rust memory.
    unsafe impl Send for Gate {}
    impl Gate {
        pub fn open(
            components: &Path,
            addresses: &[Ipv4Addr],
            processes: &[identity::Process],
        ) -> Result<Self> {
            ensure!(
                processes.len() <= 32 && addresses.len() <= 32,
                "UU 选路规则过大"
            );
            ensure!(
                processes.iter().all(identity::Process::running),
                "UU 进程已改变"
            );
            let path = std::path::absolute(components.join("WinDivert.dll"))?;
            let library: libloading::Library =
                unsafe { libloading::os::windows::Library::load_with_flags(path, 0x1100)? }.into();
            let (open, close) = unsafe {
                (
                    *library.get::<Open>(b"WinDivertOpen\0")?,
                    *library.get::<Close>(b"WinDivertClose\0")?,
                )
            };
            let pid = processes
                .iter()
                .map(|p| format!("processId == {}", p.pid))
                .collect::<Vec<_>>()
                .join(" or ");
            let ips = addresses
                .iter()
                .map(|ip| format!("localAddr != {ip}"))
                .collect::<Vec<_>>()
                .join(" and ");
            let filter = CString::new(format!(
                "({pid}) and event == 3 and {ips} and localAddr != 0.0.0.0 and localAddr != 127.0.0.1 and localAddr != :: and localAddr != ::1"
            ))?;
            let handle = unsafe { open(filter.as_ptr(), 3, 0, 2 | 4) };
            if handle as isize == -1 {
                anyhow::bail!("UU 选路规则启用失败：{}", std::io::Error::last_os_error())
            }
            Ok(Self {
                _library: library,
                handle,
                close,
                _processes: processes.to_vec(),
            })
        }
    }
    impl Drop for Gate {
        fn drop(&mut self) {
            unsafe {
                (self.close)(self.handle);
            }
        }
    }
    fn socket_address(
        entry: &[u8],
        ipv6: bool,
        deny_ambiguous: bool,
    ) -> Option<std::net::SocketAddrV4> {
        let ip = if ipv6 {
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&entry[..16]).unwrap());
            if deny_ambiguous && ip.is_unspecified() {
                Ipv4Addr::UNSPECIFIED
            } else {
                ip.to_ipv4_mapped()?
            }
        } else {
            Ipv4Addr::from(<[u8; 4]>::try_from(&entry[..4]).unwrap())
        };
        let at = entry.len() - 4;
        let port = u16::from_be_bytes([entry[at], entry[at + 1]]);
        Some(std::net::SocketAddrV4::new(ip, port))
    }

    pub fn owners(pids: &[u32]) -> Result<SocketOwners> {
        use windows_sys::Win32::{
            NetworkManagement::IpHelper::MIB_TCP_STATE_ESTAB,
            Networking::WinSock::{AF_INET, AF_INET6},
        };
        let mut owners = SocketOwners::default();
        for (tcp, ipv6, width) in [
            (false, false, 12),
            (true, false, 24),
            (false, true, 28),
            (true, true, 56),
        ] {
            let family = u32::from(if ipv6 { AF_INET6 } else { AF_INET });
            let mut size = 0;
            let table = |p, size: &mut u32| unsafe {
                if tcp {
                    GetExtendedTcpTable(p, size, 0, family, 5, 0)
                } else {
                    GetExtendedUdpTable(p, size, 0, family, 1, 0)
                }
            };
            let code = table(std::ptr::null_mut(), &mut size);
            if ipv6 && matches!(code, 50 | 10047) {
                continue;
            }
            ensure!(
                matches!(code, 0 | 122) && size <= 16 * 1024 * 1024,
                "套接字归属查询失败"
            );
            let mut bytes = vec![];
            for _ in 0..3 {
                ensure!(
                    (4..=16 * 1024 * 1024).contains(&size),
                    "套接字归属表大小无效"
                );
                bytes.resize(size as usize, 0);
                let code = table(bytes.as_mut_ptr().cast(), &mut size);
                if code == 0 {
                    break;
                }
                ensure!(code == 122, "套接字归属查询失败：{code}");
                bytes.clear();
            }
            ensure!(
                size >= 4 && bytes.len() >= size as usize,
                "套接字归属表变化，请重试"
            );
            let count = u32::from_ne_bytes(bytes[..4].try_into()?) as usize;
            ensure!(count <= (size as usize - 4) / width, "套接字表截断");

            // MIB_TCPROW_OWNER_PID starts with the state; TCP6 stores it after
            // the addresses. All four OWNER_PID table types end with the PID.
            let addr_len = if ipv6 { 24 } else { 8 };
            let base = if tcp && !ipv6 { 4 } else { 0 };
            for row in bytes[4..4 + count * width].chunks_exact(width) {
                let pid = u32::from_ne_bytes(row[width - 4..].try_into().unwrap());
                let uu = pids.contains(&pid);
                // A v6 wildcard may be v6-only; it may also conflict with
                // an IPv4 UDP socket. Count it conservatively for conflicts.
                let Some(local) = socket_address(&row[base..base + addr_len], ipv6, !uu && !tcp)
                else {
                    continue;
                };
                if !tcp {
                    owners.add_udp(local, uu);
                    continue;
                }
                let state_offset = if ipv6 { width - 8 } else { 0 };
                let state =
                    i32::from_ne_bytes(row[state_offset..state_offset + 4].try_into().unwrap());
                if state == MIB_TCP_STATE_ESTAB {
                    let peer = &row[base + addr_len..base + 2 * addr_len];
                    if let Some(peer) = socket_address(peer, ipv6, false) {
                        owners.add_tcp(local, peer, uu);
                    }
                }
            }
        }
        Ok(owners)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path(ip: Ipv4Addr) -> ConnectedPath {
        ConnectedPath {
            local_ip: ip,
            peer_ip: Ipv4Addr::new(10, 0, 0, 1),
            boot: uuid::Uuid::new_v4(),
            since: 10,
            endpoint: "192.0.2.1:1234".into(),
        }
    }

    #[test]
    fn rule_replacement_and_deleted_networks_cannot_reuse_traffic_confirmation() {
        let valid = HashSet::from(["current".to_string()]);
        let paths = BTreeMap::from([("current".to_string(), path(Ipv4Addr::new(10, 0, 0, 2)))]);
        let mut s = State {
            active: true,
            eligible: paths.clone(),
            owners: Some(SocketOwners::default()),
            ..State::default()
        };
        s.networks.insert(
            "deleted".into(),
            Counters {
                sent: 999999,
                ..Counters::default()
            },
        );
        let mut traffic = Counters::default();
        // Short, authenticated packets qualify when their combined rate is sustained.
        for second in [98, 99] {
            for _ in 0..128 {
                traffic.record(256, true, second);
            }
        }
        assert!(traffic.confirmed);
        s.networks.insert("current".into(), traffic);
        let report = s.traffic(&valid, 100);
        assert_eq!(report["trafficObserved"], true);
        assert_eq!(report["sentBytes"], 65536);
        assert_eq!(report["networks"].as_array().unwrap().len(), 1);
        assert_eq!(s.traffic(&valid, 110)["trafficObserved"], false);
        assert_eq!(s.traffic(&valid, 110)["sessionConfirmed"], true);
        s.reset_rules();
        s.active = true;
        s.owners = Some(SocketOwners::default());
        s.sync_paths(paths);
        let report = s.traffic(&valid, 110);
        assert_eq!(report["trafficObserved"], false);
        assert_eq!(report["sessionConfirmed"], false);
        assert_eq!(report["sentBytes"], 65536);
        assert_eq!(retry_delay(1), Duration::from_secs(1));
        assert_eq!(retry_delay(u32::MAX), Duration::from_secs(15));
    }

    #[test]
    fn endpoint_changes_reset_only_that_network_without_rebuilding_socket_rules() {
        let mut paths = BTreeMap::from([
            ("moving".to_owned(), path(Ipv4Addr::new(10, 0, 0, 2))),
            ("other".to_owned(), path(Ipv4Addr::new(10, 0, 1, 2))),
        ]);
        let pids = vec![42, 44];
        let rules = RuleInputs::new(pids.clone(), &paths);
        let mut state = State {
            active: true,
            generation: 1,
            eligible: paths.clone(),
            owners: Some(SocketOwners::default()),
            ..State::default()
        };
        for id in paths.keys() {
            state.networks.insert(
                id.clone(),
                Counters {
                    received: 65536,
                    confirmed: true,
                    buckets: BTreeMap::from([(98, 32768), (99, 32768)]),
                    ..Counters::default()
                },
            );
        }
        paths.get_mut("moving").unwrap().endpoint = "192.0.2.2:4321".into();
        assert_eq!(RuleInputs::new(pids.clone(), &paths), rules);
        let valid = paths.keys().cloned().collect();
        state.sync_paths(paths.clone());
        let traffic = state.traffic(&valid, 100);
        let rows = traffic["networks"].as_array().unwrap();
        assert_eq!(rows[0]["id"], "moving");
        assert_eq!(rows[0]["trafficObserved"], false);
        assert_eq!(rows[0]["sessionConfirmed"], false);
        assert_eq!(rows[0]["receivedBytes"], 65536);
        assert_eq!(rows[1]["sessionConfirmed"], true);
        assert_eq!(rows[1]["trafficObserved"], true);
        assert_eq!(state.generation, 1);
        paths.get_mut("moving").unwrap().local_ip = Ipv4Addr::new(10, 0, 0, 3);
        assert_ne!(RuleInputs::new(pids, &paths), rules);
        assert_ne!(RuleInputs::new(vec![42], &state.eligible), rules);
    }

    #[test]
    fn transient_socket_query_failure_keeps_the_gate_and_clears_recent_evidence() {
        let id = "current".to_owned();
        let mut observed = Counters::default();
        observed.record(32768, false, 98);
        observed.record(32768, false, 99);
        let mut state = State {
            active: true,
            generation: 3,
            owners: Some(SocketOwners::default()),
            eligible: BTreeMap::from([(id.clone(), path(Ipv4Addr::new(10, 0, 0, 2)))]),
            networks: BTreeMap::from([(id.clone(), observed)]),
            ..State::default()
        };
        let valid = HashSet::from([id]);
        assert_eq!(state.traffic(&valid, 100)["trafficObserved"], true);
        state.lose_observation("socket table changed".into());
        assert!(state.active);
        assert_eq!(state.generation, 3);
        assert_eq!(state.traffic(&valid, 100)["sessionConfirmed"], false);
        state.owners = Some(SocketOwners::default());
        state.observation_error.clear();
        let status = state.traffic(&valid, 100);
        assert_eq!(status["trafficObserved"], false);
        assert_eq!(status["sessionConfirmed"], true);
        assert_eq!(status["receivedBytes"], 65536);
    }

    #[cfg(windows)]
    #[test]
    fn windows_socket_table_matches_real_udp_bind_and_tcp_connection() -> Result<()> {
        use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};

        fn ipv4(addr: SocketAddr) -> SocketAddrV4 {
            let SocketAddr::V4(addr) = addr else {
                panic!("expected IPv4")
            };
            addr
        }
        fn matches(
            owners: &SocketOwners,
            proto: u8,
            local: SocketAddrV4,
            peer: SocketAddrV4,
        ) -> bool {
            let mut packet = [0u8; 40];
            packet[0] = 0x45;
            packet[9] = proto;
            packet[12..16].copy_from_slice(&local.ip().octets());
            packet[16..20].copy_from_slice(&peer.ip().octets());
            packet[20..22].copy_from_slice(&local.port().to_be_bytes());
            packet[22..24].copy_from_slice(&peer.port().to_be_bytes());
            owners.contains(&Flow::from_packet(&packet, true).unwrap())
        }

        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (accepted, _) = listener.accept()?;
        let udp_local = ipv4(udp.local_addr()?);
        let local = ipv4(client.local_addr()?);
        let peer = ipv4(accepted.local_addr()?);
        let owned = windows::owners(&[std::process::id()])?;
        assert!(matches(&owned, sockets::UDP, udp_local, peer));
        assert!(!matches(
            &owned,
            sockets::UDP,
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), udp_local.port()),
            peer
        ));
        assert!(matches(&owned, sockets::TCP, local, peer));
        assert!(!matches(
            &owned,
            sockets::TCP,
            local,
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), peer.port())
        ));
        assert!(!matches(&windows::owners(&[])?, sockets::TCP, local, peer));
        Ok(())
    }
}
