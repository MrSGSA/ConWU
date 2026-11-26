use anyhow::{Result, ensure};
use conwu_core::{crypto as c, identity::Profile};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROJECTION_PORT: u16 = 46424;
pub const TCP_STUN: &[&str] = &[
    "fwa.lifesizecloud.com:3478",
    "stun.nextcloud.com:3478",
    "stun.sipnet.com:3478",
    "global.turn.twilio.com:3478",
];
pub fn default_tcp_stun() -> Vec<String> {
    let mut result: Vec<String> = TCP_STUN.iter().map(|s| s.to_string()).collect();
    for server in include_str!("../../../assets/tcp-stun-snapshot.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
    {
        if !result.iter().any(|old| old.eq_ignore_ascii_case(server)) {
            result.push(server.to_owned());
        }
    }
    result
}
pub const PKARR: &[&str] = &["https://pkarr.pubky.app", "https://pkarr.pubky.org"];
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    #[serde(alias = "PeerSlot")]
    pub peer_slot: i16,
    #[serde(alias = "Source")]
    pub source: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub service: String,
    pub certificate_pin: String,
    pub manual_endpoint: String,
    pub path_selection: String,
    pub listen_port: u16,
    pub source_port: u16,
    pub stream_flow_lanes: bool,
    pub tcp_peer_reflexive: bool,
    pub connection_source: String,
    pub direct_mode: bool,
    pub discovery_mode: String,
    pub existing_entries: Vec<Entry>,
    pub entry_refresh_seconds: u64,
    pub tcp_stun: Vec<String>,
    pub pkarr_gateways: Vec<String>,
    pub pkarr_publish: bool,
    pub allow_manual_quality_requests: bool,
    pub requested_virtual_ip: String,
    pub pairing_service: String,
    pub pairing_certificate_pin: String,
    pub coordinator_backup: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            service: String::new(),
            certificate_pin: String::new(),
            manual_endpoint: String::new(),
            path_selection: "faketcp-only".into(),
            listen_port: 44680,
            source_port: 44691,
            stream_flow_lanes: false,
            tcp_peer_reflexive: true,
            connection_source: "custom".into(),
            direct_mode: true,
            discovery_mode: "pkarr".into(),
            existing_entries: vec![],
            entry_refresh_seconds: 60,
            tcp_stun: default_tcp_stun(),
            pkarr_gateways: PKARR.iter().map(|s| s.to_string()).collect(),
            pkarr_publish: true,
            allow_manual_quality_requests: false,
            requested_virtual_ip: String::new(),
            pairing_service: String::new(),
            pairing_certificate_pin: String::new(),
            coordinator_backup: false,
            extra: BTreeMap::new(),
        }
    }
}
impl Settings {
    pub fn new_network() -> Self {
        Self { discovery_mode: "coordinator".into(), direct_mode: false, pkarr_publish: false, ..Self::default() }
    }

    pub fn mode(&self) -> Result<&str> {
        let m = self.path_selection.strip_suffix("-only").unwrap_or("");
        ensure!(
            conwu_core::code::valid_mode(m) && m != "udp",
            "请选择当前六种固定连接协议"
        );
        Ok(m)
    }
    pub fn validate(&self) -> Result<()> {
        self.mode()?;
        ensure!(
            self.listen_port >= 1024
                && self.source_port >= 1024
                && self.listen_port != self.source_port,
            "监听端口与源端口必须是不同的1024–65535端口"
        );
        ensure!(
            matches!(self.connection_source.as_str(), "custom" | "existing"),
            "连接方式无效"
        );
        ensure!(
            matches!(
                self.discovery_mode.as_str(),
                "pkarr" | "coordinator" | "direct" | "existing"
            ),
            "发现方式无效"
        );
        crate::discovery::validate_service(&self.service)?;
        crate::discovery::validate_service(&self.pairing_service)?;
        for pin in [&self.certificate_pin, &self.pairing_certificate_pin] {
            ensure!(
                pin.is_empty() || pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit()),
                "证书 SHA-256 指纹应为64位十六进制字符"
            );
        }
        ensure!(
            self.tcp_stun.len() <= 256 && self.pkarr_gateways.len() <= 8,
            "发现服务器过多"
        );
        for server in &self.tcp_stun {
            crate::discovery::validate_endpoint(server)?;
        }
        for gateway in &self.pkarr_gateways {
            let url = url::Url::parse(gateway)?;
            ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "PKARR 网关应为 HTTPS 地址"
            );
        }
        if !self.requested_virtual_ip.is_empty() {
            let ip: std::net::Ipv4Addr = self.requested_virtual_ip.parse()?;
            ensure!(
                ip.is_private() && !matches!(ip.octets()[3], 0 | 255),
                "虚拟IP须为私网可用地址"
            );
        }
        if !self.manual_endpoint.is_empty() {
            crate::discovery::validate_endpoint(&self.manual_endpoint)?;
        }
        ensure!(
            (1..=86400).contains(&self.entry_refresh_seconds) && self.existing_entries.len() <= 12,
            "入口或刷新间隔超过限制"
        );
        for e in &self.existing_entries {
            ensure!(
                (-2..=254).contains(&e.peer_slot)
                    && !e.source.is_empty()
                    && e.source.len() <= 2048
                    && !e.source.chars().any(char::is_control),
                "入口来源无效"
            );
            crate::discovery::validate_source(&e.source)?;
        }
        Ok(())
    }
    pub fn existing_only(&self) -> bool {
        self.connection_source == "existing" || !self.manual_endpoint.is_empty()
    }
    pub fn approved(&self, profile: &Profile, name: &str, entries: &[Entry]) -> Value {
        json!({"PathSelection":self.path_selection,"ConnectionSource":self.connection_source,"Entries":entries.iter().map(|e|json!({"PeerSlot":profile.member.slot,"Source":e.source})).collect::<Vec<_>>(),"EntryRefreshSeconds":self.entry_refresh_seconds,
            "TcpStun":self.tcp_stun,"CoordinatorBackup":false,"Service":self.service,"CertificatePin":self.certificate_pin,"HostListenPort":self.listen_port,
            "StreamFlowLanes":self.stream_flow_lanes,"NetworkName":name,"DiscoveryMode":self.discovery_mode,"PairingService":self.pairing_service,"PairingCertificatePin":self.pairing_certificate_pin,"PkarrGateways":self.pkarr_gateways})
    }
    pub fn inherit(&mut self, profile: &Profile, approved: &Value) -> Result<()> {
        ensure!(
            approved["PathSelection"] == format!("{}-only", profile.pair.mode),
            "获批身份和主机协议不一致"
        );
        self.path_selection = format!("{}-only", profile.pair.mode);
        self.connection_source = approved["ConnectionSource"]
            .as_str()
            .unwrap_or("existing")
            .into();
        self.discovery_mode = approved["DiscoveryMode"]
            .as_str()
            .unwrap_or("existing")
            .into();
        self.direct_mode = profile.pair.direct;
        self.service = approved["Service"].as_str().unwrap_or("").into();
        self.certificate_pin = approved["CertificatePin"].as_str().unwrap_or("").into();
        self.stream_flow_lanes = approved["StreamFlowLanes"].as_bool().unwrap_or(false);
        if let Ok(servers) = serde_json::from_value(approved["TcpStun"].clone()) {
            self.tcp_stun = servers;
        }
        self.entry_refresh_seconds = approved["EntryRefreshSeconds"].as_u64().unwrap_or(60);
        self.existing_entries =
            serde_json::from_value(approved["Entries"].clone()).unwrap_or_default();
        for e in &mut self.existing_entries {
            ensure!(
                e.peer_slot == profile.introducer_slot as i16,
                "主机入口归属不符"
            );
            e.peer_slot = -1;
        }
        if let Ok(v) = serde_json::from_value(approved["PkarrGateways"].clone()) {
            self.pkarr_gateways = v;
        }
        self.validate()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyAdapter {
    pub owner: String,
    pub network: String,
    pub slot: u8,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ProjectionSettings {
    pub port: u16,
    pub allowed: bool,
    pub files: bool,
    pub file_browser: bool,
    pub clipboard: bool,
    pub video: ProjectionVideo,
}
impl Default for ProjectionSettings {
    fn default() -> Self {
        Self {
            port: PROJECTION_PORT,
            allowed: false,
            files: false,
            file_browser: false,
            clipboard: false,
            video: ProjectionVideo::default(),
        }
    }
}
impl ProjectionSettings {
    pub fn validate(self, network: &Settings) -> Result<()> {
        ensure!(self.port >= 1024 && (!self.allowed || ![network.source_port, network.listen_port].contains(&self.port)),
            "Projection 端口须为1024–65535，启用远控时须与组网端口区分");
        self.video.validate()
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectionCodec {
    #[default]
    Auto,
    H264,
    Hevc,
    Av1,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ProjectionVideo {
    pub width: u16,
    pub height: u16,
    pub fps: u16,
    pub resolution_mode: ProjectionResolution,
    pub bitrate_mbps: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitrate_preset: Option<ProjectionBitrate>,
    pub codec: ProjectionCodec,
    pub scale_percent: u8,
}

impl Default for ProjectionVideo {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps: 60,
            resolution_mode: ProjectionResolution::Custom,
            bitrate_mbps: 20,
            bitrate_preset: Some(ProjectionBitrate::Medium),
            codec: ProjectionCodec::Auto,
            scale_percent: 100,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProjectionResolution {
    Local,
    Peer,
    #[default]
    Custom,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectionBitrate {
    Low,
    #[default]
    Medium,
    High,
}

impl ProjectionVideo {
    pub fn validate(self) -> Result<()> {
        ensure!((640..=7680).contains(&self.width) && (360..=4320).contains(&self.height)
            && self.width % 2 == 0 && self.height % 2 == 0, "分辨率宽高须为偶数，支持 640×360 至 7680×4320");
        ensure!((15..=240).contains(&self.fps), "帧率须为 15–240 FPS");
        ensure!((5..=200).contains(&self.bitrate_mbps), "码率须为 5–200 Mb/s");
        ensure!([50, 75, 100].contains(&self.scale_percent), "播放缩放支持 50%、75% 和 100%");
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn bitrate_kbps(self, width: u16, height: u16) -> u32 {
        let Some(preset) = self.bitrate_preset else {
            return u32::from(self.bitrate_mbps) * 1000;
        };
        // Match Moonlight's default resolution table and sub-linear scaling above 60 FPS.
        const POINTS: [(u32, f64); 6] = [
            (640 * 360, 1.0),
            (854 * 480, 2.0),
            (1280 * 720, 5.0),
            (1920 * 1080, 10.0),
            (2560 * 1440, 20.0),
            (3840 * 2160, 40.0),
        ];
        let pixels = u32::from(width) * u32::from(height);
        let factor = POINTS.windows(2)
            .find(|pair| pixels <= pair[1].0)
            .map_or(40.0, |pair| {
                let [(start, low), (end, high)] = [pair[0], pair[1]];
                low + (high - low) * f64::from(pixels.saturating_sub(start)) / f64::from(end - start)
            });
        let fps = f64::from(self.fps);
        let scale = if fps <= 60.0 { fps / 30.0 } else { 2.0 * (fps / 60.0).sqrt() };
        let base = (factor * scale).round();
        let multiplier = match preset {
            ProjectionBitrate::Low => 0.65,
            ProjectionBitrate::Medium => 1.0,
            ProjectionBitrate::High => 1.25,
        };
        ((base * multiplier * 1000.0).round() as u32).clamp(500, 200_000)
    }
}

#[cfg(all(test, windows))]
mod projection_video_tests {
    use super::*;

    #[test]
    fn bitrate_respects_old_preferences_and_scales_new_presets() -> Result<()> {
        let old: ProjectionVideo = serde_json::from_value(json!({
            "width":1920,"height":1200,"fps":120,"bitrateMbps":40
        }))?;
        assert!(old.resolution_mode == ProjectionResolution::Custom);
        assert_eq!(old.bitrate_kbps(old.width, old.height), 40_000);
        let rate = |preset| ProjectionVideo {
            bitrate_preset: Some(preset),
            ..ProjectionVideo::default()
        }.bitrate_kbps(1920, 1080);
        assert_eq!(rate(ProjectionBitrate::Low), 13_000);
        assert_eq!(rate(ProjectionBitrate::Medium), 20_000);
        assert_eq!(rate(ProjectionBitrate::High), 25_000);
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Network {
    #[serde(default)]
    pub projection: ProjectionSettings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_adapter: Option<LegacyAdapter>,
    #[serde(default)]
    pub creation_operation: String,
    #[serde(default)]
    pub creation_digest: String,
    pub id: String,
    pub name: String,
    pub configuration_id: String,
    pub settings: Settings,
    pub profile: Option<Profile>,
    pub enabled: bool,
    pub paused: bool,
    pub created_here: bool,
    pub created_at: i64,
    #[serde(default)]
    pub approved_settings: Option<Value>,
    #[serde(default)]
    pub peer_name: String,
    #[serde(default)]
    pub pkarr_seed: String,
    #[serde(default)]
    pub pkarr_sequence: i64,
    #[serde(default)]
    pub peer_pkarr: String,
    #[serde(default)]
    pub bootstrap: Vec<String>,
}
impl Network {
    pub fn is_join_request(&self) -> bool {
        !self.created_here && self.profile.is_none() && self.enabled
    }

    pub fn is_revoked(&self) -> bool {
        // Earlier Rust releases also persisted received revocations this way.
        !self.created_here && self.profile.is_none() && !self.enabled
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    pub id: String,
    pub name: String,
    pub revision: u64,
    pub settings: Settings,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Database {
    pub schema: u32,
    pub device_name: String,
    pub node_private: String,
    pub log_level: String,
    pub selected_network_id: String,
    pub device_settings: Value,
    pub networks: Vec<Network>,
    pub configurations: Vec<Configuration>,
    pub departures: Vec<PendingDeparture>,
    pub rejoin_credentials: Vec<conwu_core::rejoin::Credential>,
    pub rejoin_history: BTreeMap<String, Vec<conwu_core::rejoin::History>>,
}
impl Database {
    pub fn configuration_slots(&self) -> usize {
        self.configurations.len() + self.networks.iter().filter(|n| n.is_join_request()).count()
    }

    pub fn remove_network(&mut self, network: &Network) {
        self.networks.retain(|n| n.id != network.id);
        if !self.networks.iter().any(|n| n.configuration_id == network.configuration_id) {
            self.configurations.retain(|c| c.id != network.configuration_id);
        }
        if self.selected_network_id == network.id {
            self.selected_network_id.clear();
        }
        self.rejoin_history.remove(&network.id);
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingDeparture {
    pub id: String,
    pub notice: conwu_core::departure::Notice,
    pub owner_key: String,
    pub mode: String,
    pub pin: String,
    pub entries: Vec<Entry>,
    pub bootstrap: Vec<String>,
    #[serde(default = "default_gateways")]
    pub pkarr_gateways: Vec<String>,
}
fn default_gateways() -> Vec<String> {
    PKARR.iter().map(|s| s.to_string()).collect()
}
pub fn default_device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "ConWU".into())
}
pub fn default_device_settings() -> Value {
    json!({"autoStart":false,"coordinator":{"enabled":false,"listenUrl":"https://0.0.0.0:1145","certificateFile":"","certificateKeyFile":""},"uuTakeover":{"enabled":false,"automatic":true}})
}

impl Default for Database {
    fn default() -> Self {
        Self {
            schema: 1,
            device_name: default_device_name(),
            node_private: c::new_private().expect("system P256 key generation"),
            log_level: "info".into(),
            selected_network_id: String::new(),
            device_settings: default_device_settings(),
            networks: vec![],
            configurations: vec![],
            departures: vec![],
            rejoin_credentials: vec![],
            rejoin_history: BTreeMap::new(),
        }
    }
}
