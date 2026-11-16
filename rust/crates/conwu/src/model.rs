use anyhow::{Result, ensure};
use conwu_core::{crypto as c, identity::Profile};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const VERSION: &str = "1.4.5-rust.1";
pub const TCP_STUN: &[&str] = &[
    "stun.nextcloud.com:3478",
    "fwa.lifesizecloud.com:3478",
    "stun.sipnet.com:3478",
    "global.turn.twilio.com:3478",
];
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
    pub port_control_mapping: bool,
    pub connection_source: String,
    pub direct_mode: bool,
    pub discovery_mode: String,
    pub existing_entries: Vec<Entry>,
    pub entry_refresh_seconds: u64,
    pub tcp_stun: Vec<String>,
    pub udp_stun: Vec<String>,
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
            port_control_mapping: false,
            connection_source: "custom".into(),
            direct_mode: true,
            discovery_mode: "pkarr".into(),
            existing_entries: vec![],
            entry_refresh_seconds: 60,
            tcp_stun: TCP_STUN.iter().map(|s| s.to_string()).collect(),
            udp_stun: vec!["stun.nextcloud.com:3478".into()],
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
            self.tcp_stun.len() <= 8 && self.udp_stun.len() <= 8 && self.pkarr_gateways.len() <= 8,
            "发现服务器过多"
        );
        for server in self.tcp_stun.iter().chain(&self.udp_stun) {
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
            "TcpStun":self.tcp_stun,"UdpStun":self.udp_stun,"CoordinatorBackup":false,"Service":self.service,"CertificatePin":self.certificate_pin,"HostListenPort":self.listen_port,
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
        if let Ok(servers) = serde_json::from_value(approved["UdpStun"].clone()) {
            self.udp_stun = servers;
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
pub struct Network {
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
impl Default for Database {
    fn default() -> Self {
        Self {
            schema: 1,
            device_name: std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "ConWU".into()),
            node_private: c::new_private().expect("system P256 key generation"),
            log_level: "info".into(),
            selected_network_id: String::new(),
            device_settings: json!({"autoStart":false,"coordinator":{"enabled":false,"listenUrl":"https://0.0.0.0:1145","certificateFile":"","certificateKeyFile":""},"uuTakeover":{"enabled":false,"automatic":true}}),
            networks: vec![],
            configurations: vec![],
            departures: vec![],
        }
    }
}
