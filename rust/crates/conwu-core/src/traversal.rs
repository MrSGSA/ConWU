//! Existing signed v3 traversal contract. Control messages never authenticate a
//! business path; a prepared transport still needs MeshLink and path validation.
use crate::{
    crypto as c,
    identity::{Member, Profile},
    unix_seconds, valid_id,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Prediction {
    pub model_id: Uuid,
    pub stable_model: bool,
    pub ports: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Candidate {
    pub id: Uuid,
    pub version: i64,
    pub endpoint: String,
    pub observation_target: Option<String>,
    pub observed_at: i64,
    pub expires: i64,
    pub purpose: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prediction: Option<Prediction>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub peer_reflexive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploration: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub standby: bool,
}
fn is_false(v: &bool) -> bool {
    !*v
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Message {
    pub version: u8,
    pub message_id: Uuid,
    pub from_slot: u8,
    pub from_device: String,
    pub from_boot: Uuid,
    pub to_slot: u8,
    pub to_device: String,
    pub to_boot: Uuid,
    pub sequence: i64,
    pub attempt_id: Uuid,
    pub nomination_revision: i64,
    pub validation_nonce: Uuid,
    pub profile: u8,
    pub protocol_client_slot: u8,
    pub nominator_slot: u8,
    pub candidate: Option<Candidate>,
    pub peer_candidate: Option<Candidate>,
    pub stage: u8,
    pub expires: i64,
    pub signature: String,
}
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Capabilities {
    pub version: u8,
    pub native_abi: u8,
    pub boot_id: Uuid,
    pub profiles: Vec<u8>,
    pub background_upgrade: u8,
    pub udp_ipv6: u8,
    pub fake_tcp_ipv6: u8,
    #[serde(skip_serializing_if = "zero")]
    pub tcp_prediction: u8,
    #[serde(skip_serializing_if = "zero")]
    pub tcp_peer_reflexive: u8,
    #[serde(skip_serializing_if = "zero")]
    pub udp_exploration: u8,
    #[serde(skip_serializing_if = "zero")]
    pub quality_feedback: u8,
    #[serde(skip_serializing_if = "zero")]
    pub standby_paths: u8,
    #[serde(skip_serializing_if = "zero")]
    pub path_diagnostics: u8,
    #[serde(skip_serializing_if = "zero")]
    pub diagnostic_mbps: u8,
    #[serde(skip_serializing_if = "zero")]
    pub auto_quality: u8,
    #[serde(skip_serializing_if = "zero")]
    pub diagnostic_timing: u8,
    #[serde(skip_serializing_if = "zero")]
    pub udp_empirical_stability: u8,
}
fn zero(v: &u8) -> bool {
    *v == 0
}
impl Capabilities {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.native_abi <= 1
                && !self.boot_id.is_nil()
                && (1..=2).contains(&self.profiles.len())
                && self.profiles.iter().all(|p| matches!(p, 2 | 3))
                && self
                    .profiles
                    .iter()
                    .enumerate()
                    .all(|(i, p)| !self.profiles[..i].contains(p)),
            "打洞能力与启动代次无效"
        );
        for v in [
            self.background_upgrade,
            self.udp_ipv6,
            self.fake_tcp_ipv6,
            self.tcp_prediction,
            self.tcp_peer_reflexive,
            self.udp_exploration,
            self.quality_feedback,
            self.standby_paths,
            self.path_diagnostics,
            self.auto_quality,
            self.diagnostic_timing,
            self.udp_empirical_stability,
        ] {
            ensure!(v <= 1, "打洞能力版本不支持");
        }
        ensure!(
            !self.profiles.contains(&2) || self.native_abi == 1,
            "FakeTCP SO 需要原生 ABI"
        );
        ensure!(
            (self.fake_tcp_ipv6 == 0 && self.tcp_prediction == 0 && self.tcp_peer_reflexive == 0)
                || self.profiles.contains(&2),
            "TCP 扩展缺少对应协议"
        );
        ensure!(
            (self.udp_ipv6 == 0 && self.udp_exploration == 0) || self.profiles.contains(&3),
            "UDP 扩展缺少对应协议"
        );
        ensure!(
            self.udp_empirical_stability == 0 || self.udp_exploration == 1,
            "经验稳定性需要独立探索授权"
        );
        ensure!(
            self.path_diagnostics == 0 && self.diagnostic_mbps == 0
                || self.path_diagnostics == 1
                    && self.standby_paths == 1
                    && (1..=50).contains(&self.diagnostic_mbps),
            "诊断能力依赖无效"
        );
        ensure!(
            self.auto_quality == 0 || self.path_diagnostics == 1,
            "质量选择需要诊断授权"
        );
        ensure!(
            self.diagnostic_timing == 0 || self.path_diagnostics == 1,
            "诊断计时需要诊断授权"
        );
        Ok(())
    }
}
impl Prediction {
    pub fn ports(&self) -> Result<Vec<u16>> {
        ensure!(
            !self.model_id.is_nil() && self.ports.len() <= 47,
            "预测模型或端口窗口无效"
        );
        if self.ports.is_empty() {
            return Ok(vec![]);
        }
        let mut ports = vec![];
        for text in self.ports.split(',') {
            let port = text.parse::<u16>()?;
            ensure!(
                port >= 1024 && text == port.to_string() && ports.last().is_none_or(|p| *p < port),
                "预测端口需有序、唯一且为标准十进制"
            );
            ports.push(port);
        }
        ensure!(
            (1..=8).contains(&ports.len()) && (!self.stable_model || ports.len() == 1),
            "预测端口数量无效"
        );
        Ok(ports)
    }
}
fn endpoint(value: &str) -> Result<std::net::SocketAddr> {
    ensure!(value.len() <= 64, "打洞候选过长");
    let e = value.parse::<std::net::SocketAddr>()?;
    ensure!(crate::code::valid_endpoint(&e), "打洞候选不是有效单播入口");
    Ok(e)
}
impl Candidate {
    fn validate(&self, profile: u8, fresh: bool, now: i64) -> Result<()> {
        let ep = endpoint(&self.endpoint)?;
        if let Some(target) = &self.observation_target {
            ensure!(
                endpoint(target)?.is_ipv4() == ep.is_ipv4(),
                "观察与候选地址族不同"
            );
        }
        ensure!(
            !self.id.is_nil()
                && self.version > 0
                && self.observed_at > 0
                && self.observed_at <= now + 5
                && self.expires >= self.observed_at
                && self.expires <= self.observed_at + 180
                && (!fresh || self.observed_at >= now - 180 && self.expires > now)
                && (self.purpose == 4 || self.purpose == if profile == 3 { 3 } else { 2 }),
            "候选身份、协议或有效期无效"
        );
        if let Some(p) = &self.prediction {
            let ports = p.ports()?;
            ensure!(
                profile == 2
                    && self.purpose == 2
                    && ep.is_ipv4()
                    && (1..=2).contains(&self.version),
                "预测候选协议无效"
            );
            ensure!(
                if ports.is_empty() {
                    self.version == 1
                } else {
                    self.version == 2
                        && ports[0] == ep.port()
                        && self.expires <= self.observed_at + 8
                },
                "预测预约或最终窗口无效"
            );
        }
        ensure!(
            !self.peer_reflexive || profile == 2 && self.prediction.is_none() && ep.is_ipv4(),
            "来源学习需要独立 IPv4 SO 候选"
        );
        ensure!(
            !self.standby
                || self.prediction.is_none() && !self.peer_reflexive && self.exploration.is_none(),
            "备用不能复用高成本候选授权"
        );
        if let Some(exploration) = &self.exploration {
            ensure!(
                profile == 3
                    && self.purpose == 3
                    && ep.is_ipv4()
                    && self.prediction.is_none()
                    && !self.peer_reflexive
                    && exploration.is_object(),
                "探索候选协议无效"
            );
        }
        Ok(())
    }
}
impl Message {
    fn signed(&self, network: &str) -> Result<Vec<u8>> {
        c::signed_json(
            &json!({"domain":"streamlink-traversal-state-v1","network":network,
        "Version":self.version,"MessageId":self.message_id,"FromSlot":self.from_slot,"FromDevice":self.from_device,"FromBoot":self.from_boot,
        "ToSlot":self.to_slot,"ToDevice":self.to_device,"ToBoot":self.to_boot,"Sequence":self.sequence,"AttemptId":self.attempt_id,
        "NominationRevision":self.nomination_revision,"ValidationNonce":self.validation_nonce,"Profile":self.profile,
        "ProtocolClientSlot":self.protocol_client_slot,"NominatorSlot":self.nominator_slot,"Candidate":self.candidate,
        "PeerCandidate":self.peer_candidate,"Stage":self.stage,"Expires":self.expires}),
        )
    }
    pub fn validate(&self, now: i64) -> Result<()> {
        ensure!(
            self.version == 1
                && !self.message_id.is_nil()
                && (1..=254).contains(&self.from_slot)
                && (1..=254).contains(&self.to_slot)
                && self.from_slot != self.to_slot
                && valid_id(&self.from_device)
                && valid_id(&self.to_device)
                && self.from_device != self.to_device
                && !self.from_boot.is_nil()
                && !self.to_boot.is_nil()
                && self.sequence > 0
                && !self.attempt_id.is_nil()
                && self.nomination_revision > 0
                && !self.validation_nonce.is_nil()
                && matches!(self.profile, 2 | 3)
                && [self.from_slot, self.to_slot].contains(&self.protocol_client_slot)
                && [self.from_slot, self.to_slot].contains(&self.nominator_slot)
                && (1..=9).contains(&self.stage)
                && self.expires > now
                && self.expires <= now + 60
                && self.signature.len() <= 256,
            "打洞控制身份、阶段或期限无效"
        );
        ensure!(
            self.stage == 4 || self.candidate.is_some(),
            "此打洞阶段缺少候选"
        );
        ensure!(
            !matches!(self.stage, 2 | 3 | 5 | 6 | 7 | 8 | 9) || self.peer_candidate.is_some(),
            "此打洞阶段缺少候选对"
        );
        ensure!(
            self.stage != 1 || self.peer_candidate.is_none(),
            "Offer 不能自行指定候选对"
        );
        let fresh = !matches!(self.stage, 5 | 9);
        if let Some(c) = &self.candidate {
            c.validate(self.profile, fresh, now)?;
        }
        if let Some(c) = &self.peer_candidate {
            c.validate(self.profile, fresh, now)?;
        }
        if let (Some(a), Some(b)) = (&self.candidate, &self.peer_candidate) {
            ensure!(
                a.id != b.id
                    && a.standby == b.standby
                    && endpoint(&a.endpoint)?.is_ipv4() == endpoint(&b.endpoint)?.is_ipv4(),
                "候选对或备用授权不一致"
            );
        }
        ensure!(
            self.stage != 9 || self.candidate.as_ref().is_some_and(|c| c.standby),
            "Standby 需要独立备用授权"
        );
        Ok(())
    }
    pub fn sign(&mut self, profile: &Profile) -> Result<()> {
        self.validate(unix_seconds())?;
        ensure!(
            self.from_slot == profile.member.slot
                && self.from_device == profile.member.device
                && profile.directory.as_ref().is_some_and(|d| d
                    .members
                    .iter()
                    .any(|m| m.slot == self.to_slot && m.device == self.to_device)),
            "不能代其他成员发布打洞状态"
        );
        self.signature = c::sign(
            &profile.signing_private,
            &self.signed(&profile.pair.network)?,
        )?;
        Ok(())
    }
    pub fn verify(&self, network: &str, from: &Member, to: &Member) -> Result<()> {
        self.validate(unix_seconds())?;
        ensure!(
            self.from_slot == from.slot
                && self.from_device == from.device
                && self.to_slot == to.slot
                && self.to_device == to.device
                && c::verify(&from.signing_key, &self.signed(network)?, &self.signature),
            "打洞控制成员或签名无效"
        );
        Ok(())
    }
    pub fn fingerprint(&self, network: &str) -> Result<[u8; 32]> {
        Ok(c::hash(self.signed(network)?))
    }
}

/// Replays are idempotent only while both ID and signed bytes match. A reused
/// sequence or MessageId never gains a fresh TTL or a new transport allocation.
#[derive(Default, Clone)]
pub struct Inbox {
    network: String,
    rows: Vec<Message>,
    seen: HashMapKey,
}
type HashMapKey = std::collections::HashMap<(String, u8, Uuid), (i64, [u8; 32], i64)>;
impl Inbox {
    pub fn insert(
        &mut self,
        network: &str,
        directory: &crate::identity::Directory,
        batch: Vec<Message>,
    ) -> Result<()> {
        ensure!(
            valid_id(network) && batch.len() <= 7,
            "打洞消息批次或网络无效"
        );
        let mut next = self.clone();
        ensure!(
            next.network.is_empty() || next.network == network,
            "打洞邮箱不能跨网络复用"
        );
        next.network = network.into();
        for m in batch {
            next.insert_one(network, directory, m)?;
        }
        *self = next;
        Ok(())
    }
    fn insert_one(
        &mut self,
        network: &str,
        directory: &crate::identity::Directory,
        m: Message,
    ) -> Result<()> {
        let now = unix_seconds();
        self.rows.retain(|m| m.expires > now);
        self.seen.retain(|_, (_, _, expiry)| *expiry > now - 60);
        ensure!(self.seen.len() < 4096, "打洞重放表已满");
        let from = directory
            .members
            .iter()
            .find(|p| p.slot == m.from_slot)
            .ok_or_else(|| anyhow::anyhow!("发送成员已撤销"))?;
        let to = directory
            .members
            .iter()
            .find(|p| p.slot == m.to_slot)
            .ok_or_else(|| anyhow::anyhow!("接收成员已撤销"))?;
        m.verify(network, from, to)?;
        let key = (network.to_owned(), m.from_slot, m.message_id);
        let hash = m.fingerprint(network)?;
        if let Some((sequence, prior, _)) = self.seen.get(&key) {
            ensure!(
                *sequence == m.sequence && *prior == hash,
                "重复消息 ID 的签名内容已改变"
            );
        }
        if let Some(old) = self
            .rows
            .iter()
            .filter(|r| {
                r.from_slot == m.from_slot && r.to_slot == m.to_slot && r.from_boot == m.from_boot
            })
            .max_by_key(|r| r.sequence)
        {
            ensure!(
                m.sequence > old.sequence
                    || m.sequence == old.sequence && m.message_id == old.message_id,
                "打洞控制序号回退或冲突"
            );
        }
        self.seen
            .entry((network.into(), m.from_slot, m.message_id))
            .or_insert((m.sequence, m.fingerprint(network)?, m.expires));
        self.rows.retain(|old| {
            !(old.from_slot == m.from_slot
                && old.to_slot == m.to_slot
                && old.attempt_id == m.attempt_id)
        });
        self.rows.push(m);
        self.rows.sort_by_key(|r| r.sequence);
        if self.rows.len() > 14 {
            self.rows.drain(..self.rows.len() - 14);
        }
        Ok(())
    }
    pub fn snapshot(&mut self) -> Vec<Message> {
        self.rows.retain(|m| m.expires > unix_seconds());
        self.rows.clone()
    }
}
