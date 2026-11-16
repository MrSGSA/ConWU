//! Authenticated in-path nomination and full-size native checks, compatible
//! with the former managed transport. HTTPS Selected never selects a path.
use crate::{crypto as c, traversal::Message};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{Duration, Instant};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Context {
    pub network_id: String,
    pub local_node_id: String,
    pub local_boot_id: Uuid,
    pub remote_node_id: String,
    pub remote_boot_id: Uuid,
    pub attempt_id: Uuid,
    pub local_candidate_id: Uuid,
    pub local_candidate_version: i64,
    pub remote_candidate_id: Uuid,
    pub remote_candidate_version: i64,
    pub profile: u8,
    pub protocol_client: bool,
    pub nominator: bool,
    pub validation_nonce: Uuid,
    #[serde(default)]
    pub udp_exploration: bool,
    #[serde(default)]
    pub standby: bool,
}
impl Context {
    pub fn from_message(network: &str, m: &Message, sender: bool) -> Result<Self> {
        m.validate(crate::unix_seconds())?;
        let (a, b) = if sender {
            (m.candidate.as_ref(), m.peer_candidate.as_ref())
        } else {
            (m.peer_candidate.as_ref(), m.candidate.as_ref())
        };
        let a = a.ok_or_else(|| anyhow::anyhow!("本机候选缺失"))?;
        let b = b.ok_or_else(|| anyhow::anyhow!("对端候选缺失"))?;
        let (local_node_id, local_boot_id, remote_node_id, remote_boot_id, slot) = if sender {
            (
                m.from_device.clone(),
                m.from_boot,
                m.to_device.clone(),
                m.to_boot,
                m.from_slot,
            )
        } else {
            (
                m.to_device.clone(),
                m.to_boot,
                m.from_device.clone(),
                m.from_boot,
                m.to_slot,
            )
        };
        Ok(Self {
            network_id: network.into(),
            local_node_id,
            local_boot_id,
            remote_node_id,
            remote_boot_id,
            attempt_id: m.attempt_id,
            local_candidate_id: a.id,
            local_candidate_version: a.version,
            remote_candidate_id: b.id,
            remote_candidate_version: b.version,
            profile: m.profile,
            protocol_client: slot == m.protocol_client_slot,
            nominator: slot == m.nominator_slot,
            validation_nonce: m.validation_nonce,
            udp_exploration: a.exploration.is_some(),
            standby: a.standby,
        })
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        ensure!(
            !self.network_id.is_empty()
                && self.network_id.len() <= 128
                && !self.local_node_id.is_empty()
                && self.local_node_id.len() <= 128
                && !self.remote_node_id.is_empty()
                && self.remote_node_id.len() <= 128
                && self.local_node_id != self.remote_node_id
                && !self.local_boot_id.is_nil()
                && !self.remote_boot_id.is_nil()
                && !self.attempt_id.is_nil()
                && !self.local_candidate_id.is_nil()
                && !self.remote_candidate_id.is_nil()
                && self.local_candidate_version > 0
                && self.remote_candidate_version > 0
                && !self.validation_nonce.is_nil()
                && matches!(self.profile, 1..=3)
                && (!self.udp_exploration || self.profile == 3)
                && (!self.standby || !self.udp_exploration && matches!(self.profile, 2 | 3)),
            "路径提名上下文无效"
        );
        let local = json!({"node":self.local_node_id,"boot":self.local_boot_id,"candidate":self.local_candidate_id,"version":self.local_candidate_version,"client":self.protocol_client,"nominator":self.nominator});
        let remote = json!({"node":self.remote_node_id,"boot":self.remote_boot_id,"candidate":self.remote_candidate_id,"version":self.remote_candidate_version,"client":!self.protocol_client,"nominator":!self.nominator});
        let (a, b) = if self.local_node_id < self.remote_node_id {
            (local, remote)
        } else {
            (remote, local)
        };
        Ok(c::hash(c::signed_json(
            &json!({"domain":if self.standby{"streamlink-path-standby-v1"}else if self.udp_exploration{"streamlink-path-nomination-udp-exploration-v1"}else{"streamlink-path-nomination-v1"},"NetworkId":self.network_id,"a":a,"b":b,"AttemptId":self.attempt_id,"Profile":self.profile,"ValidationNonce":self.validation_nonce}),
        )?))
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    Checking,
    Prepared,
    Nominating,
    Confirming,
    Committing,
    Selected,
    Cancelled,
}
pub struct Nomination {
    context: Context,
    path: Uuid,
    revision: i64,
    deadline: Instant,
    digest: [u8; 32],
    challenge: [u8; 16],
    peer: Option<[u8; 16]>,
    checked_peer: bool,
    peer_checked: bool,
    mtu: bool,
    last: Option<Instant>,
    cancel_sends: u8,
    pub stage: Stage,
}
impl Nomination {
    pub fn new(
        context: Context,
        path: Uuid,
        revision: i64,
        remaining: Duration,
        mtu: bool,
    ) -> Result<Self> {
        ensure!(
            !path.is_nil()
                && revision > 0
                && !remaining.is_zero()
                && remaining <= Duration::from_secs(8)
                && !context.standby,
            "路径提名的身份、期限或普通路径授权无效"
        );
        let digest = context.digest()?;
        Ok(Self {
            context,
            path,
            revision,
            deadline: Instant::now() + remaining,
            digest,
            challenge: c::random(),
            peer: None,
            checked_peer: false,
            peer_checked: false,
            mtu,
            last: None,
            cancel_sends: 0,
            stage: Stage::Checking,
        })
    }
    pub fn switch_requested(&self) -> bool {
        matches!(self.stage, Stage::Committing | Stage::Selected)
    }
    pub fn attempt(&self) -> Uuid {
        self.context.attempt_id
    }
    pub fn cancel(&mut self) {
        self.stage = Stage::Cancelled;
        self.last = None;
    }
    fn prepare(&mut self) {
        if self.stage == Stage::Checking && self.checked_peer && self.peer_checked && self.mtu {
            self.stage = Stage::Prepared;
        }
    }
    fn frame(&self, kind: u8, echo: bool) -> Vec<u8> {
        let mut f = vec![0; 80];
        f[..4].copy_from_slice(b"SLN1");
        f[4] = kind;
        f[6..8].copy_from_slice(&80u16.to_be_bytes());
        f[8..16].copy_from_slice(&self.revision.to_be_bytes());
        f[16..48].copy_from_slice(&self.digest);
        f[48..64].copy_from_slice(&self.challenge);
        if echo && let Some(peer) = self.peer {
            f[64..80].copy_from_slice(&peer);
        }
        f
    }
    pub fn tick(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        if now >= self.deadline && !matches!(self.stage, Stage::Selected | Stage::Cancelled) {
            self.cancel();
        }
        if self.stage == Stage::Cancelled {
            if self.cancel_sends >= 3 || now > self.deadline + Duration::from_secs(1) {
                return vec![];
            }
        } else if now >= self.deadline {
            return vec![];
        }
        if self
            .last
            .is_some_and(|t| t.elapsed() < Duration::from_millis(250))
        {
            return vec![];
        }
        self.last = Some(now);
        self.prepare();
        if self.stage == Stage::Cancelled {
            self.cancel_sends += 1;
            return vec![self.frame(7, true)];
        }
        if self.stage == Stage::Prepared && self.context.nominator {
            self.stage = Stage::Nominating;
        }
        let kind = match self.stage {
            Stage::Checking | Stage::Prepared => 1,
            Stage::Nominating => 3,
            Stage::Confirming => 4,
            Stage::Committing => 5,
            Stage::Selected => {
                if self.context.nominator {
                    5
                } else {
                    6
                }
            }
            Stage::Cancelled => 7,
        };
        vec![self.frame(kind, kind != 1)]
    }
    pub fn receive(&mut self, path: Uuid, f: &[u8]) -> Vec<Vec<u8>> {
        if path != self.path
            || f.len() != 80
            || &f[..4] != b"SLN1"
            || !(1..=7).contains(&f[4])
            || f[5] != 0
            || f[6..8] != 80u16.to_be_bytes()
            || f[8..16] != self.revision.to_be_bytes()
            || !c::eq(&f[16..48], &self.digest)
            || f[48..64].iter().all(|b| *b == 0)
            || self.stage == Stage::Cancelled
        {
            return vec![];
        }
        let kind = f[4];
        let now = Instant::now();
        if now >= self.deadline && kind != 7 {
            return vec![];
        }
        if kind == 7 {
            if now < self.deadline + Duration::from_secs(2) {
                self.cancel();
            }
            return vec![];
        }
        let theirs: [u8; 16] = f[48..64].try_into().unwrap();
        if self.peer.is_some_and(|p| p != theirs)
            || kind != 1 && !c::eq(&f[64..80], &self.challenge)
        {
            return vec![];
        }
        self.peer.get_or_insert(theirs);
        if kind == 1 {
            self.peer_checked = true;
            self.prepare();
            return vec![self.frame(2, true)];
        }
        if kind == 2 {
            self.checked_peer = true;
            self.prepare();
            return vec![];
        }
        self.prepare();
        if self.stage == Stage::Checking {
            return vec![];
        }
        if kind == 3 && !self.context.nominator {
            if matches!(self.stage, Stage::Prepared | Stage::Confirming) {
                self.stage = Stage::Confirming;
            }
            return if self.stage == Stage::Confirming {
                vec![self.frame(4, true)]
            } else if self.stage == Stage::Selected {
                vec![self.frame(6, true)]
            } else {
                vec![]
            };
        }
        if kind == 4
            && self.context.nominator
            && matches!(
                self.stage,
                Stage::Nominating | Stage::Committing | Stage::Selected
            )
        {
            if self.stage != Stage::Selected {
                self.stage = Stage::Committing;
            }
            return vec![self.frame(5, true)];
        }
        if kind == 5
            && !self.context.nominator
            && matches!(self.stage, Stage::Confirming | Stage::Selected)
        {
            self.stage = Stage::Selected;
            return vec![self.frame(6, true)];
        }
        if kind == 6
            && self.context.nominator
            && matches!(self.stage, Stage::Committing | Stage::Selected)
        {
            self.stage = Stage::Selected;
        }
        vec![]
    }
}
pub const PROBE_SIZE: usize = 1344;
#[derive(Clone)]
pub struct NativeCheck {
    pub digest: [u8; 32],
    key: zeroize::Zeroizing<[u8; 32]>,
    client: bool,
    pub challenge: [u8; 16],
}
impl NativeCheck {
    pub fn new(context: &Context, shared: &[u8; 32]) -> Result<Self> {
        let digest = context.digest()?;
        Ok(Self {
            digest,
            key: c::hkdf(shared, &digest, b"streamlink-native-path-check-v1"),
            client: context.protocol_client,
            challenge: c::random(),
        })
    }
    pub fn frame(&self, kind: u8, nonce: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            (1..=2).contains(&kind) && nonce.len() == 16,
            "原生路径探测格式无效"
        );
        let mut f = vec![0; PROBE_SIZE];
        f[..4].copy_from_slice(b"SLF1");
        f[4] = kind;
        f[5] = if self.client { 1 } else { 2 };
        f[8..40].copy_from_slice(&self.digest);
        f[40..56].copy_from_slice(nonce);
        let tag = c::mac(&*self.key, &f[..PROBE_SIZE - 32]);
        f[PROBE_SIZE - 32..].copy_from_slice(&tag);
        Ok(f)
    }
    pub fn valid(&self, f: &[u8]) -> bool {
        f.len() == PROBE_SIZE
            && &f[..4] == b"SLF1"
            && matches!(f[4], 1 | 2)
            && f[5] == if self.client { 2 } else { 1 }
            && f[6..8] == [0, 0]
            && c::eq(&f[8..40], &self.digest)
            && c::eq(
                &f[PROBE_SIZE - 32..],
                &c::mac(&*self.key, &f[..PROBE_SIZE - 32]),
            )
    }
}
