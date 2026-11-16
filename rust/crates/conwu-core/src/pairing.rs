use crate::{
    crypto as c, id,
    identity::{self, Profile},
    unix_seconds, valid_id,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub const ENTRY_LOCATOR: &str = "conwu-network-entry";
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const CARRIAGE_KEY: &str = "streamlink-direct-rendezvous-v1";
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct NodeProof {
    pub public_key: String,
    pub signature: String,
}
impl NodeProof {
    pub fn create(private: &str, commitment: &str) -> Result<Self> {
        let public_key = c::public(private)?;
        let data = c::signed_json(
            &json!({"domain":"conwu-node-pairing-v1","publicKey":public_key,"commitment":commitment}),
        )?;
        Ok(Self {
            public_key,
            signature: c::sign(private, &data)?,
        })
    }
    pub fn valid(&self, commitment: &str) -> bool {
        valid_commitment(commitment)&&(||->Result<bool>{Ok(c::verify(&self.public_key,&c::signed_json(&json!({"domain":"conwu-node-pairing-v1","publicKey":self.public_key,"commitment":commitment}))?,&self.signature))})().unwrap_or(false)
    }
    pub fn fingerprint(&self) -> Result<String> {
        Ok(hex::encode_upper(c::hash(c::signed_json(self)?)))
    }
}
pub fn valid_commitment(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}
#[derive(Clone)]
pub struct KeyExchange {
    private: Zeroizing<String>,
    pub public: String,
    pub commitment: String,
    pub identity: Option<NodeProof>,
}
impl KeyExchange {
    pub fn new(node_private: Option<&str>) -> Result<Self> {
        let private = Zeroizing::new(c::new_private()?);
        let public = c::public(&private)?;
        let commitment = hex::encode_upper(c::hash(c::unb64(&public)?));
        let identity = node_private
            .map(|p| NodeProof::create(p, &commitment))
            .transpose()?;
        Ok(Self {
            private,
            public,
            commitment,
            identity,
        })
    }
    pub fn validate_public(public: &str, commitment: &str) -> Result<()> {
        ensure!(
            valid_commitment(commitment)
                && c::eq(&c::hash(c::unb64(public)?), &hex::decode(commitment)?),
            "ephemeral commitment mismatch"
        );
        c::valid_public(public)
    }
    pub fn derive(
        &self,
        remote: &str,
        commitment: &str,
        room: &str,
        candidate: &str,
        owner: bool,
    ) -> Result<Zeroizing<[u8; 32]>> {
        Self::validate_public(remote, commitment)?;
        ensure!(
            valid_id(room) && valid_id(candidate),
            "pairing session invalid"
        );
        let (host, guest) = if owner {
            (self.public.as_str(), remote)
        } else {
            (remote, self.public.as_str())
        };
        Ok(c::hkdf(
            &*c::exchange(&self.private, remote)?,
            format!("{room}{candidate}").as_bytes(),
            format!("streamlink-pair-v3/{host}/{guest}").as_bytes(),
        ))
    }
    pub fn sas(shared: &[u8; 32]) -> String {
        let h = c::mac(shared, b"verification");
        format!(
            "{:06}",
            u32::from_le_bytes(h[..4].try_into().unwrap()) % 1_000_000
        )
    }
    pub fn encrypt(shared: &[u8; 32], value: &str, room: &str, candidate: &str) -> Result<String> {
        c::seal(
            shared,
            format!("{room}/{candidate}").as_bytes(),
            value.as_bytes(),
        )
    }
    pub fn decrypt(shared: &[u8; 32], value: &str, room: &str, candidate: &str) -> Result<String> {
        Ok(String::from_utf8(
            c::open(
                shared,
                format!("{room}/{candidate}").as_bytes(),
                value,
                44000,
            )?
            .to_vec(),
        )?)
    }
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Ticket {
    pub room: String,
    pub code: String,
    pub token: String,
    pub host_commitment: String,
    pub host_name: String,
    pub expires: i64,
    #[serde(default)]
    pub candidate: String,
    #[serde(default)]
    pub identity: Option<NodeProof>,
}
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct State {
    pub candidate: String,
    pub guest_commitment: String,
    pub guest_name: String,
    pub host_public: String,
    pub guest_public: String,
    pub ciphertext: String,
    pub approved: bool,
    pub expires: i64,
    pub network_settings_version: u8,
    pub guest_identity: Option<NodeProof>,
    pub guest_identity_digest: String,
    pub outcome: String,
    pub requested_ip: String,
    pub addressing: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejoin: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejoin_digest: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, Default, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct Request {
    pub id: String,
    pub method: String,
    pub room: String,
    pub token: String,
    pub code: String,
    pub commitment: String,
    pub name: String,
    pub public_key: String,
    pub offset: usize,
    pub network_settings_version: u8,
    pub target_network: String,
    pub identity: Option<NodeProof>,
    pub requested_ip: String,
    pub entry_admission: bool,
    pub rejoin: Option<Value>,
    pub departure: Option<Value>,
}
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Reply {
    pub id: String,
    pub error: String,
    pub ticket: Option<Ticket>,
    pub state: Option<State>,
    pub part: String,
    pub total: usize,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub retryable: bool,
}
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(value)?;
    ensure!(json.len() <= 1196, "pairing datagram exceeds limit");
    Ok([b"SLP1".as_slice(), &json].concat())
}
pub fn decode<T: serde::de::DeserializeOwned>(value: &[u8]) -> Result<T> {
    ensure!(
        (4..=1200).contains(&value.len()) && &value[..4] == b"SLP1",
        "invalid pairing datagram"
    );
    Ok(serde_json::from_slice(&value[4..])?)
}
#[derive(Clone)]
pub struct Host {
    pub key: KeyExchange,
    pub ticket: Ticket,
    pub state: State,
    guest: Option<Ticket>,
    pub delivered: bool,
    pub rejoin_history: Vec<crate::rejoin::History>,
    pub entry_admission: bool,
    window: Instant,
    replies: u8,
    bad_codes: u8,
}
impl Host {
    pub fn new(name: &str, node_private: Option<&str>) -> Result<Self> {
        use rand::Rng;
        c::check_name(name)?;
        let key = KeyExchange::new(node_private)?;
        let ticket = Ticket {
            room: id(),
            code: format!("{:06}", rand::thread_rng().gen_range(0..1_000_000)),
            token: hex::encode_upper(c::random::<32>()),
            host_commitment: key.commitment.clone(),
            host_name: name.into(),
            expires: unix_seconds() + 300,
            candidate: String::new(),
            identity: key.identity.clone(),
        };
        let state = State {
            expires: ticket.expires,
            addressing: 1,
            ..Default::default()
        };
        Ok(Self {
            key,
            ticket,
            state,
            guest: None,
            delivered: false,
            rejoin_history: vec![],
            entry_admission: false,
            window: Instant::now(),
            replies: 0,
            bad_codes: 0,
        })
    }
    pub fn handle(&mut self, packet: &[u8], network: &str) -> Option<Vec<u8>> {
        if self.ticket.expires <= unix_seconds() {
            return None;
        }
        if self.window.elapsed() >= Duration::from_secs(1) {
            self.window = Instant::now();
            self.replies = 0;
        }
        self.replies = self.replies.saturating_add(1);
        if self.replies > 5 {
            return None;
        }
        let r: Request = decode(packet).ok()?;
        if !valid_id(&r.id)
            || r.entry_admission != self.entry_admission
            || !r.target_network.is_empty() && r.target_network != network
        {
            return None;
        }
        let result = self.request(&r);
        let reply = result.unwrap_or_else(|_| Reply {
            id: r.id,
            error: "配对请求无效、已过期或状态已改变".into(),
            ..Default::default()
        });
        encode(&reply).ok()
    }
    pub fn request(&mut self, r: &Request) -> Result<Reply> {
        ensure!(
            self.ticket.expires > unix_seconds() && self.bad_codes < 20,
            "pairing expired"
        );
        if r.method == "join" {
            if let Some(proof) = &r.rejoin {
                let proof: crate::rejoin::Proof = serde_json::from_value(proof.clone())?;
                ensure!(proof.well_formed(), "重新加入证明格式无效");
            }
            let locator = if self.entry_admission {
                ENTRY_LOCATOR
            } else {
                &self.ticket.code
            };
            if !c::eq(r.code.as_bytes(), locator.as_bytes()) {
                self.bad_codes += 1;
                anyhow::bail!("room locator mismatch")
            }
            ensure!(
                !self.state.approved
                    && self.state.outcome.is_empty()
                    && valid_commitment(&r.commitment)
                    && r.network_settings_version <= 1,
                "pairing state changed"
            );
            c::check_name(&r.name)?;
            if let Some(p) = &r.identity {
                ensure!(p.valid(&r.commitment), "invalid persistent device proof");
            }
            if let Some(g) = &self.guest {
                ensure!(
                    r.commitment == self.state.guest_commitment
                        && r.name == self.state.guest_name
                        && r.requested_ip == self.state.requested_ip
                        && r.rejoin == self.state.rejoin,
                    "another candidate is pending"
                );
                return Ok(Reply {
                    id: r.id.clone(),
                    ticket: Some(g.clone()),
                    ..Default::default()
                });
            }
            // Both commitments exist before revealing either ephemeral key.
            self.state.candidate = id();
            self.state.guest_commitment = r.commitment.clone();
            self.state.guest_name = r.name.clone();
            self.state.requested_ip = r.requested_ip.clone();
            self.state.network_settings_version = r.network_settings_version;
            self.state.guest_identity = r.identity.clone();
            self.state.rejoin = r.rejoin.clone();
            self.state.host_public = self.key.public.clone();
            let guest = Ticket {
                room: self.ticket.room.clone(),
                code: String::new(),
                token: hex::encode_upper(c::random::<32>()),
                host_commitment: self.ticket.host_commitment.clone(),
                host_name: self.ticket.host_name.clone(),
                expires: self.ticket.expires,
                candidate: self.state.candidate.clone(),
                identity: self.ticket.identity.clone(),
            };
            self.guest = Some(guest.clone());
            return Ok(Reply {
                id: r.id.clone(),
                ticket: Some(guest),
                ..Default::default()
            });
        }
        let guest = self
            .guest
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no candidate"))?;
        ensure!(
            r.room == guest.room && c::eq(r.token.as_bytes(), guest.token.as_bytes()),
            "invalid candidate token"
        );
        match r.method.as_str() {
            "poll" => {}
            "reveal" => {
                ensure!(
                    !self.state.approved && self.state.outcome.is_empty(),
                    "pairing finished"
                );
                KeyExchange::validate_public(&r.public_key, &self.state.guest_commitment)?;
                ensure!(
                    self.state.guest_public.is_empty() || self.state.guest_public == r.public_key,
                    "ephemeral key changed"
                );
                self.state.guest_public = r.public_key.clone();
            }
            "cancel" => {
                ensure!(!self.state.approved, "already approved");
                self.state.outcome = "Cancelled".into();
                self.delivered = true;
            }
            "received" => {
                ensure!(self.state.approved, "approval missing");
                self.delivered = true;
            }
            "chunk" => {
                ensure!(
                    self.state.approved
                        && r.offset < self.state.ciphertext.len()
                        && r.offset % 800 == 0,
                    "invalid enrollment chunk"
                );
                return Ok(Reply {
                    id: r.id.clone(),
                    part: self.state.ciphertext
                        [r.offset..(r.offset + 800).min(self.state.ciphertext.len())]
                        .into(),
                    total: self.state.ciphertext.len(),
                    ..Default::default()
                });
            }
            _ => anyhow::bail!("unknown pairing operation"),
        }
        let mut state = self.state.clone();
        state.ciphertext.clear();
        state.guest_identity_digest = state
            .guest_identity
            .as_ref()
            .map(NodeProof::fingerprint)
            .transpose()?
            .unwrap_or_default();
        state.guest_identity = None;
        state.rejoin_digest = state
            .rejoin
            .as_ref()
            .map(|v| serde_json::from_value::<crate::rejoin::Proof>(v.clone())?.fingerprint())
            .transpose()?;
        state.rejoin = None;
        Ok(Reply {
            id: r.id.clone(),
            state: Some(state),
            total: if self.state.approved {
                self.state.ciphertext.len()
            } else {
                0
            },
            ..Default::default()
        })
    }
    pub fn shared(&self) -> Result<Zeroizing<[u8; 32]>> {
        ensure!(!self.state.guest_public.is_empty(), "guest reveal missing");
        self.key.derive(
            &self.state.guest_public,
            &self.state.guest_commitment,
            &self.ticket.room,
            &self.state.candidate,
            true,
        )
    }
    pub fn sas(&self) -> Result<String> {
        Ok(KeyExchange::sas(&*self.shared()?))
    }
    pub fn reject(&mut self) -> Result<()> {
        ensure!(!self.state.approved, "cannot reject a delivered membership");
        self.state.outcome = "Rejected".into();
        Ok(())
    }
    pub fn approve(
        &mut self,
        profile: &mut Profile,
        sas: &str,
        entries: &[Value],
        settings: Option<Value>,
    ) -> Result<()> {
        ensure!(
            !self.state.approved
                && self.state.outcome.is_empty()
                && self.ticket.expires > unix_seconds(),
            "pairing is not pending"
        );
        let shared = self.shared()?;
        ensure!(
            c::eq(sas.as_bytes(), KeyExchange::sas(&shared).as_bytes()),
            "SAS mismatch"
        );
        let mut next = profile.clone();
        let requested =
            (!self.state.requested_ip.is_empty()).then(|| self.state.requested_ip.clone());
        let device = self
            .state
            .guest_identity
            .as_ref()
            .map(|p| identity::network_id(&p.public_key))
            .transpose()?;
        let former = self
            .state
            .rejoin
            .as_ref()
            .map(|v| {
                let proof: crate::rejoin::Proof = serde_json::from_value(v.clone())?;
                proof.resolve(
                    &next,
                    if self.entry_admission {
                        ENTRY_LOCATOR
                    } else {
                        &self.ticket.code
                    },
                    &self.state.guest_commitment,
                    &self.rejoin_history,
                )
            })
            .transpose()?
            .flatten();
        if let Some(former) = &former {
            ensure!(
                device.as_ref().is_none_or(|d| d == &former.device),
                "重新加入与持久设备身份不符"
            );
        }
        let device = device.or_else(|| former.as_ref().map(|m| m.device.clone()));
        let e = if let Some(device) = device.as_ref().filter(|device| {
            next.directory.as_ref().is_some_and(|d| {
                d.members
                    .iter()
                    .any(|m| m.slot != next.member.slot && m.device == **device)
            })
        }) {
            next.reissue_for_device(device, requested)?
        } else {
            next.issue_for_device(requested, device)?
        };
        let bundle = identity::enrollment_bundle(&e, entries, settings)?;
        if let Some(former) = former {
            self.rejoin_history =
                crate::rejoin::remember(&next, &self.rejoin_history, former, &e.member);
        }
        let cipher =
            KeyExchange::encrypt(&shared, &bundle, &self.ticket.room, &self.state.candidate)?;
        self.state.ciphertext = cipher;
        self.state.approved = true;
        *profile = next;
        Ok(())
    }
}
