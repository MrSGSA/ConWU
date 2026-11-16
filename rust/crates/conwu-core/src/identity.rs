use crate::{crypto as c, unix_seconds, valid_id};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

fn is_false(v: &bool) -> bool {
    !*v
}
fn one() -> u8 {
    1
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Pairing {
    pub network: String,
    pub secret: String,
    pub service: String,
    pub certificate_pin: String,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_key_pin: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub direct: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub direct_bootstrap: bool,
}
impl Pairing {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_id(&self.network)
                && self.secret.len() == 43
                && self
                    .secret
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
            "invalid network identity"
        );
        ensure!(
            crate::code::valid_mode(&self.mode),
            "unknown selected carrier"
        );
        ensure!(
            !self.direct || self.service.is_empty() && self.certificate_pin.is_empty(),
            "direct network cannot contain coordinator credentials"
        );
        if !self.direct {
            let service = url::Url::parse(&self.service)?;
            ensure!(
                service.scheme() == "https"
                    && service.username().is_empty()
                    && service.password().is_none()
                    && service.path().ends_with('/')
                    && service.query().is_none()
                    && service.fragment().is_none(),
                "invalid coordinator identity"
            );
        }
        ensure!(
            self.certificate_pin.is_empty()
                || self.certificate_pin.len() == 64
                    && self.certificate_pin.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid coordinator certificate pin"
        );
        ensure!(
            !self.direct_bootstrap || self.direct,
            "bootstrap requires direct enrollment"
        );
        ensure!(
            self.transport_key_pin
                .as_ref()
                .is_none_or(|p| p.is_empty() || self.mode == "https"),
            "TLS pin cannot be attached to another carrier"
        );
        if self.mode == "https" {
            if let Some(pin) = &self.transport_key_pin {
                ensure!(
                    pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit()),
                    "invalid TLS identity"
                );
            }
        }
        Ok(())
    }
    pub fn key(&self, purpose: &str) -> [u8; 32] {
        c::mac(
            self.secret.as_bytes(),
            format!("streamlink-v2/{purpose}").as_bytes(),
        )
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Member {
    pub slot: u8,
    pub device: String,
    pub signing_key: String,
    pub exchange_key: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_ip: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Directory {
    pub network: String,
    pub owner_key: String,
    pub revision: i64,
    pub next_slot: u16,
    pub members: Vec<Member>,
    pub signature: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub pairwise: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub closed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_addresses: Option<Vec<String>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Profile {
    pub pair: Pairing,
    pub owner_key: String,
    #[serde(default)]
    pub owner_private: String,
    #[serde(rename = "Self")]
    pub member: Member,
    pub signing_private: String,
    pub exchange_private: String,
    #[serde(default)]
    pub directory: Option<Directory>,
    #[serde(default = "one")]
    pub introducer_slot: u8,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Enrollment {
    pub pair: Pairing,
    pub owner_key: String,
    pub member: Member,
    pub signing_private: String,
    pub exchange_private: String,
    pub expires: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<Directory>,
    #[serde(default = "one")]
    pub introducer_slot: u8,
}

pub fn network_id(owner: &str) -> Result<String> {
    Ok(hex::encode(&c::hash(c::unb64(owner)?)[..16]))
}
pub fn prefix(network: &str) -> Result<[u8; 3]> {
    ensure!(valid_id(network), "invalid network ID");
    let b = hex::decode(network)?;
    Ok([10, 160 + b[0] % 64, 1 + b[1] % 253])
}
pub fn member_data(network: &str, m: &Member) -> Result<Vec<u8>> {
    c::signed_json(&if let Some(ip) = &m.virtual_ip {
        json!({"domain":"streamlink-member-address-v1","network":network,"Slot":m.slot,"Device":m.device,"SigningKey":m.signing_key,"ExchangeKey":m.exchange_key,"VirtualIp":ip})
    } else {
        json!({"domain":"streamlink-member-v4","network":network,"Slot":m.slot,"Device":m.device,"SigningKey":m.signing_key,"ExchangeKey":m.exchange_key})
    })
}
pub fn directory_data(d: &Directory) -> Result<Vec<u8>> {
    let mut value = json!({"domain":if d.pairwise{"conwu-pair-directory-v1"}else if d.reserved_addresses.is_some(){"streamlink-directory-address-v1"}else{"streamlink-directory-v4"},
        "Network":d.network,"OwnerKey":d.owner_key,"Revision":d.revision,"NextSlot":d.next_slot,"Members":d.members});
    if d.reserved_addresses.is_some() || d.pairwise {
        value["ReservedAddresses"] = json!(d.reserved_addresses);
    }
    if d.pairwise {
        value["Pairwise"] = json!(true);
    }
    c::signed_json(&value)
}
pub fn validate_member(network: &str, owner: &str, m: &Member) -> Result<()> {
    ensure!(
        (1..=254).contains(&m.slot) && valid_id(&m.device),
        "invalid member slot/device"
    );
    c::valid_public(&m.signing_key)?;
    c::valid_public(&m.exchange_key)?;
    if let Some(ip) = &m.virtual_ip {
        let ip = ip.parse::<std::net::Ipv4Addr>()?;
        ensure!(
            ip.is_private() && !matches!(ip.octets()[3], 0 | 255),
            "invalid virtual IP"
        );
    }
    ensure!(
        c::verify(owner, &member_data(network, m)?, &m.signature),
        "member signature mismatch"
    );
    Ok(())
}
pub fn validate_directory(d: &Directory, network: &str, owner: &str, minimum: i64) -> Result<()> {
    ensure!(
        d.network == network && d.owner_key == owner && d.revision >= minimum && d.revision > 0,
        "directory identity or revision mismatch"
    );
    ensure!(
        d.governance.is_none(),
        "legacy equal-member governance requires explicit import, never silently downgrade it"
    );
    ensure!(
        !d.members.is_empty()
            && d.members.len() <= 8
            && d.next_slot >= 2
            && d.next_slot <= 255
            && !d.closed
            && d.members.iter().filter(|m| m.slot == 1).count() == 1,
        "directory exceeds capacity or has no owner"
    );
    let mut slots = std::collections::HashSet::new();
    let mut devices = std::collections::HashSet::new();
    let mut ips = std::collections::HashSet::new();
    let address = |m: &Member| -> Result<std::net::Ipv4Addr> {
        if let Some(ip) = &m.virtual_ip {
            return Ok(ip.parse()?);
        }
        let p = prefix(network)?;
        Ok(std::net::Ipv4Addr::new(p[0], p[1], p[2], m.slot))
    };
    let subnet = address(d.members.iter().find(|m| m.slot == 1).unwrap())?.octets();
    for member in &d.members {
        validate_member(network, owner, member)?;
        ensure!(
            (member.slot as u16) < d.next_slot
                && slots.insert(member.slot)
                && devices.insert(&member.device),
            "duplicate/recycled member"
        );
        let ip = address(member)?;
        ensure!(
            ip.octets()[..3] == subnet[..3] && ips.insert(ip),
            "duplicate virtual address or outside owner subnet"
        );
    }
    if let Some(reserved) = &d.reserved_addresses {
        let mut seen = std::collections::HashSet::new();
        ensure!(reserved.len() <= 254, "too many reserved virtual addresses");
        for ip in reserved {
            let ip: std::net::Ipv4Addr = ip.parse()?;
            ensure!(
                ip.octets()[..3] == subnet[..3]
                    && !matches!(ip.octets()[3], 0 | 255)
                    && seen.insert(ip),
                "invalid reserved virtual address"
            );
        }
    }
    ensure!(
        !d.pairwise || d.members.len() <= 2,
        "pairwise directory has more than two members"
    );
    ensure!(
        c::verify(owner, &directory_data(d)?, &d.signature),
        "directory signature mismatch"
    );
    Ok(())
}
impl Profile {
    pub fn validate(&self) -> Result<()> {
        self.pair.validate()?;
        ensure!(
            network_id(&self.owner_key)? == self.pair.network,
            "network root mismatch"
        );
        validate_member(&self.pair.network, &self.owner_key, &self.member)?;
        ensure!(
            c::public(&self.signing_private)? == self.member.signing_key
                && c::public(&self.exchange_private)? == self.member.exchange_key,
            "device private keys mismatch"
        );
        if !self.owner_private.is_empty() {
            ensure!(
                self.member.slot == 1 && c::public(&self.owner_private)? == self.owner_key,
                "owner private key mismatch"
            );
        }
        if let Some(d) = &self.directory {
            validate_directory(d, &self.pair.network, &self.owner_key, 0)?;
            ensure!(
                d.members.contains(&self.member) && !d.closed,
                "member revoked or network closed"
            );
        }
        Ok(())
    }
    pub fn create(mode: &str) -> Result<Self> {
        ensure!(crate::code::valid_mode(mode), "unknown carrier");
        let owner = c::new_private()?;
        let owner_key = c::public(&owner)?;
        let network = network_id(&owner_key)?;
        let (member, signing_private, exchange_private) = new_member(&network, &owner, 1, None)?;
        let mut p = Self {
            pair: Pairing {
                network,
                secret: base64_url(&c::random::<32>()),
                service: String::new(),
                certificate_pin: String::new(),
                mode: mode.into(),
                transport_key_pin: None,
                direct: true,
                direct_bootstrap: true,
            },
            owner_key,
            owner_private: owner,
            member,
            signing_private,
            exchange_private,
            directory: None,
            introducer_slot: 1,
        };
        p.sign_directory(vec![p.member.clone()], 2)?;
        p.validate()?;
        Ok(p)
    }
    pub fn create_for_device(
        mode: &str,
        node_private: &str,
        virtual_ip: Option<String>,
    ) -> Result<Self> {
        let mut p = Self::create(mode)?;
        p.member.device = network_id(&c::public(node_private)?)?;
        p.member.virtual_ip = virtual_ip;
        p.member.signature = c::sign(&p.owner_private, &member_data(&p.pair.network, &p.member)?)?;
        p.sign_directory(vec![p.member.clone()], 2)?;
        p.validate()?;
        Ok(p)
    }
    fn sign_directory(&mut self, members: Vec<Member>, next: u16) -> Result<()> {
        ensure!(
            !self.owner_private.is_empty(),
            "only owner can change pairwise membership"
        );
        let mut reserved = self
            .directory
            .as_ref()
            .and_then(|d| d.reserved_addresses.clone());
        if reserved.is_some() || members.iter().any(|m| m.virtual_ip.is_some()) {
            let p = prefix(&self.pair.network)?;
            let all = reserved.get_or_insert_with(Vec::new);
            all.extend(members.iter().map(|m| {
                m.virtual_ip
                    .clone()
                    .unwrap_or_else(|| format!("{}.{}.{}.{}", p[0], p[1], p[2], m.slot))
            }));
            all.sort();
            all.dedup();
        }
        let mut d = Directory {
            network: self.pair.network.clone(),
            owner_key: self.owner_key.clone(),
            revision: self.directory.as_ref().map_or(1, |d| d.revision + 1),
            next_slot: next,
            members,
            signature: String::new(),
            pairwise: true,
            governance: None,
            closed: false,
            reserved_addresses: reserved,
        };
        d.signature = c::sign(&self.owner_private, &directory_data(&d)?)?;
        self.directory = Some(d);
        Ok(())
    }
    pub fn issue(&mut self, requested_ip: Option<String>) -> Result<Enrollment> {
        self.issue_for_device(requested_ip, None)
    }
    pub fn issue_for_device(
        &mut self,
        mut requested_ip: Option<String>,
        device: Option<String>,
    ) -> Result<Enrollment> {
        self.validate()?;
        let d = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing directory"))?;
        ensure!(
            d.members.len() < 2 && !self.owner_private.is_empty() && d.next_slot <= 254,
            "pairwise network already has a peer"
        );
        if requested_ip.is_none()
            && (self.member.virtual_ip.is_some() || d.reserved_addresses.is_some())
        {
            let ip = self.local_ip()?.octets();
            let used = d.reserved_addresses.clone().unwrap_or_default();
            requested_ip = (1..=254)
                .map(|last| format!("{}.{}.{}.{last}", ip[0], ip[1], ip[2]))
                .find(|ip| {
                    !used.contains(ip) && self.local_ip().is_ok_and(|own| own.to_string() != *ip)
                });
            ensure!(requested_ip.is_some(), "virtual subnet exhausted");
        }
        if let Some(ip) = &requested_ip {
            let target: std::net::Ipv4Addr = ip.parse()?;
            let local = self.local_ip()?;
            ensure!(
                target.is_private()
                    && target.octets()[..3] == local.octets()[..3]
                    && !matches!(target.octets()[3], 0 | 255),
                "requested virtual IP is outside the network"
            );
            ensure!(
                target != local
                    && !d
                        .reserved_addresses
                        .as_ref()
                        .is_some_and(|v| v.contains(ip))
                    && !d.members.iter().any(|m| m.virtual_ip.as_ref() == Some(ip)),
                "virtual IP was already allocated"
            );
        }
        let slot = d.next_slot as u8;
        let (mut member, signing_private, exchange_private) =
            new_member(&self.pair.network, &self.owner_private, slot, requested_ip)?;
        if let Some(device) = device {
            ensure!(valid_id(&device), "invalid persistent device ID");
            member.device = device;
            member.signature = c::sign(
                &self.owner_private,
                &member_data(&self.pair.network, &member)?,
            )?;
        }
        let mut members = d.members.clone();
        members.push(member.clone());
        self.sign_directory(members, u16::from(slot) + 1)?;
        Ok(Enrollment {
            pair: self.pair.clone(),
            owner_key: self.owner_key.clone(),
            member,
            signing_private,
            exchange_private,
            expires: unix_seconds() + 300,
            directory: self.directory.clone(),
            introducer_slot: 1,
        })
    }
    pub fn remove_peer(&mut self, slot: u8) -> Result<()> {
        ensure!(slot != self.member.slot, "owner cannot revoke itself");
        let d = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing directory"))?;
        let keep = d
            .members
            .iter()
            .filter(|m| m.slot != slot)
            .cloned()
            .collect();
        self.sign_directory(keep, d.next_slot)
    }
    pub fn reissue_for_device(
        &mut self,
        device: &str,
        requested: Option<String>,
    ) -> Result<Enrollment> {
        self.validate()?;
        let old = self
            .directory
            .as_ref()
            .and_then(|d| {
                d.members
                    .iter()
                    .find(|m| m.slot != self.member.slot && m.device == device)
            })
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no matching former device"))?;
        ensure!(!self.owner_private.is_empty(), "owner approval required");
        let old_ip = old.virtual_ip.clone().unwrap_or_else(|| {
            let p = prefix(&self.pair.network).unwrap();
            format!("{}.{}.{}.{}", p[0], p[1], p[2], old.slot)
        });
        ensure!(
            requested.as_ref().is_none_or(|ip| ip == &old_ip),
            "recovering device must keep its prior virtual address"
        );
        let slot = self.directory.as_ref().unwrap().next_slot;
        ensure!(slot <= 254, "member slot space exhausted");
        let (mut member, signing_private, exchange_private) = new_member(
            &self.pair.network,
            &self.owner_private,
            slot as u8,
            Some(old_ip),
        )?;
        member.device = device.into();
        member.signature = c::sign(
            &self.owner_private,
            &member_data(&self.pair.network, &member)?,
        )?;
        let mut members = self
            .directory
            .as_ref()
            .unwrap()
            .members
            .iter()
            .filter(|m| m.slot != old.slot)
            .cloned()
            .collect::<Vec<_>>();
        members.push(member.clone());
        self.sign_directory(members, slot + 1)?;
        Ok(Enrollment {
            pair: self.pair.clone(),
            owner_key: self.owner_key.clone(),
            member,
            signing_private,
            exchange_private,
            expires: unix_seconds() + 300,
            directory: self.directory.clone(),
            introducer_slot: 1,
        })
    }
    pub fn local_ip(&self) -> Result<std::net::Ipv4Addr> {
        if let Some(ip) = &self.member.virtual_ip {
            return Ok(ip.parse()?);
        }
        let p = prefix(&self.pair.network)?;
        Ok(std::net::Ipv4Addr::new(p[0], p[1], p[2], self.member.slot))
    }
    pub fn shared_key(&self, peer: &Member) -> Result<Zeroizing<[u8; 32]>> {
        validate_member(&self.pair.network, &self.owner_key, peer)?;
        ensure!(
            self.directory
                .as_ref()
                .is_some_and(|d| d.members.contains(peer))
                && peer.slot != self.member.slot,
            "peer is not a current network member"
        );
        Ok(c::hkdf(
            &*c::exchange(&self.exchange_private, &peer.exchange_key)?,
            self.pair.network.as_bytes(),
            b"streamlink-mesh-link-v4",
        ))
    }
    pub fn import(text: &str) -> Result<Self> {
        ensure!(
            text.starts_with("SL4.") && text.len() <= 32768,
            "expected SL4 member enrollment"
        );
        let e: Enrollment = serde_json::from_slice(&c::unb64(&text[4..])?)?;
        ensure!(
            e.expires > unix_seconds() && e.expires <= unix_seconds() + 600,
            "enrollment expired"
        );
        let p = Self {
            pair: e.pair,
            owner_key: e.owner_key,
            owner_private: String::new(),
            member: e.member,
            signing_private: e.signing_private,
            exchange_private: e.exchange_private,
            directory: e.directory,
            introducer_slot: e.introducer_slot,
        };
        p.validate()?;
        Ok(p)
    }
}
impl Enrollment {
    pub fn export(&self) -> Result<String> {
        Ok(format!("SL4.{}", c::b64(c::signed_json(self)?)))
    }
}
fn new_member(
    network: &str,
    owner: &str,
    slot: u8,
    virtual_ip: Option<String>,
) -> Result<(Member, String, String)> {
    let signing = c::new_private()?;
    let exchange = c::new_private()?;
    let mut m = Member {
        slot,
        device: crate::id(),
        signing_key: c::public(&signing)?,
        exchange_key: c::public(&exchange)?,
        signature: String::new(),
        virtual_ip,
    };
    m.signature = c::sign(owner, &member_data(network, &m)?)?;
    Ok((m, signing, exchange))
}
fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn enrollment_bundle(
    enrollment: &Enrollment,
    entries: &[Value],
    settings: Option<Value>,
) -> Result<String> {
    let mut v = json!({"Credential":enrollment.export()?,"Entries":entries});
    if let Some(s) = settings {
        v["Settings"] = s;
    }
    let bytes = c::signed_json(&v)?;
    ensure!(bytes.len() <= 24000, "enrollment bundle too large");
    Ok(format!("SL7.{}", c::b64(bytes)))
}
pub fn import_bundle(text: &str) -> Result<(Profile, Vec<Value>, Option<Value>)> {
    ensure!(text.len() <= 44000, "enrollment bundle too large");
    if text.starts_with("SL4.") {
        return Ok((Profile::import(text)?, vec![], None));
    }
    ensure!(
        text.starts_with("SL7."),
        "expected approved enrollment bundle"
    );
    let v: Value = serde_json::from_slice(&c::unb64(&text[4..])?)?;
    let credential = v["Credential"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing enrollment"))?;
    if !credential.starts_with("SL4.") {
        bail!("legacy invitation wrapper must be explicitly verified before import")
    }
    Ok((
        Profile::import(credential)?,
        v["Entries"].as_array().cloned().unwrap_or_default(),
        v.get("Settings").cloned(),
    ))
}
