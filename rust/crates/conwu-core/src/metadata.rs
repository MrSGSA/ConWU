use crate::{
    crypto as c,
    identity::{Directory, Member, Profile, validate_directory},
    unix_seconds,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Announcement {
    pub slot: u8,
    pub device: String,
    pub revision: i64,
    pub expires: i64,
    pub endpoint: String,
    pub name: String,
    #[serde(default)]
    pub traversal: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkarr_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_endpoints: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub existing_entry_only: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub connection_paused: bool,
}
fn is_false(v: &bool) -> bool {
    !*v
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Envelope {
    pub slot: u8,
    pub device: String,
    pub revision: i64,
    pub data: String,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Snapshot {
    pub directory: Directory,
    pub nodes: Vec<Envelope>,
}
fn signed(network: &str, e: &Envelope) -> Result<Vec<u8>> {
    c::signed_json(
        &json!({"domain":"streamlink-metadata-v4","network":network,"Slot":e.slot,"Device":e.device,"Revision":e.revision,"Data":e.data}),
    )
}
impl Envelope {
    pub fn seal(profile: &Profile, a: &Announcement) -> Result<Self> {
        ensure!(
            a.slot == profile.member.slot && a.device == profile.member.device && a.revision > 0,
            "公告身份无效"
        );
        c::check_name(&a.name)?;
        let data = c::seal(
            &profile.pair.key("mesh-metadata-v4"),
            format!("{}/{}", profile.pair.network, a.slot).as_bytes(),
            &c::signed_json(a)?,
        )?;
        ensure!(data.len() <= 4096, "公告过大");
        let mut e = Self {
            slot: a.slot,
            device: a.device.clone(),
            revision: a.revision,
            data,
            signature: String::new(),
        };
        e.signature = c::sign(
            &profile.signing_private,
            &signed(&profile.pair.network, &e)?,
        )?;
        Ok(e)
    }
    pub fn validate(&self, network: &str, member: &Member) -> Result<()> {
        ensure!(
            self.slot == member.slot
                && self.device == member.device
                && self.revision > 0
                && (40..=4096).contains(&self.data.len())
                && c::verify(
                    &member.signing_key,
                    &signed(network, self)?,
                    &self.signature
                ),
            "公告签名无效"
        );
        Ok(())
    }
    pub fn open(&self, profile: &Profile, member: &Member) -> Result<Announcement> {
        self.validate(&profile.pair.network, member)?;
        let plain = c::open(
            &profile.pair.key("mesh-metadata-v4"),
            format!("{}/{}", profile.pair.network, self.slot).as_bytes(),
            &self.data,
            4096,
        )?;
        let a: Announcement = serde_json::from_slice(&plain)?;
        let now = unix_seconds();
        ensure!(
            a.slot == self.slot
                && a.device == self.device
                && a.revision == self.revision
                && a.expires > now
                && a.expires <= now + 180,
            "公告身份或有效期无效"
        );
        c::check_name(&a.name)?;
        ensure!(
            a.endpoint.len() <= 64
                && (a.endpoint.is_empty()
                    || a.endpoint
                        .parse()
                        .is_ok_and(|e| crate::code::valid_endpoint(&e))),
            "公告入口无效"
        );
        ensure!(
            a.existing_endpoints.as_ref().is_none_or(|v| v.len() <= 8
                && v.iter()
                    .all(|s| s.parse().is_ok_and(|e| crate::code::valid_endpoint(&e)))),
            "公告入口集合无效"
        );
        Ok(a)
    }
}
pub fn successor(next: &Directory, prior: &Directory) -> Result<()> {
    validate_directory(next, &prior.network, &prior.owner_key, prior.revision)?;
    ensure!(
        next.next_slot >= prior.next_slot
            && next.pairwise == prior.pairwise
            && next.governance == prior.governance,
        "目录权限或槽位回退"
    );
    if next.revision == prior.revision {
        ensure!(
            c::signed_json(next)? == c::signed_json(prior)?,
            "同版本目录冲突"
        );
        return Ok(());
    }
    for m in &next.members {
        ensure!(
            m.slot as u16 >= prior.next_slot || prior.members.contains(m),
            "回收或改写已用成员身份"
        );
    }
    if let Some(addresses) = &prior.reserved_addresses {
        ensure!(
            next.reserved_addresses
                .as_ref()
                .is_some_and(|v| addresses.iter().all(|ip| v.contains(ip))),
            "地址高水位回退"
        );
    }
    Ok(())
}
pub fn frames(snapshot: &Snapshot) -> Result<Vec<Vec<u8>>> {
    let bytes = c::signed_json(snapshot)?;
    ensure!(bytes.len() <= 49152, "同步数据过大");
    let id = c::random::<16>();
    let n = bytes.len() as u32;
    Ok(bytes
        .chunks(1200)
        .enumerate()
        .map(|(i, b)| {
            [
                id.as_slice(),
                &n.to_be_bytes(),
                &(i as u32).to_be_bytes(),
                b,
            ]
            .concat()
        })
        .collect())
}
pub struct Assembly {
    id: [u8; 16],
    data: Vec<u8>,
    seen: Vec<bool>,
    created: Instant,
}
pub fn receive(assembly: &mut Option<Assembly>, frame: &[u8]) -> Result<Option<Snapshot>> {
    ensure!((25..=1224).contains(&frame.len()), "同步分片大小无效");
    let id: [u8; 16] = frame[..16].try_into()?;
    let len = u32::from_be_bytes(frame[16..20].try_into()?) as usize;
    let index = u32::from_be_bytes(frame[20..24].try_into()?) as usize;
    ensure!(
        (1..=49152).contains(&len)
            && index < (len + 1199) / 1200
            && frame.len() == 24 + 1200.min(len - index * 1200),
        "同步分片范围无效"
    );
    if assembly
        .as_ref()
        .is_none_or(|a| a.id != id || a.created.elapsed() > Duration::from_secs(10))
    {
        *assembly = Some(Assembly {
            id,
            data: vec![0; len],
            seen: vec![false; (len + 1199) / 1200],
            created: Instant::now(),
        });
    }
    let a = assembly.as_mut().context("同步缓冲缺失")?;
    ensure!(a.data.len() == len, "同步长度改变");
    if a.seen[index] {
        return Ok(None);
    }
    a.data[index * 1200..index * 1200 + frame.len() - 24].copy_from_slice(&frame[24..]);
    a.seen[index] = true;
    if a.seen.iter().all(|b| *b) {
        let a = assembly.take().unwrap();
        return Ok(Some(serde_json::from_slice(&a.data)?));
    }
    Ok(None)
}
