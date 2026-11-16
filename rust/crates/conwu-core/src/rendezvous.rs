//! Pair-encrypted PKARR boot/entry acknowledgements. Endpoints remain public
//! signed hints; member state is bound to the record and the sending member.
use crate::{
    crypto as c,
    identity::{Member, Profile},
    unix_seconds,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Announcement {
    pub version: u8,
    pub mode: String,
    pub expires: i64,
    pub endpoints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct State {
    pub boot: Uuid,
    pub acknowledged_boot: Uuid,
    pub observed_at: i64,
    pub expires: i64,
    pub name: String,
    pub entry: Uuid,
    pub acknowledged_entry: Uuid,
}
fn aad(p: &Profile, sender: u8, source: &str, r: &Announcement) -> Result<Vec<u8>> {
    c::signed_json(
        &json!({"domain":"conwu-pkarr-state-v1","network":p.pair.network,"sender":sender,"source":source,"Mode":r.mode,"Expires":r.expires,"Endpoints":r.endpoints}),
    )
}
fn key(p: &Profile, peer: &Member, sender: u8) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    Ok(c::hkdf(
        &*p.shared_key(peer)?,
        p.pair.network.as_bytes(),
        format!("conwu-pkarr-state-v1/{sender}").as_bytes(),
    ))
}
pub fn entry_id(source: &str, r: &Announcement, boot: Uuid) -> Result<Uuid> {
    let data = c::signed_json(
        &json!({"domain":"conwu-pkarr-entry-v1","source":source,"boot":boot.to_string(),"Mode":r.mode,"Endpoints":r.endpoints}),
    )?;
    Ok(Uuid::from_bytes_le(c::hash(&data)[..16].try_into()?))
}
impl State {
    pub fn new(boot: Uuid, name: &str) -> Self {
        Self {
            boot,
            acknowledged_boot: Uuid::nil(),
            observed_at: unix_seconds(),
            expires: unix_seconds() + 120,
            name: name.into(),
            entry: Uuid::nil(),
            acknowledged_entry: Uuid::nil(),
        }
    }
    fn validate(&self) -> Result<()> {
        let now = unix_seconds();
        ensure!(
            !self.boot.is_nil()
                && !self.entry.is_nil()
                && self.observed_at > 0
                && self.observed_at <= now + 5
                && self.expires > now
                && self.expires <= self.observed_at + 180,
            "PKARR 对端状态已过期或无效"
        );
        c::check_name(&self.name)?;
        ensure!(self.name.len() <= 256, "PKARR 名称过长");
        Ok(())
    }
    pub fn seal(
        &self,
        p: &Profile,
        peer: &Member,
        source: &str,
        r: &Announcement,
    ) -> Result<String> {
        let mut state = self.clone();
        state.entry = entry_id(source, r, state.boot)?;
        state.validate()?;
        let mut bytes = zeroize::Zeroizing::new(vec![1]);
        for id in [
            state.boot,
            state.acknowledged_boot,
            state.entry,
            state.acknowledged_entry,
        ] {
            bytes.extend_from_slice(&id.to_bytes_le());
        }
        bytes.extend_from_slice(&state.observed_at.to_le_bytes());
        bytes.extend_from_slice(&state.expires.to_le_bytes());
        bytes.extend_from_slice(&(state.name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(state.name.as_bytes());
        c::seal(
            &*key(p, peer, p.member.slot)?,
            &aad(p, p.member.slot, source, r)?,
            &bytes,
        )
    }
    pub fn open(p: &Profile, peer: &Member, source: &str, r: &Announcement) -> Result<Self> {
        let cipher = r.state.as_deref().context("PKARR 对端状态缺失")?;
        let bytes = c::open(
            &*key(p, peer, peer.slot)?,
            &aad(p, peer.slot, source, r)?,
            cipher,
            512,
        )?;
        ensure!(
            (83..=339).contains(&bytes.len()) && bytes[0] == 1,
            "PKARR 状态长度或版本无效"
        );
        let id =
            |at: usize| -> Result<Uuid> { Ok(Uuid::from_bytes_le(bytes[at..at + 16].try_into()?)) };
        let length = u16::from_le_bytes(bytes[81..83].try_into()?) as usize;
        ensure!(
            length <= 256 && bytes.len() == 83 + length,
            "PKARR 名称长度无效"
        );
        let state = Self {
            boot: id(1)?,
            acknowledged_boot: id(17)?,
            entry: id(33)?,
            acknowledged_entry: id(49)?,
            observed_at: i64::from_le_bytes(bytes[65..73].try_into()?),
            expires: i64::from_le_bytes(bytes[73..81].try_into()?),
            name: std::str::from_utf8(&bytes[83..])?.to_owned(),
        };
        state.validate()?;
        ensure!(
            state.entry == entry_id(source, r, state.boot)?,
            "PKARR 状态与入口版本不符"
        );
        Ok(state)
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn state_is_bound_to_record_and_member() -> anyhow::Result<()> {
        let mut host = crate::identity::Profile::create("tcp")?;
        let guest = crate::identity::Profile::import(&host.issue(None)?.export()?)?;
        let mut record = super::Announcement {
            version: 1,
            mode: "tcp".into(),
            expires: crate::unix_seconds() + 300,
            endpoints: vec!["203.0.113.1:443".into()],
            state: None,
        };
        record.state = Some(super::State::new(uuid::Uuid::new_v4(), "主机").seal(
            &host,
            &guest.member,
            "pkarr://fixture",
            &record,
        )?);
        assert_eq!(
            super::State::open(&guest, &host.member, "pkarr://fixture", &record)?.name,
            "主机"
        );
        record.endpoints[0] = "203.0.113.2:443".into();
        assert!(super::State::open(&guest, &host.member, "pkarr://fixture", &record).is_err());
        Ok(())
    }
}
