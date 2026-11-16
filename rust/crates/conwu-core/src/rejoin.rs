//! Former-membership proofs identify an applicant; SAS and owner approval are
//! still mandatory. Revoked members cannot use history to resurrect a slot.
use crate::{
    crypto as c,
    identity::{self, Directory, Member, Profile},
    unix_seconds, valid_id,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Credential {
    pub network: String,
    pub owner_key: String,
    pub member: Member,
    pub signing_private: String,
    #[serde(default)]
    pub directory: Option<Directory>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Proof {
    pub network: String,
    pub slot: u8,
    pub device: String,
    pub expires: i64,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct History {
    pub network: String,
    pub former: Member,
    pub current_slot: u8,
}

impl Credential {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.member.slot != 1 && self.signing_private.len() <= 512,
            "重新加入凭据无效"
        );
        identity::validate_member(&self.network, &self.owner_key, &self.member)?;
        ensure!(
            c::public(&self.signing_private)? == self.member.signing_key,
            "重新加入私钥不符"
        );
        Ok(())
    }
    pub fn retain(profile: &Profile) -> Option<Self> {
        profile.owner_private.is_empty().then(|| Self {
            network: profile.pair.network.clone(),
            owner_key: profile.owner_key.clone(),
            member: profile.member.clone(),
            signing_private: profile.signing_private.clone(),
            directory: None,
        })
    }
    pub fn prove(&self, code: &str, commitment: &str) -> Result<Proof> {
        self.validate()?;
        ensure!(
            crate::pairing::valid_commitment(commitment),
            "重新加入承诺无效"
        );
        let mut p = Proof {
            network: self.network.clone(),
            slot: self.member.slot,
            device: self.member.device.clone(),
            expires: unix_seconds() + 300,
            signature: String::new(),
        };
        p.signature = c::sign(&self.signing_private, &p.signed(code, commitment)?)?;
        Ok(p)
    }
}
impl Proof {
    fn signed(&self, code: &str, commitment: &str) -> Result<Vec<u8>> {
        c::signed_json(
            &json!({"domain":"streamlink-member-rejoin-v1","Network":self.network,
            "Slot":self.slot,"Device":self.device,"commitment":commitment,
            "locator":hex::encode_upper(c::hash(code.as_bytes())),"Expires":self.expires}),
        )
    }
    pub fn well_formed(&self) -> bool {
        valid_id(&self.network)
            && valid_id(&self.device)
            && (1..=254).contains(&self.slot)
            && !self.signature.is_empty()
            && self.signature.len() <= 128
    }
    pub fn fingerprint(&self) -> Result<String> {
        Ok(hex::encode_upper(c::hash(c::signed_json(self)?)))
    }
    pub fn resolve(
        &self,
        owner: &Profile,
        code: &str,
        commitment: &str,
        history: &[History],
    ) -> Result<Option<Member>> {
        if self.network != owner.pair.network {
            return Ok(None);
        }
        ensure!(
            self.well_formed()
                && self.slot != owner.member.slot
                && self.slot != 1
                && crate::pairing::valid_commitment(commitment)
                && self.expires > unix_seconds()
                && self.expires <= unix_seconds() + 360,
            "重新加入证明无效，请重新申请"
        );
        let members = &owner
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("目录缺失"))?
            .members;
        let mut signing = members
            .iter()
            .find(|m| m.slot == self.slot && m.device == self.device);
        let mut current = signing;
        if current.is_none() {
            if let Some(h) = history.iter().rev().find(|h| {
                h.network == self.network
                    && h.former.slot == self.slot
                    && h.former.device == self.device
            }) {
                identity::validate_member(&self.network, &owner.owner_key, &h.former)?;
                current = members
                    .iter()
                    .find(|m| m.slot == h.current_slot && m.slot != owner.member.slot);
                signing = Some(&h.former);
            }
        }
        let Some(current) = current else {
            return Ok(None);
        };
        ensure!(
            c::verify(
                &signing.unwrap().signing_key,
                &self.signed(code, commitment)?,
                &self.signature
            ),
            "重新加入证明签名不符，请重新申请"
        );
        Ok(Some(current.clone()))
    }
}
pub fn remember(
    owner: &Profile,
    history: &[History],
    former: Member,
    current: &Member,
) -> Vec<History> {
    let mut result = history
        .iter()
        .filter(|h| h.network == owner.pair.network)
        .cloned()
        .collect::<Vec<_>>();
    for h in &mut result {
        if h.current_slot == former.slot {
            h.current_slot = current.slot;
        }
    }
    result.push(History {
        network: owner.pair.network.clone(),
        former,
        current_slot: current.slot,
    });
    result.retain(|h| {
        owner
            .directory
            .as_ref()
            .is_some_and(|d| d.members.iter().any(|m| m.slot == h.current_slot))
    });
    if result.len() > 32 {
        result.drain(..result.len() - 32);
    }
    result
}
