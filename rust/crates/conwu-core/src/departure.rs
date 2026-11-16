use crate::{
    crypto as c,
    identity::{Member, Profile, validate_member},
    valid_id,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, Serialize, Deserialize)]
pub struct Notice {
    #[serde(rename = "n")]
    pub network: String,
    #[serde(rename = "m")]
    pub member: Member,
    #[serde(rename = "r")]
    pub nonce: String,
    #[serde(rename = "s")]
    pub signature: String,
}
impl Notice {
    fn data(&self, owner: &str) -> Result<Vec<u8>> {
        c::signed_json(
            &json!({"domain":"conwu-member-departure-v1","owner":owner,"Network":self.network,"Member":self.member,"Nonce":self.nonce}),
        )
    }
    pub fn create(profile: &Profile) -> Result<Self> {
        profile.validate()?;
        ensure!(
            profile.owner_private.is_empty() && profile.member.slot > 1,
            "仅从机能发送本人退出通知"
        );
        let mut n = Self {
            network: profile.pair.network.clone(),
            member: profile.member.clone(),
            nonce: crate::id(),
            signature: String::new(),
        };
        n.signature = c::sign(&profile.signing_private, &n.data(&profile.owner_key)?)?;
        Ok(n)
    }
    pub fn validate(&self, owner: &str) -> Result<()> {
        ensure!(
            valid_id(&self.network) && valid_id(&self.nonce) && self.member.slot > 1,
            "退出通知无效"
        );
        validate_member(&self.network, owner, &self.member)?;
        ensure!(
            c::verify(
                &self.member.signing_key,
                &self.data(owner)?,
                &self.signature
            ),
            "退出通知签名无效"
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Receipt {
    pub network: String,
    pub nonce: String,
    pub slot: u8,
    pub revision: i64,
    pub signature: String,
}
impl Receipt {
    fn data(&self) -> Result<Vec<u8>> {
        c::signed_json(
            &json!({"domain":"conwu-member-departure-receipt-v1","Network":self.network,"Nonce":self.nonce,"Slot":self.slot,"Revision":self.revision}),
        )
    }
    pub fn create(profile: &Profile, notice: &Notice) -> Result<Self> {
        let d = profile
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("目录缺失"))?;
        ensure!(
            !profile.owner_private.is_empty()
                && profile.pair.network == notice.network
                && !d.members.iter().any(|m| m.slot == notice.member.slot),
            "尚未移除此成员"
        );
        let mut r = Self {
            network: notice.network.clone(),
            nonce: notice.nonce.clone(),
            slot: notice.member.slot,
            revision: d.revision,
            signature: String::new(),
        };
        r.signature = c::sign(&profile.owner_private, &r.data()?)?;
        Ok(r)
    }
    pub fn validate(&self, owner: &str, notice: &Notice) -> Result<()> {
        ensure!(
            self.network == notice.network
                && self.nonce == notice.nonce
                && self.slot == notice.member.slot
                && self.revision > 0
                && c::verify(owner, &self.data()?, &self.signature),
            "退出回执无效"
        );
        Ok(())
    }
}
