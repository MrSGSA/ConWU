//! Authenticated CWF1 connection grouping, compatible with the desktop wire.
use crate::{crypto as c, identity::Profile};
use anyhow::{Context, Result, ensure};
use zeroize::Zeroizing;
pub const SIZE: usize = 100;
pub struct Identity {
    pub network: String,
    pub client: u8,
    pub server: u8,
    pub https: bool,
    pub key: Zeroizing<[u8; 32]>,
}
impl Identity {
    pub fn new(profile: &Profile, client: u8, server: u8) -> Result<Self> {
        ensure!(
            client != server
                && [client, server].contains(&profile.member.slot)
                && profile.directory.as_ref().is_some_and(|d| d.pairwise),
            "invalid flow roles"
        );
        let remote = if client == profile.member.slot {
            server
        } else {
            client
        };
        let peer = profile
            .directory
            .as_ref()
            .unwrap()
            .members
            .iter()
            .find(|m| m.slot == remote)
            .context("missing flow member")?;
        let shared = profile.shared_key(peer)?;
        let info = format!(
            "conwu-stream-flow-v1/{}/{}/{}/{}",
            profile.pair.network,
            profile.pair.mode,
            client.min(server),
            client.max(server)
        );
        Ok(Self {
            network: profile.pair.network.clone(),
            client,
            server,
            https: profile.pair.mode == "https",
            key: c::hkdf(&*shared, &[], info.as_bytes()),
        })
    }
    pub fn frame(
        &self,
        kind: u8,
        lane: u8,
        from_server: bool,
        client_nonce: &[u8; 16],
        server_nonce: &[u8; 16],
        issued: i64,
    ) -> Vec<u8> {
        let mut f = vec![0; SIZE];
        f[..4].copy_from_slice(b"CWF1");
        f[4] = 1;
        f[5] = kind;
        f[6] = lane;
        f[7] = if self.https { 2 } else { 1 };
        f[8..24].copy_from_slice(&hex::decode(&self.network).unwrap());
        f[24] = self.client;
        f[25] = self.server;
        f[26] = u8::from(from_server);
        f[28..44].copy_from_slice(client_nonce);
        f[44..60].copy_from_slice(server_nonce);
        f[60..68].copy_from_slice(&issued.to_be_bytes());
        let mac = c::mac(&self.key[..], &f[..68]);
        f[68..].copy_from_slice(&mac);
        f
    }
    pub fn valid(
        &self,
        f: &[u8],
        kind: u8,
        lane: u8,
        from_server: bool,
        client_nonce: &[u8; 16],
        server_nonce: &[u8; 16],
        issued: i64,
    ) -> bool {
        is_control(f)
            && c::eq(
                f,
                &self.frame(kind, lane, from_server, client_nonce, server_nonce, issued),
            )
    }
}
pub fn is_control(f: &[u8]) -> bool {
    f.len() == SIZE && &f[..4] == b"CWF1" && f[4] == 1
}
pub fn lane(packet: &[u8]) -> u8 {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return 1;
    }
    let header = (packet[0] & 15) as usize * 4;
    let fragmented = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0;
    let mut hash = 2166136261u32;
    for b in &packet[12..20] {
        hash = (hash ^ *b as u32).wrapping_mul(16777619);
    }
    hash = (hash ^ packet[9] as u32).wrapping_mul(16777619);
    if !fragmented && matches!(packet[9], 6 | 17) && header >= 20 && packet.len() >= header + 4 {
        let from = u16::from_be_bytes([packet[header], packet[header + 1]]);
        let to = u16::from_be_bytes([packet[header + 2], packet[header + 3]]);
        if [from, to].iter().any(|p| matches!(p, 47999 | 48010)) {
            return 1;
        }
        if [from, to].contains(&48000) {
            return 2;
        }
        if [from, to].contains(&47998) {
            return 3;
        }
        for b in &packet[header..header + 4] {
            hash = (hash ^ *b as u32).wrapping_mul(16777619);
        }
    }
    1 + (hash % 3) as u8
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roles_and_mac_are_bound() {
        let mut p = Profile::create("tcp").unwrap();
        let enrollment = p.issue(None).unwrap();
        let g = Profile::import(&enrollment.export().unwrap()).unwrap();
        let a = Identity::new(&p, 2, 1).unwrap();
        let b = Identity::new(&g, 2, 1).unwrap();
        let client = c::random();
        let server = c::random();
        let f = a.frame(4, 0, true, &client, &server, 123);
        assert!(b.valid(&f, 4, 0, true, &client, &server, 123));
        assert!(!b.valid(&f, 4, 0, false, &client, &server, 123));
        let mut tamper = f;
        tamper[25] ^= 1;
        assert!(!b.valid(&tamper, 4, 0, true, &client, &server, 123));
    }
}
