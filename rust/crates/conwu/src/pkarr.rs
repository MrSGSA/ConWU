use crate::store::Store;
use anyhow::{Context, Result, ensure};
use conwu_core::{code, crypto as c, identity::Profile, unix_seconds};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use futures_util::{StreamExt, stream::FuturesUnordered};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
};

const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
pub use conwu_core::rendezvous::Announcement;
#[derive(Clone)]
pub struct Record {
    pub sequence: i64,
    pub announcement: Announcement,
    pub wire: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Checkpoint {
    sequence: i64,
    digest: String,
}
pub struct Client {
    http: reqwest::Client,
    store: Arc<Store>,
    checkpoints: Mutex<BTreeMap<String, Checkpoint>>,
}

pub fn key(seed: &[u8; 32]) -> String {
    encode_key(&SigningKey::from_bytes(seed).verifying_key().to_bytes())
}
pub fn source(seed: &[u8; 32]) -> String {
    format!("pkarr://{}", key(seed))
}
pub fn member_seed(profile: &Profile) -> Result<[u8; 32]> {
    Ok(*c::hkdf(
        &c::unb64(&profile.signing_private)?,
        profile.pair.network.as_bytes(),
        b"conwu-pkarr-member-source-v1",
    ))
}
pub fn encode_key(bytes: &[u8; 32]) -> String {
    let (mut bits, mut acc, mut out) = (0u8, 0u32, String::with_capacity(52));
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}
pub fn decode_key(text: &str) -> Result<[u8; 32]> {
    ensure!(text.len() == 52, "PKARR 需要完整的52位公钥");
    let (mut out, mut bits, mut acc, mut at) = ([0u8; 32], 0u8, 0u32, 0usize);
    for b in text.bytes() {
        let n = ALPHABET
            .iter()
            .position(|v| *v == b)
            .context("PKARR 公钥无效")?;
        acc = (acc << 5) | n as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            ensure!(at < 32, "PKARR 公钥过长");
            out[at] = (acc >> bits) as u8;
            at += 1;
        }
    }
    ensure!(at == 32 && encode_key(&out) == text, "PKARR 公钥编码不规范");
    Ok(out)
}
pub(crate) fn source_key(text: &str) -> Result<&str> {
    let key = text.strip_prefix("pkarr://").context("PKARR 来源无效")?;
    decode_key(key)?;
    Ok(key)
}
fn signable(sequence: i64, dns: &[u8]) -> Vec<u8> {
    [
        format!("3:seqi{sequence}e1:v{}:", dns.len()).as_bytes(),
        dns,
    ]
    .concat()
}
fn validate(a: &Announcement, seq: i64) -> Result<()> {
    let now = unix_seconds();
    ensure!(
        seq > 0 && seq / 1_000_000 <= now + 300 && seq / 1_000_000 >= now - 7200,
        "PKARR 时间无效"
    );
    ensure!(
        a.version == 1
            && code::valid_mode(&a.mode)
            && a.expires > now
            && a.expires <= seq / 1_000_000 + 7200
            && (1..=8).contains(&a.endpoints.len())
            && a.state.as_ref().is_none_or(|s| s.len() <= 512),
        "PKARR 公告已过期或无效"
    );
    for e in &a.endpoints {
        ensure!(
            e.parse::<SocketAddr>()
                .is_ok_and(|e| code::valid_endpoint(&e)),
            "PKARR 入口无效"
        );
    }
    Ok(())
}
pub fn create(seed: &[u8; 32], seq: i64, a: &Announcement) -> Result<Vec<u8>> {
    validate(a, seq)?;
    let text = serde_json::to_vec(a)?;
    let mut txt = Vec::new();
    for part in text.chunks(255) {
        txt.push(part.len() as u8);
        txt.extend_from_slice(part);
    }
    let mut dns = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    for label in ["_conwu", &key(seed)] {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&[0, 16, 0, 1, 0, 0, 1, 44]);
    dns.extend_from_slice(&(txt.len() as u16).to_be_bytes());
    dns.extend(txt);
    ensure!(dns.len() <= 1000, "PKARR 公告过大");
    let signature = SigningKey::from_bytes(seed).sign(&signable(seq, &dns));
    Ok([signature.to_bytes().as_slice(), &seq.to_be_bytes(), &dns].concat())
}
fn read_name(dns: &[u8], offset: &mut usize) -> Result<String> {
    let (mut at, mut jumped, mut seen, mut labels) = (*offset, false, HashSet::new(), Vec::new());
    for _ in 0..128 {
        ensure!(at < dns.len() && seen.insert(at), "DNS 名称越界或循环");
        let n = dns[at];
        at += 1;
        if n == 0 {
            if !jumped {
                *offset = at;
            }
            return Ok(labels.join("."));
        }
        if n & 0xc0 == 0xc0 {
            ensure!(at < dns.len(), "DNS 指针截断");
            let target = (((n & 0x3f) as usize) << 8) | dns[at] as usize;
            at += 1;
            if !jumped {
                *offset = at;
            }
            jumped = true;
            at = target;
            continue;
        }
        ensure!(n <= 63 && at + n as usize <= dns.len(), "DNS 标签截断");
        labels.push(std::str::from_utf8(&dns[at..at + n as usize])?.to_ascii_lowercase());
        at += n as usize;
        ensure!(
            labels.iter().map(|s| s.len() + 1).sum::<usize>() <= 255,
            "DNS 名称过长"
        );
    }
    anyhow::bail!("DNS 指针过多")
}
pub fn read(key: &str, wire: &[u8]) -> Result<Record> {
    ensure!((84..=1072).contains(&wire.len()), "PKARR 公告长度无效");
    let public = VerifyingKey::from_bytes(&decode_key(key)?)?;
    let seq = i64::from_be_bytes(wire[64..72].try_into()?);
    let dns = &wire[72..];
    public.verify_strict(&signable(seq, dns), &Signature::from_slice(&wire[..64])?)?;
    ensure!(
        dns.len() >= 12 && dns[2] & 0x82 == 0x80 && dns[4..6] == [0, 0],
        "PKARR DNS 头无效"
    );
    let count = u16::from_be_bytes(dns[6..8].try_into()?);
    ensure!((1..=32).contains(&count), "PKARR 记录数无效");
    let (mut at, mut found) = (12, None);
    for _ in 0..count {
        let name = read_name(dns, &mut at)?;
        ensure!(at + 10 <= dns.len(), "DNS 记录截断");
        let kind = u16::from_be_bytes(dns[at..at + 2].try_into()?);
        let class = u16::from_be_bytes(dns[at + 2..at + 4].try_into()?);
        let n = u16::from_be_bytes(dns[at + 8..at + 10].try_into()?) as usize;
        at += 10;
        let end = at + n;
        ensure!(end <= dns.len(), "DNS 数据截断");
        if kind == 16 && class & 0x7fff == 1 && name == format!("_conwu.{key}") {
            ensure!(found.is_none(), "重复 PKARR 公告");
            let mut txt = Vec::new();
            while at < end {
                let n = dns[at] as usize;
                at += 1;
                ensure!(at + n <= end, "TXT 截断");
                txt.extend_from_slice(&dns[at..at + n]);
                at += n;
            }
            found = Some(serde_json::from_slice::<Announcement>(&txt)?);
        }
        at = end;
    }
    let announcement = found.context("没有 ConWU 公告")?;
    validate(&announcement, seq)?;
    Ok(Record {
        sequence: seq,
        announcement,
        wire: wire.to_vec(),
    })
}
impl Client {
    pub fn open(store: Arc<Store>) -> Result<Arc<Self>> {
        let file = store.root.join("pkarr-checkpoints.json");
        let checkpoints = if file.exists() {
            ensure!(
                std::fs::metadata(&file)?.len() <= 1024 * 1024,
                "PKARR 检查点过大"
            );
            serde_json::from_slice(&std::fs::read(file)?)?
        } else {
            BTreeMap::new()
        };
        let client = Arc::new(Self {
            http: crate::discovery::http_client()?,
            store,
            checkpoints: Mutex::new(checkpoints),
        });
        Ok(client)
    }
    pub async fn resolve(&self, source: &str, mode: &str, gateways: &[String]) -> Result<Record> {
        let key = source_key(source)?;
        let mut tasks = FuturesUnordered::new();
        for gateway in gateways.iter().take(4) {
            validate_gateway(gateway)?;
            let request = self
                .http
                .get(format!("{}/{key}", gateway.trim_end_matches('/')));
            tasks.push(async move {
                let response = request.send().await?.error_for_status()?;
                let bytes = bounded(response, 1072).await?;
                read(key, &bytes)
            });
        }
        let mut records = vec![];
        while let Some(result) = tasks.next().await {
            if let Ok(r) = result {
                if r.announcement.mode == mode {
                    records.push(r);
                }
            }
        }
        records.sort_by_key(|r| r.sequence);
        let record = records.pop().context("PKARR 网关暂无有效记录")?;
        let digest = hex::encode(c::hash(&record.wire));
        let mut checkpoints = self.checkpoints.lock().unwrap();
        if let Some(prior) = checkpoints.get(key) {
            ensure!(
                record.sequence >= prior.sequence
                    && (record.sequence != prior.sequence || digest == prior.digest),
                "拒绝 PKARR 回退或同序号冲突"
            );
        }
        if checkpoints
            .get(key)
            .is_none_or(|p| p.sequence < record.sequence)
        {
            ensure!(
                checkpoints.contains_key(key) || checkpoints.len() < 4096,
                "PKARR 检查点已满"
            );
            let mut next = checkpoints.clone();
            next.insert(
                key.into(),
                Checkpoint {
                    sequence: record.sequence,
                    digest,
                },
            );
            self.store
                .write("pkarr-checkpoints.json", &serde_json::to_vec(&next)?, true)?;
            *checkpoints = next;
        }
        Ok(record)
    }
    pub async fn publish(
        &self,
        seed: &[u8; 32],
        seq: i64,
        a: &Announcement,
        gateways: &[String],
    ) -> Result<usize> {
        let wire = create(seed, seq, a)?;
        let key = key(seed);
        let mut tasks = FuturesUnordered::new();
        for gateway in gateways.iter().take(4) {
            validate_gateway(gateway)?;
            tasks.push(
                self.http
                    .put(format!("{}/{key}", gateway.trim_end_matches('/')))
                    .header("Content-Type", "application/octet-stream")
                    .body(wire.clone())
                    .send(),
            );
        }
        let mut accepted = 0;
        while let Some(r) = tasks.next().await {
            if r.is_ok_and(|r| r.status().is_success()) {
                accepted += 1;
            }
        }
        ensure!(accepted > 0, "PKARR 暂未发布成功，将保留当前连接并重试");
        Ok(accepted)
    }
}
fn validate_gateway(value: &str) -> Result<()> {
    let u = url::Url::parse(value)?;
    ensure!(
        u.scheme() == "https"
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none(),
        "PKARR 网关必须是 HTTPS 地址"
    );
    Ok(())
}
async fn bounded(response: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    ensure!(
        response.content_length().is_none_or(|n| n <= max as u64),
        "响应过大"
    );
    let mut stream = response.bytes_stream();
    let mut out = vec![];
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk?);
        ensure!(out.len() <= max, "响应过大");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_dns_roundtrip_and_tamper() {
        let seed = c::random();
        let a = Announcement {
            version: 1,
            mode: "tcp".into(),
            expires: unix_seconds() + 3600,
            endpoints: vec!["203.0.113.10:44680".into()],
            state: None,
        };
        let wire = create(&seed, unix_seconds() * 1_000_000, &a).unwrap();
        assert_eq!(
            read(&key(&seed), &wire).unwrap().announcement.endpoints,
            a.endpoints
        );
        let mut wrong = wire;
        *wrong.last_mut().unwrap() ^= 1;
        assert!(read(&key(&seed), &wrong).is_err());
        assert_eq!(
            decode_key(&key(&seed)).unwrap(),
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        );
    }
}
