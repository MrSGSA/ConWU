use crate::crypto as c;
use anyhow::{Result, ensure};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const MTU: usize = 1280;
pub const HEADER: usize = 48;
pub const OVERHEAD: usize = 64;
#[derive(Default, Debug)]
pub struct Received {
    pub authenticated: bool,
    pub reply: Option<Vec<u8>>,
    pub packet: Option<Vec<u8>>,
    pub pong: Option<i64>,
    pub control: Option<Vec<u8>>,
    pub synchronization: Option<Vec<u8>>,
    pub diagnostic: Option<Vec<u8>>,
}
struct Lane {
    send: c::Cipher,
    receive: Option<c::Cipher>,
    counter: u64,
    highest: u64,
    seen: Box<[u64; 4096]>,
}
pub struct Link {
    local: u8,
    remote: u8,
    secret: Zeroizing<[u8; 32]>,
    epoch: [u8; 16],
    remote_epoch: Option<[u8; 16]>,
    retired: HashSet<[u8; 16]>,
    send: c::Cipher,
    receive: Option<c::Cipher>,
    counter: u64,
    highest: u64,
    seen: Box<[u64; 4096]>,
    lanes: [Option<Lane>; 3],
    last_receive: Option<Instant>,
    pending_ping: Option<(i64, Instant)>,
    pub rtt: Option<Duration>,
}
fn key(secret: &[u8], epoch: &[u8], from: u8, to: u8, lane: u8) -> c::Cipher {
    let mut context = format!("streamlink-datagram-v4/{from}/{to}");
    if lane != 0 {
        context.push_str(&format!("/stream-lane/{lane}"));
    }
    c::Cipher::new(&c::hkdf(secret, epoch, context.as_bytes()))
}
impl Link {
    pub fn new(local: u8, remote: u8, secret: [u8; 32]) -> Result<Self> {
        Self::with_epoch(local, remote, secret, c::random())
    }
    pub fn with_epoch(local: u8, remote: u8, secret: [u8; 32], epoch: [u8; 16]) -> Result<Self> {
        ensure!(
            (1..=254).contains(&local) && (1..=254).contains(&remote) && local != remote,
            "invalid link identity"
        );
        Ok(Self {
            local,
            remote,
            secret: Zeroizing::new(secret),
            epoch,
            remote_epoch: None,
            retired: HashSet::new(),
            send: key(&secret, &epoch, local, remote, 0),
            receive: None,
            counter: 0,
            highest: 0,
            seen: Box::new([0; 4096]),
            lanes: [None, None, None],
            last_receive: None,
            pending_ping: None,
            rtt: None,
        })
    }
    pub fn connected(&self) -> bool {
        self.remote_epoch.is_some()
            && self
                .last_receive
                .is_some_and(|t| t.elapsed() < Duration::from_secs(12))
    }
    pub fn epoch(&self) -> [u8; 16] {
        self.epoch
    }
    fn lane(&mut self, lane: u8) {
        if lane != 0 && self.lanes[lane as usize - 1].is_none() {
            self.lanes[lane as usize - 1] = Some(Lane {
                send: key(&*self.secret, &self.epoch, self.local, self.remote, lane),
                receive: self
                    .remote_epoch
                    .map(|e| key(&*self.secret, &e, self.remote, self.local, lane)),
                counter: 0,
                highest: 0,
                seen: Box::new([0; 4096]),
            });
        }
    }
    fn encode(&mut self, kind: u8, target: [u8; 16], payload: &[u8], lane: u8) -> Result<Vec<u8>> {
        ensure!(payload.len() <= MTU && lane <= 3, "invalid datagram/lane");
        self.lane(lane);
        let (counter, send) = if lane == 0 {
            (&mut self.counter, &self.send)
        } else {
            let lane = self.lanes[lane as usize - 1].as_mut().unwrap();
            (&mut lane.counter, &lane.send)
        };
        ensure!(*counter != u64::MAX, "session exhausted");
        *counter += 1;
        let mut header = [0; HEADER];
        header[..4].copy_from_slice(b"SLM4");
        header[4] = kind;
        header[5] = self.local;
        header[6] = self.remote;
        header[7] = lane;
        header[8..24].copy_from_slice(&self.epoch);
        header[24..40].copy_from_slice(&target);
        header[40..].copy_from_slice(&counter.to_be_bytes());
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&header[40..]);
        send.packet(&nonce, &header, payload)
    }
    pub fn hello(&mut self) -> Result<Vec<u8>> {
        self.encode(1, [0; 16], &[], 0)
    }
    pub fn probe(&mut self, nonce: i64) -> Result<Option<Vec<u8>>> {
        self.remote_epoch
            .map(|e| self.encode(5, e, &nonce.to_be_bytes(), 0))
            .transpose()
    }
    pub fn ping(&mut self) -> Result<Option<Vec<u8>>> {
        let n = i64::from_be_bytes(c::random());
        self.pending_ping = Some((n, Instant::now()));
        self.probe(n)
    }
    pub fn data(&mut self, payload: &[u8], lane: u8) -> Result<Option<Vec<u8>>> {
        if !self.connected() {
            return Ok(None);
        }
        self.encode(4, self.remote_epoch.unwrap(), payload, lane)
            .map(Some)
    }
    pub fn synchronize(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        if !self.connected() {
            return Ok(None);
        }
        self.encode(9, self.remote_epoch.unwrap(), payload, 0)
            .map(Some)
    }
    pub fn control(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        ensure!((1..=256).contains(&payload.len()), "路径控制长度无效");
        if !self.connected() {
            return Ok(None);
        }
        self.encode(7, self.remote_epoch.unwrap(), payload, 0)
            .map(Some)
    }
    pub fn receive(&mut self, message: &[u8], allow_lanes: bool) -> Received {
        self.try_receive(message, allow_lanes).unwrap_or_default()
    }
    fn try_receive(&mut self, m: &[u8], allow_lanes: bool) -> Result<Received> {
        ensure!(
            (OVERHEAD..=OVERHEAD + MTU).contains(&m.len())
                && &m[..4] == b"SLM4"
                && m[5] == self.remote
                && m[6] == self.local
                && (1..=9).contains(&m[4]),
            "invalid frame"
        );
        let kind = m[4];
        let lane = m[7];
        ensure!(
            lane == 0 || allow_lanes && lane <= 3 && kind == 4,
            "unnegotiated lane"
        );
        let sender: [u8; 16] = m[8..24].try_into()?;
        let target: [u8; 16] = m[24..40].try_into()?;
        ensure!(
            if kind == 1 {
                target == [0; 16]
            } else {
                target == self.epoch
            },
            "wrong destination epoch"
        );
        ensure!(
            !matches!(kind, 1..=3) || m.len() == OVERHEAD,
            "invalid handshake size"
        );
        ensure!(
            !matches!(kind, 5 | 6) || m.len() == OVERHEAD + 8,
            "invalid ping size"
        );
        ensure!(
            kind != 7 || (OVERHEAD + 1..=OVERHEAD + 256).contains(&m.len()),
            "invalid control size"
        );
        ensure!(
            kind != 8 || (OVERHEAD + 512..=OVERHEAD + MTU).contains(&m.len()),
            "invalid diagnostic size"
        );
        let same = self.remote_epoch == Some(sender);
        ensure!(
            same || kind <= 3 && !self.retired.contains(&sender),
            "old or unknown session"
        );
        let sequence = u64::from_be_bytes(m[40..48].try_into()?);
        ensure!(sequence != 0, "invalid sequence");
        self.lane(lane);
        let (top, seen) = if lane == 0 {
            (self.highest, &*self.seen)
        } else {
            let l = self.lanes[lane as usize - 1].as_ref().unwrap();
            (l.highest, &*l.seen)
        };
        if kind != 1 && same {
            ensure!(
                !(sequence <= top && top - sequence >= 4096)
                    && seen[(sequence % 4096) as usize] != sequence,
                "replay"
            );
        }
        let derived;
        let cipher = if same {
            if lane == 0 {
                self.receive.as_ref()
            } else {
                self.lanes[lane as usize - 1]
                    .as_ref()
                    .and_then(|l| l.receive.as_ref())
            }
            .ok_or_else(|| anyhow::anyhow!("missing receive cipher"))?
        } else {
            derived = key(&*self.secret, &sender, self.remote, self.local, lane);
            &derived
        };
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&m[40..48]);
        let mut body = m[48..].to_vec();
        cipher.decrypt(&nonce, &m[..48], &mut body)?;
        if !same && self.retired.len() >= 64 {
            self.epoch = c::random();
            self.send = key(&*self.secret, &self.epoch, self.local, self.remote, 0);
            self.receive = None;
            self.remote_epoch = None;
            self.retired.clear();
            self.seen.fill(0);
            self.counter = 0;
            self.highest = 0;
            self.last_receive = None;
            self.pending_ping = None;
            self.rtt = None;
            self.lanes = [None, None, None];
            return Ok(Received::default());
        }
        if kind == 1 {
            return Ok(Received {
                authenticated: true,
                reply: Some(self.encode(2, sender, &[], 0)?),
                ..Default::default()
            });
        }
        if !same {
            if let Some(old) = self.remote_epoch {
                self.retired.insert(old);
            }
            self.remote_epoch = Some(sender);
            self.receive = Some(key(&*self.secret, &sender, self.remote, self.local, 0));
            self.seen.fill(0);
            self.highest = 0;
            for (i, l) in self.lanes.iter_mut().enumerate() {
                if let Some(l) = l {
                    l.receive = Some(key(
                        &*self.secret,
                        &sender,
                        self.remote,
                        self.local,
                        (i + 1) as u8,
                    ));
                    l.seen.fill(0);
                    l.highest = 0;
                }
            }
        }
        if lane == 0 {
            self.seen[(sequence % 4096) as usize] = sequence;
            self.highest = self.highest.max(sequence);
        } else {
            let l = self.lanes[lane as usize - 1].as_mut().unwrap();
            l.seen[(sequence % 4096) as usize] = sequence;
            l.highest = l.highest.max(sequence);
        }
        self.last_receive = Some(Instant::now());
        let mut r = Received {
            authenticated: true,
            ..Default::default()
        };
        match kind {
            2 => r.reply = Some(self.encode(3, sender, &[], 0)?),
            4 => r.packet = Some(body),
            5 => r.reply = Some(self.encode(6, sender, &body, 0)?),
            6 => {
                let nonce = i64::from_be_bytes(body.as_slice().try_into()?);
                r.pong = Some(nonce);
                if self.pending_ping.is_some_and(|(n, _)| n == nonce) {
                    self.rtt = self.pending_ping.take().map(|(_, t)| t.elapsed());
                }
            }
            7 => r.control = Some(body),
            8 => r.diagnostic = Some(body),
            9 => r.synchronization = Some(body),
            _ => {}
        }
        Ok(r)
    }
}
pub fn wrap(network: &str, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(crate::valid_id(network), "invalid network ID");
    Ok([b"CNW1".as_slice(), &hex::decode(network)?, payload].concat())
}
pub fn unwrap(bytes: &[u8]) -> Option<(String, &[u8])> {
    (bytes.len() >= 20 && &bytes[..4] == b"CNW1")
        .then(|| (hex::encode(&bytes[4..20]), &bytes[20..]))
}
pub fn valid_packet(p: &[u8]) -> bool {
    if !(20..=MTU).contains(&p.len()) || p[0] >> 4 != 4 {
        return false;
    }
    let n = (p[0] & 15) as usize * 4;
    if n < 20 || n > p.len() || u16::from_be_bytes([p[2], p[3]]) as usize != p.len() || p[8] == 0 {
        return false;
    }
    let mut sum: u32 = p[..n]
        .chunks_exact(2)
        .map(|w| u16::from_be_bytes([w[0], w[1]]) as u32)
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    sum == 65535
}
