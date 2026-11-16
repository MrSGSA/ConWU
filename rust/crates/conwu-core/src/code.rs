use anyhow::{Result, ensure};
use std::net::{IpAddr, SocketAddr};
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectCode {
    pub endpoint: SocketAddr,
    pub mode: String,
    pub room: String,
    pub punch: bool,
    pub coordinator: bool,
}
pub fn valid_mode(mode: &str) -> bool {
    matches!(
        mode,
        "faketcp" | "phantun" | "mimic" | "tcpraw" | "tcp" | "https" | "udp"
    )
}
pub fn stream_mode(mode: &str) -> bool {
    matches!(mode, "tcp" | "https")
}
pub fn valid_endpoint(e: &SocketAddr) -> bool {
    if e.port() == 0 {
        return false;
    }
    match e.ip() {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            b[0] > 0
                && b[0] < 224
                && b[0] != 127
                && !(b[0] == 169 && b[1] == 254)
                && !(b[0] == 192 && b[1] == 0 && b[2] == 0)
        }
        IpAddr::V6(ip) => {
            let b = ip.octets();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && b[..12] != [0; 12]
                && ip.to_ipv4_mapped().is_none()
                && !(b[0] == 0xfe && b[1] & 0x80 != 0)
                && matches!(e,SocketAddr::V6(e)if e.scope_id()==0)
        }
    }
}
pub fn global_ipv6(ip: std::net::Ipv6Addr) -> bool {
    let b = ip.octets();
    b[0] & 0xe0 == 0x20
        && !(b[0] == 0x20 && b[1] == 2)
        && !(b[..2] == [0x20, 1] && b[2] < 2)
        && b[..4] != [0x20, 1, 0x0d, 0xb8]
        && !(b[0] == 0x3f && b[1] == 0xff && b[2] & 0xf0 == 0)
}
fn crc(bytes: &[u8]) -> u8 {
    let mut crc = 0u8;
    for b in bytes {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 128 != 0 {
                (crc << 1) ^ 7
            } else {
                crc << 1
            };
        }
    }
    crc
}
fn bits(value: u128, n: usize, out: &mut Vec<bool>) {
    for i in (0..n).rev() {
        out.push((value >> i) & 1 == 1)
    }
}
fn bytes(bits: &[bool]) -> Vec<u8> {
    let pad = (8 - bits.len() % 8) % 8;
    let mut out = vec![0; (bits.len() + pad) / 8];
    for (i, b) in bits.iter().enumerate() {
        if *b {
            out[(pad + i) / 8] |= 1 << (7 - (pad + i) % 8)
        }
    }
    out
}
fn take(bits: &[bool], at: &mut usize, n: usize) -> u128 {
    let mut v = 0;
    for b in &bits[*at..*at + n] {
        v = (v << 1) | u128::from(*b);
    }
    *at += n;
    v
}
impl DirectCode {
    pub fn issue(&self) -> Result<String> {
        ensure!(
            valid_endpoint(&self.endpoint)
                && self.room.len() == 6
                && self.room.bytes().all(|b| b.is_ascii_digit()),
            "invalid direct-code endpoint or room"
        );
        let header = match self.mode.as_str() {
            "faketcp" => 2,
            "udp" => 3,
            "tcp" => 4,
            "https" => 5,
            "phantun" => 6,
            "mimic" => 7,
            "tcpraw" => 8,
            _ => anyhow::bail!("unknown carrier"),
        };
        let mut out = vec![];
        match self.endpoint.ip() {
            IpAddr::V4(ip) => {
                let h = if self.coordinator {
                    ensure!(!self.punch && self.mode != "udp", "invalid assistance mode");
                    match header {
                        2 => 11,
                        4 => 14,
                        5 => 15,
                        6 => 12,
                        7 => 10,
                        _ => 13,
                    }
                } else if self.punch {
                    ensure!(
                        header == 7,
                        "first pairing discovery is not supported by this carrier"
                    );
                    9
                } else {
                    header
                };
                bits(h, 4, &mut out);
                bits(u32::from(ip) as u128, 32, &mut out);
            }
            IpAddr::V6(ip) => {
                ensure!(
                    stream_mode(&self.mode) && !self.punch && !self.coordinator,
                    "IPv6 direct code requires TCP/HTTPS without IPv4 assistance flags"
                );
                bits(1, 4, &mut out);
                bits(header, 4, &mut out);
                bits(u128::from(ip), 128, &mut out);
            }
        }
        bits(self.endpoint.port() as u128, 16, &mut out);
        bits(self.room.parse::<u128>()?, 20, &mut out);
        let crc = crc(&bytes(&out));
        bits(crc as u128, 8, &mut out);
        let text: Vec<char> = out
            .chunks_exact(5)
            .map(|b| {
                let mut n = 0;
                for x in b {
                    n = n * 2 + usize::from(*x)
                }
                ALPHABET[n] as char
            })
            .collect();
        Ok(text
            .chunks(4)
            .map(|g| g.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("-"))
    }
    pub fn import(text: &str) -> Result<Self> {
        ensure!(text.len() <= 64, "direct code is too long");
        let mut value = vec![];
        for c in text.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            let d = ALPHABET
                .iter()
                .position(|b| *b == c as u8)
                .filter(|_| c.is_ascii())
                .ok_or_else(|| anyhow::anyhow!("invalid direct-code symbol"))?;
            bits(d as u128, 5, &mut value);
        }
        ensure!(
            matches!(value.len(), 80 | 180),
            "direct code must contain 16 or 36 symbols"
        );
        let checksum = value.len() - 8;
        let mut at = checksum;
        ensure!(
            take(&value, &mut at, 8) as u8 == crc(&bytes(&value[..checksum])),
            "direct-code checksum mismatch"
        );
        at = 0;
        let header = take(&value, &mut at, 4) as u8;
        let (mode, address, punch, coordinator) = if value.len() == 180 {
            ensure!(header == 1, "unsupported IPv6 code version");
            let mode = take(&value, &mut at, 4);
            ensure!(matches!(mode, 4 | 5), "unsupported IPv6 carrier");
            (
                if mode == 4 { "tcp" } else { "https" },
                IpAddr::V6((take(&value, &mut at, 128) as u128).into()),
                false,
                false,
            )
        } else {
            ensure!(
                (2..=15).contains(&header),
                "unsupported direct-code version"
            );
            let mode = match header {
                2 | 11 => "faketcp",
                3 => "udp",
                4 | 14 => "tcp",
                5 | 15 => "https",
                6 | 12 => "phantun",
                7 | 9 | 10 => "mimic",
                _ => "tcpraw",
            };
            (
                mode,
                IpAddr::V4((take(&value, &mut at, 32) as u32).into()),
                header == 9,
                header >= 10,
            )
        };
        let port = take(&value, &mut at, 16) as u16;
        let room = take(&value, &mut at, 20);
        let endpoint = SocketAddr::new(address, port);
        ensure!(
            room < 1_000_000 && valid_endpoint(&endpoint),
            "invalid direct-code locator"
        );
        Ok(Self {
            endpoint,
            mode: mode.into(),
            room: format!("{room:06}"),
            punch,
            coordinator,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_vectors() {
        for (endpoint, mode, text) in [
            ("203.0.113.10:42000", "faketcp", "5JR0-E45A-840Y-4G12"),
            (
                "[2606:4700:4700::1111]:443",
                "https",
                "2MK0-CHR0-8W00-0000-0000-0000-248G-3ERY-4G2V",
            ),
        ] {
            let c = DirectCode {
                endpoint: endpoint.parse().unwrap(),
                mode: mode.into(),
                room: "123456".into(),
                punch: false,
                coordinator: false,
            };
            assert_eq!(c.issue().unwrap(), text);
            assert_eq!(DirectCode::import(text).unwrap(), c);
        }
    }
}
