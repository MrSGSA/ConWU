//! IPv4 wire boundary. Mimic's zero-padding format rotates the first twelve
//! UDP payload octets to the tail; TCPRAW puts each datagram in a PSH segment.
use std::net::{Ipv4Addr, SocketAddrV4};

pub const FIN: u8 = 1;
pub const SYN: u8 = 2;
pub const RST: u8 = 4;
pub const PSH: u8 = 8;
pub const ACK: u8 = 16;
pub const MAX_DATAGRAM: usize = 1448;
pub const MIMIC_WINDOW: u32 = 0x3400000;
pub const MIMIC_SCALE: u8 = 12;

#[derive(Debug)]
pub struct Segment<'a> {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub scale: u8,
    pub timestamp: Option<(u32, u32)>,
    pub payload: &'a [u8],
}
fn word(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap())
}
fn dword(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}
pub fn parse(bytes: &[u8]) -> Option<Segment<'_>> {
    if bytes.len() < 40 || bytes[0] >> 4 != 4 || bytes[9] != 6 || word(bytes, 6) & 0x3fff != 0 {
        return None;
    }
    let start = (bytes[0] & 15) as usize * 4;
    let end = word(bytes, 2) as usize;
    if start < 20 || end > bytes.len() || end > 1500 || end < start + 20 {
        return None;
    }
    let tcp = &bytes[start..end];
    let header = (tcp[12] >> 4) as usize * 4;
    if header < 20 || header > tcp.len() {
        return None;
    }
    let mut scale = 0;
    let mut timestamp = None;
    let mut offset = 20;
    while offset < header {
        let kind = tcp[offset];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            offset += 1;
            continue;
        }
        if offset + 2 > header {
            return None;
        }
        let len = tcp[offset + 1] as usize;
        if len < 2 || offset + len > header {
            return None;
        }
        match (kind, len) {
            (3, 3) if tcp[offset + 2] <= 14 => scale = tcp[offset + 2],
            (8, 10) => timestamp = Some((dword(tcp, offset + 2), dword(tcp, offset + 6))),
            _ => {}
        }
        offset += len;
    }
    Some(Segment {
        local: SocketAddrV4::new(
            Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
            word(tcp, 2),
        ),
        remote: SocketAddrV4::new(
            Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
            word(tcp, 0),
        ),
        seq: dword(tcp, 4),
        ack: dword(tcp, 8),
        flags: tcp[13],
        window: word(tcp, 14),
        scale,
        timestamp,
        payload: &tcp[header..],
    })
}
pub fn after(value: u32, before: u32) -> bool {
    value.wrapping_sub(before) as i32 > 0
}
fn sum(data: &[u8]) -> u32 {
    data.chunks(2)
        .map(|p| ((p[0] as u32) << 8) | p.get(1).copied().unwrap_or(0) as u32)
        .sum()
}
fn checksum(mut value: u32) -> u16 {
    while value >> 16 != 0 {
        value = (value & 65535) + (value >> 16);
    }
    !(value as u16)
}
pub fn build(
    local: SocketAddrV4,
    remote: SocketAddrV4,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    assert!(options.len() <= 40 && options.len() % 4 == 0 && payload.len() + options.len() <= 1460);
    let mut packet = vec![0u8; 40 + options.len() + payload.len()];
    let total = packet.len() as u16;
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&local.ip().octets());
    packet[16..20].copy_from_slice(&remote.ip().octets());
    let ip_sum = checksum(sum(&packet[..20]));
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let tcp = &mut packet[20..];
    tcp[0..2].copy_from_slice(&local.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&remote.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = (((20 + options.len()) / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    tcp[20..20 + options.len()].copy_from_slice(options);
    tcp[20 + options.len()..].copy_from_slice(payload);
    let check = checksum(
        sum(&local.ip().octets()) + sum(&remote.ip().octets()) + 6 + tcp.len() as u32 + sum(tcp),
    );
    tcp[16..18].copy_from_slice(&check.to_be_bytes());
    packet
}
pub fn mimic_encode(data: &[u8]) -> Vec<u8> {
    let n = data.len().min(12);
    [&data[n..], &data[..n]].concat()
}
pub fn mimic_decode(data: &[u8]) -> Vec<u8> {
    let n = data.len().min(12);
    [&data[data.len() - n..], &data[..data.len() - n]].concat()
}
pub fn syn_options() -> [u8; 8] {
    [2, 4, 5, 180, 1, 3, 3, MIMIC_SCALE]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mimic_rotation() {
        for n in [0, 1, 2, 11, 12, 13, 127, 128, 1448] {
            let input: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let wire = mimic_encode(&input);
            assert_eq!(wire.len(), n);
            assert_eq!(mimic_decode(&wire), input);
            if n > 12 {
                assert_eq!(&wire[..n - 12], &input[12..]);
            }
        }
    }
    #[test]
    fn full_packet() {
        let a = "198.18.0.1:41420".parse().unwrap();
        let b = "198.18.0.2:41421".parse().unwrap();
        let packet = build(a, b, u32::MAX, 4, ACK | PSH, 65535, &[], &[1, 2, 3]);
        let parsed = parse(&packet).unwrap();
        assert_eq!(parsed.local, b);
        assert_eq!(parsed.remote, a);
        assert_eq!(parsed.seq, u32::MAX);
        assert_eq!(parsed.payload, &[1, 2, 3]);
        assert_eq!(checksum(sum(&packet[..20])), 0);
        assert_eq!(
            checksum(sum(&packet[12..20]) + 6 + (packet.len() - 20) as u32 + sum(&packet[20..])),
            0
        );
    }
    #[test]
    fn malformed() {
        let a = "198.18.0.1:41420".parse().unwrap();
        let b = "198.18.0.2:41421".parse().unwrap();
        let valid = build(a, b, 0, 0, SYN, 65535, &syn_options(), &[]);
        for n in 0..valid.len() {
            assert!(parse(&valid[..n]).is_none());
        }
        for (at, value) in [(0, 0x44), (6, 0x20), (32, 0x40), (32, 0xf0), (41, 0xff)] {
            let mut bad = valid.clone();
            bad[at] = value;
            assert!(parse(&bad).is_none());
        }
    }
    #[test]
    fn wrap_and_loss() {
        assert!(after(3, u32::MAX - 5));
        assert!(!after(u32::MAX - 5, 3));
        let newer = mimic_encode(&[5; 100]);
        let older = mimic_encode(&[6; 100]);
        assert_eq!(mimic_decode(&newer), [5; 100]);
        assert_eq!(mimic_decode(&older), [6; 100]);
    }
}
