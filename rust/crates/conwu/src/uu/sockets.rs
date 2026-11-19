use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
};

pub(super) const TCP: u8 = 6;
pub(super) const UDP: u8 = 17;

#[derive(Clone, Copy, Default)]
struct Ownership {
    uu: bool,
    other: bool,
}

impl Ownership {
    #[cfg(any(windows, test))]
    fn record(&mut self, uu: bool) {
        self.uu |= uu;
        self.other |= !uu;
    }
}

#[derive(Default)]
pub(super) struct SocketOwners {
    tcp: HashMap<(SocketAddrV4, SocketAddrV4), Ownership>,
    udp: HashMap<SocketAddrV4, Ownership>,
}

impl SocketOwners {
    #[cfg(any(windows, test))]
    pub fn add_tcp(&mut self, local: SocketAddrV4, peer: SocketAddrV4, uu: bool) {
        self.tcp.entry((local, peer)).or_default().record(uu);
    }

    #[cfg(any(windows, test))]
    pub fn add_udp(&mut self, local: SocketAddrV4, uu: bool) {
        self.udp.entry(local).or_default().record(uu);
    }

    pub fn contains(&self, flow: &Flow) -> bool {
        match flow.protocol {
            TCP => self
                .tcp
                .get(&(flow.local, flow.peer))
                .is_some_and(|owner| owner.uu && !owner.other),
            UDP => {
                let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, flow.local.port());
                let exact = self.udp.get(&flow.local).copied().unwrap_or_default();
                let wildcard = self.udp.get(&wildcard).copied().unwrap_or_default();
                (exact.uu || wildcard.uu) && !(exact.other || wildcard.other)
            }
            _ => false,
        }
    }
}

pub(super) struct Flow {
    protocol: u8,
    pub local: SocketAddrV4,
    pub peer: SocketAddrV4,
}

impl Flow {
    pub fn from_packet(packet: &[u8], outbound: bool) -> Option<Self> {
        if packet.len() < 28 || packet[0] >> 4 != 4 {
            return None;
        }
        let ihl = (packet[0] & 15) as usize * 4;
        let protocol = packet[9];
        if !matches!(protocol, TCP | UDP)
            || ihl < 20
            || packet.len() < ihl + 8
            || u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0
        {
            return None;
        }
        let src = SocketAddrV4::new(
            Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap()),
            u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
        );
        let dst = SocketAddrV4::new(
            Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap()),
            u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
        );
        let (local, peer) = if outbound { (src, dst) } else { (dst, src) };
        Some(Self {
            protocol,
            local,
            peer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(protocol: u8) -> Flow {
        Flow {
            protocol,
            local: "10.200.42.1:49700".parse().unwrap(),
            peer: "10.200.42.2:49701".parse().unwrap(),
        }
    }

    #[test]
    fn udp_ownership_follows_the_actual_destination_address() {
        let f = flow(UDP);
        let physical = "192.0.2.2:49700".parse().unwrap();
        let mut owners = SocketOwners::default();
        owners.add_udp(physical, true);
        assert!(!owners.contains(&f));

        let mut owners = SocketOwners::default();
        owners.add_udp(physical, false);
        owners.add_udp("0.0.0.0:49700".parse().unwrap(), true);
        assert!(owners.contains(&f));
        owners.add_udp(f.local, false);
        assert!(!owners.contains(&f));

        let mut owners = SocketOwners::default();
        owners.add_udp(physical, false);
        owners.add_udp(f.local, true);
        assert!(owners.contains(&f));
        owners.add_udp("0.0.0.0:49700".parse().unwrap(), false);
        assert!(!owners.contains(&f));
    }

    #[test]
    fn tcp_flows_sharing_a_local_port_keep_separate_owners() {
        let f = flow(TCP);
        let same_port_other_peer = "10.200.42.3:49701".parse().unwrap();
        let mut owners = SocketOwners::default();
        owners.add_tcp(f.local, same_port_other_peer, true);
        assert!(!owners.contains(&f));
        owners.add_tcp(f.local, f.peer, false);
        assert!(!owners.contains(&f));

        let mut owners = SocketOwners::default();
        owners.add_tcp(f.local, same_port_other_peer, false);
        owners.add_tcp(f.local, f.peer, true);
        assert!(owners.contains(&f));
    }

    #[test]
    fn inbound_and_outbound_packets_match_the_same_local_socket() {
        let f = flow(UDP);
        let mut packet = [0; 28];
        packet[0] = 0x45;
        packet[9] = UDP;
        for outbound in [false, true] {
            let (src, dst) = if outbound {
                (f.local, f.peer)
            } else {
                (f.peer, f.local)
            };
            packet[12..16].copy_from_slice(&src.ip().octets());
            packet[16..20].copy_from_slice(&dst.ip().octets());
            packet[20..22].copy_from_slice(&src.port().to_be_bytes());
            packet[22..24].copy_from_slice(&dst.port().to_be_bytes());
            let parsed = Flow::from_packet(&packet, outbound).unwrap();
            assert_eq!(parsed.local, f.local);
            assert_eq!(parsed.peer, f.peer);
        }
        packet[7] = 1;
        assert!(Flow::from_packet(&packet, true).is_none());
    }
}
