//! Copy-only TCP handshake observations for one local endpoint.
use super::Trace;
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
};

pub(crate) struct Watch {
    #[cfg(windows)]
    _handle: crate::capture::HandshakeWatch,
    #[cfg(target_os = "linux")]
    _handle: linux::Capture,
}

pub(super) enum PeerPorts<'a> {
    Burst(u16),
    Candidates(&'a [u16]),
}

#[cfg(windows)]
pub(super) struct MimicWatch {
    _ingress: Option<crate::capture::HandshakeWatch>,
    _egress: Option<crate::capture::HandshakeWatch>,
}

#[cfg(windows)]
fn mimic_filters(local: SocketAddrV4, peer: Ipv4Addr) -> (String, String) {
    let ip = local.ip();
    let port = local.port();
    // Copy incoming SYNs from any source. The carrier owns its own filter.
    (
        format!("!loopback and inbound and ip and tcp and ip.DstAddr == {ip} and tcp.DstPort == {port} and (tcp.Syn or (tcp.Rst and ip.SrcAddr == {peer}))"),
        format!("!loopback and outbound and ip and tcp and ip.SrcAddr == {ip} and tcp.SrcPort == {port} and ip.DstAddr == {peer} and (tcp.Syn or tcp.Rst)"),
    )
}

#[cfg(windows)]
impl MimicWatch {
    pub(super) fn open(components: &Path, local: SocketAddrV4, peer: Ipv4Addr, trace: &Trace) -> Self {
        use crate::capture::HandshakeWatch;

        trace.begin_network_capture();
        let (ingress, egress) = mimic_filters(local, peer);
        let dll = components.join("WinDivert.dll");
        let open = |filter, priority| {
            let trace = trace.clone();
            HandshakeWatch::sniff(&dll, filter, priority, local, move |remote, out, flags, interface| {
                if let Some(stage) = handshake_stage(out, flags) {
                    trace.observe_packet(local.into(), remote, stage, interface, remote.ip() == peer);
                }
            }).ok()
        };
        // The raw helper consumes ingress at priority 0. Its outbound
        // injections continue below its handle, so observe those separately.
        let ingress = open(ingress, 101);
        let egress = open(egress, -2);
        trace.capture_opened(ingress.is_some(), egress.is_some());
        Self { _ingress: ingress, _egress: egress }
    }
}

fn handshake_stage(out: bool, flags: u8) -> Option<&'static str> {
    Some(match (out, flags & 0x16) {
        (true, f) if f & 4 != 0 => "tx_rst",
        (false, f) if f & 4 != 0 => "rx_rst",
        (true, 18) => "tx_syn_ack",
        (false, 18) => "rx_syn_ack",
        (true, 2) => "tx_syn",
        (false, 2) => "rx_syn",
        _ => return None,
    })
}

#[cfg(windows)]
fn native_filter(
    local: SocketAddrV4, peer: Ipv4Addr, outbound_ports: &[u16], inbound_ports: Option<&[u16]>,
) -> String {
    let ports_for = |ports: &[u16], field: &str| {
        ports.iter().map(|p| format!("tcp.{field} == {p}")).collect::<Vec<_>>().join(" or ")
    };
    let ip = local.ip();
    let port = local.port();
    let tx = ports_for(outbound_ports, "DstPort");
    let rx = inbound_ports.map_or_else(String::new, |ports| {
        format!(" and (tcp.Syn or tcp.Rst) and ({})", ports_for(ports, "SrcPort"))
    });
    format!("ip and tcp and ((outbound and ip.SrcAddr == {ip} and tcp.SrcPort == {port} and ip.DstAddr == {peer} and (tcp.Syn or tcp.Rst) and ({tx})) or (inbound and ip.DstAddr == {ip} and tcp.DstPort == {port} and ip.SrcAddr == {peer}{rx}))")
}

#[cfg(all(test, windows))]
#[test]
fn mimic_sniff_matches_syn_by_local_port_before_peer_filtering() {
    let local = "192.0.2.1:63432".parse().unwrap();
    let peer = "198.51.100.1".parse().unwrap();
    let (inbound, outbound) = mimic_filters(local, peer);
    assert!(inbound.contains("inbound and ip and tcp and ip.DstAddr == 192.0.2.1 and tcp.DstPort == 63432"));
    assert!(inbound.ends_with("(tcp.Syn or (tcp.Rst and ip.SrcAddr == 198.51.100.1))"));
    assert!(!inbound.contains("tcp.SrcPort"));
    assert!(outbound.contains("outbound and ip and tcp and ip.SrcAddr == 192.0.2.1 and tcp.SrcPort == 63432"));
}

#[cfg(all(test, windows))]
#[test]
fn native_burst_sniffs_all_inbound_ports_from_the_peer() {
    let local = "192.0.2.1:63432".parse().unwrap();
    let peer = "198.51.100.1".parse().unwrap();
    let ports = [42000];
    let filter = native_filter(local, peer, &ports, None);
    assert!(filter.contains("outbound and ip.SrcAddr == 192.0.2.1 and tcp.SrcPort == 63432"));
    assert!(filter.contains("tcp.DstPort == 42000"));
    assert!(filter.ends_with("inbound and ip.DstAddr == 192.0.2.1 and tcp.DstPort == 63432 and ip.SrcAddr == 198.51.100.1))"));
    let exact = native_filter(local, peer, &ports, Some(&ports));
    assert!(exact.ends_with("and (tcp.Syn or tcp.Rst) and (tcp.SrcPort == 42000)))"));
}

impl Watch {
    pub(super) fn open(
        components: &Path,
        local: SocketAddrV4,
        peer: Ipv4Addr,
        peer_ports: PeerPorts<'_>,
        trace: &Trace,
        attempt: usize,
    ) -> Option<Self> {
        let (ports, burst_port) = match &peer_ports {
            PeerPorts::Burst(port) => (std::slice::from_ref(port), Some(*port)),
            PeerPorts::Candidates(ports) => (*ports, None),
        };
        if local.ip().is_loopback() || ports.is_empty() {
            trace.source(attempt, "socket_only");
            return None;
        }
        let inbound_ports = burst_port.is_none().then_some(ports);
        let observer = trace.clone();
        let record = move |remote: SocketAddr, out: bool, flags: u8| {
            let burst_ingress = !out && burst_port.is_some();
            let stage = handshake_stage(out, flags).or_else(|| {
                burst_ingress.then_some(if flags & 1 != 0 { "rx_fin" } else { "rx_tcp" })
            });
            if let Some(stage) = stage {
                observer.socket(attempt, local.into(), remote, stage, None);
            }
            if burst_ingress && burst_port != Some(remote.port()) {
                observer.socket(attempt, local.into(), remote, "rx_peer_port_mismatch", None);
            }
        };
        #[cfg(windows)]
        let capture = crate::capture::HandshakeWatch::sniff(
            &components.join("WinDivert.dll"),
            native_filter(local, peer, ports, inbound_ports),
            101,
            local,
            move |remote, out, flags, _| record(remote, out, flags),
        );
        #[cfg(target_os = "linux")]
        let capture = {
            let _ = components;
            linux::Capture::open(local, peer, ports, inbound_ports, record)
        };
        #[cfg(any(windows, target_os = "linux"))]
        match capture {
            Ok(handle) => {
                trace.source(attempt, "passive_headers");
                Some(Self { _handle: handle })
            }
            Err(_) => {
                trace.source(attempt, "capture_unavailable");
                None
            }
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = (components, peer, inbound_ports, record);
            trace.source(attempt, "socket_only");
            None
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        io,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
    };

    pub(super) struct Capture {
        stop: Arc<AtomicBool>,
        reader: Option<thread::JoinHandle<()>>,
    }
    impl Capture {
        pub(super) fn open(
            local: SocketAddrV4,
            peer: Ipv4Addr,
            outbound_ports: &[u16],
            inbound_ports: Option<&[u16]>,
            record: impl Fn(SocketAddr, bool, u8) + Send + 'static,
        ) -> io::Result<Self> {
            // Protocol zero receives nothing until the filter has been attached. SOCK_DGRAM strips L2.
            let fd = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let socket = unsafe { OwnedFd::from_raw_fd(fd) };
            let ins = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
            // The Linux protocol ancillary load (SKF_AD_OFF + SKF_AD_PROTOCOL) also
            // rejects non-IPv4 frames on interfaces without an Ethernet header.
            let mut bpf = vec![
                ins(0x20, 0, 0, (-4096i32) as u32),
                ins(0x15, 1, 0, libc::ETH_P_IP as u32),
                ins(6, 0, 0, 0),
                ins(0x30, 0, 0, 9),
                ins(0x15, 1, 0, 6),
                ins(6, 0, 0, 0),
                ins(0x28, 0, 0, 6),
                ins(0x45, 0, 1, 0x1fff),
                ins(6, 0, 0, 0),
                ins(0xb1, 0, 0, 0),
            ];
            for (src, dst, lp, rp, ports) in [
                (*local.ip(), peer, 0, 2, Some(outbound_ports)),
                (peer, *local.ip(), 2, 0, inbound_ports),
            ] {
                let extra_checks = ports.map_or(0, |ports| 3 + ports.len() as u8);
                // Failed checks jump to the next direction.
                bpf.extend([
                    ins(0x20, 0, 0, 12),
                    ins(0x15, 0, 7 + extra_checks, u32::from(src)),
                    ins(0x20, 0, 0, 16),
                    ins(0x15, 0, 5 + extra_checks, u32::from(dst)),
                    ins(0x48, 0, 0, lp),
                    ins(0x15, 0, 3 + extra_checks, u32::from(local.port())),
                ]);
                if let Some(ports) = ports {
                    let n = ports.len() as u8;
                    bpf.extend([
                        ins(0x50, 0, 0, 13),
                        ins(0x45, 0, n + 4, 6),
                        ins(0x48, 0, 0, rp),
                    ]);
                    for (i, p) in ports.iter().enumerate() {
                        bpf.push(ins(
                            0x15,
                            n - 1 - i as u8,
                            if i + 1 == ports.len() { 3 } else { 0 },
                            u32::from(*p),
                        ));
                    }
                }
                // Return through the TCP flags byte. The reader only needs the headers.
                bpf.extend([ins(0x87, 0, 0, 0), ins(0x04, 0, 0, 14), ins(0x16, 0, 0, 0)]);
            }
            bpf.push(ins(6, 0, 0, 0));
            let program = libc::sock_fprog {
                len: bpf.len() as _,
                filter: bpf.as_mut_ptr(),
            };
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            addr.sll_family = libc::AF_PACKET as _;
            addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ATTACH_FILTER,
                    (&program as *const libc::sock_fprog).cast(),
                    std::mem::size_of_val(&program) as _,
                )
            } < 0
                || unsafe {
                    libc::bind(
                        fd,
                        (&addr as *const libc::sockaddr_ll).cast(),
                        std::mem::size_of_val(&addr) as _,
                    )
                } < 0
            {
                return Err(io::Error::last_os_error());
            }
            let stop = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            let reader = thread::Builder::new()
                .name("tcp-round-observer".into())
                .spawn(move || {
                    let mut poll = libc::pollfd {
                        fd: socket.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let mut buf = [0u8; 80];
                    while !flag.load(Ordering::Relaxed) {
                        if unsafe { libc::poll(&mut poll, 1, 20) } <= 0 {
                            continue;
                        }
                        let n =
                            unsafe { libc::recv(poll.fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
                        let h = usize::from(buf[0] & 15) * 4;
                        if h < 20 || n < (h + 14) as isize {
                            continue;
                        }
                        let src = SocketAddrV4::new(
                            Ipv4Addr::from(<[u8; 4]>::try_from(&buf[12..16]).unwrap()),
                            u16::from_be_bytes([buf[h], buf[h + 1]]),
                        );
                        let dst = SocketAddrV4::new(
                            Ipv4Addr::from(<[u8; 4]>::try_from(&buf[16..20]).unwrap()),
                            u16::from_be_bytes([buf[h + 2], buf[h + 3]]),
                        );
                        record(
                            if src == local { dst.into() } else { src.into() },
                            src == local,
                            buf[h + 13],
                        );
                    }
                })?;
            Ok(Self {
                stop,
                reader: Some(reader),
            })
        }
    }
    impl Drop for Capture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(t) = self.reader.take() {
                let _ = t.join();
            }
        }
    }

    #[cfg(test)]
    #[test]
    #[ignore = "Linux AF_PACKET needs CAP_NET_RAW"]
    fn burst_capture_records_a_syn_from_an_unlisted_port() -> io::Result<()> {
        use std::{net::TcpListener, sync::mpsc, time::Duration};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let SocketAddr::V4(local) = listener.local_addr()? else { unreachable!() };
        let peer = Ipv4Addr::new(127, 0, 0, 2);
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        socket.bind(&SocketAddr::from((peer, 0)).into())?;
        let source = socket.local_addr()?.as_socket().unwrap();
        let expected_port = if source.port() == 42000 { 42001 } else { 42000 };
        let (tx, rx) = mpsc::channel();
        let (tx_exact, rx_exact) = mpsc::channel();
        let capture = |ports, tx: mpsc::Sender<SocketAddr>| {
            Capture::open(local, peer, &[expected_port], ports, move |remote, out, flags| {
                if !out && handshake_stage(out, flags) == Some("rx_syn") {
                    let _ = tx.send(remote);
                }
            })
        };
        let _wildcard = capture(None, tx)?;
        let exact = [expected_port];
        let _exact = capture(Some(&exact[..]), tx_exact)?;
        socket.connect(&local.into())?;
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), source);
        assert_eq!(rx_exact.recv_timeout(Duration::from_millis(100)), Err(mpsc::RecvTimeoutError::Timeout));
        Ok(())
    }
}
