//! Synchronous TCP socket preparation and consecutive nonblocking opens.

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const WARMUP_SPAN: u16 = 16;
const MAX_WARMUP_RESERVATIONS: usize = WARMUP_SPAN as usize;
const ADJACENT_BLOCKS_PER_SIDE: i16 = 8;
const ANCHOR_GRACE: Duration = Duration::from_millis(150);

/// Local timestamp at socket or driver submission. Helpers share the host clock.
pub fn submission_micros() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_micros() as u64
}

#[derive(Clone, Copy, Debug)]
pub struct BurstOptions {
    pub local_ip: Ipv4Addr,
    pub prefer_wide_delta_l: bool,
}

impl Default for BurstOptions {
    fn default() -> Self {
        Self {
            local_ip: Ipv4Addr::UNSPECIFIED,
            prefer_wide_delta_l: false,
        }
    }
}

/// Three IPv4 sockets ready for active open. Preparation and sending can run
/// in the same blocking task, with the ports available before the first send.
#[derive(Debug)]
pub struct PreparedBurst {
    sockets: [Socket; 3],
    local_ports: (u16, u16, u16),
}

impl PreparedBurst {
    pub fn bind(options: BurstOptions) -> io::Result<Self> {
        let local = SocketAddrV4::new(options.local_ip, 0);
        if !options.prefer_wide_delta_l {
            return Self::bind_adjacent(local);
        }
        let mut reserved = Vec::with_capacity(3);
        for _ in 0..3 {
            reserved.push(reserve_port(local)?);
        }

        for _ in 0..MAX_WARMUP_RESERVATIONS {
            let (min, max) = reserved.iter().fold((u16::MAX, 0), |(min, max), (port, _)| {
                (min.min(*port), max.max(*port))
            });
            if max - min >= WARMUP_SPAN {
                break;
            }
            let Ok(extra) = reserve_port(local) else {
                break;
            };
            reserved.push(extra);
        }
        // Allocate the two ends from the widest observed gap.
        reserved.sort_unstable_by_key(|(port, _)| *port);
        let last = reserved.len() - 1;
        reserved.swap(2, last);

        let mut ports = reserved.into_iter();
        let [(l1, first), (l_mid, middle), (l2, last)] =
            std::array::from_fn(|_| ports.next().expect("three prebound sockets"));
        Ok(Self {
            sockets: [first, middle, last],
            local_ports: (l1, l_mid, l2),
        })
    }

    fn bind_adjacent(local: SocketAddrV4) -> io::Result<Self> {
        let (port, socket) = reserve_port(local)?;
        let seed = SocketAddrV4::new(*local.ip(), port);
        let mut last_error = match Self::bind_neighbors(seed, socket) {
            Ok(burst) => return Ok(burst),
            Err(error) => error,
        };
        // Walk disjoint triples. Retrying bind(:0) can return consecutively
        // allocated ports whose neighbors overlap a failed trial on Windows.
        for delta in (1..=ADJACENT_BLOCKS_PER_SIDE).flat_map(|step| [step * 3, -step * 3]) {
            let burst = PreparedAnchor::offset(seed, delta).and_then(|middle| {
                let address = SocketAddrV4::new(*seed.ip(), middle.port);
                Self::bind_neighbors(address, middle.socket)
            });
            match burst {
                Ok(burst) => return Ok(burst),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    fn bind_neighbors(middle: SocketAddrV4, socket: Socket) -> io::Result<Self> {
        let first = PreparedAnchor::offset(middle, -1)?;
        let last = PreparedAnchor::offset(middle, 1)?;
        Ok(Self {
            local_ports: (first.port, middle.port(), last.port),
            sockets: [first.socket, socket, last.socket],
        })
    }

    pub fn local_ports(&self) -> (u16, u16, u16) {
        self.local_ports
    }

    /// Start the first anchor, peer, and last anchor connects in that order.
    /// Every call is attempted, with immediate failures recorded per socket.
    pub fn connect(self, targets: [SocketAddrV4; 3]) -> Burst {
        let addresses = targets.map(SockAddr::from);
        let started = Instant::now();
        let results = std::array::from_fn(|idx| {
            let error = start_connect(&self.sockets[idx], &addresses[idx]).err();
            (error, submission_micros())
        });
        let sent_at = Instant::now();

        let [(first_error, first_us), (middle_error, middle_us), (last_error, last_us)] = results;
        let [first, middle, last] = self.sockets;
        Burst {
            anchors: AnchorSockets {
                first: ConnectAttempt {
                    socket: first,
                    start_error: first_error,
                    submitted_us: first_us,
                },
                last: ConnectAttempt {
                    socket: last,
                    start_error: last_error,
                    submitted_us: last_us,
                },
                sent_at,
            },
            middle: ConnectAttempt {
                socket: middle,
                start_error: middle_error,
                submitted_us: middle_us,
            },
            local_ports: self.local_ports,
            connect_elapsed: sent_at.duration_since(started),
        }
    }
}

#[derive(Debug)]
pub struct ConnectAttempt {
    pub socket: Socket,
    /// Immediate error from starting this connect. Pending opens have no error.
    pub start_error: Option<io::Error>,
    pub submitted_us: u64,
}

/// One prebound anchor for a three-send burst whose middle connection is
/// owned by a packet carrier. The caller starts each anchor around that send.
pub struct PreparedAnchor {
    socket: Socket,
    port: u16,
}

impl PreparedAnchor {
    fn offset(middle: SocketAddrV4, delta: i16) -> io::Result<Self> {
        let port = middle.port().checked_add_signed(delta).filter(|&port| port >= 1024)
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "anchor port is out of range"))?;
        let socket = bind_tcp(SocketAddrV4::new(*middle.ip(), port).into(), false)?;
        Ok(Self { socket, port })
    }

    /// Prefer the closest eligible unused port on each side of the carrier port.
    pub fn around(middle: SocketAddrV4, available: impl Fn(u16) -> bool) -> io::Result<[Self; 2]> {
        let reserve = |side: i16, exclude: Option<u16>| {
            (1..=16).find_map(|distance| {
                let delta = side * distance;
                let port = middle.port().checked_add_signed(delta)?;
                (Some(port) != exclude && available(port))
                    .then(|| Self::offset(middle, delta).ok())
                    .flatten()
            })
        };
        let anchors = match (reserve(-1, None), reserve(1, None)) {
            (Some(first), Some(last)) => Some([first, last]),
            (Some(last), None) => reserve(-1, Some(last.port)).map(|first| [first, last]),
            (None, Some(first)) => reserve(1, Some(first.port)).map(|last| [first, last]),
            (None, None) => None,
        };
        anchors.ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "没有可用的邻近 STUN 锚点端口"))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn connect(self, target: SocketAddrV4) -> ConnectAttempt {
        let start_error = start_connect(&self.socket, &target.into()).err();
        ConnectAttempt { socket: self.socket, start_error, submitted_us: submission_micros() }
    }
}

impl ConnectAttempt {
    pub fn into_socket(self) -> io::Result<Socket> {
        match self.start_error {
            Some(error) => Err(error),
            None => Ok(self.socket),
        }
    }
}

#[derive(Debug)]
pub struct AnchorSockets {
    pub first: ConnectAttempt,
    pub last: ConnectAttempt,
    sent_at: Instant,
}

impl AnchorSockets {
    /// Drop the anchors once their mapping replies have arrived. This blocking
    /// fallback keeps them open for at least 150 ms from the end of the burst.
    pub fn close_after_grace(self) {
        let remaining = ANCHOR_GRACE.saturating_sub(self.sent_at.elapsed());
        if !remaining.is_zero() {
            thread::sleep(remaining);
        }
        drop(self);
    }
}

#[derive(Debug)]
pub struct Burst {
    pub anchors: AnchorSockets,
    pub middle: ConnectAttempt,
    pub local_ports: (u16, u16, u16),
    /// Wall-clock span of the three nonblocking connect calls.
    pub connect_elapsed: Duration,
}

fn reserve_port(local: SocketAddrV4) -> io::Result<(u16, Socket)> {
    let socket = bind_tcp(local.into(), false)?;
    let address = socket.local_addr()?.as_socket_ipv4().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "expected an IPv4 local address")
    })?;
    Ok((address.port(), socket))
}

pub(super) fn bind_tcp(local: SocketAddr, reuse_address: bool) -> io::Result<Socket> {
    let socket = Socket::new(
        Domain::for_address(local),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if reuse_address {
        socket.set_reuse_address(true)?;
        #[cfg(target_os = "linux")]
        socket.set_reuse_port(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&local.into())?;
    Ok(socket)
}

pub(super) fn start_connect(socket: &Socket, target: &SockAddr) -> io::Result<()> {
    match socket.connect(target) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock || connect_pending(&error) => {
            Ok(())
        }
        result => result,
    }
}

#[cfg(unix)]
fn connect_pending(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINPROGRESS | libc::EALREADY | libc::EINTR)
    )
}

#[cfg(test)]
#[test]
fn occupied_neighbor_moves_the_formal_burst_to_another_block() -> io::Result<()> {
    let ip = Ipv4Addr::LOCALHOST;
    let burst = PreparedBurst::bind(BurstOptions { local_ip: ip, ..Default::default() })?;
    let (_, port, _) = burst.local_ports();
    let [_occupied, middle, last] = burst.sockets;
    drop((middle, last));

    let replacement = PreparedBurst::bind_adjacent(SocketAddrV4::new(ip, port))?;
    let (l1, l_mid, l2) = replacement.local_ports();
    assert!(l_mid.abs_diff(port) >= 3);
    assert_eq!((l1 + 1, l_mid + 1), (l_mid, l2));
    Ok(())
}

#[cfg(windows)]
fn connect_pending(error: &io::Error) -> bool {
    use windows_sys::Win32::Networking::WinSock::{WSAEALREADY, WSAEINPROGRESS, WSAEWOULDBLOCK};
    matches!(
        error.raw_os_error(),
        Some(WSAEWOULDBLOCK | WSAEINPROGRESS | WSAEALREADY)
    )
}
