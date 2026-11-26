//! GPL-2.0-only optional process. Mimic zero-padding wire behavior is adapted
//! from hack3ric/mimic; TCPRAW's kernel-handshake/raw-data mechanism follows
//! xtaci/tcpraw (MIT). Application identity and encryption stay in ConWU.
mod engine;
mod packet;
#[path = "../../conwu-phantun/src/parent.rs"]
mod parent;
mod platform;

pub use packet::MAX_DATAGRAM;
use serde_json::json;
use std::{io, net::{Ipv4Addr, SocketAddrV4}};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    Mimic,
    TcpRaw,
}
impl Carrier {
    pub fn name(self) -> &'static str {
        match self {
            Self::Mimic => "mimic",
            Self::TcpRaw => "tcpraw",
        }
    }
}
#[derive(Clone, Debug)]
pub struct Config {
    pub server: bool,
    pub source: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub parent: u32,
    pub carrier: Carrier,
    /// A kernel TCP control connection sharing this local port. Its exact
    /// inbound tuple must bypass raw capture so STUN can remain connected.
    pub protected_tcp_peer: Option<SocketAddrV4>,
    pub control_peer: std::sync::Arc<std::sync::RwLock<Option<SocketAddrV4>>>,
    pub peer_reflexive: bool,
    // Temporary listener for one coordinated peer, including changed source ports.
    pub peer_ip: Option<Ipv4Addr>,
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn arguments() -> io::Result<Config> {
    let mut flags = std::collections::HashMap::new();
    let mut args = std::env::args().skip(1);
    let mut server = None;
    let mut peer_reflexive = false;
    while let Some(flag) = args.next() {
        if flag == "--peer-reflexive" {
            if peer_reflexive { return Err(invalid("duplicate peer-reflexive flag")); }
            peer_reflexive = true;
            continue;
        }
        if matches!(flag.as_str(), "--server" | "--client") {
            if server.replace(flag == "--server").is_some() {
                return Err(invalid("duplicate role"));
            }
            continue;
        }
        if !matches!(
            flag.as_str(),
            "--source" | "--remote" | "--parent" | "--carrier" | "--protected-tcp-peer" | "--peer-ip"
        ) {
            return Err(invalid("unknown argument"));
        }
        if flags
            .insert(flag, args.next().ok_or_else(|| invalid("missing value"))?)
            .is_some()
        {
            return Err(invalid("duplicate argument"));
        }
    }
    let protected_tcp_peer = flags.remove("--protected-tcp-peer")
        .map(|value| value.parse().map_err(|_| invalid("invalid protected TCP peer")))
        .transpose()?;
    let peer_ip = flags.remove("--peer-ip")
        .map(|value| value.parse::<Ipv4Addr>().map_err(|_| invalid("invalid coordinated peer IP")))
        .transpose()?;
    let mut take = |name| {
        flags
            .remove(name)
            .ok_or_else(|| invalid("missing required argument"))
    };
    let config = Config {
        server: server.ok_or_else(|| invalid("missing role"))?,
        source: take("--source")?
            .parse()
            .map_err(|_| invalid("invalid source"))?,
        remote: take("--remote")?
            .parse()
            .map_err(|_| invalid("invalid remote"))?,
        parent: take("--parent")?
            .parse()
            .map_err(|_| invalid("invalid parent"))?,
        carrier: match take("--carrier")?.as_str() {
            "mimic" => Carrier::Mimic,
            "tcpraw" => Carrier::TcpRaw,
            _ => return Err(invalid("invalid carrier")),
        },
        protected_tcp_peer,
        control_peer: std::sync::Arc::new(std::sync::RwLock::new(protected_tcp_peer)),
        peer_reflexive,
        peer_ip,
    };
    if config.parent == 0
        || config.parent == std::process::id()
        || config.source.port() < 1024
        || config.source.ip().is_multicast()
        || config.source.ip().is_broadcast()
        || config.remote.port() == 0
        || config.remote.ip().is_unspecified()
        || config.remote.ip().is_multicast()
        || config.remote.ip().is_broadcast()
        || config.server && !config.remote.ip().is_loopback()
        || !config.server
            && (config.source.ip().is_unspecified() || config.source.ip().is_loopback())
    {
        return Err(invalid("invalid owned carrier endpoint"));
    }
    if config.peer_reflexive && (!cfg!(target_os = "windows") || config.server || config.carrier != Carrier::Mimic) {
        return Err(invalid("peer-reflexive learning requires a Windows Mimic client"));
    }
    if config.peer_ip.is_some_and(|ip| {
        !cfg!(target_os = "windows") || !config.server || config.carrier != Carrier::Mimic
            || config.source.ip().is_unspecified() || ip.is_unspecified() || ip.is_loopback()
            || ip.is_multicast() || ip.is_broadcast()
    }) {
        return Err(invalid("peer IP scope requires a Windows Mimic listener"));
    }
    if config.protected_tcp_peer.is_some_and(|peer| {
        config.source.ip().is_unspecified() || peer.port() == 0
            || peer.ip().is_unspecified() || peer.ip().is_multicast() || peer.ip().is_broadcast()
    }) {
        return Err(invalid("protected TCP peer requires an explicit source"));
    }
    Ok(config)
}
pub fn event(value: serde_json::Value) {
    use std::io::Write;
    println!("CONWU_RAW {}", value);
    let _ = io::stdout().flush();
}
pub fn udp_endpoint() -> io::Result<tokio::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_recv_buffer_size(1 << 20)?;
    socket.set_send_buffer_size(1 << 20)?;
    socket.set_nonblocking(true)?;
    socket.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 0)).into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}
fn main() {
    #[cfg(target_os = "windows")]
    {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.first().is_some_and(|s| s == "--xdp-probe") {
            let index = args.get(1).and_then(|s| s.parse::<u32>().ok()).filter(|i| *i > 0);
            let result = match index.filter(|_| args.len() == 2) {
                Some(index) => platform::xdp_probe(index),
                None => Err(invalid("--xdp-probe requires one positive interface index")),
            };
            let ok = result.is_ok();
            match result {
                Ok(queues) => event(json!({"event":"xdp-probe","abi":1,"ready":true,
                    "interfaceIndex":index,"receiveQueues":queues,"redirectionAttached":false,
                    "backend":"xdp-afxdp-generic"})),
                Err(error) => event(json!({"event":"xdp-probe","abi":1,"ready":false,
                    "interfaceIndex":index,"reason":error.to_string()})),
            }
            std::process::exit(if ok { 0 } else { 1 });
        }
    }
    if std::env::args().skip(1).collect::<Vec<_>>() == ["--conwu-info"] {
        println!(
            "{}",
            json!({"component":"ConWU.RawCarriers","abi":1,"platform":std::env::consts::OS,"carriers":["mimic-v1-zero-padding","tcpraw-v1-kernel-handshake"],"maxDatagram":MAX_DATAGRAM,"fixedSourcePort":true,"boundedConnections":true,"parentWatchdog":true,"inputStop":true,"routeCloseEvents":true,"routeOpenEvents":true,"samePortMimic":true,"samePortTcpraw":true,"tcpControlGuard":1,"assistedPunch":1,"windowsMimicBackend":"xdp-afxdp-generic","windowsTcprawBackend":"windivert-tcpraw","mimicBackendFallback":false,"xdpRuntimeVersion":"1.4.0"})
        );
        return;
    }
    let result = arguments().and_then(|config| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(engine::run(config))
    });
    if let Err(error) = result {
        event(json!({"event":"failed","abi":1,"reason":error.to_string()}));
        std::process::exit(1);
    }
    std::process::exit(0);
}
