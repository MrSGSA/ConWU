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
use std::{io, net::SocketAddrV4};

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
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn arguments() -> io::Result<Config> {
    let mut flags = std::collections::HashMap::new();
    let mut args = std::env::args().skip(1);
    let mut server = None;
    while let Some(flag) = args.next() {
        if matches!(flag.as_str(), "--server" | "--client") {
            if server.replace(flag == "--server").is_some() {
                return Err(invalid("duplicate role"));
            }
            continue;
        }
        if !matches!(
            flag.as_str(),
            "--source" | "--remote" | "--parent" | "--carrier"
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
    if std::env::args().skip(1).collect::<Vec<_>>() == ["--conwu-info"] {
        println!(
            "{}",
            json!({"component":"ConWU.RawCarriers","abi":1,"platform":std::env::consts::OS,"carriers":["mimic-v1-zero-padding","tcpraw-v1-kernel-handshake"],"maxDatagram":MAX_DATAGRAM,"fixedSourcePort":true,"boundedConnections":true,"parentWatchdog":true,"inputStop":true,"routeCloseEvents":true,"routeOpenEvents":true})
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
