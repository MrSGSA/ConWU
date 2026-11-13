//! Process-owned Phantun carrier. The ConWU parent owns authorization and keys;
//! this child sees only already protected datagrams and public endpoint tuples.
mod parent;
mod platform;

use fake_tcp::{Socket, Stack};
use serde_json::json;
use std::{
    io,
    net::{SocketAddr, SocketAddrV4},
    time::Duration,
};
use tokio::net::UdpSocket;

const ABI: u32 = 1;
const MAX_DATAGRAM: usize = 1460;
const IDLE: Duration = Duration::from_secs(180);

fn udp_endpoint() -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_recv_buffer_size(1 << 20)?;
    socket.set_send_buffer_size(1 << 20)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())?;
    UdpSocket::from_std(socket.into())
}

#[derive(Clone, Debug)]
pub struct Config {
    pub server: bool,
    pub source: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub parent: u32,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn arguments() -> io::Result<Config> {
    let mut args = std::env::args().skip(1);
    let mut role = None;
    let (mut source, mut remote, mut owner) = (None, None, None);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--server" | "--client" => {
                if role.replace(flag == "--server").is_some() {
                    return Err(invalid("role specified twice"));
                }
            }
            "--source" => {
                if source.is_some() {
                    return Err(invalid("source specified twice"));
                }
                source = Some(
                    args.next()
                        .ok_or_else(|| invalid("missing source"))?
                        .parse::<SocketAddrV4>()
                        .map_err(|_| invalid("invalid IPv4 source"))?,
                );
            }
            "--remote" => {
                if remote.is_some() {
                    return Err(invalid("remote specified twice"));
                }
                remote = Some(
                    args.next()
                        .ok_or_else(|| invalid("missing remote"))?
                        .parse::<SocketAddrV4>()
                        .map_err(|_| invalid("invalid IPv4 remote"))?,
                );
            }
            "--parent" => {
                if owner.is_some() {
                    return Err(invalid("parent specified twice"));
                }
                owner = Some(
                    args.next()
                        .ok_or_else(|| invalid("missing parent"))?
                        .parse::<u32>()
                        .map_err(|_| invalid("invalid parent"))?,
                );
            }
            _ => return Err(invalid("unknown argument")),
        }
    }
    let result = Config {
        server: role.ok_or_else(|| invalid("missing role"))?,
        source: source.ok_or_else(|| invalid("missing source"))?,
        remote: remote.ok_or_else(|| invalid("missing remote"))?,
        parent: owner.ok_or_else(|| invalid("missing parent"))?,
    };
    if result.parent == 0
        || result.parent == std::process::id()
        || result.source.port() < 1024
        || result.source.ip().is_multicast()
        || result.source.ip().is_broadcast()
        || result.remote.port() == 0
        || result.remote.ip().is_unspecified()
        || result.remote.ip().is_multicast()
        || result.remote.ip().is_broadcast()
        || result.server && !result.remote.ip().is_loopback()
        || !result.server
            && (result.source.ip().is_unspecified() || result.source.ip().is_loopback())
    {
        return Err(invalid("invalid owned carrier endpoint"));
    }
    Ok(result)
}

fn event(value: serde_json::Value) {
    use std::io::Write;
    println!("CONWU_PHANTUN {}", value);
    let _ = io::stdout().flush();
}

fn info() -> serde_json::Value {
    json!({"component":"ConWU.Phantun", "abi":ABI, "wire":"phantun-0.8", "maxDatagram":MAX_DATAGRAM,
        "platform":std::env::consts::OS, "fixedSourcePort":true, "boundedConnections":true, "parentWatchdog":true, "inputStop":true, "routeCloseEvents":true, "routeOpenEvents":true})
}

struct PeerLifetime(SocketAddr);
impl Drop for PeerLifetime {
    fn drop(&mut self) {
        event(json!({"event":"peer-closed", "abi":ABI, "udp":self.0.to_string()}));
    }
}

async fn forward_server(socket: Socket, target: SocketAddrV4) -> io::Result<()> {
    let udp = udp_endpoint()?;
    udp.connect(target).await?;
    let _lifetime = PeerLifetime(udp.local_addr()?);
    event(json!({"event":"peer-opened", "abi":ABI, "udp":udp.local_addr()?.to_string()}));
    let mut from_udp = [0u8; 2048];
    let mut from_tcp = [0u8; 1500];
    loop {
        tokio::select! {
            res = udp.recv(&mut from_udp) => {
                let size = res?;
                if size > MAX_DATAGRAM { continue; }
                if socket.send(&from_udp[..size]).await.is_none() { return Ok(()); }
            },
            res = socket.recv(&mut from_tcp) => {
                let Some(size) = res else { return Ok(()); };
                if size > 0 { udp.send(&from_tcp[..size]).await?; }
            },
            _ = tokio::time::sleep(IDLE) => return Ok(()),
        }
    }
}

async fn run(config: Config) -> io::Result<()> {
    // Validate parent before acquiring any packet capture or UDP endpoint.
    let parent_gone = parent::watch(config.parent)?;
    let input_stop = parent::input_stop()?;
    let device = platform::open(&config)?;
    let mut stack = Stack::new(vec![device], *config.source.ip(), None);
    let mut capture_failure = stack.failures();
    if config.server {
        stack.listen(config.source.port());
        event(
            json!({"event":"ready", "abi":ABI, "role":"server", "pid":std::process::id(), "source":config.source.to_string()}),
        );
        tokio::select! {
            _ = parent_gone => Ok(()),
            _ = input_stop => Ok(()),
            _ = tokio::signal::ctrl_c() => Ok(()),
            reason = capture_failure.wait_for(Option::is_some) => Err(io::Error::other(reason.ok().and_then(|value|value.as_ref().cloned()).unwrap_or_else(||"Phantun capture stopped".into()))),
            res = async {
                loop {
                    let socket = stack.accept().await;
                    let target = config.remote;
                    tokio::spawn(async move {
                        if let Err(error) = forward_server(socket, target).await {
                            eprintln!("Phantun peer closed: {}", error);
                        }
                    });
                }
                #[allow(unreachable_code)]
                Ok::<(),io::Error>(())
            } => res,
        }
    } else {
        let udp = udp_endpoint()?;
        event(
            json!({"event":"ready", "abi":ABI, "role":"client", "pid":std::process::id(), "source":config.source.to_string(), "udp":udp.local_addr()?.to_string()}),
        );
        let client = async {
            let mut from_udp = [0u8; 2048];
            let (size, application) = loop {
                let (size, application) = udp.recv_from(&mut from_udp).await?;
                if application.ip().is_loopback() && size > 0 && size <= MAX_DATAGRAM {
                    break (size, application);
                }
            };
            let remote = SocketAddr::V4(config.remote);
            let socket = tokio::time::timeout(
                Duration::from_secs(8),
                stack.connect_from(remote, config.source.port()),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Phantun handshake deadline"))?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "Phantun handshake not completed",
                )
            })?;
            if socket.send(&from_udp[..size]).await.is_none() {
                return Err(io::Error::other("Phantun initial send failed"));
            }
            let mut from_tcp = [0u8; 1500];
            loop {
                tokio::select! {
                    res = udp.recv_from(&mut from_udp) => {
                        let (size, source) = res?;
                        if source != application || size == 0 || size > MAX_DATAGRAM { continue; }
                        if socket.send(&from_udp[..size]).await.is_none() { return Ok(()); }
                    },
                    res = socket.recv(&mut from_tcp) => {
                        let Some(size) = res else { return Ok(()); };
                        if size > 0 { udp.send_to(&from_tcp[..size], application).await?; }
                    },
                    _ = tokio::time::sleep(IDLE) => return Ok(()),
                }
            }
        };
        tokio::select! {
            _ = parent_gone => Ok(()),
            _ = input_stop => Ok(()),
            _ = tokio::signal::ctrl_c() => Ok(()),
            reason = capture_failure.wait_for(Option::is_some) => Err(io::Error::other(reason.ok().and_then(|value|value.as_ref().cloned()).unwrap_or_else(||"Phantun capture stopped".into()))),
            result = client => result,
        }
    }
}

fn main() {
    if std::env::args().skip(1).collect::<Vec<_>>() == ["--conwu-info"] {
        println!("{}", info());
        return;
    }
    let result = arguments().and_then(|config| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        runtime.block_on(run(config))
    });
    if let Err(error) = result {
        event(json!({"event":"failed", "abi":ABI, "reason":error.to_string()}));
        std::process::exit(1);
    }
    // Capture workers must not outlive their owning component process.
    std::process::exit(0);
}
