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
    pub protected_tcp_peer: Option<SocketAddrV4>,
    pub control_peer: std::sync::Arc<std::sync::RwLock<Option<SocketAddrV4>>>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn arguments() -> io::Result<Config> {
    let mut args = std::env::args().skip(1);
    let mut role = None;
    let mut protected_tcp_peer = None;
    let (mut source, mut remote, mut owner) = (None, None, None);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--server" | "--client" => {
                if role.replace(flag == "--server").is_some() {
                    return Err(invalid("role specified twice"));
                }
            }
            "--protected-tcp-peer" => {
                if protected_tcp_peer.is_some() { return Err(invalid("duplicate protected TCP peer")); }
                protected_tcp_peer = Some(args.next().ok_or_else(||invalid("missing protected TCP peer"))?.parse::<SocketAddrV4>().map_err(|_|invalid("invalid protected TCP peer"))?);
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
        protected_tcp_peer,
        control_peer: std::sync::Arc::new(std::sync::RwLock::new(protected_tcp_peer)),
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
    if result.protected_tcp_peer.is_some_and(|peer| result.source.ip().is_unspecified() || peer.port()==0 || peer.ip().is_unspecified() || peer.ip().is_multicast() || peer.ip().is_broadcast()) {
        return Err(invalid("invalid protected TCP tuple"));
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
        "platform":std::env::consts::OS, "fixedSourcePort":true, "boundedConnections":true, "parentWatchdog":true, "inputStop":true, "routeCloseEvents":true, "routeOpenEvents":true,"samePortPhantun":true,"tcpControlGuard":1,"assistedPunch":1})
}

struct PeerLifetime(SocketAddr);
impl Drop for PeerLifetime {
    fn drop(&mut self) {
        event(json!({"event":"peer-closed", "abi":ABI, "udp":self.0.to_string()}));
    }
}

async fn forward_server(socket: Socket, target: SocketAddrV4, mut hello:tokio::sync::mpsc::Receiver<Vec<u8>>) -> io::Result<()> {
    let udp = udp_endpoint()?;
    udp.connect(target).await?;
    let _lifetime = PeerLifetime(udp.local_addr()?);
    event(json!({"event":"peer-opened", "abi":ABI, "udp":udp.local_addr()?.to_string(), "peer":socket.remote_addr().to_string()}));
    let mut from_udp = [0u8; 2048];
    let mut from_tcp = [0u8; 1500];
    let mut last_received = tokio::time::Instant::now();
    let mut timer = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            Some(greeting) = hello.recv() => { if !greeting.is_empty() && socket.send(&greeting).await.is_none(){return Ok(());} },
            _ = timer.tick() => { if last_received.elapsed()>Duration::from_secs(30){return Ok(());} },
            res = udp.recv(&mut from_udp) => {
                let size = res?;
                if size > MAX_DATAGRAM { continue; }
                if socket.send(&from_udp[..size]).await.is_none() { return Ok(()); }
            },
            res = socket.recv(&mut from_tcp) => {
                let Some(size) = res else { return Ok(()); };
                if size > 0 { last_received=tokio::time::Instant::now();udp.send(&from_tcp[..size]).await?; }
            },
            _ = tokio::time::sleep(IDLE) => return Ok(()),
        }
    }
}

async fn run(config: Config) -> io::Result<()> {
    // Validate parent before acquiring any packet capture or UDP endpoint.
    let parent_gone = parent::watch(config.parent)?;
    let (mut commands,input_stop) = input_commands()?;
    let device = platform::open(&config)?;
    let mut stack = Stack::new(vec![device], *config.source.ip(), None);
    let mut capture_failure = stack.failures();
    if config.server {
        stack.listen(config.source.port());
        event(
            json!({"event":"ready", "abi":ABI, "role":"server", "pid":std::process::id(), "source":config.source.to_string()}),
        );
        let connector=stack.connector();
        let mut peers=std::collections::HashMap::<SocketAddrV4,tokio::sync::mpsc::Sender<Vec<u8>>>::new();
        let mut tasks=tokio::task::JoinSet::new();
        tokio::select! {
            _ = parent_gone => Ok(()),
            _ = input_stop => Ok(()),
            _ = tokio::signal::ctrl_c() => Ok(()),
            reason = capture_failure.wait_for(Option::is_some) => Err(io::Error::other(reason.ok().and_then(|value|value.as_ref().cloned()).unwrap_or_else(||"Phantun capture stopped".into()))),
            res = async {
                loop {
                    tokio::select! {
                        Some(Ok(peer))=tasks.join_next(),if !tasks.is_empty()=>{peers.remove(&peer);},
                        command=commands.recv()=>{
                            let Some(command)=command else{return Ok(());};
                            match command {
                                Command::Protect(peer,id)=>{
                                    *config.control_peer.write().unwrap()=Some(peer);
                                    event(json!({"event":"protected","abi":ABI,"peer":peer.to_string(),"id":id}));
                                },
                                Command::Punch(peer,greeting)=>{
                                    if Some(peer)==*config.control_peer.read().unwrap(){continue;}
                                    if let Some(tx)=peers.get(&peer){let _=tx.try_send(greeting);continue;}
                                    if peers.len()>=64{continue;}
                                    let (tx,rx)=tokio::sync::mpsc::channel(8);let _=tx.try_send(greeting);peers.insert(peer,tx);
                                    let active=connector.clone();let target=config.remote;let port=config.source.port();
                                    tasks.spawn(async move{
                                        if let Ok(Some(socket))=tokio::time::timeout(Duration::from_secs(8),active.connect_from(peer.into(),port)).await {
                                            let _=forward_server(socket,target,rx).await;
                                        }
                                        peer
                                    });
                                }
                            }
                        },
                        socket=stack.accept()=>{
                            let SocketAddr::V4(peer)=socket.remote_addr() else {continue;};
                            if peers.contains_key(&peer)||peers.len()>=64{continue;}
                            let (tx,rx)=tokio::sync::mpsc::channel(8);peers.insert(peer,tx);let target=config.remote;
                            tasks.spawn(async move{let _=forward_server(socket,target,rx).await;peer});
                        }
                    }
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
            _ = async { while let Some(command)=commands.recv().await {
                if let Command::Protect(peer,id)=command {
                    *config.control_peer.write().unwrap()=Some(peer);
                    event(json!({"event":"protected","abi":ABI,"peer":peer.to_string(),"id":id}));
                }
            }} => Ok(()),
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

enum Command { Punch(SocketAddrV4,Vec<u8>),Protect(SocketAddrV4,String) }
fn input_commands()->io::Result<(tokio::sync::mpsc::Receiver<Command>,tokio::sync::oneshot::Receiver<()>)>{
    let(tx,rx)=tokio::sync::mpsc::channel(8);let(stop,stopped)=tokio::sync::oneshot::channel();
    std::thread::Builder::new().name("phantun-control".into()).spawn(move||{
        use std::io::{BufRead,Read};let stdin=std::io::stdin();let mut reader=stdin.lock();
        loop {
            let mut line=Vec::with_capacity(128);
            if !matches!(reader.by_ref().take(513).read_until(b'\n',&mut line),Ok(1..=512))||!line.ends_with(b"\n"){break;}
            let Ok(v)=serde_json::from_slice::<serde_json::Value>(&line) else {break;};
            let Some(o)=v.as_object() else{break;};
            let Some(peer)=v["peer"].as_str().and_then(|p|p.parse::<SocketAddrV4>().ok()) else{break;};
            if peer.port()==0||peer.ip().is_unspecified()||peer.ip().is_loopback()||peer.ip().is_multicast()||peer.ip().is_broadcast(){break;}
            let command=match v["command"].as_str(){
                Some("protect") if o.len()==3=>{
                    let Some(id)=v["id"].as_str().filter(|s|s.len()==32&&s.bytes().all(|b|b.is_ascii_hexdigit())) else{break;};
                    Command::Protect(peer,id.into())
                },
                Some("punch") if (2..=3).contains(&o.len())=>{
                    let hello=if o.len()==3 {
                        let Some(text)=v["hello"].as_str().filter(|s|!s.is_empty()&&s.len()<=256&&s.len()%2==0&&s.bytes().all(|b|b.is_ascii_hexdigit())) else{break;};
                        (0..text.len()).step_by(2).map(|i|u8::from_str_radix(&text[i..i+2],16).unwrap()).collect()
                    }else{vec![]};Command::Punch(peer,hello)
                },_=>break
            };
            if tx.blocking_send(command).is_err(){break;}
        }let _=stop.send(());
    })?;Ok((rx,stopped))
}
