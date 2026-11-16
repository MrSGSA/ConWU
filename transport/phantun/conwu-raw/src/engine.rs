use crate::{Carrier, Config, event, packet::*, udp_endpoint};
use fake_tcp::tun::TunDevice;
use serde_json::json;
use std::{
    collections::HashMap,
    io,
    net::{SocketAddr, SocketAddrV4},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
};

const LIMIT: usize = 128;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    SynSent,
    SynReceived,
    Kernel,
    Established,
}
struct Flow {
    generation:u64,
    local: SocketAddrV4,
    remote: SocketAddrV4,
    phase: Phase,
    seq: u32,
    ack: u32,
    isn: u32,
    peer_scale: u8,
    peer_window: u32,
    received_since_window: u32,
    timestamp: Option<(u32, u32)>,
    timestamp_at: Instant,
    last_received: Instant,
    last_sent: Instant,
    created: Instant,
    retry_at: Instant,
    retries: u8,
    udp: Option<Arc<UdpSocket>>,
    application: Option<SocketAddr>,
    pending: Option<Vec<u8>>,
    reader: Option<JoinHandle<()>>,
    writer: Option<tokio::net::tcp::OwnedWriteHalf>,
    pump: Option<JoinHandle<()>>,
    opened: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct Wire(Mutex<Vec<Vec<u8>>>);
    #[async_trait::async_trait]
    impl TunDevice for Wire {
        async fn recv(&self, _: &mut [u8]) -> io::Result<usize> {
            std::future::pending().await
        }
        async fn send(&self, data: &[u8]) -> io::Result<usize> {
            self.try_send(data)?;
            Ok(data.len())
        }
        fn try_send(&self, data: &[u8]) -> io::Result<()> {
            self.0.lock().unwrap().push(data.to_vec());
            Ok(())
        }
        fn name(&self) -> String {
            "isolated-memory-wire".into()
        }
    }
    impl Wire {
        fn packets(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }
    struct ErrorOnce {
        code: i32,
        calls: std::sync::atomic::AtomicU32,
    }
    #[async_trait::async_trait]
    impl TunDevice for ErrorOnce {
        async fn recv(&self, _: &mut [u8]) -> io::Result<usize> {
            std::future::pending().await
        }
        async fn send(&self, data: &[u8]) -> io::Result<usize> {
            self.try_send(data)?;
            Ok(data.len())
        }
        fn try_send(&self, _: &[u8]) -> io::Result<()> {
            if self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                == 0
            {
                Err(io::Error::from_raw_os_error(self.code))
            } else {
                Ok(())
            }
        }
        fn name(&self) -> String {
            "isolated-error-wire".into()
        }
    }
    #[tokio::test]
    async fn failed_active_tcpraw_probe_does_not_retire_the_listener_or_healthy_flow() {
        let (mut engine,_)=fixture(true,"127.0.0.1:12345".parse().unwrap());
        engine.config.carrier=Carrier::TcpRaw;
        let failed="198.18.0.2:42200".parse().unwrap();
        let live="198.18.0.3:42201".parse().unwrap();
        engine.flows.insert(failed,Flow::new(engine.config.source,failed,Phase::Kernel));
        engine.flows.insert(live,Flow::new(engine.config.source,live,Phase::Established));
        engine.message(Message::ConnectFailed(failed,engine.flows[&failed].generation,"probe timeout".into())).await.unwrap();
        assert!(!engine.flows.contains_key(&failed));
        assert!(engine.flows[&live].phase==Phase::Established);
    }
    async fn tcp_pair() -> (TcpStream,TcpStream) {
        let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (a,b)=tokio::join!(TcpStream::connect(listener.local_addr().unwrap()),listener.accept());
        (a.unwrap(),b.unwrap().0)
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn assisted_listener_and_active_handshake_share_the_observed_source_port() {
        let reflector = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let helper = tcp_socket(true).unwrap();
        helper.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = helper.local_addr().unwrap();
        let helper = helper.connect(reflector.local_addr().unwrap()).await.unwrap();
        let _reflection = reflector.accept().await.unwrap();
        let listener = tcp_socket(true).unwrap();
        listener.bind(local).unwrap();
        let _listener = listener.listen(8).unwrap();
        let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let active = tcp_socket(true).unwrap();
        active.bind(local).unwrap();
        let active = tokio::time::timeout(Duration::from_secs(1), active.connect(peer.local_addr().unwrap())).await.unwrap().unwrap();
        let _accepted = peer.accept().await.unwrap();
        assert_eq!(active.local_addr().unwrap(), helper.local_addr().unwrap());
        let unrelated = tcp_socket(false).unwrap();
        let result = unrelated.bind(local).and_then(|_| unrelated.listen(8));
        assert_eq!(result.err().expect("ordinary listener stole the assisted port").kind(), io::ErrorKind::AddrInUse);
    }
    #[tokio::test]
    async fn duplicate_kernel_completion_keeps_the_existing_writer_alive() {
        use tokio::io::AsyncWriteExt;
        let (mut engine,_)=fixture(true,"127.0.0.1:12345".parse().unwrap());
        engine.config.carrier=Carrier::TcpRaw;
        let peer="198.18.0.2:42200".parse().unwrap();
        let (stream,mut application)=tcp_pair().await;
        let (_read,write)=stream.into_split();
        let mut flow=Flow::new(engine.config.source,peer,Phase::Established);
        let generation=flow.generation;flow.writer=Some(write);engine.flows.insert(peer,flow);
        let (duplicate,_unused)=tcp_pair().await;
        engine.message(Message::Connected(peer,None,duplicate)).await.unwrap();
        let flow=engine.flows.get_mut(&peer).expect("duplicate completion removed the live peer");
        assert_eq!(flow.generation,generation);
        flow.writer.as_mut().unwrap().write_all(b"retained").await.unwrap();
        let mut bytes=[0;8];
        tokio::time::timeout(Duration::from_secs(1),application.read_exact(&mut bytes)).await.unwrap().unwrap();
        assert_eq!(&bytes,b"retained");
    }
    #[tokio::test]
    async fn late_kernel_callbacks_cannot_retire_a_reused_tuple() {
        let (mut engine,_)=fixture(true,"127.0.0.1:12345".parse().unwrap());
        engine.config.carrier=Carrier::TcpRaw;
        let peer="198.18.0.2:42200".parse().unwrap();
        let old=Flow::new(engine.config.source,peer,Phase::Kernel).generation;
        let mut replacement=Flow::new(engine.config.source,peer,Phase::Kernel);
        replacement.generation=old.wrapping_add(1);let current=replacement.generation;
        engine.flows.insert(peer,replacement);
        engine.message(Message::Closed(peer,old)).await.unwrap();
        engine.message(Message::ConnectFailed(peer,old,"old connect timed out".into())).await.unwrap();
        let (late,_unused)=tcp_pair().await;
        engine.message(Message::Connected(peer,Some(old),late)).await.unwrap();
        let flow=&engine.flows[&peer];
        assert_eq!(flow.generation,current);assert!(flow.writer.is_none());
    }
    #[tokio::test]
    async fn mtu_or_capacity_failure_does_not_retire_the_shared_carrier() {
        for code in [90, 105, 10040, 10055] {
            let (mut engine, _) = fixture(true, "127.0.0.1:12345".parse().unwrap());
            engine.device = Arc::new(ErrorOnce {
                code,
                calls: std::sync::atomic::AtomicU32::new(0),
            });
            let mut flow = Flow::new(
                engine.config.source,
                "198.18.0.2:41421".parse().unwrap(),
                Phase::Established,
            );
            engine.output(&mut flow, &[3; 1280]).unwrap();
            assert_eq!(engine.dropped, 1);
            engine.output(&mut flow, &[4; 128]).unwrap();
            assert_eq!(engine.dropped, 1);
            assert!(flow.phase == Phase::Established);
        }
    }
    fn fixture(server: bool, target: SocketAddrV4) -> (Engine, Arc<Wire>) {
        let config = Config {
            server,
            source: if server {
                "198.18.0.1:41420"
            } else {
                "198.18.0.2:41421"
            }
            .parse()
            .unwrap(),
            remote: if server {
                target
            } else {
                "198.18.0.1:41420".parse().unwrap()
            },
            parent: 1,
            carrier: Carrier::Mimic,
            protected_tcp_peer: None,
            control_peer: Arc::new(std::sync::RwLock::new(None)),
            peer_reflexive: false,
        };
        let (tx, rx) = mpsc::channel(512);
        let wire = Arc::new(Wire(Mutex::new(vec![])));
        let engine = Engine {
            config,
            device: wire.clone(),
            flows: HashMap::new(),
            observations: HashMap::new(),
            tx,
            rx,
            udp: None,
            application: None,
            tasks: vec![],
            admission_at: Instant::now(),
            admissions: 0,
            dropped: 0,
            send_warning_at: None,
        };
        (engine, wire)
    }
    async fn receive(socket: &UdpSocket) -> Vec<u8> {
        let mut bytes = [0; 2048];
        let size = tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        bytes[..size].to_vec()
    }
    #[tokio::test]
    async fn mimic_handshake_loss_reordering_bidirectional() {
        let target = udp_endpoint().unwrap();
        let application = Arc::new(udp_endpoint().unwrap());
        let bridge = Arc::new(udp_endpoint().unwrap());
        let (mut host, hostwire) = fixture(true, v4(target.local_addr().unwrap()).unwrap());
        let (mut guest, guestwire) = fixture(false, v4(target.local_addr().unwrap()).unwrap());
        guest.udp = Some(bridge);
        guest
            .message(Message::Client(
                application.local_addr().unwrap(),
                vec![42; 37],
            ))
            .await
            .unwrap();
        let syn = guestwire.packets().pop().unwrap();
        host.incoming(parse(&syn).unwrap()).await.unwrap();
        let synack = hostwire.packets().pop().unwrap();
        host.incoming(parse(&syn).unwrap()).await.unwrap();
        assert_eq!(
            hostwire.packets().pop().unwrap(),
            synack,
            "duplicate SYN must reuse sequence state"
        );
        guest.incoming(parse(&synack).unwrap()).await.unwrap();
        let packets = guestwire.packets();
        assert_eq!(packets.len(), 2);
        for packet in packets {
            host.incoming(parse(&packet).unwrap()).await.unwrap();
        }
        assert_eq!(receive(&target).await, vec![42; 37]);
        let remote = guest.config.source;
        for data in [vec![10; 100], vec![11; 100], vec![12; 100]] {
            guest
                .message(Message::Client(application.local_addr().unwrap(), data))
                .await
                .unwrap();
        }
        let packets = guestwire.packets();
        assert_eq!(packets.len(), 3);
        // Drop one complete packet and deliver the next two in reverse order.
        host.incoming(parse(&packets[2]).unwrap()).await.unwrap();
        host.incoming(parse(&packets[1]).unwrap()).await.unwrap();
        assert_eq!(receive(&target).await, vec![12; 100]);
        assert_eq!(receive(&target).await, vec![11; 100]);
        host.message(Message::Output(remote, vec![33; 79]))
            .await
            .unwrap();
        let reply = hostwire.packets().pop().unwrap();
        guest.incoming(parse(&reply).unwrap()).await.unwrap();
        assert_eq!(receive(&application).await, vec![33; 79]);
        guest.tick().unwrap();
        assert!(
            guestwire.packets().is_empty(),
            "lost data is never retransmitted by the carrier"
        );
    }
    #[tokio::test]
    async fn mimic_simultaneous_open_preserves_both_sequence_spaces() {
        let target = udp_endpoint().unwrap();
        let application = Arc::new(udp_endpoint().unwrap());
        let (mut host, hostwire) = fixture(true, v4(target.local_addr().unwrap()).unwrap());
        let (mut guest, guestwire) = fixture(false, v4(target.local_addr().unwrap()).unwrap());
        guest.udp = Some(Arc::new(udp_endpoint().unwrap()));
        host.message(Message::Punch(guest.config.source, vec![])).await.unwrap();
        let host_syn = hostwire.packets().pop().unwrap();
        guest.message(Message::Client(application.local_addr().unwrap(), vec![57; 91])).await.unwrap();
        let guest_syn = guestwire.packets().pop().unwrap();
        host.incoming(parse(&guest_syn).unwrap()).await.unwrap();
        guest.incoming(parse(&host_syn).unwrap()).await.unwrap();
        let host_synack = hostwire.packets().pop().unwrap();
        let guest_synack = guestwire.packets().pop().unwrap();
        assert_eq!(parse(&host_syn).unwrap().seq, parse(&host_synack).unwrap().seq);
        assert_eq!(parse(&guest_syn).unwrap().seq, parse(&guest_synack).unwrap().seq);
        host.incoming(parse(&guest_synack).unwrap()).await.unwrap();
        guest.incoming(parse(&host_synack).unwrap()).await.unwrap();
        for packet in guestwire.packets() { host.incoming(parse(&packet).unwrap()).await.unwrap(); }
        for packet in hostwire.packets() { guest.incoming(parse(&packet).unwrap()).await.unwrap(); }
        assert_eq!(receive(&target).await, vec![57; 91]);
        host.message(Message::Output(guest.config.source, vec![71; 83])).await.unwrap();
        guest.incoming(parse(&hostwire.packets().pop().unwrap()).unwrap()).await.unwrap();
        assert_eq!(receive(&application).await, vec![71; 83]);
    }
    #[tokio::test]
    async fn punch_does_not_replace_established_or_protected_flows() {
        let target = udp_endpoint().unwrap();
        let (mut host, wire) = fixture(true, v4(target.local_addr().unwrap()).unwrap());
        let peer = "198.18.0.2:41421".parse().unwrap();
        *host.config.control_peer.write().unwrap() = Some(peer);
        host.message(Message::Punch(peer, vec![])).await.unwrap();
        assert!(host.flows.is_empty() && wire.packets().is_empty());
        *host.config.control_peer.write().unwrap() = None;
        host.flows.insert(peer, Flow::new(host.config.source, peer, Phase::Established));
        host.message(Message::Punch(peer, vec![])).await.unwrap();
        assert!(host.flows[&peer].phase == Phase::Established);
        assert!(wire.packets().is_empty());
    }
    #[tokio::test]
    async fn assisted_two_listeners_send_greetings_only_after_handshake() {
        let target_a=udp_endpoint().unwrap();
        let target_b=udp_endpoint().unwrap();
        let (mut a,wire_a)=fixture(true,v4(target_a.local_addr().unwrap()).unwrap());
        let (mut b,wire_b)=fixture(true,v4(target_b.local_addr().unwrap()).unwrap());
        b.config.source="198.18.0.2:41421".parse().unwrap();
        a.message(Message::Punch(b.config.source,vec![31;84])).await.unwrap();
        b.message(Message::Punch(a.config.source,vec![47;84])).await.unwrap();
        let syn_a=wire_a.packets().pop().unwrap();
        let syn_b=wire_b.packets().pop().unwrap();
        assert!(parse(&syn_a).unwrap().payload.is_empty()&&parse(&syn_b).unwrap().payload.is_empty());
        a.incoming(parse(&syn_b).unwrap()).await.unwrap();
        b.incoming(parse(&syn_a).unwrap()).await.unwrap();
        for _ in 0..4 {
            for packet in wire_a.packets(){b.incoming(parse(&packet).unwrap()).await.unwrap();}
            for packet in wire_b.packets(){a.incoming(parse(&packet).unwrap()).await.unwrap();}
        }
        assert_eq!(receive(&target_a).await,vec![47;84]);
        assert_eq!(receive(&target_b).await,vec![31;84]);
        let before=a.flows[&b.config.source].isn;
        a.message(Message::Punch(b.config.source,vec![59;84])).await.unwrap();
        assert_eq!(a.flows[&b.config.source].isn,before);
        for packet in wire_a.packets(){b.incoming(parse(&packet).unwrap()).await.unwrap();}
        assert_eq!(receive(&target_b).await,vec![59;84]);
    }
    #[tokio::test]
    async fn reflexive_port_learning_requires_handshake_and_freezes_after_establishment() {
        let application = Arc::new(udp_endpoint().unwrap());
        let (mut guest, wire) = fixture(false, "127.0.0.1:12345".parse().unwrap());
        guest.config.peer_reflexive = true;
        guest.udp = Some(Arc::new(udp_endpoint().unwrap()));
        guest.message(Message::Client(application.local_addr().unwrap(), vec![5; 80])).await.unwrap();
        let syn = wire.packets().pop().unwrap();
        let expected_ack = parse(&syn).unwrap().seq.wrapping_add(1);
        let alternate = SocketAddrV4::new(*guest.config.remote.ip(), 49921);
        let invalid = build(alternate,guest.config.source,77,expected_ack.wrapping_add(1),SYN|ACK,65535,&[],&[]);
        guest.incoming(parse(&invalid).unwrap()).await.unwrap();
        assert_eq!(guest.flows.len(),1);
        let wrong_ip = build("198.18.0.9:49921".parse().unwrap(),guest.config.source,77,0,SYN,65535,&[],&[]);
        guest.incoming(parse(&wrong_ip).unwrap()).await.unwrap();
        assert_eq!(guest.flows.len(),1);
        let inbound = build(alternate,guest.config.source,77,0,SYN,65535,&[],&[]);
        guest.incoming(parse(&inbound).unwrap()).await.unwrap();
        assert!(guest.flows[&alternate].phase == Phase::SynReceived);
        assert_ne!(guest.config.remote,alternate,"a SYN alone cannot select the peer");
        let ack = build(alternate,guest.config.source,78,expected_ack,ACK,65535,&[],&[]);
        guest.incoming(parse(&ack).unwrap()).await.unwrap();
        assert_eq!(guest.config.remote,alternate);
        assert_eq!(guest.flows.len(),1,"obsolete candidates are removed");
        assert!(guest.flows[&alternate].phase == Phase::Established);
        let other = SocketAddrV4::new(*alternate.ip(),49922);
        let late = build(other,guest.config.source,91,0,SYN,65535,&[],&[]);
        guest.incoming(parse(&late).unwrap()).await.unwrap();
        assert_eq!(guest.config.remote,alternate);
        assert_eq!(guest.flows.len(),1,"an established peer cannot be moved by another SYN");
    }
    #[tokio::test]
    async fn pending_admission_and_unowned_packets() {
        let (mut host, wire) = fixture(true, "127.0.0.1:12345".parse().unwrap());
        for index in 0..200 {
            let remote = SocketAddrV4::new("198.18.0.2".parse().unwrap(), 42000 + index);
            let syn = build(
                remote,
                host.config.source,
                index as u32,
                0,
                SYN,
                65535,
                &syn_options(),
                &[],
            );
            host.incoming(parse(&syn).unwrap()).await.unwrap();
        }
        assert_eq!(host.flows.len(), 16);
        assert_eq!(wire.packets().len(), 16);
        assert!(host.flows.values().all(|flow| flow.udp.is_none()));
        let wrong = build(
            "198.18.0.3:42001".parse().unwrap(),
            "198.18.0.1:9999".parse().unwrap(),
            0,
            0,
            SYN,
            65535,
            &[],
            &[],
        );
        host.incoming(parse(&wrong).unwrap()).await.unwrap();
        assert_eq!(host.flows.len(), 16);
        for flow in host.flows.values_mut() {
            flow.created = Instant::now() - Duration::from_secs(11);
        }
        host.tick().unwrap();
        assert!(host.flows.is_empty());
    }
}
impl Flow {
    fn new(local: SocketAddrV4, remote: SocketAddrV4, phase: Phase) -> Self {
        let now = Instant::now();
        let isn = rand::random();
        Self {
            generation:rand::random(),
            local,
            remote,
            phase,
            seq: isn,
            ack: 0,
            isn,
            peer_scale: 0,
            peer_window: 65535,
            received_since_window: 0,
            timestamp: None,
            timestamp_at: now,
            last_received: now,
            last_sent: now,
            created: now,
            retry_at: now,
            retries: 0,
            udp: None,
            application: None,
            pending: None,
            reader: None,
            writer: None,
            pump: None,
            opened: false,
        }
    }
}
impl Drop for Flow {
    fn drop(&mut self) {
        if let Some(task) = self.reader.take() {
            task.abort();
        }
        if let Some(task) = self.pump.take() {
            task.abort();
        }
        if self.opened {
            if let Some(udp) = &self.udp {
                if let Ok(endpoint) = udp.local_addr() {
                    event(json!({"event":"peer-closed","abi":1,"udp":endpoint.to_string()}));
                }
            }
        }
    }
}
#[derive(Default)]
struct Observation {
    seq: Option<u32>,
    ack: u32,
    syn: Option<u32>,
    timestamp: Option<(u32, u32)>,
    at: Option<Instant>,
}
enum Message {
    Punch(SocketAddrV4, Vec<u8>),
    Protect(SocketAddrV4, String),
    Client(SocketAddr, Vec<u8>),
    Output(SocketAddrV4, Vec<u8>),
    Connected(SocketAddrV4, Option<u64>, TcpStream),
    ConnectFailed(SocketAddrV4,u64,String),
    Closed(SocketAddrV4,u64),
}
struct Engine {
    config: Config,
    device: Arc<dyn TunDevice>,
    flows: HashMap<SocketAddrV4, Flow>,
    observations: HashMap<SocketAddrV4, Observation>,
    tx: mpsc::Sender<Message>,
    rx: mpsc::Receiver<Message>,
    udp: Option<Arc<UdpSocket>>,
    application: Option<SocketAddr>,
    tasks: Vec<JoinHandle<()>>,
    admission_at: Instant,
    admissions: u8,
    dropped: u64,
    send_warning_at: Option<Instant>,
}
impl Drop for Engine {
    fn drop(&mut self) {
        for flow in self.flows.values() {
            if flow.phase == Phase::Established {
                let packet = build(
                    flow.local,
                    flow.remote,
                    flow.seq,
                    flow.ack,
                    RST | ACK,
                    0,
                    &[],
                    &[],
                );
                let _ = self.device.try_send(&packet);
            }
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}
fn v4(endpoint: SocketAddr) -> io::Result<SocketAddrV4> {
    match endpoint {
        SocketAddr::V4(value) => Ok(value),
        _ => Err(io::Error::other("IPv4 carrier required")),
    }
}

fn tcp_socket(assisted: bool) -> io::Result<TcpSocket> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(cfg!(target_os = "linux") || assisted)?;
    // The retained reflector, listener and active handshake belong to one
    // source-port lease. Linux needs REUSEPORT on all three; REUSEADDR alone
    // cannot bind an active socket beside the listener. Ordinary entry
    // listeners must not join that group or admit independent port owners.
    #[cfg(target_os = "linux")]
    if assisted { socket.set_reuseport(true)?; }
    Ok(socket)
}

pub async fn run(config: Config) -> io::Result<()> {
    let gone = crate::parent::watch(config.parent)?;
    let (mut commands, input) = input_commands()?;
    let device = crate::platform::open(&config)?;
    let (tx, rx) = mpsc::channel(512);
    let mut engine = Engine {
        config: config.clone(),
        device: device.clone(),
        flows: HashMap::new(),
        observations: HashMap::new(),
        tx: tx.clone(),
        rx,
        udp: None,
        application: None,
        tasks: vec![],
        admission_at: Instant::now(),
        admissions: 0,
        dropped: 0,
        send_warning_at: None,
    };
    if config.server && config.carrier == Carrier::TcpRaw {
        let socket = tcp_socket(config.protected_tcp_peer.is_some())?;
        socket.bind(config.source.into())?;
        let listener = socket.listen(128)?;
        engine
            .tasks
            .push(tokio::spawn(accept(listener, tx.clone())));
    }
    if !config.server {
        let udp = Arc::new(udp_endpoint()?);
        let pump = udp.clone();
        engine.udp = Some(udp.clone());
        engine.tasks.push(tokio::spawn(async move {
            let mut bytes = [0u8; 2048];
            while let Ok((size, source)) = pump.recv_from(&mut bytes).await {
                if source.ip().is_loopback() && size > 0 && size <= MAX_DATAGRAM {
                    let _ = tx.try_send(Message::Client(source, bytes[..size].to_vec()));
                }
            }
        }));
    }
    event(
        json!({"event":"ready","abi":1,"carrier":config.carrier.name(),"backend":device.name(),"role":if config.server{"server"}else{"client"},"pid":std::process::id(),"source":config.source.to_string(),"udp":engine.udp.as_ref().and_then(|s|s.local_addr().ok()).map(|s|s.to_string())}),
    );
    let work = async {
        let mut buffer = [0u8; 65535];
        let mut timer = tokio::time::interval(Duration::from_millis(200));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                packet=device.recv(&mut buffer)=>{let size=packet?;if let Some(segment)=parse(&buffer[..size]){engine.incoming(segment).await?;}},
                message=engine.rx.recv()=>{if let Some(message)=message{engine.message(message).await?;}else{return Err(io::Error::other("carrier bridge closed"));}},
                _=timer.tick()=>engine.tick()?,
                command=commands.recv()=>{if let Some(command)=command{engine.message(command).await?;}},
            }
        }
    };
    tokio::select! {result=work=>result,_=gone=>Ok(()),_=input=>Ok(()),_=tokio::signal::ctrl_c()=>Ok(())}
}

fn input_commands() -> io::Result<(mpsc::Receiver<Message>, tokio::sync::oneshot::Receiver<()>)> {
    let (tx, rx) = mpsc::channel(8);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    std::thread::Builder::new().name("raw-control".into()).spawn(move || {
        use std::io::{BufRead, Read};
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        loop {
            let mut line = Vec::with_capacity(128);
            let size = reader.by_ref().take(513).read_until(b'\n', &mut line);
            if !matches!(size, Ok(1..=512)) || !line.ends_with(b"\n") { break; }
            let Ok(command) = serde_json::from_slice::<serde_json::Value>(&line) else { break; };
            let kind = command["command"].as_str();
            if !matches!(kind, Some("punch" | "protect"))
                || command.as_object().is_none_or(|object| if kind == Some("protect") {object.len()!=3} else {!(2..=3).contains(&object.len())}) { break; }
            let Some(peer) = command["peer"].as_str().and_then(|value| value.parse::<SocketAddrV4>().ok()) else { break; };
            if peer.port() == 0 || peer.ip().is_unspecified()
                || peer.ip().is_loopback() || peer.ip().is_multicast() || peer.ip().is_broadcast()
                { break; }
            let message = if kind == Some("punch") {
                let hello = if command.as_object().unwrap().len()==3 {
                    let Some(text)=command["hello"].as_str().filter(|s| !s.is_empty()&&s.len()<=256&&s.len()%2==0&&s.bytes().all(|b| b.is_ascii_hexdigit())) else {break;};
                    (0..text.len()).step_by(2).map(|i|u8::from_str_radix(&text[i..i+2],16).unwrap()).collect()
                }else{vec![]};
                Message::Punch(peer,hello)
            } else {
                let Some(id) = command["id"].as_str().filter(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())) else {break;};
                Message::Protect(peer, id.to_owned())
            };
            if tx.blocking_send(message).is_err() { break; }
        }
        let _ = stop.send(());
    })?;
    Ok((rx, stopped))
}
async fn accept(listener: TcpListener, tx: mpsc::Sender<Message>) {
    loop {
        match listener.accept().await {
            Ok((stream, remote)) => {
                let Ok(remote) = v4(remote) else {
                    continue;
                };
                // Kernel packets only get TTL=1 after its complete three-way handshake.
                // The parent's owned output rule prevents them from reaching the wire.
                if prepare_system(&stream).is_err() {
                    continue;
                }
                if tx.try_send(Message::Connected(remote, None, stream)).is_err() {
                    continue;
                }
            }
            Err(_) => break,
        }
    }
}
fn prepare_system(stream: &TcpStream) -> io::Result<()> {
    socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO))?;
    socket2::SockRef::from(stream).set_recv_buffer_size(65536)?;
    stream.set_ttl(1)?;
    stream.set_nodelay(true)
}
impl Engine {
    fn admit(&mut self) -> bool {
        if self.admission_at.elapsed() >= Duration::from_secs(1) {
            self.admissions = 0;
            self.admission_at = Instant::now();
        }
        if self.flows.len() >= LIMIT || self.admissions >= 16 {
            return false;
        }
        self.admissions += 1;
        true
    }
    fn send(
        &mut self,
        flow: &mut Flow,
        flags: u8,
        seq: u32,
        options: &[u8],
        data: &[u8],
    ) -> io::Result<()> {
        let window = if flags & SYN != 0 {
            65535
        } else if self.config.carrier == Carrier::Mimic {
            (MIMIC_WINDOW >> MIMIC_SCALE) as u16
        } else {
            65535
        };
        let packet = build(
            flow.local,
            flow.remote,
            seq,
            flow.ack,
            flags,
            window,
            options,
            data,
        );
        match self.device.try_send(&packet) {
            Ok(()) => {}
            Err(ex)
                if ex.kind() == io::ErrorKind::WouldBlock
                    || matches!(
                        ex.raw_os_error(),
                        Some(90 | 105 | 101 | 113 | 10040 | 10055 | 10050 | 10051 | 10052 | 10065)
                    ) =>
            {
                self.dropped += 1;
                if self
                    .send_warning_at
                    .is_none_or(|at| at.elapsed() > Duration::from_secs(30))
                {
                    eprintln!(
                        "Raw packet not sent: {} ({} bytes); check route MTU/capacity; shared listener retained",
                        ex,
                        packet.len()
                    );
                    self.send_warning_at = Some(Instant::now());
                }
            }
            Err(ex) => return Err(ex),
        }
        flow.last_sent = Instant::now();
        Ok(())
    }
    fn control(&mut self, flow: &mut Flow, flags: u8, seq: u32) -> io::Result<()> {
        let options = if flags & SYN != 0 {
            syn_options().to_vec()
        } else {
            vec![]
        };
        self.send(flow, flags, seq, &options, &[])
    }
    fn output(&mut self, flow: &mut Flow, data: &[u8]) -> io::Result<()> {
        if data.is_empty() || data.len() > MAX_DATAGRAM {
            return Ok(());
        }
        if flow.phase != Phase::Established {
            if flow.pending.is_none() {
                flow.pending = Some(data.to_vec());
            }
            return Ok(());
        }
        let seq = flow.seq;
        if self.config.carrier == Carrier::Mimic {
            if flow.peer_window < data.len() as u32 {
                // Window probes are control only; a late frame is discarded,
                // never queued awaiting reliable TCP retransmission.
                self.dropped += 1;
                return self.send(flow, ACK, seq.wrapping_sub(1), &[], &[0]);
            }
            let payload = mimic_encode(data);
            // The original XDP ingress runs before GRO. Our shared raw-device
            // path also runs after virtual-NIC offloads on some platforms;
            // PSH preserves datagram segment boundaries there. Mimic's ingress
            // accepts PSH on ordinary data, while probes stay ACK-only.
            self.send(flow, ACK | PSH, seq, &[], &payload)?;
            flow.peer_window = flow.peer_window.saturating_sub(data.len() as u32);
        } else {
            let mut options = vec![];
            if let Some((peer, own)) = flow.timestamp {
                options.extend_from_slice(&[1, 1, 8, 10]);
                options.extend_from_slice(
                    &own.wrapping_add(flow.timestamp_at.elapsed().as_millis() as u32)
                        .to_be_bytes(),
                );
                options.extend_from_slice(&peer.to_be_bytes());
            }
            self.send(flow, ACK | PSH, seq, &options, data)?;
        }
        flow.seq = seq.wrapping_add(data.len() as u32);
        Ok(())
    }
    async fn establish(&mut self, flow: &mut Flow) -> io::Result<()> {
        if self.config.carrier==Carrier::TcpRaw {
            event(json!({"event":"kernel-established","peer":flow.remote.to_string(),"seq":flow.seq,"ack":flow.ack}));
        }
        if flow.phase == Phase::Established {
            return Ok(());
        }
        flow.phase = Phase::Established;
        if !self.config.server && self.config.peer_reflexive {
            // Choose the observed tuple only after its handshake acknowledges
            // our original random ISN. MeshLink / pairing still authenticate it.
            self.config.remote = flow.remote;
            self.flows.clear();
        }
        if self.config.server {
            let udp = Arc::new(udp_endpoint()?);
            udp.connect(self.config.remote).await?;
            let pump = udp.clone();
            let tx = self.tx.clone();
            let remote = flow.remote;
            flow.pump = Some(tokio::spawn(async move {
                let mut bytes = [0u8; 2048];
                while let Ok(size) = pump.recv(&mut bytes).await {
                    if size > 0 && size <= MAX_DATAGRAM {
                        let _ = tx.try_send(Message::Output(remote, bytes[..size].to_vec()));
                    }
                }
            }));
            event(json!({"event":"peer-opened","abi":1,"udp":udp.local_addr()?.to_string(),"peer":flow.remote.to_string()}));
            flow.udp = Some(udp);
            flow.opened = true;
        }
        if let Some(pending) = flow.pending.take() {
            self.output(flow, &pending)?;
        }
        Ok(())
    }
    async fn incoming(&mut self, segment: Segment<'_>) -> io::Result<()> {
        if *self.config.control_peer.read().unwrap() == Some(segment.remote) { return Ok(()); }
        if segment.local.port() != self.config.source.port()
            || (!self.config.source.ip().is_unspecified()
                && segment.local.ip() != self.config.source.ip())
            || (!self.config.server && segment.remote != self.config.remote
                && !(self.config.peer_reflexive && segment.remote.ip() == self.config.remote.ip()
                    && !self.flows.values().any(|flow| flow.phase == Phase::Established)))
        {
            return Ok(());
        }
        let key = segment.remote;
        if !self.config.server && self.config.peer_reflexive && !self.flows.contains_key(&key) {
            if self.flows.len() >= 8 || segment.flags & (SYN | RST | FIN) != SYN { return Ok(()); }
            let Some(original) = self.flows.get(&self.config.remote) else { return Ok(()); };
            if original.phase != Phase::SynSent { return Ok(()); }
            if segment.flags & ACK != 0 && segment.ack != original.seq { return Ok(()); }
            let mut candidate = Flow::new(self.config.source, key, Phase::SynSent);
            candidate.isn = original.isn;
            candidate.seq = original.seq;
            candidate.udp = original.udp.clone();
            candidate.application = original.application;
            candidate.pending = original.pending.clone();
            self.flows.insert(key, candidate);
        }
        if self.config.carrier == Carrier::TcpRaw && !self.flows.contains_key(&key) {
            if !self.config.server && key != self.config.remote {
                return Ok(());
            }
            if self.observations.len() >= LIMIT && !self.observations.contains_key(&key) {
                return Ok(());
            }
            let observation = self.observations.entry(key).or_default();
            observation.at = Some(Instant::now());
            if segment.flags & SYN != 0 {
                observation.syn = Some(segment.seq);
                observation.ack = segment.seq.wrapping_add(1);
                if segment.flags & ACK != 0 {
                    observation.seq = Some(segment.ack);
                }
            } else if segment.flags & ACK != 0
                && observation
                    .syn
                    .is_some_and(|seq| segment.seq == seq.wrapping_add(1))
            {
                observation.seq = Some(segment.ack);
            }
            if segment.timestamp.is_some() {
                observation.timestamp = segment.timestamp;
            }
            return Ok(());
        }
        if !self.flows.contains_key(&key) {
            if !self.config.server
                || segment.flags & (SYN | ACK | RST | FIN) != SYN
                || !self.admit()
            {
                return Ok(());
            }
            let mut flow = Flow::new(segment.local, key, Phase::SynReceived);
            flow.seq = flow.isn.wrapping_add(1);
            flow.ack = segment.seq.wrapping_add(1);
            flow.peer_scale = segment.scale;
            flow.peer_window = segment.window as u32;
            let isn = flow.isn;
            self.control(&mut flow, SYN | ACK, isn)?;
            self.flows.insert(key, flow);
            return Ok(());
        }
        let mut flow = self.flows.remove(&key).unwrap();
        if segment.flags & (RST | FIN) != 0 {
            if !self.config.server {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "raw carrier peer closed",
                ));
            }
            return Ok(());
        }
        flow.last_received = Instant::now();
        if segment.flags & SYN != 0 {
            flow.peer_scale = segment.scale;
        }
        if self.config.carrier == Carrier::Mimic {
            flow.peer_window = (segment.window as u32) << flow.peer_scale;
        }
        if let Some((peer, echo)) = segment.timestamp {
            let own = flow
                .timestamp
                .map(|(_, own)| own.wrapping_add(flow.timestamp_at.elapsed().as_millis() as u32))
                .unwrap_or(echo);
            flow.timestamp = Some((peer, own));
            flow.timestamp_at = Instant::now();
        }
        match flow.phase {
            Phase::SynSent if segment.flags & (SYN | ACK) == SYN => {
                // Simultaneous open: both NATs may require an outbound SYN.
                // Keep our original ISN, so each NAT sees the expected ACK.
                flow.ack = segment.seq.wrapping_add(1);
                flow.phase = Phase::SynReceived;
                let isn = flow.isn;
                self.control(&mut flow, SYN | ACK, isn)?;
            }
            Phase::SynSent
                if segment.flags & (SYN | ACK) == SYN | ACK && segment.ack == flow.seq =>
            {
                flow.ack = segment.seq.wrapping_add(1);
                let seq = flow.seq;
                self.control(&mut flow, ACK, seq)?;
                self.establish(&mut flow).await?;
            }
            Phase::SynReceived
                if segment.flags & (SYN | ACK) == SYN | ACK
                    && segment.ack == flow.seq && segment.seq.wrapping_add(1) == flow.ack =>
            {
                let seq = flow.seq;
                self.control(&mut flow, ACK, seq)?;
                self.establish(&mut flow).await?;
            }
            Phase::SynReceived
                if segment.flags & SYN != 0 && segment.seq.wrapping_add(1) == flow.ack =>
            {
                let isn = flow.isn;
                self.control(&mut flow, SYN | ACK, isn)?;
            }
            Phase::SynReceived if self.config.peer_reflexive && segment.flags & (SYN | ACK) == SYN => {
                flow.ack = segment.seq.wrapping_add(1);
                let isn = flow.isn;
                self.control(&mut flow, SYN | ACK, isn)?;
            }
            Phase::SynReceived
                if segment.flags & ACK != 0
                    && segment.ack == flow.seq
                    && segment.seq == flow.ack =>
            {
                self.establish(&mut flow).await?;
            }
            Phase::Kernel if segment.flags & ACK != 0 => {
                if segment.flags & SYN != 0 {
                    flow.seq = segment.ack;
                    flow.ack = segment.seq.wrapping_add(1);
                } else {
                    flow.seq = segment.ack;
                    flow.ack = segment.seq;
                }
                if flow.writer.is_some() {
                    self.establish(&mut flow).await?;
                }
            }
            Phase::Established
                if self.config.carrier == Carrier::Mimic
                    && segment.flags & (SYN | ACK) == SYN | ACK
                    && segment.seq.wrapping_add(1) == flow.ack =>
            {
                // Retransmitted SYN-ACK after a lost final ACK. Reuse the
                // original handshake sequence even if business data was sent.
                let seq = flow.isn.wrapping_add(1);
                self.control(&mut flow, ACK, seq)?;
            }
            _ => {}
        }
        if flow.phase == Phase::Established && segment.flags & SYN == 0 && segment.flags & ACK != 0
        {
            let consumed = segment.seq.wrapping_add(segment.payload.len() as u32);
            let deliver = if self.config.carrier == Carrier::Mimic {
                if segment.seq == flow.ack.wrapping_sub(1) && segment.payload.len() < 2 {
                    let seq = flow.seq;
                    self.control(&mut flow, ACK, seq)?;
                    false
                } else if segment.payload.len() == 1 && segment.flags & PSH == 0 {
                    flow.ack = consumed;
                    let seq = flow.seq;
                    self.control(&mut flow, ACK, seq)?;
                    false
                } else {
                    segment.payload.len() >= 2 || segment.flags & PSH != 0
                }
            } else {
                segment.flags & PSH != 0 && !segment.payload.is_empty()
            };
            if deliver && segment.payload.len() <= MAX_DATAGRAM {
                if after(consumed, flow.ack) || consumed == flow.ack {
                    flow.ack = consumed;
                }
                let data = if self.config.carrier == Carrier::Mimic {
                    mimic_decode(segment.payload)
                } else {
                    segment.payload.to_vec()
                };
                if let Some(udp) = &flow.udp {
                    let send = async {
                        if self.config.server {
                            udp.send(&data).await
                        } else {
                            udp.send_to(&data, flow.application.unwrap()).await
                        }
                    };
                    if !matches!(
                        tokio::time::timeout(Duration::from_millis(20), send).await,
                        Ok(Ok(_))
                    ) {
                        self.dropped += 1;
                    }
                }
                // Always refresh the advertised window, even when the reverse
                // direction has no business data. Never wait for missing bytes.
                flow.received_since_window =
                    flow.received_since_window.saturating_add(data.len() as u32);
                if self.config.carrier == Carrier::Mimic && flow.received_since_window >= 65536 {
                    let seq = flow.seq;
                    self.control(&mut flow, ACK, seq)?;
                    flow.received_since_window = 0;
                }
            }
        }
        self.flows.insert(key, flow);
        Ok(())
    }
    async fn message(&mut self, message: Message) -> io::Result<()> {
        match message {
            Message::Protect(peer, id) => {
                self.device.protect_tcp_peer(peer)?;
                *self.config.control_peer.write().unwrap() = Some(peer);
                event(json!({"event":"protected","abi":1,"peer":peer.to_string(),"id":id}));
            }
            Message::Punch(peer, hello) => {
                if !self.config.server
                    || self.config.source.ip().is_unspecified()
                    || *self.config.control_peer.read().unwrap() == Some(peer)
                    || hello.len()>128 { return Ok(()); }
                if let Some(mut flow)=self.flows.remove(&peer) {
                    if !hello.is_empty(){self.output(&mut flow,&hello)?;}
                    self.flows.insert(peer,flow);return Ok(());
                }
                if !self.admit(){return Ok(());}
                let phase=if self.config.carrier==Carrier::Mimic{Phase::SynSent}else{Phase::Kernel};
                let mut flow = Flow::new(self.config.source, peer, phase);
                if !hello.is_empty(){flow.pending=Some(hello);}
                if self.config.carrier==Carrier::Mimic {
                    flow.seq = flow.isn.wrapping_add(1);
                    let isn = flow.isn; self.control(&mut flow, SYN, isn)?;
                }else{self.kernel_connect(peer,flow.generation);}
                self.flows.insert(peer, flow);
            }
            Message::Client(source, data) => {
                if self.application.is_some_and(|app| app != source) {
                    return Ok(());
                }
                self.application = Some(source);
                let key = self.config.remote;
                if let Some(mut flow) = self.flows.remove(&key) {
                    self.output(&mut flow, &data)?;
                    self.flows.insert(key, flow);
                } else {
                    let phase = if self.config.carrier == Carrier::Mimic {
                        Phase::SynSent
                    } else {
                        Phase::Kernel
                    };
                    let mut flow = Flow::new(self.config.source, key, phase);
                    flow.udp = self.udp.clone();
                    flow.application = Some(source);
                    flow.pending = Some(data);
                    if self.config.carrier == Carrier::Mimic {
                        flow.seq = flow.isn.wrapping_add(1);
                        let isn = flow.isn;
                        self.control(&mut flow, SYN, isn)?;
                    } else {
                        self.kernel_connect(key,flow.generation);
                    }
                    self.flows.insert(key, flow);
                }
            }
            Message::Output(key, data) => {
                if let Some(mut flow) = self.flows.remove(&key) {
                    self.output(&mut flow, &data)?;
                    self.flows.insert(key, flow);
                }
            }
            Message::ConnectFailed(key,generation,reason) => {
                event(json!({"event":"kernel-connect-failed","peer":key.to_string(),"reason":reason}));
                if self.flows.get(&key).is_some_and(|f|f.generation==generation&&f.writer.is_none()) {
                    self.flows.remove(&key);self.observations.remove(&key);
                    if !self.config.server{return Err(io::Error::other(reason));}
                }
            },
            Message::Closed(key,generation) => {
                if !self.flows.get(&key).is_some_and(|flow|flow.generation==generation){return Ok(());}
                event(json!({"event":"kernel-stream-closed","peer":key.to_string()}));
                self.flows.remove(&key);
                if !self.config.server {
                    return Err(io::Error::other("kernel TCP association closed"));
                }
            }
            Message::Connected(key, generation, stream) => {
                if generation.is_some_and(|expected|!self.flows.get(&key).is_some_and(|flow|flow.generation==expected)) {return Ok(());}

                // No kernel application data is sent. Abortive close avoids a
                // suppressed FIN lingering on the shared listening port after
                // a carrier restart; raw RST notification is handled separately.
                socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO))?;
                socket2::SockRef::from(&stream).set_recv_buffer_size(65536)?;
                if self.config.server && !self.flows.contains_key(&key) && !self.admit() {
                    return Ok(());
                }
                let local = v4(stream.local_addr()?)?;
                let mut flow = self
                    .flows
                    .remove(&key)
                    .unwrap_or_else(|| Flow::new(local, key, Phase::Kernel));
                if flow.writer.is_some() {
                    self.flows.insert(key,flow);
                    return Ok(());
                }
                flow.local = local;
                event(json!({"event":"kernel-connected","peer":key.to_string(),"phase":format!("{:?}",flow.phase),"seq":flow.seq,"ack":flow.ack,"active":generation.is_some()}));
                let generation=flow.generation;
                let (read, write) = stream.into_split();
                flow.writer = Some(write);
                let tx = self.tx.clone();
                flow.reader = Some(tokio::spawn(async move {
                    let mut read = read;
                    let mut sink = [0u8; 8192];
                    while let Ok(size) = read.read(&mut sink).await {
                        if size == 0 {
                            break;
                        }
                    }
                    let _ = tx.send(Message::Closed(key,generation)).await;
                }));
                if let Some(observation) = self.observations.remove(&key) {
                    if let Some(seq) = observation.seq {
                        flow.seq = seq;
                        flow.ack = observation.ack;
                        flow.timestamp = observation.timestamp;
                        self.establish(&mut flow).await?;
                    }
                }
                // The inbound SYN-ACK can be captured before the connect task
                // completes; a client flow records it in Phase::Kernel above.
                if flow.phase == Phase::Kernel && flow.ack != 0 {
                    self.establish(&mut flow).await?;
                }
                self.flows.insert(key, flow);
            }
        }
        Ok(())
    }
    fn kernel_connect(&mut self,key:SocketAddrV4,generation:u64) {
        let tx=self.tx.clone();let local=self.config.source;
        let assisted=self.config.protected_tcp_peer.is_some();
        self.tasks.push(tokio::spawn(async move{
            let result=async {
                let socket=tcp_socket(assisted)?;socket.bind(local.into())?;
                let stream=tokio::time::timeout(Duration::from_secs(8),socket.connect(key.into())).await
                    .map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"kernel TCP handshake deadline"))??;
                prepare_system(&stream)?;Ok::<_,io::Error>(stream)
            }.await;
            let message=match result{Ok(stream)=>Message::Connected(key,Some(generation),stream),Err(error)=>Message::ConnectFailed(key,generation,error.to_string())};
            let _=tx.send(message).await;
        }));
    }
    fn tick(&mut self) -> io::Result<()> {
        self.tasks.retain(|task|!task.is_finished());
        let now = Instant::now();
        self.observations.retain(|_, o| {
            o.at.is_some_and(|at| now.duration_since(at) < Duration::from_secs(10))
        });
        let keys = self.flows.keys().copied().collect::<Vec<_>>();
        for key in keys {
            let mut flow = self.flows.remove(&key).unwrap();
            let expired = if flow.phase == Phase::Established {
                flow.last_received.elapsed() > Duration::from_secs(180)
            } else {
                flow.created.elapsed() > Duration::from_secs(if self.config.peer_reflexive {40} else {10})
            };
            if expired {
                if !self.config.server {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "raw carrier peer deadline",
                    ));
                }
                continue;
            }
            if matches!(flow.phase, Phase::SynSent | Phase::SynReceived)
                && flow.retry_at.elapsed() > Duration::from_secs(2)
            {
                if flow.retries >= if self.config.peer_reflexive {18} else {3} {
                    if !self.config.server {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Mimic handshake deadline",
                        ));
                    }
                    continue;
                }
                let flags = if flow.phase == Phase::SynSent {
                    SYN
                } else {
                    SYN | ACK
                };
                let isn = flow.isn;
                self.control(&mut flow, flags, isn)?;
                flow.retries += 1;
                flow.retry_at = now;
            } else if flow.phase == Phase::Established
                && self.config.carrier == Carrier::Mimic
                && flow.last_sent.elapsed() > Duration::from_secs(20)
            {
                let seq = flow.seq.wrapping_sub(1);
                self.control(&mut flow, ACK, seq)?;
            }
            self.flows.insert(key, flow);
        }
        Ok(())
    }
}
