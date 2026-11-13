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
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    SynSent,
    SynReceived,
    Kernel,
    Established,
}
struct Flow {
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
    Client(SocketAddr, Vec<u8>),
    Output(SocketAddrV4, Vec<u8>),
    Connected(SocketAddrV4, TcpStream),
    ConnectFailed(String),
    Closed(SocketAddrV4),
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

pub async fn run(config: Config) -> io::Result<()> {
    let gone = crate::parent::watch(config.parent)?;
    let input = crate::parent::input_stop()?;
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
        let socket = TcpSocket::new_v4()?;
        socket.set_reuseaddr(cfg!(target_os = "linux"))?;
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
        json!({"event":"ready","abi":1,"carrier":config.carrier.name(),"role":if config.server{"server"}else{"client"},"pid":std::process::id(),"source":config.source.to_string(),"udp":engine.udp.as_ref().and_then(|s|s.local_addr().ok()).map(|s|s.to_string())}),
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
            }
        }
    };
    tokio::select! {result=work=>result,_=gone=>Ok(()),_=input=>Ok(()),_=tokio::signal::ctrl_c()=>Ok(())}
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
                if tx.try_send(Message::Connected(remote, stream)).is_err() {
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
        if flow.phase == Phase::Established {
            return Ok(());
        }
        flow.phase = Phase::Established;
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
            event(json!({"event":"peer-opened","abi":1,"udp":udp.local_addr()?.to_string()}));
            flow.udp = Some(udp);
            flow.opened = true;
        }
        if let Some(pending) = flow.pending.take() {
            self.output(flow, &pending)?;
        }
        Ok(())
    }
    async fn incoming(&mut self, segment: Segment<'_>) -> io::Result<()> {
        if segment.local.port() != self.config.source.port()
            || (!self.config.source.ip().is_unspecified()
                && segment.local.ip() != self.config.source.ip())
            || (!self.config.server && segment.remote != self.config.remote)
        {
            return Ok(());
        }
        let key = segment.remote;
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
            Phase::SynSent
                if segment.flags & (SYN | ACK) == SYN | ACK && segment.ack == flow.seq =>
            {
                flow.ack = segment.seq.wrapping_add(1);
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
                        let tx = self.tx.clone();
                        let local = self.config.source;
                        self.tasks.push(tokio::spawn(async move {
                            let result = async {
                                let socket = TcpSocket::new_v4()?;
                                socket.bind(local.into())?;
                                let stream = tokio::time::timeout(
                                    Duration::from_secs(8),
                                    socket.connect(key.into()),
                                )
                                .await
                                .map_err(|_| {
                                    io::Error::new(
                                        io::ErrorKind::TimedOut,
                                        "kernel TCP handshake deadline",
                                    )
                                })??;
                                prepare_system(&stream)?;
                                Ok::<_, io::Error>(stream)
                            }
                            .await;
                            let message = match result {
                                Ok(stream) => Message::Connected(key, stream),
                                Err(error) => Message::ConnectFailed(error.to_string()),
                            };
                            let _ = tx.send(message).await;
                        }));
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
            Message::ConnectFailed(reason) => return Err(io::Error::other(reason)),
            Message::Closed(key) => {
                self.flows.remove(&key);
                if !self.config.server {
                    return Err(io::Error::other("kernel TCP association closed"));
                }
            }
            Message::Connected(key, stream) => {
                // No kernel application data is sent. Abortive close avoids a
                // suppressed FIN lingering on the shared listening port after
                // a carrier restart; raw RST notification is handled separately.
                socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO))?;
                socket2::SockRef::from(&stream).set_recv_buffer_size(65536)?;
                if self.config.server && !self.admit() {
                    return Ok(());
                }
                let local = v4(stream.local_addr()?)?;
                let mut flow = self
                    .flows
                    .remove(&key)
                    .unwrap_or_else(|| Flow::new(local, key, Phase::Kernel));
                if flow.writer.is_some() {
                    return Ok(());
                }
                flow.local = local;
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
                    let _ = tx.send(Message::Closed(key)).await;
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
    fn tick(&mut self) -> io::Result<()> {
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
                flow.created.elapsed() > Duration::from_secs(10)
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
                if flow.retries >= 3 {
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
