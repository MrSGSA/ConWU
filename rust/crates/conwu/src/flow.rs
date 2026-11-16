//! Three independent TCP connections with the existing CWF1 authenticated
//! negotiation and FIFO fence before changing the packet's physical stream.
use crate::{
    runtime::Engine,
    transport::{self, Pipe},
};
use anyhow::{Context, Result, ensure};
use conwu_core::{
    crypto as c,
    identity::Profile,
    link,
    stream::{self, Identity},
    unix_seconds,
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

struct State {
    server_nonce: [u8; 16],
    stage: u8,
    negotiated: bool,
    active: bool,
    holding: bool,
    fence: bool,
    lanes: [Option<mpsc::Sender<Vec<u8>>>; 4],
    tokens: [Option<CancellationToken>; 4],
    retired: [bool; 4],
    fallback: [bool; 4],
    held: [VecDeque<Vec<u8>>; 4],
    bytes: usize,
    rejected: u64,
}
pub struct Group {
    identity: Identity,
    pub network: String,
    pub key: String,
    pub route: String,
    client_nonce: [u8; 16],
    issued: i64,
    client: bool,
    remote: SocketAddr,
    pin: String,
    state: Mutex<State>,
    negotiated_flag: AtomicBool,
    active_flag: AtomicBool,
    connections: AtomicUsize,
    rejected: AtomicU64,
    pub tx: mpsc::Sender<Vec<u8>>,
    primary: mpsc::Sender<Vec<u8>>,
    pub cancel: CancellationToken,
    engine: Weak<Engine>,
}
struct Locked<'a> {
    guard: MutexGuard<'a, State>,
    group: &'a Group,
}
impl std::ops::Deref for Locked<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        &self.guard
    }
}
impl std::ops::DerefMut for Locked<'_> {
    fn deref_mut(&mut self) -> &mut State {
        &mut self.guard
    }
}
impl Drop for Locked<'_> {
    fn drop(&mut self) {
        let s = &self.guard;
        self.group
            .negotiated_flag
            .store(s.negotiated, Ordering::Relaxed);
        self.group.active_flag.store(s.active, Ordering::Relaxed);
        self.group.connections.store(
            1 + [2, 3]
                .iter()
                .filter(|i| s.lanes[**i].is_some() && !s.retired[**i])
                .count(),
            Ordering::Relaxed,
        );
        self.group.rejected.store(s.rejected, Ordering::Relaxed);
    }
}
impl Group {
    pub fn mode(&self) -> &str {
        if self.identity.https { "https" } else { "tcp" }
    }
    fn lock_state(&self) -> Locked<'_> {
        Locked {
            guard: self.state.lock().unwrap(),
            group: self,
        }
    }
    pub fn client(
        engine: &Arc<Engine>,
        p: &Profile,
        route: &str,
        pipe: &Pipe,
        remote: SocketAddr,
    ) -> Result<Arc<Self>> {
        let peer = crate::runtime::remote_member(p).context("flow peer missing")?;
        let identity = Identity::new(p, p.member.slot, peer.slot)?;
        let group = Self::create(
            engine,
            identity,
            route,
            pipe,
            remote,
            true,
            c::random(),
            unix_seconds(),
            1,
        );
        group.control(1, 0);
        Ok(group)
    }
    pub fn server(
        engine: &Arc<Engine>,
        p: &Profile,
        route: &str,
        pipe: &Pipe,
        remote: SocketAddr,
        frame: &[u8],
    ) -> Result<Arc<Self>> {
        ensure!(
            stream::is_control(frame)
                && frame[5] == 1
                && frame[6] == 0
                && frame[25] == p.member.slot
                && frame[44..60] == [0; 16],
            "invalid stream offer"
        );
        let issued = i64::from_be_bytes(frame[60..68].try_into()?);
        ensure!(
            (unix_seconds() - issued).abs() <= 30,
            "expired stream offer"
        );
        let identity = Identity::new(p, frame[24], p.member.slot)?;
        let nonce = frame[28..44].try_into()?;
        ensure!(
            identity.valid(frame, 1, 0, false, &nonce, &[0; 16], issued),
            "stream offer MAC mismatch"
        );
        let group = Self::create(
            engine, identity, route, pipe, remote, false, nonce, issued, 2,
        );
        group.lock_state().server_nonce = c::random();
        group.control(2, 0);
        Ok(group)
    }
    fn create(
        engine: &Arc<Engine>,
        identity: Identity,
        route: &str,
        pipe: &Pipe,
        remote: SocketAddr,
        client: bool,
        client_nonce: [u8; 16],
        issued: i64,
        stage: u8,
    ) -> Arc<Self> {
        let (tx, mut incoming) = mpsc::channel(96);
        let group = Arc::new(Self {
            network: identity.network.clone(),
            identity,
            key: hex::encode(client_nonce),
            route: route.into(),
            client_nonce,
            issued,
            client,
            remote,
            pin: pipe.pin.clone(),
            negotiated_flag: AtomicBool::new(false),
            active_flag: AtomicBool::new(false),
            connections: AtomicUsize::new(1),
            rejected: AtomicU64::new(0),
            state: Mutex::new(State {
                server_nonce: [0; 16],
                stage,
                negotiated: false,
                active: false,
                holding: false,
                fence: false,
                lanes: [None, None, None, None],
                tokens: [None, None, None, None],
                retired: [false; 4],
                fallback: [false; 4],
                held: std::array::from_fn(|_| VecDeque::new()),
                bytes: 0,
                rejected: 0,
            }),
            tx,
            primary: pipe.tx.clone(),
            cancel: pipe.cancel.child_token(),
            engine: Arc::downgrade(engine),
        });
        let task = group.clone();
        engine.tracker.spawn(async move{loop{let frame=tokio::select!{_=task.cancel.cancelled()=>break,p=incoming.recv()=>match p{Some(p)=>p,None=>break}};let mut state=task.lock_state();task.enqueue(&mut state,frame);}task.close();});
        group
    }
    fn frame(&self, s: &State, kind: u8, lane: u8) -> Vec<u8> {
        self.identity.frame(
            kind,
            lane,
            !self.client,
            &self.client_nonce,
            &s.server_nonce,
            self.issued,
        )
    }
    fn valid(&self, s: &State, frame: &[u8], kind: u8, lane: u8) -> bool {
        self.identity.valid(
            frame,
            kind,
            lane,
            self.client,
            &self.client_nonce,
            &s.server_nonce,
            self.issued,
        )
    }
    fn send_control(&self, s: &State, kind: u8, lane: u8) {
        if self.primary.try_send(self.frame(s, kind, lane)).is_err() {
            self.cancel.cancel();
        }
    }
    fn control(&self, kind: u8, lane: u8) {
        self.send_control(&self.lock_state(), kind, lane)
    }
    fn ready(s: &State) -> bool {
        [2, 3]
            .iter()
            .all(|i| s.lanes[*i].is_some() && !s.retired[*i])
    }
    fn fence(&self, s: &mut State) {
        if !s.fence {
            s.fence = true;
            s.holding = true;
            self.send_control(s, 7, 0);
        }
    }
    fn enqueue(&self, s: &mut State, packet: Vec<u8>) {
        let lane = packet_lane(&packet);
        if lane != 0 && (s.holding || s.retired[lane] && !s.fallback[lane]) {
            if s.bytes + packet.len() > 196608 || lane == 3 && s.held[lane].len() >= 96 {
                s.rejected += 1;
                return;
            }
            s.bytes += packet.len();
            s.held[lane].push_back(packet);
            return;
        }
        let tx = if s.active && lane >= 2 && !s.fallback[lane] {
            s.lanes[lane].as_ref().unwrap_or(&self.primary)
        } else {
            &self.primary
        };
        if tx.try_send(packet).is_err() {
            s.rejected += 1;
        }
    }
    fn flush(&self, s: &mut State) {
        for lane in 1..=3 {
            for _ in 0..s.held[lane].len() {
                if let Some(packet) = s.held[lane].pop_front() {
                    s.bytes -= packet.len();
                    self.enqueue(s, packet);
                }
            }
        }
    }
    pub fn negotiated(&self) -> bool {
        self.negotiated_flag.load(Ordering::Relaxed) && !self.cancel.is_cancelled()
    }
    pub fn status(&self) -> Value {
        let connections = self.connections.load(Ordering::Relaxed);
        json!({"negotiated":self.negotiated(),"connections":connections,"splitActive":self.active_flag.load(Ordering::Relaxed)&&!self.cancel.is_cancelled()&&connections>1,"rejectedPackets":self.rejected.load(Ordering::Relaxed),"receiveRejectedPackets":0})
    }
    pub fn handle(self: &Arc<Self>, frame: &[u8]) -> bool {
        if !stream::is_control(frame) {
            return false;
        }
        let mut open = false;
        {
            let mut s = self.lock_state();
            if self.client && s.stage == 1 && frame[5] == 2 {
                let nonce: [u8; 16] = frame[44..60].try_into().unwrap();
                if self
                    .identity
                    .valid(frame, 2, 0, true, &self.client_nonce, &nonce, self.issued)
                {
                    s.server_nonce = nonce;
                    s.stage = 3;
                    self.send_control(&s, 3, 0);
                }
                return true;
            }
            if !self.client && s.stage == 2 && self.valid(&s, frame, 3, 0) {
                s.negotiated = true;
                s.stage = 4;
                self.send_control(&s, 4, 0);
                return true;
            }
            if self.client && s.stage == 3 && self.valid(&s, frame, 4, 0) {
                s.negotiated = true;
                s.stage = 4;
                open = true;
            } else if s.negotiated && self.valid(&s, frame, 7, 0) {
                if Self::ready(&s) {
                    self.fence(&mut s);
                    self.send_control(&s, 8, 0);
                }
                return true;
            } else if s.fence && self.valid(&s, frame, 8, 0) {
                s.active = true;
                s.holding = false;
                self.flush(&mut s);
                return true;
            } else if s.negotiated && matches!(frame[6], 2 | 3) {
                let lane = frame[6] as usize;
                if self.valid(&s, frame, 9, frame[6]) {
                    s.retired[lane] = true;
                    if let Some(token) = s.tokens[lane].take() {
                        token.cancel();
                    }
                    s.lanes[lane] = None;
                    self.send_control(&s, 10, frame[6]);
                    s.fallback[lane] = true;
                    self.flush(&mut s);
                    return true;
                }
                if s.retired[lane] && self.valid(&s, frame, 10, frame[6]) {
                    s.fallback[lane] = true;
                    self.flush(&mut s);
                    return true;
                }
            }
        }
        if open {
            if let Some(engine) = self.engine.upgrade() {
                for lane in [2, 3] {
                    let group = self.clone();
                    engine.tracker.spawn(async move {
                        let _ = group.open_aux(lane).await;
                        group.fail(lane);
                    });
                }
                let group = self.clone();
                engine.tracker.spawn(async move{tokio::select!{_=group.cancel.cancelled()=>{},_=tokio::time::sleep(Duration::from_secs(8))=>{let mut s=group.lock_state();if !s.fence{for lane in [2,3]{s.retired[lane]=true;s.fallback[lane]=true;if let Some(token)=s.tokens[lane].take(){token.cancel();}s.lanes[lane]=None;}group.flush(&mut s);}else if s.holding{group.cancel.cancel();}}}});
            }
        }
        true
    }
    async fn open_aux(self: &Arc<Self>, lane: usize) -> Result<()> {
        let engine = self.engine.upgrade().context("engine stopped")?;
        let mode = if self.identity.https { "https" } else { "tcp" };
        let mut pipe = transport::connect_role(
            mode,
            self.remote,
            &self.pin,
            0,
            (if self.client {
                self.identity.client
            } else {
                self.identity.server
            }) != 1,
            &engine.identity,
            &self.cancel,
        )
        .await?;
        let request = {
            let s = self.lock_state();
            self.frame(&s, 5, lane as u8)
        };
        pipe.tx.send(request).await?;
        let reply = tokio::time::timeout(Duration::from_secs(6), pipe.rx.recv())
            .await?
            .context("auxiliary closed")?;
        ensure!(
            self.valid(&self.lock_state(), &reply, 6, lane as u8),
            "auxiliary authentication failed"
        );
        self.attach(lane, &pipe)?;
        {
            let mut s = self.lock_state();
            if Self::ready(&s) {
                self.fence(&mut s);
            }
        }
        self.read_aux(&engine, &mut pipe, lane).await;
        Ok(())
    }
    fn attach(&self, lane: usize, pipe: &Pipe) -> Result<()> {
        let mut s = self.lock_state();
        ensure!(
            s.negotiated && matches!(lane, 2 | 3) && !s.retired[lane] && s.lanes[lane].is_none(),
            "auxiliary is stale or already attached"
        );
        s.lanes[lane] = Some(pipe.tx.clone());
        s.tokens[lane] = Some(pipe.cancel.clone());
        Ok(())
    }
    pub async fn accept_aux(
        self: &Arc<Self>,
        engine: &Arc<Engine>,
        mut pipe: Pipe,
        request: &[u8],
    ) -> Result<()> {
        let lane = request[6] as usize;
        ensure!(
            matches!(lane, 2 | 3) && self.valid(&self.lock_state(), request, 5, lane as u8),
            "invalid auxiliary session"
        );
        self.attach(lane, &pipe)?;
        let reply = {
            let s = self.lock_state();
            self.frame(&s, 6, lane as u8)
        };
        pipe.tx.send(reply).await?;
        self.read_aux(engine, &mut pipe, lane).await;
        self.fail(lane);
        Ok(())
    }
    async fn read_aux(&self, engine: &Arc<Engine>, pipe: &mut Pipe, lane: usize) {
        loop {
            let packet = tokio::select! {_=self.cancel.cancelled()=>break,_=pipe.cancel.cancelled()=>break,p=pipe.rx.recv()=>match p{Some(p)=>p,None=>break}};
            let s = self.lock_state();
            if s.retired[lane] || packet_lane(&packet) != lane {
                continue;
            }
            let Some((network, body)) = link::unwrap(&packet) else {
                continue;
            };
            if network != self.network {
                continue;
            }
            if let Some(running) = engine.find_wire(&network) {
                running.receive(body, &self.route, &engine.events);
            }
            drop(s);
        }
    }
    fn fail(&self, lane: usize) {
        if self.cancel.is_cancelled() {
            return;
        }
        let mut s = self.lock_state();
        if !s.retired[lane] {
            s.retired[lane] = true;
            s.lanes[lane] = None;
            if let Some(token) = s.tokens[lane].take() {
                token.cancel();
            }
            self.send_control(&s, 9, lane as u8);
        }
    }
    pub fn close(&self) {
        self.cancel.cancel();
        if let Some(engine) = self.engine.upgrade() {
            engine.flow_groups.lock().unwrap().remove(&self.key);
        }
        let mut s = self.lock_state();
        for token in s.tokens.iter_mut().filter_map(Option::take) {
            token.cancel();
        }
        s.held.iter_mut().for_each(VecDeque::clear);
    }
    #[cfg(test)]
    pub fn interrupt_lane(&self, lane: usize) {
        if let Some(token) = self.lock_state().tokens[lane].as_ref() {
            token.cancel();
        }
    }
}
pub fn packet_lane(frame: &[u8]) -> usize {
    if frame.len() >= 84
        && frame.starts_with(b"CNW1")
        && &frame[20..24] == b"SLM4"
        && frame[24] == 4
        && (1..=3).contains(&frame[27])
    {
        frame[27] as usize
    } else {
        0
    }
}
