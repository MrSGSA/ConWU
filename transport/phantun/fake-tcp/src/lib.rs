//! A minimum, userspace TCP based datagram stack
//!
//! # Overview
//!
//! `fake-tcp` is a reusable library that implements a minimum TCP stack in
//! user space using the Tun interface. It allows programs to send datagrams
//! as if they are part of a TCP connection. `fake-tcp` has been tested to
//! be able to pass through a variety of NAT and stateful firewalls while
//! fully preserves certain desirable behavior such as out of order delivery
//! and no congestion/flow controls.
//!
//! # Core Concepts
//!
//! The core of the `fake-tcp` crate compose of two structures. [`Stack`] and
//! [`Socket`].
//!
//! ## [`Stack`]
//!
//! [`Stack`] represents a virtual TCP stack that operates at
//! Layer 3. It is responsible for:
//!
//! * TCP active and passive open and handshake
//! * `RST` handling
//! * Interact with the Tun interface at Layer 3
//! * Distribute incoming datagrams to corresponding [`Socket`]
//!
//! ## [`Socket`]
//!
//! [`Socket`] represents a TCP connection. It registers the identifying
//! tuple `(src_ip, src_port, dest_ip, dest_port)` inside the [`Stack`] so
//! so that incoming packets can be distributed to the right [`Socket`] with
//! using a channel. It is also what the client should use for
//! sending/receiving datagrams.
//!
//! # Examples
//!
//! Please see [`client.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/client.rs)
//! and [`server.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/server.rs) files
//! from the `phantun` crate for how to use this library in client/server mode, respectively.

#![cfg_attr(feature = "benchmark", feature(test))]

pub mod packet;
pub mod tun;

#[cfg(test)]
mod regression;

use bytes::{Bytes, BytesMut};
use log::{error, info, trace, warn};
use packet::*;
use pnet_packet::{Packet, tcp};
use rand::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU32, Ordering},
};
use tokio::sync::broadcast;
use tokio::sync::{mpsc, watch};
use tokio::time;
use tun::TunDevice;

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 512;
const MPSC_BUFFER_LEN: usize = 128;
const MAX_UNACKED_LEN: u32 = 128 * 1024 * 1024; // 128MB
const MAX_CONNECTIONS: usize = 64;
const MAX_CONNECTIONS_PER_IP: usize = 32;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct AddrTuple {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl AddrTuple {
    fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> AddrTuple {
        AddrTuple {
            local_addr,
            remote_addr,
        }
    }
}

struct Shared {
    tuples: RwLock<HashMap<AddrTuple, flume::Sender<Bytes>>>,
    listening: RwLock<HashSet<u16>>,
    tun: Vec<Arc<dyn TunDevice>>,
    ready: mpsc::Sender<Socket>,
    tuples_purge: broadcast::Sender<AddrTuple>,
    failure: watch::Sender<Option<String>>,
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    local_ip6: Option<Ipv6Addr>,
    ready: mpsc::Receiver<Socket>,
}

pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
}

pub struct Socket {
    shared: Arc<Shared>,
    tun: Arc<dyn TunDevice>,
    incoming: flume::Receiver<Bytes>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: AtomicU32,
    ack: AtomicU32,
    last_ack: AtomicU32,
    state: State,
}

/// A socket that represents a unique TCP connection between a server and client.
///
/// The `Socket` object itself satisfies `Sync` and `Send`, which means it can
/// be safely called within an async future.
///
/// To close a TCP connection that is no longer needed, simply drop this object
/// out of scope.
impl Socket {
    fn new(
        shared: Arc<Shared>,
        tun: Arc<dyn TunDevice>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        ack: Option<u32>,
        state: State,
    ) -> (Socket, flume::Sender<Bytes>) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);

        (
            Socket {
                shared,
                tun,
                incoming: incoming_rx,
                local_addr,
                remote_addr,
                seq: AtomicU32::new(0),
                ack: AtomicU32::new(ack.unwrap_or(0)),
                last_ack: AtomicU32::new(ack.unwrap_or(0)),
                state,
            },
            incoming_tx,
        )
    }

    fn build_tcp_packet(&self, flags: u8, payload: Option<&[u8]>) -> Bytes {
        let ack = self.ack.load(Ordering::Relaxed);
        self.last_ack.store(ack, Ordering::Relaxed);

        build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            ack,
            flags,
            payload,
        )
    }

    /// Sends a datagram to the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the Tun socket returned an error
    /// and this socket must be closed.
    pub async fn send(&self, payload: &[u8]) -> Option<()> {
        let overhead = if self.local_addr.is_ipv4() { 40 } else { 60 };
        if payload.len() > MAX_PACKET_LEN - overhead {
            return None;
        }
        match self.state {
            State::Established => {
                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, Some(payload));
                self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
                self.tun.send(&buf).await.ok().and(Some(()))
            }
            _ => unreachable!(),
        }
    }

    /// Attempt to receive a datagram from the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the TCP connection is broken
    /// and this socket must be closed.
    pub async fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        match self.state {
            State::Established => {
                self.incoming.recv_async().await.ok().and_then(|raw_buf| {
                    let (_, tcp_packet) = parse_ip_packet(&raw_buf)?;

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        // A delayed reset from a previous use of this tuple must
                        // not retire a newly established session.
                        if tcp_packet.get_sequence() != self.ack.load(Ordering::Relaxed) {
                            return Some(0);
                        }
                        info!("Connection {} reset by peer", self);
                        return None;
                    }

                    let payload = tcp_packet.payload();
                    if payload.len() > buf.len() {
                        return Some(0);
                    }

                    let new_ack = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
                    let last_ask = self.last_ack.load(Ordering::Relaxed);
                    self.ack.store(new_ack, Ordering::Relaxed);

                    if new_ack.overflowing_sub(last_ask).0 > MAX_UNACKED_LEN {
                        let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                        if let Err(e) = self.tun.try_send(&buf) {
                            // This should not really happen as we have not sent anything for
                            // quite some time...
                            info!("Connection {} unable to send idling ACK back: {}", self, e)
                        }
                    }

                    buf[..payload.len()].copy_from_slice(payload);

                    Some(payload.len())
                })
            }
            _ => unreachable!(),
        }
    }

    async fn accept(mut self) {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None);
                    // ACK set by constructor
                    if let Err(error) = self.tun.send(&buf).await {
                        warn!("Unable to send SYN+ACK: {}", error);
                        return;
                    }
                    self.state = State::SynReceived;
                    info!("Sent SYN + ACK to client");
                }
                State::SynReceived => {
                    let res = time::timeout(TIMEOUT, self.incoming.recv_async()).await;
                    if let Ok(buf) = res {
                        let Ok(buf) = buf else {
                            return;
                        };
                        let Some((_, tcp_packet)) = parse_ip_packet(&buf) else {
                            continue;
                        };

                        if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                            return;
                        }

                        if tcp_packet.get_flags() == tcp::TcpFlags::ACK
                            && tcp_packet.get_acknowledgement()
                                == self.seq.load(Ordering::Relaxed).wrapping_add(1)
                        {
                            // found our ACK
                            self.seq.fetch_add(1, Ordering::Relaxed);
                            self.state = State::Established;

                            info!("Connection from {:?} established", self.remote_addr);
                            let ready = self.shared.ready.clone();
                            if let Err(e) = ready.send(self).await {
                                error!("Unable to send accepted socket to ready queue: {}", e);
                            }
                            return;
                        }
                    } else {
                        info!("Waiting for client ACK timed out");
                        self.state = State::Idle;
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    async fn connect(&mut self) -> Option<()> {
        for retry in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN, None);
                    info!(
                        "[connect] Retry {}/{}: Sending SYN from {} to {} (seq={})",
                        retry + 1,
                        RETRIES,
                        self.local_addr,
                        self.remote_addr,
                        self.seq.load(Ordering::Relaxed)
                    );
                    if let Err(e) = self.tun.send(&buf).await {
                        error!("[connect] Failed to send SYN through TUN: {}", e);
                        return None;
                    }
                    self.state = State::SynSent;
                    info!("[connect] SYN sent, waiting for SYN+ACK...");
                }
                State::SynSent => {
                    info!("[connect] Waiting for SYN+ACK (timeout={:?})...", TIMEOUT);
                    match time::timeout(TIMEOUT, self.incoming.recv_async()).await {
                        Ok(buf) => {
                            let Ok(buf) = buf else {
                                return None;
                            };
                            let Some((ip_packet, tcp_packet)) = parse_ip_packet(&buf) else {
                                continue;
                            };
                            let flags = tcp_packet.get_flags();
                            info!(
                                "[connect] Received packet from {} to {} flags=0x{:02x} seq={} ack={}",
                                ip_packet.get_source(),
                                ip_packet.get_destination(),
                                flags,
                                tcp_packet.get_sequence(),
                                tcp_packet.get_acknowledgement()
                            );

                            if (flags & tcp::TcpFlags::RST) != 0 {
                                info!("[connect] Received RST from server, connection rejected");
                                return None;
                            }

                            let expected_ack = self.seq.load(Ordering::Relaxed).wrapping_add(1);
                            if flags == (tcp::TcpFlags::SYN | tcp::TcpFlags::ACK)
                                && tcp_packet.get_acknowledgement() == expected_ack
                            {
                                info!(
                                    "[connect] Got valid SYN+ACK (ack={} matches expected {}), sending ACK",
                                    tcp_packet.get_acknowledgement(),
                                    expected_ack
                                );
                                self.seq.fetch_add(1, Ordering::Relaxed);
                                self.ack.store(
                                    tcp_packet.get_sequence().wrapping_add(1),
                                    Ordering::Relaxed,
                                );

                                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                                if let Err(e) = self.tun.send(&buf).await {
                                    error!("[connect] Failed to send final ACK: {}", e);
                                    return None;
                                }
                                self.state = State::Established;
                                info!("Connection to {:?} established", self.remote_addr);
                                return Some(());
                            } else {
                                info!(
                                    "[connect] Unexpected packet: flags=0x{:02x} (expected SYN+ACK=0x{:02x}), ack={} (expected {})",
                                    flags,
                                    tcp::TcpFlags::SYN | tcp::TcpFlags::ACK,
                                    tcp_packet.get_acknowledgement(),
                                    expected_ack
                                );
                            }
                        }
                        Err(_) => {
                            info!("[connect] Timeout waiting for SYN+ACK, will retry");
                            self.state = State::Idle;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        error!(
            "[connect] All {} retries exhausted, fake TCP connection failed",
            RETRIES
        );
        None
    }
}

impl Drop for Socket {
    /// Drop the socket and close the TCP connection
    fn drop(&mut self) {
        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        // dissociates ourself from the dispatch map
        assert!(self.shared.tuples.write().unwrap().remove(&tuple).is_some());
        // purge cache
        let _ = self.shared.tuples_purge.send(tuple);

        let buf = build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            0,
            tcp::TcpFlags::RST,
            None,
        );
        if let Err(e) = self.tun.try_send(&buf) {
            warn!("Unable to send RST to remote end: {}", e);
        }

        info!("Fake TCP connection to {} closed", self);
    }
}

impl fmt::Display for Socket {
    /// User-friendly string representation of the socket
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Fake TCP connection from {} to {})",
            self.local_addr, self.remote_addr
        )
    }
}

/// A userspace TCP state machine
impl Stack {
    /// Create a new stack, `tun` is an array of [`TunDevice`](tun::TunDevice).
    pub fn new(
        tun: Vec<Arc<dyn TunDevice>>,
        local_ip: Ipv4Addr,
        local_ip6: Option<Ipv6Addr>,
    ) -> Stack {
        let (ready_tx, ready_rx) = mpsc::channel(MPSC_BUFFER_LEN);
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let (failure, _) = watch::channel(None);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            tun: tun.clone(),
            listening: RwLock::new(HashSet::new()),
            ready: ready_tx,
            tuples_purge: tuples_purge_tx.clone(),
            failure,
        });

        for t in tun {
            tokio::spawn(Stack::reader_task(
                t,
                shared.clone(),
                tuples_purge_tx.subscribe(),
            ));
        }

        Stack {
            shared,
            local_ip,
            local_ip6,
            ready: ready_rx,
        }
    }

    /// A lost capture device is fatal to this carrier, not a silent listener.
    pub fn failures(&self) -> watch::Receiver<Option<String>> {
        self.shared.failure.subscribe()
    }

    /// Listens for incoming connections on the given `port`.
    pub fn listen(&mut self, port: u16) {
        assert!(self.shared.listening.write().unwrap().insert(port));
    }

    /// Accepts an incoming connection.
    pub async fn accept(&mut self) -> Socket {
        self.ready.recv().await.unwrap()
    }

    /// Connects to the remote end. `None` returned means
    /// the connection attempt failed.
    pub async fn connect(&mut self, addr: SocketAddr) -> Option<Socket> {
        let mut rng = SmallRng::from_os_rng();
        for local_port in rng.random_range(32768..=60999)..=60999 {
            let local_addr = SocketAddr::new(
                if addr.is_ipv4() {
                    IpAddr::V4(self.local_ip)
                } else {
                    IpAddr::V6(self.local_ip6.expect("IPv6 local address undefined"))
                },
                local_port,
            );
            let tuple = AddrTuple::new(local_addr, addr);
            let mut sock;

            {
                let mut tuples = self.shared.tuples.write().unwrap();
                if tuples.contains_key(&tuple) {
                    trace!(
                        "Fake TCP connection to {}, local port number {} already in use, trying another one",
                        addr, local_port
                    );
                    continue;
                }

                let incoming;
                (sock, incoming) = Socket::new(
                    self.shared.clone(),
                    self.shared.tun.choose(&mut rng).unwrap().clone(),
                    local_addr,
                    addr,
                    None,
                    State::Idle,
                );

                assert!(tuples.insert(tuple, incoming).is_none());
            }

            return sock.connect().await.map(|_| sock);
        }

        error!(
            "Fake TCP connection to {} failed, emphemeral port number exhausted",
            addr
        );
        None
    }

    /// Connect using the source port held exclusively by the ConWU parent.
    /// This never allocates a second kernel TCP socket or changes a NAT helper.
    pub async fn connect_from(&mut self, addr: SocketAddr, port: u16) -> Option<Socket> {
        if port == 0 || !addr.is_ipv4() {
            return None;
        }
        let local = SocketAddr::new(IpAddr::V4(self.local_ip), port);
        let tuple = AddrTuple::new(local, addr);
        let mut socket = {
            let mut tuples = self.shared.tuples.write().unwrap();
            if tuples.len() >= MAX_CONNECTIONS || tuples.contains_key(&tuple) {
                return None;
            }
            let (socket, incoming) = Socket::new(
                self.shared.clone(),
                self.shared.tun[0].clone(),
                local,
                addr,
                None,
                State::Idle,
            );
            tuples.insert(tuple, incoming);
            socket
        };
        socket.connect().await.map(|_| socket)
    }

    async fn reader_task(
        tun: Arc<dyn TunDevice>,
        shared: Arc<Shared>,
        mut tuples_purge: broadcast::Receiver<AddrTuple>,
    ) {
        let mut tuples: HashMap<AddrTuple, flume::Sender<Bytes>> = HashMap::new();

        loop {
            let mut buf = BytesMut::zeroed(MAX_PACKET_LEN);

            tokio::select! {
                size = tun.recv(&mut buf) => {
                    let size = match size {
                        Ok(size) => size,
                        Err(error) => {
                            shared.failure.send_replace(Some(error.to_string()));
                            return;
                        },
                    };
                    buf.truncate(size);
                    let buf = buf.freeze();

                    match parse_ip_packet(&buf) {
                        Some((ip_packet, tcp_packet)) => {
                            let local_addr =
                                SocketAddr::new(ip_packet.get_destination(), tcp_packet.get_destination());
                            let remote_addr = SocketAddr::new(ip_packet.get_source(), tcp_packet.get_source());

                            let tuple = AddrTuple::new(local_addr, remote_addr);
                            if let Some(c) = tuples.get(&tuple) {
                                // This is a datagram carrier. A stalled peer
                                // must not block capture for every other peer.
                                let _ = c.try_send(buf);
                                continue;
                            } else {
                                trace!("Cache miss, checking the shared tuples table for connection");
                                let sender = {
                                    let tuples = shared.tuples.read().unwrap();
                                    tuples.get(&tuple).cloned()
                                };

                                if let Some(c) = sender {
                                    trace!("Storing connection information into local tuples");
                                    tuples.insert(tuple, c.clone());
                                    // Closing a peer can race this lookup.
                                    let _ = c.try_send(buf);
                                    continue;
                                }
                            }

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN
                                && shared
                                    .listening
                                    .read()
                                    .unwrap()
                                    .contains(&tcp_packet.get_destination())
                            {
                                // SYN seen on listening socket
                                if tcp_packet.get_sequence() == 0 {
                                    let mut tuples = shared.tuples.write().unwrap();
                                    if tuples.len() >= MAX_CONNECTIONS
                                        || tuples.keys().filter(|t| t.remote_addr.ip() == remote_addr.ip()).count() >= MAX_CONNECTIONS_PER_IP
                                        || tuples.contains_key(&tuple) {
                                        continue;
                                    }
                                    let (sock, incoming) = Socket::new(
                                        shared.clone(),
                                        tun.clone(),
                                        local_addr,
                                        remote_addr,
                                        Some(tcp_packet.get_sequence().wrapping_add(1)),
                                        State::Idle,
                                    );
                                    tuples.insert(tuple, incoming);
                                    drop(tuples);
                                    tokio::spawn(sock.accept());
                                } else {
                                    trace!("Bad TCP SYN packet from {}, sending RST", remote_addr);
                                    let buf = build_tcp_packet(
                                        local_addr,
                                        remote_addr,
                                        0,
                                        tcp_packet.get_sequence().wrapping_add(tcp_packet.payload().len() as u32).wrapping_add(1),
                                        tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                        None,
                                    );
                                    let _ = shared.tun[0].try_send(&buf);
                                }
                            } else if (tcp_packet.get_flags() & tcp::TcpFlags::RST) == 0 {
                                info!("Unknown TCP packet from {}, sending RST", remote_addr);
                                let buf = build_tcp_packet(
                                    local_addr,
                                    remote_addr,
                                    tcp_packet.get_acknowledgement(),
                                    tcp_packet.get_sequence().wrapping_add(tcp_packet.payload().len() as u32),
                                    tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                    None,
                                );
                                let _ = shared.tun[0].try_send(&buf);
                            }
                        }
                        None => {
                            continue;
                        }
                    }
                },
                tuple = tuples_purge.recv() => {
                    match tuple {
                        Ok(tuple) => { tuples.remove(&tuple); },
                        // Several network exits may exceed the broadcast ring.
                        // The shared map remains authoritative; rebuild caches.
                        Err(broadcast::error::RecvError::Lagged(_)) => tuples.clear(),
                        Err(broadcast::error::RecvError::Closed) => return,
                    }
                }
            }
        }
    }
}
