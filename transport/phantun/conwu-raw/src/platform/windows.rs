// Mimic owns inbound packets; TCPRAW sniffs the kernel's handshake packets.
use crate::{Carrier, Config};
use fake_tcp::{packet::MAX_PACKET_LEN, tun::TunDevice};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use windivert::prelude::*;

pub struct Device {
    handle: Arc<WinDivert<NetworkLayer>>,
    received: flume::Receiver<Vec<u8>>,
    closing: Arc<AtomicBool>,
    _kernel_output: Option<WinDivert<NetworkLayer>>,
    mimic: bool,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Device {
    pub fn open(config: &Config) -> io::Result<Self> {
        let mimic = config.carrier == Carrier::Mimic;
        let peer_scope = config.peer_ip.map(|ip| format!(" and ip.SrcAddr == {ip}")).unwrap_or_default();
        let filter = if config.server {
            format!(
                "inbound and ip and tcp and tcp.DstPort == {}{}{peer_scope}",
                config.source.port(),
                if config.source.ip().is_unspecified() {
                    String::new()
                } else {
                    format!(" and ip.DstAddr == {}", config.source.ip())
                }
            )
        } else {
            format!(
                "inbound and ip and tcp and ip.SrcAddr == {} and ip.DstAddr == {}{} and tcp.DstPort == {}",
                config.remote.ip(),
                config.source.ip(),
                if config.peer_reflexive { String::new() } else { format!(" and tcp.SrcPort == {}",config.remote.port()) },
                config.source.port()
            )
        };
        let flags = if mimic { WinDivertFlags::default() } else { WinDivertFlags::default().set_sniff() };
        let exact = if config.server {
            format!("tcp.SrcPort == {}", config.source.port())
        } else {
            format!(
                "ip.SrcAddr == {} and ip.DstAddr == {} and tcp.SrcPort == {} and tcp.DstPort == {}",
                config.source.ip(),
                config.remote.ip(),
                config.source.port(),
                config.remote.port()
            )
        };
        let kernel_output = if mimic { None } else { Some(WinDivert::network(
            &format!("outbound and ip and tcp and ip.TTL == 1 and ({})", exact),
            -1,
            WinDivertFlags::default().set_drop(),
        )
        .map_err(io::Error::other)?) };
        let filter = if mimic {
            // Inbound ownership suppresses kernel SYN-ACK/RST. Also catch a
            // kernel RST for this owned local port, preserving protected STUN
            // packets in the worker instead of dropping their control flow.
            let reset_scope = if config.server { format!("tcp.SrcPort == {}{}{}", config.source.port(),
                if config.source.ip().is_unspecified() { String::new() } else { format!(" and ip.SrcAddr == {}", config.source.ip()) },
                config.peer_ip.map(|ip| format!(" and ip.DstAddr == {ip}")).unwrap_or_default())
            } else if config.peer_reflexive { format!("ip.SrcAddr == {} and ip.DstAddr == {} and tcp.SrcPort == {}",
                config.source.ip(), config.remote.ip(), config.source.port())
            } else { exact };
            format!("({filter}) or (outbound and ip and tcp and tcp.Rst and {reset_scope})")
        } else { filter };
        let handle = Arc::new(
            WinDivert::network(&filter, 0, flags)
                .map_err(|error| io::Error::other(format!("{}; filter={}", error, filter)))?,
        );
        handle
            .set_param(WinDivertParam::QueueLength, 4096)
            .map_err(io::Error::other)?;
        handle
            .set_param(WinDivertParam::QueueTime, 100)
            .map_err(io::Error::other)?;
        handle
            .set_param(WinDivertParam::QueueSize, 4 * 1024 * 1024)
            .map_err(io::Error::other)?;
        let (sender, received) = flume::bounded(512);
        let closing = Arc::new(AtomicBool::new(false));
        let capture = handle.clone();
        let quit = closing.clone();
        let protected = config.control_peer.clone();
        let worker = std::thread::Builder::new()
            .name("raw-carrier-capture".into())
            .spawn(move || {
                // A full IP buffer keeps oversized/malformed packets from ending
                // the capture worker. The protocol has a separate 1500-byte bound.
                let mut buffer = vec![0u8; 65535];
                while !quit.load(Ordering::Relaxed) {
                    match capture.recv_wait(&mut buffer, 100) {
                        Ok(Some(packet)) => {
                            let peer = *protected.read().unwrap();
                            if peer.is_some_and(|peer| {
                                let remote = if packet.address.outbound() {
                                    crate::packet::tcp_destination(&packet.data)
                                } else { crate::packet::tcp_remote(&packet.data) };
                                remote == Some(peer)
                            }) {
                                if mimic && let Err(error) = capture.send(&packet) {
                                    eprintln!("Mimic STUN control reinjection failed: {error}");
                                    break;
                                }
                                continue;
                            }
                            if mimic && packet.address.outbound() { continue; }
                            if packet.data.len() > MAX_PACKET_LEN {
                                continue;
                            }
                            match sender.try_send(packet.data.to_vec()) {
                                Ok(()) | Err(flume::TrySendError::Full(_)) => {}
                                Err(flume::TrySendError::Disconnected(_)) => break,
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            if !quit.load(Ordering::Relaxed) {
                                eprintln!("Raw carrier capture stopped: {}", error);
                            }
                            break;
                        }
                    }
                }
            })?;
        Ok(Self {
            handle,
            received,
            closing,
            _kernel_output: kernel_output,
            mimic,
            worker: Some(worker),
        })
    }

    fn inject(&self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_PACKET_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Raw carrier packet too large",
            ));
        }
        let mut packet = unsafe { WinDivertPacket::<NetworkLayer>::new(bytes.to_vec()) };
        packet.address.set_outbound(true);
        let injected = self.handle.send(&packet).map_err(io::Error::other)? as usize;
        if injected != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("WinDivert reported {injected} of {} injected bytes", bytes.len()),
            ));
        }
        Ok(injected)
    }
}

#[async_trait::async_trait]
impl TunDevice for Device {
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let packet = self
                .received
                .recv_async()
                .await
                .map_err(|_| io::Error::other("Raw carrier capture closed"))?;
            if packet.len() > buffer.len() {
                continue;
            }
            buffer[..packet.len()].copy_from_slice(&packet);
            return Ok(packet.len());
        }
    }
    async fn send(&self, buffer: &[u8]) -> io::Result<usize> {
        self.inject(buffer)
    }
    fn try_send(&self, buffer: &[u8]) -> io::Result<()> {
        self.inject(buffer).map(|_| ())
    }
    fn try_send_count(&self, buffer: &[u8]) -> io::Result<Option<usize>> {
        self.inject(buffer).map(Some)
    }
    fn name(&self) -> String {
        if self.mimic { "windivert-mimic" } else { "windivert-tcpraw" }.into()
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        self.closing.store(true, Ordering::Relaxed);
        let _ = self.handle.shutdown_handle().shutdown();
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}
