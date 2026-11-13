use crate::Config;
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
}

impl Device {
    pub fn open(config: &Config) -> io::Result<Self> {
        let filter = if config.server {
            format!(
                "inbound and ip and tcp and tcp.DstPort == {}{}",
                config.source.port(),
                if config.source.ip().is_unspecified() {
                    String::new()
                } else {
                    format!(" and ip.DstAddr == {}", config.source.ip())
                }
            )
        } else {
            format!(
                "inbound and ip and tcp and ip.SrcAddr == {} and ip.DstAddr == {} and tcp.SrcPort == {} and tcp.DstPort == {}",
                config.remote.ip(),
                config.source.ip(),
                config.remote.port(),
                config.source.port()
            )
        };
        let handle = Arc::new(
            WinDivert::network(&filter, 0, WinDivertFlags::default()).map_err(io::Error::other)?,
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
        std::thread::Builder::new()
            .name("phantun-capture".into())
            .spawn(move || {
                // A full IP buffer keeps oversized/malformed packets from ending
                // the capture worker. The protocol has a separate 1500-byte bound.
                let mut buffer = vec![0u8; 65535];
                while !quit.load(Ordering::Relaxed) {
                    match capture.recv_wait(&mut buffer, 100) {
                        Ok(Some(packet)) if packet.data.len() <= MAX_PACKET_LEN => {
                            match sender.try_send(packet.data.to_vec()) {
                                Ok(()) | Err(flume::TrySendError::Full(_)) => {}
                                Err(flume::TrySendError::Disconnected(_)) => break,
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            if !quit.load(Ordering::Relaxed) {
                                eprintln!("Phantun capture stopped: {}", error);
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
        })
    }

    fn inject(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > MAX_PACKET_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Phantun packet too large",
            ));
        }
        let mut packet = unsafe { WinDivertPacket::<NetworkLayer>::new(bytes.to_vec()) };
        packet.address.set_outbound(true);
        self.handle.send(&packet).map_err(io::Error::other)?;
        Ok(())
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
                .map_err(|_| io::Error::other("Phantun capture closed"))?;
            if packet.len() > buffer.len() {
                continue;
            }
            buffer[..packet.len()].copy_from_slice(&packet);
            return Ok(packet.len());
        }
    }
    async fn send(&self, buffer: &[u8]) -> io::Result<usize> {
        self.inject(buffer)?;
        Ok(buffer.len())
    }
    fn try_send(&self, buffer: &[u8]) -> io::Result<()> {
        self.inject(buffer)
    }
    fn name(&self) -> String {
        "WinDivert".into()
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        self.closing.store(true, Ordering::Relaxed);
        let _ = self.handle.shutdown_handle().shutdown();
    }
}
