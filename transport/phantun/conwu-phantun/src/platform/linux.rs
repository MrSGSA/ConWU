use crate::Config;
use fake_tcp::tun::TunDevice;
use std::{
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use tokio::io::unix::AsyncFd;

pub struct Device {
    receive: AsyncFd<OwnedFd>,
    transmit: AsyncFd<OwnedFd>,
}

fn fd(value: i32) -> io::Result<OwnedFd> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(value) })
    }
}

fn option<T>(socket: i32, level: i32, name: i32, value: &T) -> io::Result<()> {
    if unsafe {
        libc::setsockopt(
            socket,
            level,
            name,
            value as *const T as *const _,
            mem::size_of::<T>() as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl Device {
    pub fn open(config: &Config) -> io::Result<Self> {
        // SOCK_DGRAM at AF_PACKET exposes complete IP packets without Ethernet
        // headers, before the parent's owned kernel TCP-drop rule.
        let receive = fd(unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0x0800u16.to_be() as i32,
            )
        })?;
        let address = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as _,
            sll_protocol: 0x0800u16.to_be(),
            ..unsafe { mem::zeroed() }
        };
        if unsafe {
            libc::bind(
                receive.as_raw_fd(),
                &address as *const _ as *const _,
                mem::size_of_val(&address) as _,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        option(
            receive.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &(4i32 << 20),
        )?;
        let mut code = vec![];
        fn instruction(code: &mut Vec<libc::sock_filter>, op: u16, k: u32) {
            code.push(libc::sock_filter {
                code: op,
                jt: 0,
                jf: 0,
                k,
            });
        }
        fn equal(code: &mut Vec<libc::sock_filter>, expected: u32) {
            code.push(libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: expected,
            });
            instruction(code, 0x06, 0);
        }
        instruction(&mut code, 0x30, 9);
        equal(&mut code, libc::IPPROTO_TCP as u32);
        instruction(&mut code, 0x28, 6);
        code.push(libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: 0x3fff,
        });
        instruction(&mut code, 0x06, 0);
        instruction(&mut code, 0xb1, 0);
        instruction(&mut code, 0x48, 2);
        equal(&mut code, config.source.port() as u32);
        if !config.source.ip().is_unspecified() {
            instruction(&mut code, 0x20, 16);
            equal(&mut code, u32::from_be_bytes(config.source.ip().octets()));
        }
        if !config.server {
            instruction(&mut code, 0x20, 12);
            equal(&mut code, u32::from_be_bytes(config.remote.ip().octets()));
            instruction(&mut code, 0x48, 0);
            equal(&mut code, config.remote.port() as u32);
        }
        instruction(&mut code, 0x06, 65535);
        let program = libc::sock_fprog {
            len: code.len() as _,
            filter: code.as_mut_ptr(),
        };
        option(
            receive.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &program,
        )?;
        let transmit = fd(unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            )
        })?;
        option(
            transmit.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &1i32,
        )?;
        // OwnedFd is never replaced or closed through another handle while
        // registered. This upholds Tokio's explicit I/O lifetime contract.
        let receive = unsafe { AsyncFd::register(receive) }.map_err(io::Error::other)?;
        let transmit = unsafe { AsyncFd::register(transmit) }.map_err(io::Error::other)?;
        Ok(Self { receive, transmit })
    }

    fn inject(&self, buffer: &[u8]) -> io::Result<()> {
        if buffer.len() < 40 || buffer.len() > 1500 || buffer[0] >> 4 != 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Phantun IPv4 packet",
            ));
        }
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(buffer[16..20].try_into().unwrap()),
            },
            sin_zero: [0; 8],
        };
        let count = unsafe {
            libc::sendto(
                self.transmit.as_raw_fd(),
                buffer.as_ptr() as *const _,
                buffer.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                &address as *const _ as *const _,
                mem::size_of_val(&address) as _,
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count as usize != buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial Phantun raw send",
            ));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl TunDevice for Device {
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.receive.readable().await?;
            let packet = ready.try_io(|socket| {
                let mut source: libc::sockaddr_ll = unsafe { mem::zeroed() };
                let mut length = mem::size_of_val(&source) as libc::socklen_t;
                let count = unsafe {
                    libc::recvfrom(
                        socket.as_raw_fd(),
                        buffer.as_mut_ptr() as *mut _,
                        buffer.len(),
                        libc::MSG_DONTWAIT,
                        &mut source as *mut _ as *mut _,
                        &mut length,
                    )
                };
                if count < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok((count as usize, source.sll_pkttype))
            });
            match packet {
                Ok(Ok((size, kind))) if kind != libc::PACKET_OUTGOING => return Ok(size),
                Ok(Ok(_)) | Err(_) => continue,
                Ok(Err(error)) => return Err(error),
            }
        }
    }
    async fn send(&self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            match self.inject(buffer) {
                Ok(()) => return Ok(buffer.len()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut ready = self.transmit.writable().await?;
                    match ready.try_io(|_| self.inject(buffer)) {
                        Ok(result) => {
                            result?;
                            return Ok(buffer.len());
                        }
                        Err(_) => continue,
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn try_send(&self, buffer: &[u8]) -> io::Result<()> {
        self.inject(buffer)
    }
    fn name(&self) -> String {
        "LinuxRaw".into()
    }
}
