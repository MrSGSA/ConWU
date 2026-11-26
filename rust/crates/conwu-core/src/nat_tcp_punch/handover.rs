//! Wait for a native TCP connect before registering the stream with Tokio.

use super::burst::{bind_tcp, start_connect};
use socket2::Socket;
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, SocketAddr},
    thread,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, runtime::Handle};
use tokio_util::sync::CancellationToken;

const POLL_SLICE: Duration = Duration::from_millis(20);

/// Block until a connect has completed and the socket has a confirmed peer.
pub fn wait_established(
    socket: &Socket,
    timeout: Duration,
    cancel: &CancellationToken,
) -> io::Result<()> {
    let started = Instant::now();
    loop {
        check_cancel(cancel)?;
        let wait = timeout.saturating_sub(started.elapsed()).min(POLL_SLICE);
        let ready = wait_ready(std::slice::from_ref(socket), wait)?;
        check_cancel(cancel)?;
        if !ready.is_empty() {
            return confirm_peer(socket);
        }
        if started.elapsed() >= timeout {
            return Err(connect_timeout());
        }
    }
}

/// Transfer a socket after its nonblocking connect succeeds. The calling Tokio
/// runtime supplies the blocking worker and the I/O driver for the stream.
pub async fn handover(
    socket: Socket,
    timeout: Duration,
    cancel: &CancellationToken,
) -> io::Result<TcpStream> {
    on_socket_worker(cancel, move |cancel| {
        wait_established(&socket, timeout, cancel)?;
        into_tokio(socket)
    })
    .await
}

#[derive(Clone, Copy, Debug)]
pub struct DialOptions {
    pub initial_delay: Duration,
    pub candidate_interval: Duration,
    pub timeout: Duration,
    pub reuse_address: bool,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(25),
            candidate_interval: Duration::from_millis(15),
            timeout: Duration::from_millis(2500),
            reuse_address: false,
        }
    }
}

/// Race candidates in rank order with a delay between successive opens.
/// A fixed local port can have overlapping attempts when address reuse is
/// enabled and supported by the local stack. The winner owns the only socket
/// returned to the caller.
pub async fn dial_candidates(
    candidates: &[u16],
    peer_ip: IpAddr,
    local: SocketAddr,
    options: DialOptions,
    cancel: &CancellationToken,
) -> io::Result<TcpStream> {
    dial_candidates_observed(candidates, peer_ip, local, options, cancel, |_, _, _, _| {}).await
}

/// Reports socket operations only. A pending connect does not prove a SYN reached the wire.
pub async fn dial_candidates_observed(
    candidates: &[u16],
    peer_ip: IpAddr,
    local: SocketAddr,
    options: DialOptions,
    cancel: &CancellationToken,
    observe: impl Fn(SocketAddr, SocketAddr, &'static str, Option<&io::Error>) + Send + 'static,
) -> io::Result<TcpStream> {
    if peer_ip.is_unspecified() || peer_ip.is_ipv4() != local.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid peer or local address family",
        ));
    }
    let mut seen = HashSet::new();
    let ports: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|&port| port != 0 && seen.insert(port))
        .collect();
    if ports.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no TCP candidate ports",
        ));
    }

    let started = Instant::now();
    on_socket_worker(cancel, move |cancel| {
        dial_on_worker(ports, peer_ip, local, options, started, cancel, observe)
    })
    .await
}

fn dial_on_worker(
    ports: Vec<u16>,
    peer_ip: IpAddr,
    local: SocketAddr,
    options: DialOptions,
    started: Instant,
    cancel: &CancellationToken,
    observe: impl Fn(SocketAddr, SocketAddr, &'static str, Option<&io::Error>),
) -> io::Result<TcpStream> {
    let mut ports = ports.into_iter().peekable();
    let mut pending = Vec::new();
    let mut endpoints = Vec::new();
    let mut next_launch = options.initial_delay;
    let mut last_error = None;
    let can_share_local = local.port() == 0 || options.reuse_address;

    loop {
        check_cancel(cancel)?;
        let elapsed = started.elapsed();
        if elapsed >= options.timeout {
            for &(source, target) in &endpoints {
                observe(source, target, "deadline", None);
            }
            return Err(last_error.unwrap_or_else(connect_timeout));
        }
        if elapsed >= next_launch
            && (can_share_local || pending.is_empty())
            && let Some(port) = ports.next()
        {
            let target = SocketAddr::new(peer_ip, port);
            match bind_tcp(local, options.reuse_address) {
                Err(error) => {
                    observe(local, target, "bind_failed", Some(&error));
                    last_error = Some(error);
                }
                Ok(socket) => {
                    let source = socket.local_addr()?.as_socket().unwrap_or(local);
                    observe(source, target, "connect", None);
                    match start_connect(&socket, &target.into()) {
                        Ok(()) => {
                            pending.push(socket);
                            endpoints.push((source, target));
                        }
                        Err(error) => {
                            observe(source, target, "connect_failed", Some(&error));
                            last_error = Some(error);
                        }
                    }
                }
            }
            next_launch = started.elapsed().saturating_add(options.candidate_interval);
        }

        if pending.is_empty() && ports.peek().is_none() {
            return Err(last_error.unwrap_or_else(|| io::Error::from(io::ErrorKind::NotConnected)));
        }
        let elapsed = started.elapsed();
        let mut wait = options.timeout.saturating_sub(elapsed).min(POLL_SLICE);
        if ports.peek().is_some() && (can_share_local || pending.is_empty()) {
            wait = wait.min(next_launch.saturating_sub(elapsed));
        }
        if pending.is_empty() {
            thread::sleep(wait);
            continue;
        }

        let ready = wait_ready(&pending, wait)?;
        check_cancel(cancel)?;
        // Readiness indices are in rank order. Removing a socket shifts the
        // later indices, and returning drops all attempts still in the vector.
        for (removed, index) in ready.into_iter().enumerate() {
            let socket = pending.remove(index - removed);
            let (source, target) = endpoints.remove(index - removed);
            match confirm_peer(&socket).and_then(|()| into_tokio(socket)) {
                Ok(connected) => {
                    observe(source, target, "established", None);
                    for &(source, target) in &endpoints {
                        observe(source, target, "another_candidate_won", None);
                    }
                    return Ok(connected);
                }
                Err(error) => {
                    observe(source, target, "socket_failed", Some(&error));
                    last_error = Some(error);
                }

            }
        }
    }
}

fn confirm_peer(socket: &Socket) -> io::Result<()> {
    if let Some(error) = socket.take_error()? {
        return Err(error);
    }
    socket.peer_addr()?.as_socket().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotConnected,
            "TCP connect has no peer address",
        )
    })?;
    Ok(())
}

fn into_tokio(socket: Socket) -> io::Result<TcpStream> {
    let stream: std::net::TcpStream = socket.into();
    stream.set_nonblocking(true)?;
    TcpStream::from_std(stream)
}

async fn on_socket_worker<T: Send + 'static>(
    cancel: &CancellationToken,
    run: impl FnOnce(&CancellationToken) -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    check_cancel(cancel)?;
    let runtime = Handle::try_current().map_err(io::Error::other)?;
    let token = cancel.child_token();
    // A dropped caller future stops its worker without cancelling siblings.
    let _cancel_on_drop = token.clone().drop_guard();
    runtime
        .spawn_blocking(move || run(&token))
        .await
        .map_err(io::Error::other)?
}

fn check_cancel(cancel: &CancellationToken) -> io::Result<()> {
    if cancel.is_cancelled() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "TCP connect cancelled",
        ))
    } else {
        Ok(())
    }
}

fn connect_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out")
}

#[cfg(unix)]
fn wait_ready(sockets: &[Socket], timeout: Duration) -> io::Result<Vec<usize>> {
    use std::os::fd::AsRawFd;

    let mut fds: Vec<_> = sockets
        .iter()
        .map(|socket| libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        })
        .collect();
    let millis = timeout.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
    // SAFETY: The live sockets and initialized pollfd array outlive the call.
    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(Vec::new());
        }
        return Err(error);
    }
    // Error and hangup events also complete the connect attempt.
    Ok(fds
        .iter()
        .enumerate()
        .filter_map(|(index, fd)| (fd.revents != 0).then_some(index))
        .collect())
}

#[cfg(windows)]
fn wait_ready(sockets: &[Socket], timeout: Duration) -> io::Result<Vec<usize>> {
    use std::{os::windows::io::AsRawSocket, ptr};
    use windows_sys::Win32::Networking::WinSock::{
        FD_SET, FD_SETSIZE, SOCKET_ERROR, TIMEVAL, WSAEINTR, WSAGetLastError, select,
    };

    let capacity = FD_SETSIZE as usize;
    let mut ready = Vec::new();
    // Winsock uses fixed-size sets. Spend the wait budget once per pass.
    for (batch, sockets) in sockets.chunks(capacity).enumerate() {
        let mut writable = FD_SET {
            fd_count: sockets.len() as u32,
            ..FD_SET::default()
        };
        for (handle, socket) in writable.fd_array.iter_mut().zip(sockets) {
            *handle = socket.as_raw_socket() as usize;
        }
        let mut failed = writable;
        let wait = if batch == 0 { timeout } else { Duration::ZERO };
        let time = TIMEVAL {
            tv_sec: wait.as_secs().min(i32::MAX as u64) as i32,
            tv_usec: wait.subsec_micros() as i32,
        };
        // SAFETY: Both sets contain live Winsock sockets and have valid counts.
        // A failed nonblocking connect is reported in the exception set.
        if unsafe { select(0, ptr::null_mut(), &mut writable, &mut failed, &time) } == SOCKET_ERROR
        {
            // SAFETY: Read the calling thread's Winsock error immediately.
            let code = unsafe { WSAGetLastError() };
            if code == WSAEINTR {
                return Ok(ready);
            }
            return Err(io::Error::from_raw_os_error(code));
        }
        let writable = &writable.fd_array[..writable.fd_count as usize];
        let failed = &failed.fd_array[..failed.fd_count as usize];
        for (index, socket) in sockets.iter().enumerate() {
            let handle = socket.as_raw_socket() as usize;
            if writable.contains(&handle) || failed.contains(&handle) {
                ready.push(batch * capacity + index);
            }
        }
    }
    Ok(ready)
}
