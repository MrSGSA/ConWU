use super::{
    burst::{BurstOptions, PreparedAnchor, PreparedBurst, bind_tcp, start_connect},
    handover::{DialOptions, dial_candidates, handover},
};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task, time,
};
use tokio_util::sync::CancellationToken;

const LOOPBACK: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
const TEST_TIMEOUT: Duration = Duration::from_secs(3);

async fn exchange(client: &mut TcpStream, server: &mut TcpStream) -> io::Result<()> {
    time::timeout(TEST_TIMEOUT, async {
        client.write_all(b"ping").await?;
        let mut bytes = [0; 4];
        server.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"ping");
        server.write_all(b"pong").await?;
        client.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"pong");
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn burst_connects_in_order_from_prebound_ports() -> io::Result<()> {
    let listeners = [
        TcpListener::bind(LOOPBACK).await?,
        TcpListener::bind(LOOPBACK).await?,
        TcpListener::bind(LOOPBACK).await?,
    ];
    let targets = listeners
        .each_ref()
        .map(|listener| match listener.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => unreachable!("listeners are IPv4"),
        });
    let (ports, started, burst) = task::spawn_blocking(move || -> io::Result<_> {
        let prepared = PreparedBurst::bind(BurstOptions {
            prefer_wide_delta_l: true,
            ..BurstOptions::default()
        })?;
        Ok((
            prepared.local_ports(),
            Instant::now(),
            prepared.connect(targets),
        ))
    })
    .await
    .map_err(io::Error::other)??;
    assert_eq!(burst.local_ports, ports);
    let (l1, l_mid, l2) = ports;
    assert!(l1 > 0 && l1 < l_mid && l_mid < l2);
    assert!(
        burst.connect_elapsed < Duration::from_millis(100),
        "{:?}",
        burst.connect_elapsed
    );

    let (mut first, mut middle, mut last) = time::timeout(TEST_TIMEOUT, async {
        tokio::try_join!(
            listeners[0].accept(),
            listeners[1].accept(),
            listeners[2].accept()
        )
    })
    .await??;
    for ((attempt, addr), port) in [
        (&burst.anchors.first, first.1),
        (&burst.middle, middle.1),
        (&burst.anchors.last, last.1),
    ]
    .into_iter()
    .zip([l1, l_mid, l2])
    {
        assert!(attempt.start_error.is_none(), "{:?}", attempt.start_error);
        assert_eq!(
            attempt.socket.local_addr()?.as_socket().unwrap().port(),
            port
        );
        assert_eq!(addr.port(), port);
    }

    task::spawn_blocking(move || burst.anchors.close_after_grace())
        .await
        .map_err(io::Error::other)?;
    assert!(started.elapsed() >= Duration::from_millis(150));
    let mut byte = [0];
    assert_eq!(
        time::timeout(TEST_TIMEOUT, first.0.read(&mut byte)).await??,
        0
    );
    assert_eq!(
        time::timeout(TEST_TIMEOUT, last.0.read(&mut byte)).await??,
        0
    );

    let mut peer = handover(
        burst.middle.into_socket()?,
        TEST_TIMEOUT,
        &CancellationToken::new(),
    )
    .await?;
    exchange(&mut peer, &mut middle.0).await
}

#[tokio::test]
async fn nonblocking_open_hands_over_with_bidirectional_io() -> io::Result<()> {
    let listener = TcpListener::bind(LOOPBACK).await?;
    let socket = bind_tcp(LOOPBACK, false)?;
    let local = socket.local_addr()?.as_socket().unwrap();
    start_connect(&socket, &listener.local_addr()?.into())?;

    let mut stream = handover(socket, TEST_TIMEOUT, &CancellationToken::new()).await?;
    let (mut server, peer) = time::timeout(TEST_TIMEOUT, listener.accept()).await??;
    assert_eq!(peer, local);
    assert_eq!(stream.peer_addr()?, listener.local_addr()?);
    exchange(&mut stream, &mut server).await
}

#[test]
fn formal_tcp_burst_reserves_three_consecutive_ports() -> io::Result<()> {
    let burst = PreparedBurst::bind(BurstOptions {
        local_ip: Ipv4Addr::LOCALHOST,
        ..Default::default()
    })?;
    let (first, middle, last) = burst.local_ports();
    assert_eq!((first + 1, middle + 1), (middle, last));
    for port in [first, middle, last] {
        assert!(bind_tcp(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port), false).is_err());
    }
    Ok(())
}

#[test]
fn fixed_carrier_anchors_use_the_next_neighbor_when_one_is_occupied() -> io::Result<()> {
    for _ in 0..16 {
        let middle = bind_tcp(LOOPBACK, false)?;
        let port = middle.local_addr()?.as_socket_ipv4().unwrap().port();
        if !(1026..=65533).contains(&port) {
            continue;
        }
        let local = |p| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, p));
        let Ok(occupied) = bind_tcp(local(port - 1), false) else { continue };
        let Ok(lower) = bind_tcp(local(port - 2), false) else { continue };
        let Ok(upper) = bind_tcp(local(port + 1), false) else { continue };
        drop((lower, upper));
        let [first, last] = PreparedAnchor::around(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), |_| true)?;
        assert_eq!((first.port(), last.port()), (port - 2, port + 1));
        assert!(bind_tcp(local(first.port()), false).is_err());
        assert!(bind_tcp(local(last.port()), false).is_err());
        drop((occupied, middle));
        return Ok(());
    }
    Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "could not reserve a loopback test block"))
}

#[tokio::test]
async fn refused_nonblocking_open_reports_its_socket_error() -> io::Result<()> {
    let unopened = bind_tcp(LOOPBACK, false)?;
    let socket = bind_tcp(LOOPBACK, false)?;
    let error = match start_connect(&socket, &unopened.local_addr()?) {
        Ok(()) => handover(socket, TEST_TIMEOUT, &CancellationToken::new())
            .await
            .unwrap_err(),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    let code = error.raw_os_error().expect("SO_ERROR must preserve errno");
    let target = unopened.local_addr()?.as_socket().unwrap();
    let reports = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let events = reports.clone();
    let dial = super::handover::dial_candidates_observed(&[target.port()], target.ip(), LOOPBACK,
        DialOptions::default(), &CancellationToken::new(), move |src,dst,stage,err| {
            if let Some(e) = err { events.lock().unwrap().push((src,dst,stage,e.raw_os_error())); }
        }).await.unwrap_err();
    assert_eq!(dial.raw_os_error(), Some(code));
    let events = reports.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_ne!(events[0].0.port(), 0);
    assert_eq!((events[0].1,events[0].3), (target,Some(code)));
    Ok(())
}

#[tokio::test]
async fn candidate_dial_skips_closed_ports_and_releases_attempts() -> io::Result<()> {
    let listener = TcpListener::bind(LOOPBACK).await?;
    let target = listener.local_addr()?;
    // Bound sockets without listen reserve reliably closed destination ports.
    let unopened = [
        bind_tcp(LOOPBACK, false)?,
        bind_tcp(LOOPBACK, false)?,
        bind_tcp(LOOPBACK, false)?,
    ];
    let ports = unopened
        .each_ref()
        .map(|socket| socket.local_addr().unwrap().as_socket().unwrap().port());
    let reservation = bind_tcp(LOOPBACK, false)?;
    let local = reservation.local_addr()?.as_socket().unwrap();
    drop(reservation);

    let options = DialOptions {
        reuse_address: true,
        ..DialOptions::default()
    };
    let started = Instant::now();
    let mut stream = dial_candidates(
        &[ports[0], ports[1], target.port(), ports[2]],
        target.ip(),
        local,
        options,
        &CancellationToken::new(),
    )
    .await?;
    assert!(started.elapsed() >= options.initial_delay + 2 * options.candidate_interval);
    assert_eq!(stream.peer_addr()?, target);
    let (mut server, source) = time::timeout(TEST_TIMEOUT, listener.accept()).await??;
    assert_eq!(source, local);
    exchange(&mut stream, &mut server).await?;

    // Initiate shutdown on the server so the client's fixed port can be rebound.
    time::timeout(TEST_TIMEOUT, async {
        server.shutdown().await?;
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await?, 0);
        drop(stream);
        assert_eq!(server.read(&mut byte).await?, 0);
        loop {
            match bind_tcp(local, false) {
                Ok(_) => return Ok::<(), io::Error>(()),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await?
}

#[tokio::test]
async fn candidate_wait_honors_cancellation_and_total_timeout() -> io::Result<()> {
    let listener = TcpListener::bind(LOOPBACK).await?;
    let target = listener.local_addr()?;
    let ports = [target.port()];
    let options = DialOptions {
        initial_delay: Duration::from_secs(1),
        ..DialOptions::default()
    };
    let cancel = CancellationToken::new();
    let (result, ()) = time::timeout(TEST_TIMEOUT, async {
        tokio::join!(
            dial_candidates(&ports, target.ip(), LOOPBACK, options, &cancel),
            async {
                time::sleep(Duration::from_millis(25)).await;
                cancel.cancel();
            }
        )
    })
    .await?;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);

    let options = DialOptions {
        timeout: Duration::from_millis(25),
        ..options
    };
    let result = dial_candidates(
        &ports,
        target.ip(),
        LOOPBACK,
        options,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(
        time::timeout(Duration::from_millis(25), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}
