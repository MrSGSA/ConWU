use super::*;
use std::io;

struct Memory {
    send: flume::Sender<Vec<u8>>,
    receive: flume::Receiver<Vec<u8>>,
    fail_send: std::sync::atomic::AtomicBool,
    fail_try_send: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl TunDevice for Memory {
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let packet = self.receive.recv_async().await.map_err(io::Error::other)?;
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
    async fn send(&self, buffer: &[u8]) -> io::Result<usize> {
        if self.fail_send.swap(false, Ordering::Relaxed) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.send
            .send_async(buffer.to_vec())
            .await
            .map_err(io::Error::other)?;
        Ok(buffer.len())
    }
    fn try_send(&self, buffer: &[u8]) -> io::Result<()> {
        if self.fail_try_send.swap(false, Ordering::Relaxed) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.send
            .try_send(buffer.to_vec())
            .map_err(io::Error::other)
    }
    fn name(&self) -> String {
        "isolated-memory".into()
    }
}

fn pair() -> (Stack, Stack, flume::Sender<Vec<u8>>) {
    let (client, server, inject, _) = pair_with_device();
    (client, server, inject)
}

fn pair_with_device() -> (Stack, Stack, flume::Sender<Vec<u8>>, Arc<Memory>) {
    let (to_server, server_rx) = flume::bounded(2048);
    let (to_client, client_rx) = flume::bounded(2048);
    let client = Arc::new(Memory {
        send: to_server.clone(),
        receive: client_rx,
        fail_send: false.into(),
        fail_try_send: false.into(),
    });
    let server = Arc::new(Memory {
        send: to_client,
        receive: server_rx,
        fail_send: false.into(),
        fail_try_send: false.into(),
    });
    (
        Stack::new(vec![client], "192.0.2.1".parse().unwrap(), None),
        Stack::new(vec![server.clone()], "192.0.2.2".parse().unwrap(), None),
        to_server,
        server,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_peer_queue_does_not_block_another_peer() {
    let (mut client, mut server, _) = pair();
    server.listen(40002);
    let (busy, _unread) = connect(&mut client, &mut server, 42000).await;
    for _ in 0..512 {
        busy.send(b"unread").await.unwrap();
    }
    let (healthy, receiver) = connect(&mut client, &mut server, 42001).await;
    healthy.send(b"independent").await.unwrap();
    let mut buffer = [0u8; 1500];
    assert_eq!(
        time::timeout(time::Duration::from_secs(1), receiver.recv(&mut buffer))
            .await
            .unwrap(),
        Some(11)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_failure_is_reported_instead_of_leaving_a_silent_listener() {
    let (send, _receiver) = flume::unbounded();
    let (inject, receive) = flume::unbounded();
    drop(inject);
    let device = Arc::new(Memory {
        send,
        receive,
        fail_send: false.into(),
        fail_try_send: false.into(),
    });
    let stack = Stack::new(vec![device], "192.0.2.2".parse().unwrap(), None);
    // Subscribe after capture has had an opportunity to fail. The reason must
    // remain observable even when it preceded the component's select loop.
    time::sleep(time::Duration::from_millis(10)).await;
    let mut failures = stack.failures();
    let reason = time::timeout(
        time::Duration::from_secs(1),
        failures.wait_for(Option::is_some),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(reason.as_ref().is_some_and(|message| !message.is_empty()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn temporary_send_failures_do_not_kill_the_shared_listener() {
    let (mut client, mut server, inject, device) = pair_with_device();
    server.listen(40002);
    device.fail_try_send.store(true, Ordering::Relaxed);
    let unknown = build_tcp_packet(
        "192.0.2.1:43000".parse().unwrap(),
        "192.0.2.2:40002".parse().unwrap(),
        u32::MAX,
        0,
        tcp::TcpFlags::ACK,
        Some(b"wrap"),
    );
    inject.send_async(unknown.to_vec()).await.unwrap();
    time::sleep(time::Duration::from_millis(20)).await;
    device.fail_send.store(true, Ordering::Relaxed);
    assert!(
        time::timeout(
            time::Duration::from_secs(3),
            client.connect_from("192.0.2.2:40002".parse().unwrap(), 43001)
        )
        .await
        .unwrap()
        .is_none()
    );
    let (client, server) = connect(&mut client, &mut server, 43002).await;
    client.send(b"recovered").await.unwrap();
    let mut buffer = [0u8; 1500];
    assert_eq!(
        time::timeout(time::Duration::from_secs(1), server.recv(&mut buffer))
            .await
            .unwrap(),
        Some(9)
    );
}

async fn connect(client: &mut Stack, server: &mut Stack, port: u16) -> (Socket, Socket) {
    let result = time::timeout(time::Duration::from_secs(5), async {
        tokio::join!(
            client.connect_from("192.0.2.2:40002".parse().unwrap(), port),
            server.accept()
        )
    })
    .await
    .unwrap();
    (result.0.expect("fixed-port handshake"), result.1)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_input_does_not_stop_stack_and_payload_remains_datagram_oriented() {
    let (mut client, mut server, inject) = pair();
    server.listen(40002);
    for len in 0..40 {
        inject.send_async(vec![0x45; len]).await.unwrap();
    }
    let (client, server) = connect(&mut client, &mut server, 40001).await;
    let mut buffer = [0u8; 1500];
    for size in [1, 1152, 1280, 1460] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        client.send(&payload).await.unwrap();
        let size = time::timeout(time::Duration::from_secs(1), server.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..size], payload);
        server.send(&payload).await.unwrap();
        let size = time::timeout(time::Duration::from_secs(1), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..size], payload);
    }
    assert!(client.send(&[1; 1461]).await.is_none());
    client.send(b"after-rejection").await.unwrap();
    assert_eq!(server.recv(&mut buffer).await, Some(15));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simultaneous_closes_do_not_panic_purge_cache_or_prevent_tuple_reuse() {
    let (mut client, mut server, _) = pair();
    server.listen(40002);
    let mut sockets = vec![];
    for port in 41000..41024 {
        sockets.push(connect(&mut client, &mut server, port).await);
    }
    assert_eq!(client.shared.tuples.read().unwrap().len(), 24);
    drop(sockets);
    time::sleep(time::Duration::from_millis(30)).await;
    assert!(client.shared.tuples.read().unwrap().is_empty());
    assert!(server.shared.tuples.read().unwrap().is_empty());
    let (client, server) = connect(&mut client, &mut server, 41000).await;
    client.send(b"rejoined").await.unwrap();
    let mut buffer = [0u8; 1500];
    assert_eq!(
        time::timeout(time::Duration::from_secs(1), server.recv(&mut buffer))
            .await
            .unwrap(),
        Some(8)
    );
}

#[test]
fn parser_rejects_truncated_fragmented_and_oversized_packets_without_panics() {
    let valid = build_tcp_packet(
        "192.0.2.1:41000".parse().unwrap(),
        "192.0.2.2:40002".parse().unwrap(),
        1,
        1,
        tcp::TcpFlags::ACK,
        Some(b"payload"),
    );
    assert_eq!(parse_ip_packet(&valid).unwrap().1.payload(), b"payload");
    for end in 0..valid.len() {
        assert!(parse_ip_packet(&valid.slice(..end)).is_none());
    }
    let mut fragmented = valid.to_vec();
    fragmented[6] |= 0x20;
    assert!(parse_ip_packet(&Bytes::from(fragmented)).is_none());
    let mut options = valid[..20].to_vec();
    options[0] = 0x46;
    options[2..4].copy_from_slice(&((valid.len() + 4) as u16).to_be_bytes());
    options.extend_from_slice(&[1, 1, 1, 1]);
    options.extend_from_slice(&valid[20..]);
    let options = Bytes::from(options);
    assert_eq!(parse_ip_packet(&options).unwrap().1.payload(), b"payload");
    let mut seed = 17u64;
    for length in 0..1800 {
        let bytes = Bytes::from(
            (0..length)
                .map(|_| {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (seed >> 32) as u8
                })
                .collect::<Vec<_>>(),
        );
        if let Some((_, packet)) = parse_ip_packet(&bytes) {
            assert!(packet.payload().len() <= 1460);
        }
    }
}
