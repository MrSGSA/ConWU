use anyhow::{Context, Result, ensure};
use conwu_core::{code::stream_mode, crypto as c};
use futures_util::{SinkExt, StreamExt};
use rustls::{
    ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        http::{HeaderValue, Request, Response},
    },
};
use tokio_util::sync::CancellationToken;
use x509_parser::prelude::{FromDer, X509Certificate};

const MAX: usize = 2048;
fn websocket_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    let mut c = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
    c.max_message_size = Some(16384);
    c.max_frame_size = Some(16384);
    c.read_buffer_size = 16384;
    c.write_buffer_size = 0;
    c.max_write_buffer_size = 65536;
    c
}
pub fn pinned_http(pin: &str) -> Result<reqwest::Client> {
    pinned_http_bootstrap(pin, false, None)
}
pub fn pinned_http_bootstrap(
    pin: &str,
    bootstrap: bool,
    resolve: Option<(&str, &[SocketAddr])>,
) -> Result<reqwest::Client> {
    if pin.is_empty() && !bootstrap && resolve.is_none() {
        return crate::discovery::http_client();
    }
    ensure!(
        pin.is_empty() || pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit()),
        "协调服务器证书指纹无效"
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier {
            pin: pin.into(),
            bootstrap,
            whole_certificate: true,
            provider,
            first_pin: bootstrap.then(|| std::sync::Mutex::new(None)),
        }))
        .with_no_client_auth();
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8));
    if !pin.is_empty() || bootstrap {
        builder = builder.use_preconfigured_tls(config);
    }
    if let Some((host, addresses)) = resolve {
        builder = builder.resolve_to_addrs(host, addresses);
    }
    Ok(builder.build()?)
}
pub struct Pipe {
    pub tx: mpsc::Sender<Vec<u8>>,
    pub rx: mpsc::Receiver<Vec<u8>>,
    pub cancel: CancellationToken,
    pub pin: String,
}
impl Drop for Pipe {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
#[derive(Clone)]
pub struct TlsIdentity {
    pub server: Arc<ServerConfig>,
    pub pin: String,
    pub certificate_pin: String,
}
impl TlsIdentity {
    pub fn load(store: &crate::store::Store) -> Result<Self> {
        let key_path = store.root.join("stream-private.pem");
        let key = if key_path.exists() {
            let bytes = store.read_secret("stream-private.pem")?;
            rcgen::KeyPair::from_pem(std::str::from_utf8(&bytes)?)?
        } else {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            store.write_secret("stream-private.pem", key.serialize_pem().as_bytes(), false)?;
            key
        };
        let certificate_path = store.checked_file("stream-certificate.der")?;
        let der = if certificate_path.exists() {
            ensure!(
                std::fs::metadata(&certificate_path)?.len() <= 32768,
                "本机证书过大"
            );
            let bytes = std::fs::read(&certificate_path)?;
            let (_, cert) =
                X509Certificate::from_der(&bytes).map_err(|_| anyhow::anyhow!("本机证书损坏"))?;
            ensure!(
                cert.public_key().raw == key.public_key_der(),
                "本机证书与私钥不符"
            );
            let now = conwu_core::unix_seconds();
            if cert.validity().not_after.timestamp() > now + 30 * 86400
                && cert.validity().not_before.timestamp() <= now
            {
                bytes
            } else {
                let der = rcgen::CertificateParams::new(vec!["ConWU".into(), "localhost".into()])?
                    .self_signed(&key)?
                    .der()
                    .to_vec();
                store.write("stream-certificate.der", &der, true)?;
                der
            }
        } else {
            let der = rcgen::CertificateParams::new(vec!["ConWU".into(), "localhost".into()])?
                .self_signed(&key)?
                .der()
                .to_vec();
            store.write("stream-certificate.der", &der, false)?;
            der
        };
        let pin = certificate_pin(der.as_ref())?;
        let whole_pin = hex::encode_upper(c::hash(&der));
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(der)],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )?;
        Ok(Self {
            server: Arc::new(config),
            pin,
            certificate_pin: whole_pin,
        })
    }
}
fn certificate_pin(der: &[u8]) -> Result<String> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|_| anyhow::anyhow!("invalid X.509 certificate"))?;
    Ok(hex::encode_upper(c::hash(cert.public_key().raw)))
}
#[derive(Debug)]
struct PinVerifier {
    pin: String,
    bootstrap: bool,
    whole_certificate: bool,
    provider: Arc<rustls::crypto::CryptoProvider>,
    first_pin: Option<std::sync::Mutex<Option<String>>>,
}
impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let (_, cert) = X509Certificate::from_der(end.as_ref())
            .map_err(|_| rustls::Error::General("invalid certificate".into()))?;
        let now = now.as_secs() as i64;
        if now < cert.validity().not_before.timestamp()
            || now > cert.validity().not_after.timestamp()
        {
            return Err(rustls::Error::General(
                "certificate expired/not yet valid".into(),
            ));
        }
        let pin = (if self.whole_certificate {
            Ok(hex::encode_upper(c::hash(end.as_ref())))
        } else {
            certificate_pin(end.as_ref())
        })
        .map_err(|_| rustls::Error::General("invalid public key".into()))?;
        if self.pin.len() == 64 {
            if !c::eq(pin.as_bytes(), self.pin.to_ascii_uppercase().as_bytes()) {
                return Err(rustls::Error::General(
                    "paired TLS identity mismatch".into(),
                ));
            }
        } else {
            if !self.bootstrap {
                return Err(rustls::Error::General("unpaired TLS identity".into()));
            }
            if let Some(first) = &self.first_pin {
                let mut first = first.lock().unwrap();
                if first.as_ref().is_some_and(|saved| saved != &pin) {
                    return Err(rustls::Error::General(
                        "bootstrap TLS identity changed".into(),
                    ));
                }
                *first = Some(pin);
            }
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        cert: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            cert,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        cert: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            cert,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
pub async fn connect(
    mode: &str,
    endpoint: SocketAddr,
    pin: &str,
    bootstrap: bool,
    parent: &CancellationToken,
) -> Result<Pipe> {
    ensure!(
        stream_mode(mode),
        "selected carrier is not a TCP/TLS stream"
    );
    let socket = tokio::time::timeout(Duration::from_secs(6), TcpStream::connect(endpoint))
        .await
        .context("TCP connection timeout")??;
    client_socket(mode, socket, pin, bootstrap, parent).await
}
/// TCP active/passive open is independent of the TLS/WebSocket role. The host
/// remains the protocol server even when it opens the NAT mapping itself.
pub async fn connect_role(
    mode: &str,
    endpoint: SocketAddr,
    pin: &str,
    port: u16,
    protocol_client: bool,
    identity: &TlsIdentity,
    parent: &CancellationToken,
) -> Result<Pipe> {
    let local = SocketAddr::new(crate::discovery::local_route(endpoint)?, port);
    connect_role_from(mode, endpoint, pin, local, protocol_client, identity, parent).await
}
pub async fn connect_role_from(
    mode: &str,
    endpoint: SocketAddr,
    pin: &str,
    local: SocketAddr,
    protocol_client: bool,
    identity: &TlsIdentity,
    parent: &CancellationToken,
) -> Result<Pipe> {
    let socket = tcp_open_from(endpoint, local).await?;
    if protocol_client {
        client_socket(mode, socket, pin, false, parent).await
    } else {
        accept(mode, socket, identity, parent).await
    }
}
pub async fn tcp_open_from(endpoint: SocketAddr, local: SocketAddr) -> Result<TcpStream> {
    ensure!(endpoint.is_ipv4() == local.is_ipv4() && !local.ip().is_unspecified(), "同源 TCP 地址族或源地址无效");
    let socket = socket2::Socket::new(
        if endpoint.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&local.into())?;
    let socket: std::net::TcpStream = socket.into();
    let future = tokio::net::TcpSocket::from_std_stream(socket).connect(endpoint);
    Ok(tokio::time::timeout(Duration::from_secs(6), future)
        .await
        .context("同端口 TCP 建连超时")??)
}
pub async fn client_socket(
    mode: &str,
    socket: TcpStream,
    pin: &str,
    bootstrap: bool,
    parent: &CancellationToken,
) -> Result<Pipe> {
    let endpoint = socket.peer_addr()?;
    socket.set_nodelay(true)?;
    if mode == "tcp" {
        return Ok(tcp_pipe(socket, parent));
    }
    ensure!(pin.len() == 64 || bootstrap, "HTTPS peer is not paired");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier {
            pin: pin.into(),
            bootstrap,
            whole_certificate: false,
            provider,
            first_pin: None,
        }))
        .with_no_client_auth();
    let name = ServerName::try_from(endpoint.ip().to_string())?;
    let socket = tokio::time::timeout(
        Duration::from_secs(8),
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, socket),
    )
    .await
    .context("TLS handshake timeout")??;
    let actual = socket
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|v| v.first())
        .ok_or_else(|| anyhow::anyhow!("missing peer certificate"))?;
    let actual = certificate_pin(actual.as_ref())?;
    let mut request = format!("wss://{endpoint}/conwu/stream").into_client_request()?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static("conwu.stream.v1"),
    );
    request
        .headers_mut()
        .insert("X-ConWU-Datagram-Batch", HeaderValue::from_static("1"));
    let (ws, response) = tokio::time::timeout(
        Duration::from_secs(8),
        tokio_tungstenite::client_async_with_config(request, socket, Some(websocket_config())),
    )
    .await
    .context("HTTP upgrade timeout")??;
    ensure!(
        response
            .headers()
            .get("Sec-WebSocket-Protocol")
            .is_some_and(|v| v == "conwu.stream.v1"),
        "invalid ConWU WebSocket protocol"
    );
    let batch = response
        .headers()
        .get("X-ConWU-Datagram-Batch")
        .is_some_and(|v| v == "1");
    Ok(ws_pipe(ws, batch, parent, actual))
}
pub async fn accept(
    mode: &str,
    socket: TcpStream,
    identity: &TlsIdentity,
    parent: &CancellationToken,
) -> Result<Pipe> {
    socket.set_nodelay(true)?;
    if mode == "tcp" {
        return Ok(tcp_pipe(socket, parent));
    }
    ensure!(mode == "https", "selected listener is not TCP/HTTPS");
    let socket = tokio::time::timeout(
        Duration::from_secs(8),
        tokio_rustls::TlsAcceptor::from(identity.server.clone()).accept(socket),
    )
    .await??;
    let batch = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = batch.clone();
    let callback = move |r: &Request<()>,
                         mut response: Response<()>|
          -> std::result::Result<Response<()>, Response<Option<String>>> {
        if r.uri().path() != "/conwu/stream"
            || r.headers()
                .get("Sec-WebSocket-Protocol")
                .is_none_or(|v| v != "conwu.stream.v1")
        {
            let mut error = Response::new(Some("ConWU stream endpoint required".into()));
            *error.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::BAD_REQUEST;
            return Err(error);
        }
        response.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("conwu.stream.v1"),
        );
        if r.headers()
            .get("X-ConWU-Datagram-Batch")
            .is_some_and(|v| v == "1")
        {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
            response
                .headers_mut()
                .insert("X-ConWU-Datagram-Batch", HeaderValue::from_static("1"));
        }
        Ok(response)
    };
    let ws = tokio::time::timeout(
        Duration::from_secs(8),
        tokio_tungstenite::accept_hdr_async_with_config(socket, callback, Some(websocket_config())),
    )
    .await??;
    Ok(ws_pipe(
        ws,
        batch.load(std::sync::atomic::Ordering::Relaxed),
        parent,
        String::new(),
    ))
}
pub async fn listener(port: u16, ipv6: bool) -> Result<TcpListener> {
    let domain = if ipv6 {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if ipv6 {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;
    let ip = if ipv6 {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    };
    socket.bind(&SocketAddr::new(ip, port).into())?;
    socket.listen(80)?;
    Ok(TcpListener::from_std(socket.into())?)
}
fn channels(
    parent: &CancellationToken,
) -> (
    mpsc::Sender<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Sender<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
    CancellationToken,
) {
    let (tx, outgoing) = mpsc::channel(128);
    let (incoming, rx) = mpsc::channel(128);
    (tx, outgoing, incoming, rx, parent.child_token())
}
fn tcp_pipe(socket: TcpStream, parent: &CancellationToken) -> Pipe {
    let (tx, mut outgoing, incoming, rx, cancel) = channels(parent);
    let stop = cancel.clone();
    let (reader, mut writer) = socket.into_split();
    let mut reader = tokio::io::BufReader::with_capacity(16384, reader);
    let reader_stop = stop.clone();
    tokio::spawn(async move {
        let _guard = reader_stop.clone().drop_guard();
        loop {
            let read = async {
                let n = reader.read_u16().await? as usize;
                if !(1..=MAX).contains(&n) {
                    return Err(std::io::Error::other("invalid datagram length"));
                }
                let mut bytes = vec![0; n];
                reader.read_exact(&mut bytes).await?;
                Ok(bytes)
            };
            let bytes = tokio::select! {_=reader_stop.cancelled()=>break,r=read=>match r{Ok(b)=>b,Err(_)=>break}};
            tokio::select! {
                biased;
                _ = reader_stop.cancelled() => break,
                result = incoming.send(bytes) => {
                    if result.is_err() {
                        break;
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        let _guard = stop.clone().drop_guard();
        let mut buffer = Vec::with_capacity(16384);
        loop {
            tokio::select! {biased;_ = stop.cancelled()=>break,frame=outgoing.recv()=>{
                let Some(frame)=frame else{break};if frame.is_empty()||frame.len()>MAX{break}buffer.clear();push_frame(&mut buffer,&frame);
                for _ in 1..16{if buffer.len()+MAX+2>16384{break}match outgoing.try_recv(){Ok(frame)if !frame.is_empty()&&frame.len()<=MAX=>push_frame(&mut buffer,&frame),_=>break}}
                if tokio::select!{_=stop.cancelled()=>true,r=tokio::time::timeout(Duration::from_secs(4),writer.write_all(&buffer))=>!matches!(r,Ok(Ok(())))}{break}
            }}
        }
        stop.cancel();
        let _ = tokio::time::timeout(Duration::from_millis(100), writer.shutdown()).await;
    });
    Pipe {
        tx,
        rx,
        cancel,
        pin: String::new(),
    }
}
fn push_frame(out: &mut Vec<u8>, frame: &[u8]) {
    out.extend_from_slice(&(frame.len() as u16).to_be_bytes());
    out.extend_from_slice(frame);
}
fn ws_pipe<S>(ws: WebSocketStream<S>, batch: bool, parent: &CancellationToken, pin: String) -> Pipe
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut outgoing, incoming, rx, cancel) = channels(parent);
    let stop = cancel.clone();
    let (mut writer, mut reader) = ws.split();
    tokio::spawn(async move {
        let _guard = stop.clone().drop_guard();
        let mut pending = VecDeque::new();
        'pipe: loop {
            while let Some(frame) = pending.pop_front() {
                match incoming.try_send(frame) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(frame)) => {
                        pending.push_front(frame);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break 'pipe,
                }
            }
            // Keep at most one decoded message outside the receive queue. The
            // writer can continue while the receiver makes room for it.
            tokio::select! {
                _ = stop.cancelled() => break,
                permit = incoming.reserve(), if !pending.is_empty() => {
                    let Ok(permit) = permit else { break };
                    permit.send(pending.pop_front().unwrap());
                }
                item = reader.next(), if pending.is_empty() => match item {
                    Some(Ok(Message::Binary(body))) if !body.is_empty() && body.len() <= 16384 => {
                        if batch {
                            let Ok(frames) = parse_batch(&body) else { break };
                            pending.extend(frames);
                        } else if body.len() <= MAX {
                            pending.push_back(body.to_vec());
                        } else {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if !ws_send(&mut writer, Message::Pong(data), &stop).await {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    _ => break,
                },
                frame = outgoing.recv() => {
                    let Some(frame) = frame else { break };
                    if frame.is_empty() || frame.len() > MAX {
                        break;
                    }
                    let body = if batch {
                        let mut body = Vec::with_capacity(16384);
                        push_frame(&mut body, &frame);
                        for _ in 1..16 {
                            if body.len() + MAX + 2 > 16384 {
                                break;
                            }
                            match outgoing.try_recv() {
                                Ok(frame) if !frame.is_empty() && frame.len() <= MAX => {
                                    push_frame(&mut body, &frame);
                                }
                                _ => break,
                            }
                        }
                        body
                    } else {
                        frame
                    };
                    if !ws_send(&mut writer, Message::Binary(body.into()), &stop).await {
                        break;
                    }
                }
            }
        }
        stop.cancel();
        let _ = tokio::time::timeout(Duration::from_millis(100), writer.close()).await;
    });
    Pipe {
        tx,
        rx,
        cancel,
        pin,
    }
}
async fn ws_send<S>(writer: &mut S, message: Message, stop: &CancellationToken) -> bool
where
    S: futures_util::Sink<Message> + Unpin,
{
    tokio::select! {_=stop.cancelled()=>false,r=tokio::time::timeout(Duration::from_secs(4),writer.send(message))=>matches!(r,Ok(Ok(())))}
}
fn parse_batch(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut frames = vec![];
    let mut at = 0;
    while at < body.len() {
        ensure!(body.len() - at >= 2 && frames.len() < 16, "invalid batch");
        let n = u16::from_be_bytes(body[at..at + 2].try_into()?) as usize;
        at += 2;
        ensure!(
            (1..=MAX).contains(&n) && at + n <= body.len(),
            "invalid batch datagram"
        );
        frames.push(body[at..at + n].to_vec());
        at += n;
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::protocol::Role;

    async fn verify_receive_backpressure(mut sender: Pipe, mut receiver: Pipe) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(6), async {
            let capacity = receiver.rx.max_capacity();
            let count = capacity + 32;
            for sequence in 0..count {
                sender.tx.send(sequence.to_be_bytes().to_vec()).await?;
            }
            while receiver.rx.len() < capacity {
                tokio::task::yield_now().await;
            }

            // The receive side is still full. The reverse direction must be usable.
            let reply = b"reverse direction".to_vec();
            receiver.tx.send(reply.clone()).await?;
            assert_eq!(sender.rx.recv().await, Some(reply));

            for sequence in 0..count {
                assert_eq!(receiver.rx.recv().await, Some(sequence.to_be_bytes().to_vec()));
            }
            assert!(!receiver.cancel.is_cancelled());
            Ok::<_, anyhow::Error>(())
        })
        .await.context("收包积压时无法继续双向传输")??;
        Ok(())
    }

    #[tokio::test]
    async fn tcp_keeps_order_and_reverse_traffic_when_receive_queue_fills() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (client, (server, _)) =
            tokio::try_join!(TcpStream::connect(listener.local_addr()?), listener.accept())?;
        let stop = CancellationToken::new();
        verify_receive_backpressure(tcp_pipe(client, &stop), tcp_pipe(server, &stop)).await
    }

    #[tokio::test]
    async fn websocket_keeps_order_and_reverse_traffic_when_receive_queue_fills() -> Result<()> {
        for batch in [false, true] {
            let (client, server) = tokio::io::duplex(65536);
            let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
            let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
            let stop = CancellationToken::new();
            verify_receive_backpressure(
                ws_pipe(client, batch, &stop, String::new()),
                ws_pipe(server, batch, &stop, String::new()),
            ).await?;
        }
        Ok(())
    }
}
