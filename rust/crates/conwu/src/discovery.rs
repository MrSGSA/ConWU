use crate::model::Entry;
use anyhow::{Context, Result, ensure};
use conwu_core::{
    code::{stream_mode, valid_endpoint},
    crypto as c,
};
use futures_util::{FutureExt, Stream, StreamExt};
use serde_json::Value;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

mod stun_lease;
pub(crate) use stun_lease::{StunLease, StunLeaseLost, StunLeaseStatus};

pub fn validate_service(text: &str) -> Result<()> {
    if text.is_empty() {
        return Ok(());
    }
    ensure!(
        text.len() <= 2048 && !text.chars().any(char::is_control),
        "协调服务器地址无效"
    );
    let url = url::Url::parse(text)?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.host_str().is_some(),
        "协调服务器地址无效"
    );
    ensure!(
        url.scheme() == "https"
            || url.scheme() == "http"
                && url
                    .host_str()
                    .is_some_and(|h| h == "localhost"
                        || h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())),
        "对外协调服务需要 HTTPS"
    );
    Ok(())
}
pub fn validate_endpoint(text: &str) -> Result<()> {
    let text = text
        .strip_prefix("tcp://")
        .or_else(|| text.strip_prefix("udp://"))
        .unwrap_or(text);
    if let Ok(endpoint) = text.parse::<SocketAddr>() {
        ensure!(conwu_core::code::valid_endpoint(&endpoint), "入口地址无效");
        return Ok(());
    }
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("入口需要端口"))?;
    ensure!(
        crate::dns::valid_host(host) && port.parse::<u16>().is_ok_and(|p| p > 0),
        "入口格式应为 IP:端口或域名:端口"
    );
    Ok(())
}
pub fn validate_source(text: &str) -> Result<()> {
    ensure!(
        text == text.trim()
            && !text.is_empty()
            && text.len() <= 2048
            && !text.chars().any(char::is_control),
        "入口来源无效"
    );
    let (raw, tag) = text
        .split_once('#')
        .map_or((text, None), |(a, b)| (a, Some(b)));
    if let Some(tag) = tag {
        ensure!(
            !tag.is_empty()
                && tag.len() <= 32
                && tag.as_bytes()[0].is_ascii_alphabetic()
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
            "订阅标签无效"
        );
    }
    if raw.starts_with("pkarr://") {
        crate::pkarr::decode_key(crate::pkarr::source_key(raw)?)?;
    } else if let Some(host) = raw
        .strip_prefix("txt://")
        .or_else(|| (!raw.contains("://") && tag.is_some()).then_some(raw))
    {
        ensure!(crate::dns::valid_host(host), "TXT 域名无效");
    } else if raw.starts_with("http://") || raw.starts_with("https://") {
        let url = url::Url::parse(raw)?;
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.host_str().is_some_and(|h| h
                    .parse::<IpAddr>()
                    .map_or_else(|_| crate::dns::valid_host(h), public)),
            "订阅需为不含用户名的公网 HTTP(S) 地址"
        );
    } else {
        ensure!(tag.is_none(), "地址入口不支持订阅标签");
        validate_endpoint(raw)?;
    }
    Ok(())
}

pub async fn resolve(
    entries: &[Entry],
    mode: &str,
    client: &std::sync::Arc<crate::pkarr::Client>,
    gateways: &[String],
) -> Vec<SocketAddr> {
    let mut result = vec![];
    for row in detailed(entries, mode, client, gateways).await {
        if let Some(endpoints) = row["endpoints"].as_array() {
            for endpoint in endpoints {
                let Some(endpoint) = endpoint.as_str().and_then(|s| s.parse::<SocketAddr>().ok())
                else {
                    continue;
                };
                if !result.contains(&endpoint) {
                    result.push(endpoint);
                }
                if result.len() >= 8 {
                    return result;
                }
            }
        }
    }
    result
}
pub async fn detailed(
    entries: &[Entry],
    mode: &str,
    client: &std::sync::Arc<crate::pkarr::Client>,
    gateways: &[String],
) -> Vec<Value> {
    use futures_util::stream::{self, StreamExt};
    let tasks: Vec<futures_util::future::BoxFuture<'static, Value>> = entries.iter().take(12).cloned().enumerate().map(|(index, entry)| {
        let mode = mode.to_owned();
        let client = client.clone();
        let gateways = gateways.to_vec();
        Box::pin(async move {
        let begin = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(12), source(&entry.source, &mode, &client, &gateways)).await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("入口解析超时")));
        let kind = if entry.source.starts_with("pkarr://") { "PKARR" } else if entry.source.starts_with("txt://") || entry.source.contains('#') && !entry.source.contains("://") { "TXT" } else if entry.source.starts_with("https://") { "HTTPS" } else if entry.source.starts_with("http://") { "HTTP" } else { "地址" };
        serde_json::json!({"index":index,"peerSlot":entry.peer_slot,"kind":kind,"endpoints":result.as_ref().map(|v| v.iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap_or_default(),"error":result.err().map(|e|{let message=crate::logging::redact(&e.to_string());if kind=="TXT"{format!("{message}，或请检查#标签名")}else{message}}).unwrap_or_default(),"elapsedMs":begin.elapsed().as_millis() as u64,"attempts":1,"allowCached":false,"lookupDetail":"独立解析，不沿用首次配对地址"})
    }) as futures_util::future::BoxFuture<'static, Value> }).collect();
    let mut rows = stream::iter(tasks)
        .buffer_unordered(4)
        .collect::<Vec<_>>()
        .await;
    rows.sort_by_key(|v| v["index"].as_u64().unwrap_or(0));
    rows
}
pub async fn source(
    text: &str,
    mode: &str,
    client: &crate::pkarr::Client,
    gateways: &[String],
) -> Result<Vec<SocketAddr>> {
    let normalized = if !text.contains("://") && text.contains('#') {
        format!("txt://{text}")
    } else {
        text.to_owned()
    };
    let text = normalized.as_str();
    ensure!(
        text.len() <= 2048 && !text.chars().any(char::is_control),
        "invalid source"
    );
    let (text, selector) = text
        .split_once('#')
        .map_or((text, None), |(s, t)| (s, Some(t)));
    if let Some(tag) = selector {
        ensure!(
            !tag.is_empty()
                && tag.len() <= 32
                && tag.bytes().next().unwrap().is_ascii_alphabetic()
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
            "invalid subscription selector"
        )
    }
    if text.starts_with("pkarr://") {
        let record = client.resolve(text, mode, gateways).await?;
        return record
            .announcement
            .endpoints
            .iter()
            .map(|s| Ok(s.parse()?))
            .collect();
    }
    let values = if let Some(host) = text.strip_prefix("txt://") {
        let records = crate::dns::txt(host).await?;
        documents(&records, selector)?
    } else if text.starts_with("https://") || text.starts_with("http://") {
        let url = url::Url::parse(text)?;
        ensure!(
            url.username().is_empty() && url.password().is_none(),
            "subscription credentials must not be embedded in authority"
        );
        let host = match url
            .host()
            .ok_or_else(|| anyhow::anyhow!("subscription host missing"))?
        {
            url::Host::Domain(name) => name.to_owned(),
            url::Host::Ipv4(ip) => ip.to_string(),
            url::Host::Ipv6(ip) => ip.to_string(),
        };
        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("subscription port missing"))?;
        let ips = crate::dns::addresses(&host)
            .await?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();
        ensure!(
            !ips.is_empty() && ips.iter().all(|p| public(p.ip())),
            "subscription must resolve entirely to public addresses"
        );
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(7))
            .resolve_to_addrs(&host, &ips)
            .build()?;
        let response = client
            .get(url)
            .header("Cache-Control", "no-cache, no-store")
            .send()
            .await?
            .error_for_status()?;
        ensure!(
            response.content_length().is_none_or(|n| n <= 8192),
            "subscription body too large"
        );
        let mut chunks = response.bytes_stream();
        let mut body = vec![];
        while let Some(chunk) = chunks.next().await {
            body.extend_from_slice(&chunk?);
            ensure!(body.len() <= 8192, "subscription body too large");
        }
        documents(&[String::from_utf8(body)?], selector)?
    } else {
        vec![text.to_owned()]
    };
    ensure!(
        !values.is_empty() && values.len() <= 8,
        "source must return 1..8 endpoints"
    );
    let mut out = vec![];
    for value in values {
        if value.starts_with("udp://") {
            ensure!(
                mode == "udp",
                "source protocol differs from selected carrier"
            )
        }
        if value.starts_with("tcp://") {
            ensure!(
                mode != "udp",
                "source protocol differs from selected carrier"
            )
        }
        for endpoint in endpoint(&value).await? {
            if valid_endpoint(&endpoint)
                && (endpoint.is_ipv4() || stream_mode(mode))
                && !out.contains(&endpoint)
            {
                out.push(endpoint)
            }
        }
    }
    ensure!(
        !out.is_empty() && out.len() <= 8,
        "no endpoints compatible with the selected carrier"
    );
    Ok(out)
}
pub fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .user_agent("ConWU-Rust-experiment")
        .build()?)
}
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            conwu_core::code::valid_endpoint(&SocketAddr::new(ip.into(), 1))
                && !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && ip.octets()[0] != 0
                && !(ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
                && !(ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19))
        }
        IpAddr::V6(ip) => conwu_core::code::global_ipv6(ip),
    }
}
pub async fn endpoint(text: &str) -> Result<Vec<SocketAddr>> {
    resolve_endpoint(text, false).await
}

async fn resolve_endpoint(text: &str, stun: bool) -> Result<Vec<SocketAddr>> {
    let text = text
        .strip_prefix("tcp://")
        .or_else(|| text.strip_prefix("udp://"))
        .unwrap_or(text);
    if let Ok(address) = text.parse::<SocketAddr>() {
        ensure!(address.port() != 0, "port must not be zero");
        return Ok(vec![address]);
    }
    ensure!(
        !text.contains(['[', ']', '/', '@']) && text.matches(':').count() == 1,
        "endpoint must be IP:port, [IPv6]:port or hostname:port"
    );
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("endpoint port missing"))?;
    let port = port.parse::<u16>()?;
    ensure!(port > 0 && !host.is_empty(), "endpoint host/port invalid");
    let fresh = crate::dns::addresses(host);
    let addresses = if stun {
        crate::dns::with_recent_ip(crate::dns::EndpointKind::TcpStun, host, port, async {
            Ok(fresh.await?.into_iter().filter(IpAddr::is_ipv4).collect())
        }).await?
    } else { fresh.await? };
    Ok(addresses
        .into_iter()
        .take(8)
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}
fn documents(records: &[String], tag: Option<&str>) -> Result<Vec<String>> {
    ensure!(
        records.iter().map(String::len).sum::<usize>() <= 8192,
        "subscription body too large"
    );
    let prefix = format!("{}=", tag.unwrap_or("streamlink"));
    let mut selected = vec![];
    let mut untagged = vec![];
    for record in records {
        let record = record.trim();
        let lines: Vec<_> = if record.starts_with('{') || record.starts_with('[') {
            vec![record]
        } else {
            record.lines().map(str::trim).collect()
        };
        for line in lines {
            let tagged = line
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(&prefix));
            let body = if tagged {
                line[prefix.len()..].trim()
            } else {
                line
            };
            if tagged && (body.starts_with('{') || body.starts_with('[')) {
                selected.push(body.to_owned());
            } else {
                for field in line.split_whitespace() {
                    if field
                        .get(..prefix.len())
                        .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
                    {
                        selected.push(field[prefix.len()..].to_owned());
                    }
                }
            }
            untagged.push(line.to_owned());
        }
    }
    ensure!(
        tag.is_none() || !selected.is_empty(),
        "selected subscription tag missing"
    );
    let source = if selected.is_empty() {
        untagged
    } else {
        selected
    };
    let mut out = vec![];
    for value in source {
        let value = value.trim();
        if value.starts_with('{') || value.starts_with('[') && !value.contains("]:") {
            let root: Value = serde_json::from_str(value)?;
            let values = root
                .as_array()
                .or_else(|| root.get("endpoints").and_then(Value::as_array))
                .or_else(|| root.get("addresses").and_then(Value::as_array))
                .ok_or_else(|| anyhow::anyhow!("subscription JSON requires endpoint strings"))?;
            for value in values {
                out.push(
                    value
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("endpoint must be a string"))?
                        .trim()
                        .to_owned(),
                );
            }
        } else {
            out.extend(
                value
                    .split([',', ';', ' ', '\t', '\n', '\r'])
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned),
            );
        }
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|v| seen.insert(v.to_ascii_lowercase()));
    ensure!(!out.is_empty() && out.len() <= 8, "订阅需要返回1–8个入口");
    Ok(out)
}
#[cfg(test)]
mod document_tests {
    #[test]
    fn tags_json_and_shared_txt_records() {
        let parse = |s: &[&str], tag| {
            super::documents(&s.iter().map(|s| s.to_string()).collect::<Vec<_>>(), tag)
        };
        assert_eq!(
            parse(
                &[
                    "verification=unrelated",
                    "tcp://other:1 STREAMLINK=203.0.113.1:443"
                ],
                None
            )
            .unwrap(),
            ["203.0.113.1:443"]
        );
        assert_eq!(
            parse(
                &[r#"streamlink={"endpoints": ["203.0.113.1:443", "203.0.113.2:444"]}"#],
                None
            )
            .unwrap()
            .len(),
            2
        );
        assert_eq!(
            parse(&[r#"{"addresses": ["203.0.113.1:443"]}"#], None)
                .unwrap()
                .len(),
            1
        );
        assert!(parse(&["other=203.0.113.1:443"], Some("streamlink")).is_err());
        assert_eq!(
            parse(
                &["desktop-entry=203.0.113.1:1612", "other=203.0.113.2:1618"],
                Some("desktop-entry")
            )
            .unwrap(),
            ["203.0.113.1:1612"]
        );
    }
}
pub fn local_route(remote: SocketAddr) -> Result<IpAddr> {
    let socket = std::net::UdpSocket::bind(if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.connect(remote)?;
    Ok(socket.local_addr()?.ip())
}
pub fn ipv6_candidate(port: u16) -> Option<SocketAddr> {
    let remote = "[2606:4700:4700::1111]:3478".parse().ok()?;
    let ip = local_route(remote).ok()?;
    matches!(ip,IpAddr::V6(ip)if conwu_core::code::global_ipv6(ip))
        .then(|| SocketAddr::new(ip, port))
}
pub struct TcpObservation {
    pub stream: TcpStream,
    pub local: SocketAddr,
    pub mapped: SocketAddr,
    pub observer: SocketAddr,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpAddresses {
    pub local: SocketAddr,
    pub mapped: SocketAddr,
    pub observer: SocketAddr,
}

impl TcpObservation {
    pub(crate) fn addresses(&self) -> TcpAddresses {
        TcpAddresses { local: self.local, mapped: self.mapped, observer: self.observer }
    }
}
/// Each discovery pass needs one successful observation. A new TCP connection
/// already performed a Binding request in observe_tcp.
pub async fn refresh_or_observe_tcp(
    previous: Option<TcpObservation>,
    port: u16,
    servers: &[String],
    engine: &crate::runtime::Engine,
    mode: &str,
    preferred: Option<SocketAddr>,
) -> Result<TcpObservation> {
    // A healthy fallback can stay open indefinitely. Give the coordinator's
    // own observer a bounded chance before refreshing that fallback.
    if let Some(observer) = preferred
        && previous
            .as_ref()
            .is_none_or(|old| old.local.port() != port || old.observer != observer)
        && let Ok(observed) = observe_tcp_endpoint(
            port, observer, engine, mode, tokio::time::Instant::now() + TCP_OBSERVER_ATTEMPT,
        ).await
        && observed.mapped.is_ipv4()
        && public(observed.mapped.ip())
    {
        return Ok(observed);
    }
    if let Some(mut old) = previous.filter(|o| o.local.port() == port) {
        if let Ok(Ok(mapped)) =
            tokio::time::timeout(stun_lease::BINDING_TIMEOUT, stun_tcp(&mut old.stream)).await
        {
            old.mapped = mapped;
            return Ok(old);
        }
    }
    observe_tcp(port, servers, engine, mode).await
}

pub(crate) const TCP_OBSERVER_ATTEMPT: Duration = Duration::from_millis(1800);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObserverStage {
    Prepare,
    Connect,
    Binding,
}

#[derive(Debug)]
struct ObserverTimeout {
    stage: ObserverStage,
    local: SocketAddr,
    remote: SocketAddr,
}

impl std::fmt::Display for ObserverTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stage = match self.stage {
            ObserverStage::Prepare => "准备 TCP STUN 同源接收器",
            ObserverStage::Connect => "建立 TCP STUN 连接",
            ObserverStage::Binding => "等待 TCP STUN Binding 回复",
        };
        write!(f, "{stage}超时（应用层截止，{} → {}）", self.local, self.remote)
    }
}

impl std::error::Error for ObserverTimeout {}

async fn observer_stage<T>(
    deadline: Option<tokio::time::Instant>,
    error: ObserverTimeout,
    work: impl std::future::Future<Output = T>,
) -> Result<T> {
    if let Some(deadline) = deadline {
        Ok(tokio::time::timeout_at(deadline, work).await.map_err(|_| error)?)
    } else {
        Ok(work.await)
    }
}

async fn observe_tcp_endpoint(
    port: u16,
    remote: SocketAddr,
    engine: &crate::runtime::Engine,
    mode: &str,
    deadline: tokio::time::Instant,
) -> Result<TcpObservation> {
    let local = SocketAddr::new(local_route(remote)?, port);
    observer_stage(Some(deadline), ObserverTimeout { stage: ObserverStage::Prepare, local, remote },
        crate::raw::prepare_observer(engine, mode, port, remote)).await??;
    observe_tcp_before(local, remote, Some(deadline)).await
}

pub(crate) async fn observe_tcp_from(local: SocketAddr, remote: SocketAddr) -> Result<TcpObservation> {
    observe_tcp_before(local, remote, None).await
}

async fn observe_tcp_before(
    local: SocketAddr, remote: SocketAddr, deadline: Option<tokio::time::Instant>,
) -> Result<TcpObservation> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_linger(Some(Duration::ZERO))?;
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;
    socket.bind(&local.into()).with_context(|| format!("绑定 TCP STUN 源端口 {local}"))?;
    socket.set_nonblocking(true)?;
    let socket: std::net::TcpStream = socket.into();
    let connect = tokio::net::TcpSocket::from_std_stream(socket).connect(remote);
    let mut stream = observer_stage(deadline, ObserverTimeout { stage: ObserverStage::Connect, local, remote }, connect)
        .await?.with_context(|| format!("连接 TCP STUN 观察器（{local} → {remote}）"))?;
    let local = stream.local_addr()?;
    let mapped = observer_stage(deadline, ObserverTimeout { stage: ObserverStage::Binding, local, remote }, stun_tcp(&mut stream))
        .await?.with_context(|| format!("读取 TCP STUN Binding 回复（{local} → {remote}）"))?;
    Ok(TcpObservation {
        stream,
        local,
        mapped,
        observer: remote,
    })
}

/// Capture and its firewall exception are bound to this exact pair of endpoints.
pub(crate) async fn renew_native_observation(
    lease: &mut Option<TcpObservation>,
    local: SocketAddr,
    observer: SocketAddr,
) -> Result<SocketAddr> {
    if let Some(old) = lease.as_mut()
        && let Ok(Ok(mapped)) = tokio::time::timeout(stun_lease::BINDING_TIMEOUT, stun_tcp(&mut old.stream)).await
    {
        old.mapped = mapped;
        return Ok(mapped);
    }
    // Some STUN servers close after one reply. Release the old four-tuple
    // before reconnecting, and keep the raw receiver and its peers alive.
    drop(lease.take());
    let fresh = tokio::time::timeout(TCP_OBSERVER_ATTEMPT, observe_tcp_from(local, observer)).await??;
    let mapped = fresh.mapped;
    *lease = Some(fresh);
    Ok(mapped)
}

struct ObserverAddresses {
    index: usize,
    addresses: Vec<SocketAddr>,
    next: usize,
}

async fn next_observer_address(
    queries: &mut (impl Stream<Item = (usize, Vec<SocketAddr>)> + Unpin),
    ready: &mut Vec<ObserverAddresses>,
) -> Option<(usize, SocketAddr)> {
    loop {
        ready.retain(|observer| observer.next < observer.addresses.len());
        let resolved = if ready.is_empty() {
            queries.next().await
        } else {
            queries.next().now_or_never().flatten()
        };
        if let Some((index, addresses)) = resolved {
            ready.push(ObserverAddresses {
                index,
                addresses: addresses.into_iter().filter(SocketAddr::is_ipv4).take(8).collect(),
                next: 0,
            });
            continue;
        }

        // Another server's first address can use the budget before retrying
        // the remaining addresses from an already tried server.
        let observer = ready.iter_mut().min_by_key(|observer| observer.next)?;
        let address = observer.addresses[observer.next];
        observer.next += 1;
        return Some((observer.index, address));
    }
}

#[cfg(test)]
mod observer_tests {
    use super::*;

    #[tokio::test]
    async fn transient_pairing_observation_can_retry_the_same_endpoint() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let observer = listener.local_addr()?;
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().await?;
                let mut request = [0; 20];
                stream.read_exact(&mut request).await?;
                if attempt == 0 {
                    continue;
                }
                let mut response = request.to_vec();
                response[..4].copy_from_slice(&[1, 1, 0, 12]);
                response.extend_from_slice(&[0, 1, 0, 8, 0, 1, 0x9c, 0x40, 127, 0, 0, 1]);
                stream.write_all(&response).await?;
            }
            Ok::<_, anyhow::Error>(())
        });
        let local = "127.0.0.1:0".parse()?;
        let observation = tokio::time::timeout(Duration::from_secs(3), crate::assistance::retry_pair_step(
            "TCP STUN 观察", transient_observer, |_| observe_tcp_from(local, observer),
        )).await??;
        assert_eq!(observation.observer, observer);
        assert_eq!(observation.mapped.port(), 40000);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn native_refresh_recovers_a_closed_stun_stream_on_the_same_source() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let observer = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let mut first_source = None;
            for port in [40000u16, 40001] {
                let (mut stream, source) = listener.accept().await?;
                assert_eq!(*first_source.get_or_insert(source), source);
                let mut request = [0; 20];
                stream.read_exact(&mut request).await?;
                let mut reply = request.to_vec();
                reply[..4].copy_from_slice(&[1, 1, 0, 12]);
                reply.extend_from_slice(&[0, 1, 0, 8, 0, 1]);
                reply.extend_from_slice(&port.to_be_bytes());
                reply.extend_from_slice(&[127, 0, 0, 1]);
                stream.write_all(&reply).await?;
                if port == 40000 {
                    stream.read_exact(&mut request).await?;
                    socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO))?;
                }
            }
            Ok::<_, anyhow::Error>(())
        });
        let first = observe_tcp_from("127.0.0.1:0".parse()?, observer).await?;
        let local = first.local;
        assert_eq!(first.mapped.port(), 40000);
        let mut lease = Some(first);
        assert_eq!(renew_native_observation(&mut lease, local, observer).await?.port(), 40001);
        assert_eq!(lease.unwrap().local, local);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn a_newly_resolved_observer_runs_before_retrying_another_server() {
        let first = "127.0.0.1:42001".parse().unwrap();
        let fallback = "127.0.0.1:42002".parse().unwrap();
        let second = "127.0.0.1:42003".parse().unwrap();
        let mut queries = futures_util::stream::iter([(0, vec![first, fallback])])
            .chain(futures_util::stream::once(async {
                tokio::task::yield_now().await;
                (1, vec![second])
            }))
            .chain(futures_util::stream::pending())
            .boxed();
        let mut ready = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), async {
            for expected in [(0, first), (1, second), (0, fallback)] {
                assert_eq!(next_observer_address(&mut queries, &mut ready).await, Some(expected));
            }
        })
        .await
        .expect("a pending DNS lookup must not hold up ready observers");
    }

    #[tokio::test]
    async fn observation_reports_a_binding_deadline_after_tcp_connect() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let remote = listener.local_addr()?;
        let accepted = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0u8; 20];
            stream.read_exact(&mut request).await?;
            std::future::pending::<()>().await;
            Ok::<_, std::io::Error>(())
        });
        let result = observe_tcp_before("127.0.0.1:0".parse()?, remote,
            Some(tokio::time::Instant::now() + Duration::from_millis(150))).await;
        let Err(error) = result else { anyhow::bail!("未回复 Binding 的服务器不应观察成功") };
        assert!(matches!(error.downcast_ref(), Some(ObserverTimeout { stage: ObserverStage::Binding, .. })));
        assert!(transient_observer(&error));
        assert!(confirm_stalled_stun_source(&error).await.is_none());
        accepted.abort();
        Ok(())
    }

    #[tokio::test]
    async fn a_stalled_source_requires_success_from_a_different_port() -> Result<()> {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let remote = server.local_addr()?;
        let reserved = std::net::TcpListener::bind("127.0.0.1:0")?;
        let local = reserved.local_addr()?;
        let error: anyhow::Error = ObserverTimeout { stage: ObserverStage::Connect, local, remote }.into();
        let server = tokio::spawn(async move {
            let (mut stream, peer) = server.accept().await?;
            let mut request = [0u8; 20];
            stream.read_exact(&mut request).await?;
            assert_ne!(peer.port(), local.port());
            let mut response = request.to_vec();
            response[..4].copy_from_slice(&[1, 1, 0, 12]);
            response.extend_from_slice(&[0, 1, 0, 8, 0, 1]);
            response.extend_from_slice(&peer.port().to_be_bytes());
            response.extend_from_slice(&[127, 0, 0, 1]);
            stream.write_all(&response).await?;
            Ok::<_, anyhow::Error>(())
        });
        assert!(stun_source_unavailable(&confirm_stalled_stun_source(&error).await
            .context("备用源端口未被识别")?.into()));
        server.await??;
        assert!(confirm_stalled_stun_source(&error).await.is_none());
        Ok(())
    }
}

pub async fn observe_tcp(
    port: u16,
    servers: &[String],
    engine: &crate::runtime::Engine,
    mode: &str,
) -> Result<TcpObservation> {
    observe_tcp_impl(port, servers, engine, mode, false, &Default::default()).await
}

pub(crate) async fn observe_tcp_with_keepalive(
    port: u16,
    servers: &[String],
    engine: &crate::runtime::Engine,
    mode: &str,
) -> Result<TcpObservation> {
    observe_tcp_impl(port, servers, engine, mode, true, &Default::default()).await
}

pub(crate) fn transient_observer(error: &anyhow::Error) -> bool {
    use std::io::ErrorKind;
    error.is::<ObserverTimeout>() || error.chain().any(|cause| cause.downcast_ref::<std::io::Error>().is_some_and(|io| matches!(
        io.kind(),
        ErrorKind::AddrInUse | ErrorKind::ConnectionAborted | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::UnexpectedEof
            | ErrorKind::TimedOut | ErrorKind::Interrupted | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
    )))
}

pub(crate) fn stun_address_in_use(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse))
}

#[derive(Debug)]
struct StunSourceStalled {
    local: SocketAddr,
    observer: SocketAddr,
}

impl std::fmt::Display for StunSourceStalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "绑定的 TCP STUN 源地址 {} 连接超时，临时源端口可访问同一观察器 {}", self.local, self.observer)
    }
}

impl std::error::Error for StunSourceStalled {}

pub(crate) fn stun_source_unavailable(error: &anyhow::Error) -> bool {
    stun_address_in_use(error) || error.is::<StunSourceStalled>()
}

async fn confirm_stalled_stun_source(error: &anyhow::Error) -> Option<StunSourceStalled> {
    let &ObserverTimeout { stage: ObserverStage::Connect, local, remote } = error.downcast_ref()? else {
        return None;
    };
    let deadline = tokio::time::Instant::now() + TCP_OBSERVER_ATTEMPT;
    let alternate = observe_tcp_before(SocketAddr::new(local.ip(), 0), remote, Some(deadline)).await.ok()?;
    (alternate.local.port() != local.port() && (public(alternate.mapped.ip()) || remote.ip().is_loopback()))
        .then_some(StunSourceStalled { local, observer: remote })
}

type ObserverLookup = std::sync::Mutex<std::collections::HashMap<usize, Vec<SocketAddr>>>;

pub(crate) async fn observe_tcp_invite(
    port: u16, servers: &[String], engine: &crate::runtime::Engine, mode: &str,
) -> Result<TcpObservation> {
    let resolved = ObserverLookup::default();
    let resolved = &resolved;
    crate::assistance::retry_pair_step("主机 TCP STUN 观察", |error| {
        !stun_source_unavailable(error) && transient_observer(error)
    }, |attempt| async move {
        let result = observe_tcp_impl(port, servers, engine, mode, false, resolved).await;
        // Confirm that changing source can help before replacing a configured
        // listener. A Binding timeout or an unreachable server leaves it alone.
        if attempt == 1 && stream_mode(mode) && servers.len() == 1
            && let Err(error) = &result
            && let Some(stalled) = confirm_stalled_stun_source(error).await
        {
            return Err(stalled.into());
        }
        result
    }).await
}

async fn observe_tcp_impl(
    port: u16,
    servers: &[String],
    engine: &crate::runtime::Engine,
    mode: &str,
    require_keepalive: bool,
    resolved: &ObserverLookup,
) -> Result<TcpObservation> {
    ensure!(servers.len() <= 256, "STUN 列表超过限制");
    let key = (mode.to_owned(), port);
    let start = *engine.stun_cursor.lock().unwrap().get(&key).unwrap_or(&0);
    let count = servers.len().min(8);
    // Bound each round's DNS and socket work, but do not permanently ignore
    // entries after the first eight in a migrated/default server catalogue.
    let order = (0..count).map(|offset| (start + offset) % servers.len());
    engine.stun_cursor.lock().unwrap().insert(
        key.clone(),
        if servers.is_empty() {
            0
        } else {
            (start + count) % servers.len()
        },
    );
    let mut queries = futures_util::stream::FuturesUnordered::new();
    for index in order {
        let server = &servers[index];
        queries.push(async move {
            let cached = resolved.lock().unwrap().get(&index).cloned();
            let addresses = match cached {
                Some(addresses) => addresses,
                None => {
                    let addresses = resolve_endpoint(server, true).await.unwrap_or_default();
                    if !addresses.is_empty() {
                        resolved.lock().unwrap().insert(index, addresses.clone());
                    }
                    addresses
                }
            };
            (index, addresses)
        });
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    let mut tried = std::collections::HashSet::new();
    let mut ready = Vec::new();
    let mut rejected = None;
    let mut occupied = None;
    let mut failed = None;
    while tokio::time::Instant::now() < deadline
        && let Ok(Some((index, remote))) =
            tokio::time::timeout_at(deadline, next_observer_address(&mut queries, &mut ready)).await
    {
        if !tried.insert(remote) {
            continue;
        }
        let budget = std::cmp::min(deadline, tokio::time::Instant::now() + TCP_OBSERVER_ATTEMPT);
        let mut result = match observe_tcp_endpoint(port, remote, engine, mode, budget).await {
            Ok(result) => result,
            Err(error) if stun_address_in_use(&error) => {
                occupied = Some(error);
                continue;
            }
            Err(error) => { failed = Some(error); continue; }
        };
        if require_keepalive {
            match tokio::time::timeout_at(deadline, stun_lease::verify(&mut result)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => { rejected = Some(error); continue; }
                Err(_) => break,
            }
        }
        let server = servers[index].strip_prefix("tcp://").unwrap_or(&servers[index]);
        if let Some((host, _)) = server.rsplit_once(':') {
            crate::dns::remember(crate::dns::EndpointKind::TcpStun, host, remote);
        }
        engine.stun_cursor.lock().unwrap().insert(key, index);
        return Ok(result);
    }
    if let Some(error) = rejected {
        return Err(error.into());
    }
    if let Some(error) = occupied.or(failed) {
        return Err(error.context("TCP STUN 未取得候选"));
    }
    anyhow::bail!("TCP STUN 未取得候选；这不代表已证实公网入口可达")
}
fn stun_request() -> [u8; 20] {
    let mut b = [0; 20];
    b[..2].copy_from_slice(&[0, 1]);
    b[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    b[8..].copy_from_slice(&c::random::<12>());
    b
}
pub async fn stun_tcp(stream: &mut TcpStream) -> Result<SocketAddr> {
    let request = stun_request();
    stream.write_all(&request).await?;
    let mut header = [0; 20];
    stream.read_exact(&mut header).await?;
    let size = u16::from_be_bytes(header[2..4].try_into()?) as usize;
    ensure!(size <= 4096 && size % 4 == 0, "invalid STUN framing");
    let mut bytes = header.to_vec();
    bytes.resize(20 + size, 0);
    stream.read_exact(&mut bytes[20..]).await?;
    parse_stun(&bytes, &request)
}
pub fn parse_stun(reply: &[u8], request: &[u8]) -> Result<SocketAddr> {
    ensure!(
        reply.len() >= 20 && reply[..2] == [1, 1] && reply[4..20] == request[4..20],
        "STUN transaction mismatch"
    );
    let mut at = 20;
    while at + 4 <= reply.len() {
        let kind = u16::from_be_bytes(reply[at..at + 2].try_into()?);
        let size = u16::from_be_bytes(reply[at + 2..at + 4].try_into()?) as usize;
        let next = at + 4 + (size + 3) / 4 * 4;
        ensure!(next <= reply.len(), "truncated STUN attribute");
        let data = &reply[at + 4..at + 4 + size];
        if matches!(kind, 1 | 0x20)
            && matches!(size, 8 | 20)
            && data[1] == if size == 8 { 1 } else { 2 }
        {
            let mut port = u16::from_be_bytes(data[2..4].try_into()?);
            let mut ip = data[4..].to_vec();
            if kind == 0x20 {
                port ^= 0x2112;
                for (i, b) in ip.iter_mut().enumerate() {
                    *b ^= request[4 + i];
                }
            }
            ensure!(port > 0, "zero STUN port");
            let address = if size == 8 {
                IpAddr::V4(<[u8; 4]>::try_from(ip.as_slice())?.into())
            } else {
                IpAddr::V6(<[u8; 16]>::try_from(ip.as_slice())?.into())
            };
            return Ok(SocketAddr::new(address, port));
        }
        at = next;
    }
    anyhow::bail!("STUN returned no mapped address")
}
