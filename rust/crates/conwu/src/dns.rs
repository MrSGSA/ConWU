//! Resolve fresh, independent recursive caches; the first stale response cannot
//! suppress a later resolver's current address. Coordinator and STUN clients
//! can fall back to the last endpoint that answered successfully.
use anyhow::{Result, ensure};
use futures_util::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use hickory_resolver::{TokioAsyncResolver, config::ResolverOpts, system_conf::read_system_conf};
use serde_json::Value;
use std::{
    collections::HashMap, future::Future, net::{IpAddr, SocketAddr},
    sync::{LazyLock, Mutex}, time::{Duration, Instant},
};

const RECENT_IP_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const RECENT_IP_LIMIT: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum EndpointKind {
    Coordinator,
    TcpStun,
}

type RecentKey = (EndpointKind, String, u16);
static RECENT_IPS: LazyLock<Mutex<HashMap<RecentKey, (IpAddr, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn endpoint_key(kind: EndpointKind, host: &str, port: u16) -> RecentKey {
    (kind, host.trim_end_matches('.').to_ascii_lowercase(), port)
}

pub(crate) fn remember(kind: EndpointKind, host: &str, endpoint: SocketAddr) {
    if !valid_host(host) || host.parse::<IpAddr>().is_ok() {
        return;
    }
    let mut cache = RECENT_IPS.lock().unwrap();
    let key = endpoint_key(kind, host, endpoint.port());
    if cache.len() >= RECENT_IP_LIMIT && !cache.contains_key(&key)
        && let Some(oldest) = cache.iter().min_by_key(|(_, (_, used))| *used).map(|(key, _)| key.clone())
    {
        cache.remove(&oldest);
    }
    cache.insert(key, (endpoint.ip(), Instant::now()));
}

pub(crate) fn remember_coordinator(base: &url::Url, endpoint: Option<SocketAddr>) {
    if base.scheme() == "https" && let (Some(host), Some(endpoint)) = (base.host_str(), endpoint) {
        remember(EndpointKind::Coordinator, host, endpoint);
    }
}

pub(crate) async fn with_recent_ip(
    kind: EndpointKind, host: &str, port: u16, fresh: impl Future<Output = Result<Vec<IpAddr>>>,
) -> Result<Vec<IpAddr>> {
    let error = match fresh.await {
        Ok(addresses) if !addresses.is_empty() => return Ok(addresses),
        Ok(_) => anyhow::anyhow!("DNS 未取得地址"),
        Err(error) => error,
    };
    let cached = RECENT_IPS.lock().unwrap()
        .get(&endpoint_key(kind, host, port))
        .filter(|(_, confirmed)| confirmed.elapsed() < RECENT_IP_TTL)
        .map(|(ip, _)| *ip);
    if let Some(ip) = cached {
        tracing::debug!(host, port, %ip, "DNS 查询失败，使用最近可用地址");
        Ok(vec![ip])
    } else {
        Err(error)
    }
}

pub(crate) struct CoordinatorResolver(pub u16);
impl reqwest::dns::Resolve for CoordinatorResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let port = self.0;
        Box::pin(async move {
            let host = name.as_str();
            let lookup = async {
                let resolved = tokio::time::timeout(Duration::from_secs(2), tokio::net::lookup_host((host, port))).await??;
                Ok(resolved.map(|endpoint| endpoint.ip()).collect())
            };
            let addresses = with_recent_ip(EndpointKind::Coordinator, host, port, lookup)
                .await.map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })?;
            Ok(Box::new(addresses.into_iter().map(move |ip| SocketAddr::new(ip, port))) as reqwest::dns::Addrs)
        })
    }
}

pub fn valid_host(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.trim_end_matches('.').split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
}
async fn query(name: &str, kind: u16) -> Result<Vec<String>> {
    ensure!(valid_host(name), "DNS 主机名无效");
    let mut queries: FuturesUnordered<BoxFuture<'_, Result<Vec<String>>>> = FuturesUnordered::new();
    if let Ok((config, _)) = read_system_conf() {
        let mut options = ResolverOpts::default();
        options.cache_size = 0;
        options.attempts = 1;
        options.timeout = Duration::from_secs(2);
        let resolver = TokioAsyncResolver::tokio(config, options);
        queries.push(Box::pin(async move {
            Ok(match kind {
                16 => resolver
                    .txt_lookup(name)
                    .await?
                    .iter()
                    .map(|t| String::from_utf8(t.txt_data().concat()))
                    .collect::<std::result::Result<_, _>>()?,
                1 => resolver
                    .ipv4_lookup(name)
                    .await?
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                28 => resolver
                    .ipv6_lookup(name)
                    .await?
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                _ => unreachable!(),
            })
        }));
    }
    for gateway in [
        "https://dns.alidns.com/resolve",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ] {
        queries.push(Box::pin(async move {
            let response = crate::discovery::http_client()?
                .get(gateway)
                .header("Accept", "application/dns-json")
                .header("Cache-Control", "no-cache, no-store")
                .query(&[("name", name.to_owned()), ("type", kind.to_string())])
                .send()
                .await?
                .error_for_status()?;
            ensure!(
                response.content_length().is_none_or(|n| n <= 65536),
                "DNS 应答过大"
            );
            let mut stream = response.bytes_stream();
            let mut bytes = vec![];
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk?);
                ensure!(bytes.len() <= 65536, "DNS 应答过大");
            }
            let data: Value = serde_json::from_slice(&bytes)?;
            ensure!(data["Status"] == 0, "DNS 查询未成功");
            Ok(data["Answer"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| r["type"] == kind)
                .filter_map(|r| r["data"].as_str())
                .map(|s| if kind == 16 { unquote(s) } else { s.to_owned() })
                .collect())
        }));
    }
    let mut votes: HashMap<String, (usize, usize)> = HashMap::new();
    let deadline = tokio::time::sleep(Duration::from_secs(4));
    tokio::pin!(deadline);
    loop {
        let result = tokio::select! { _ = &mut deadline => break, r = queries.next() => match r { Some(r) => r, None => break } };
        if let Ok(records) = result {
            if records.len() > 32 || records.iter().map(String::len).sum::<usize>() > 8192 {
                continue;
            }
            let mut seen = std::collections::HashSet::new();
            for value in records {
                if seen.insert(value.clone()) {
                    let order = votes.len();
                    votes.entry(value).or_insert((0, order)).0 += 1;
                }
            }
        }
    }
    let mut records: Vec<_> = votes.into_iter().collect();
    records.sort_by_key(|(_, (count, order))| (std::cmp::Reverse(*count), *order));
    ensure!(
        !records.is_empty(),
        "系统 DNS 与 HTTPS 查询均未取得有效结果"
    );
    Ok(records.into_iter().take(32).map(|(s, _)| s).collect())
}
pub async fn txt(name: &str) -> Result<Vec<String>> {
    query(name, 16).await
}
pub async fn addresses(name: &str) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = name.parse() {
        return Ok(vec![ip]);
    }
    let (v4, v6) = tokio::join!(query(name, 1), query(name, 28));
    let result: Vec<_> = v4
        .unwrap_or_default()
        .into_iter()
        .chain(v6.unwrap_or_default())
        .filter_map(|s| s.parse().ok())
        .collect();
    ensure!(!result.is_empty(), "DNS 未取得地址");
    Ok(result)
}
fn unquote(s: &str) -> String {
    let (mut text, mut quote) = (String::new(), false);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => quote = !quote,
            '\\' => {
                let mut probe = chars.clone();
                let digits: String = probe.by_ref().take(3).collect();
                if digits.len() == 3
                    && digits.bytes().all(|b| b.is_ascii_digit())
                    && digits.parse::<u8>().is_ok()
                {
                    text.push(digits.parse::<u8>().unwrap() as char);
                    chars = probe;
                } else if let Some(c) = chars.next() {
                    text.push(c);
                }
            }
            _ if quote || !c.is_whitespace() => text.push(c),
            _ => {}
        }
    }
    text
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_failed_lookup_uses_only_the_last_confirmed_endpoint_for_that_service() -> Result<()> {
        let host = "conwu-cache-regression.example";
        let cached: SocketAddr = "192.0.2.40:3478".parse()?;
        let failure = || std::future::ready(Err(anyhow::anyhow!("fixture DNS deadline")));
        remember(EndpointKind::TcpStun, host, cached);
        assert_eq!(with_recent_ip(EndpointKind::TcpStun, host, cached.port(), failure()).await?,
            vec![cached.ip()]);
        assert!(with_recent_ip(EndpointKind::TcpStun, host, 3479, failure()).await.is_err());
        assert!(with_recent_ip(EndpointKind::Coordinator, host, cached.port(), failure()).await.is_err());
        assert!(with_recent_ip(EndpointKind::TcpStun, "other.example", cached.port(), failure()).await.is_err());
        let current = vec!["192.0.2.41".parse()?];
        assert_eq!(with_recent_ip(EndpointKind::TcpStun, host, cached.port(),
            std::future::ready(Ok(current.clone()))).await?, current);
        Ok(())
    }

    #[test]
    fn quoted_chunks_and_decimal_escapes() {
        assert_eq!(
            super::unquote(r#""streamlink=" "203.0.113.1:443""#),
            "streamlink=203.0.113.1:443"
        );
        assert_eq!(super::unquote(r#""a\032b""#), "a b");
        assert!(!super::valid_host("example.org/secret"));
    }
}
