//! Resolve fresh, independent recursive caches; the first stale response cannot
//! suppress a later resolver's current address. No OS/application DNS cache.
use anyhow::{Result, ensure};
use futures_util::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use hickory_resolver::{TokioAsyncResolver, config::ResolverOpts, system_conf::read_system_conf};
use serde_json::Value;
use std::{collections::HashMap, net::IpAddr, time::Duration};

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
