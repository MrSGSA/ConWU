use anyhow::{Context, Result, ensure};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

pub struct Lease {
    pub endpoint: SocketAddr,
    pub renew: Instant,
    pub expires: Instant,
    kind: Kind,
    local: Ipv4Addr,
    gateway: Ipv4Addr,
    port: u16,
}
enum Kind {
    Pcp([u8; 12]),
    Pmp,
    Upnp {
        client: reqwest::Client,
        url: url::Url,
        service: String,
        description: String,
    },
}
impl Lease {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Extend the owned mapping in place: closing it first would interrupt an
    /// otherwise healthy connection and may allocate a different external port.
    pub async fn extend(&mut self) -> Result<()> {
        let (ip, external, lifetime) = match &self.kind {
            Kind::Pcp(nonce) => {
                pcp_exchange(
                    self.local,
                    self.gateway,
                    self.port,
                    self.endpoint.port(),
                    *nonce,
                    3600,
                )
                .await?
            }
            Kind::Pmp => {
                let response = exchange(self.local, self.gateway, &[0, 0], 12).await?;
                ensure!(response[..4] == [0, 128, 0, 0], "NAT-PMP 公网地址应答无效");
                let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&response[8..12])?);
                let (port, lifetime) = pmp_exchange(
                    self.local,
                    self.gateway,
                    self.port,
                    self.endpoint.port(),
                    3600,
                )
                .await?;
                (ip, port, lifetime)
            }
            Kind::Upnp {
                client,
                url,
                service,
                description,
            } => {
                let query = query(self.endpoint.port());
                let response =
                    soap(client, url, service, "GetSpecificPortMappingEntry", &query).await?;
                ensure!(
                    upnp_owned(&response, self.local, self.port, description)?,
                    "UPnP 映射已不属于本机，拒绝覆盖"
                );
                let ip = upnp_ip(client, url, service).await?;
                public_endpoint(ip, self.endpoint.port())?;
                let args = format!(
                    "{query}<NewInternalPort>{}</NewInternalPort><NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{description}</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>",
                    self.port, self.local
                );
                soap(client, url, service, "AddPortMapping", &args).await?;
                (ip, self.endpoint.port(), 3600)
            }
        };
        ensure!(lifetime >= 30, "映射续租的租期过短");
        self.endpoint = public_endpoint(ip, external)?;
        self.renew = Instant::now() + Duration::from_secs(lifetime as u64 / 2);
        self.expires = Instant::now() + Duration::from_secs(lifetime as u64);
        Ok(())
    }
    pub async fn acquire(port: u16) -> Result<Self> {
        let (local, gateway) = tokio::task::spawn_blocking(route).await??;
        if let Ok(lease) = pcp(local, gateway, port).await {
            return Ok(lease);
        }
        if let Ok(lease) = pmp(local, gateway, port).await {
            return Ok(lease);
        }
        upnp(local, gateway, port).await
    }
    pub async fn close(&self) -> Result<()> {
        match &self.kind {
            Kind::Pcp(nonce) => {
                pcp_exchange(
                    self.local,
                    self.gateway,
                    self.port,
                    self.endpoint.port(),
                    *nonce,
                    0,
                )
                .await?;
            }
            Kind::Pmp => {
                pmp_exchange(self.local, self.gateway, self.port, self.endpoint.port(), 0).await?;
            }
            Kind::Upnp {
                client,
                url,
                service,
                description,
            } => {
                let query = query(self.endpoint.port());
                if let Ok(response) =
                    soap(client, url, service, "GetSpecificPortMappingEntry", &query).await
                {
                    if upnp_owned(&response, self.local, self.port, description)? {
                        soap(client, url, service, "DeletePortMapping", &query).await?;
                    }
                }
            }
        }
        Ok(())
    }
}
fn public_endpoint(ip: Ipv4Addr, port: u16) -> Result<SocketAddr> {
    let e = SocketAddr::new(IpAddr::V4(ip), port);
    ensure!(
        crate::discovery::public(e.ip()) && port > 0,
        "网关仍位于上游 NAT 内，未取得公网入口"
    );
    Ok(e)
}
async fn exchange(
    local: Ipv4Addr,
    gateway: Ipv4Addr,
    request: &[u8],
    minimum: usize,
) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind((local, 0)).await?;
    socket.connect((gateway, 5351)).await?;
    socket.send(request).await?;
    let mut response = vec![0; 1100];
    let n = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut response)).await??;
    ensure!(n >= minimum, "网关应答截断");
    response.truncate(n);
    Ok(response)
}
fn pcp_wire(local: Ipv4Addr, port: u16, external: u16, nonce: [u8; 12], lifetime: u32) -> [u8; 60] {
    let mut request = [0; 60];
    request[0] = 2;
    request[1] = 1;
    request[4..8].copy_from_slice(&lifetime.to_be_bytes());
    request[18..20].copy_from_slice(&[255, 255]);
    request[20..24].copy_from_slice(&local.octets());
    request[24..36].copy_from_slice(&nonce);
    request[36] = 6;
    request[40..42].copy_from_slice(&port.to_be_bytes());
    request[42..44].copy_from_slice(&external.to_be_bytes());
    request
}
async fn pcp_exchange(
    local: Ipv4Addr,
    gateway: Ipv4Addr,
    port: u16,
    external: u16,
    nonce: [u8; 12],
    lifetime: u32,
) -> Result<(Ipv4Addr, u16, u32)> {
    let response = exchange(
        local,
        gateway,
        &pcp_wire(local, port, external, nonce, lifetime),
        60,
    )
    .await?;
    ensure!(
        response[0] == 2
            && response[1] == 0x81
            && response[3] == 0
            && response[24..36] == nonce
            && response[36] == 6
            && response[40..42] == port.to_be_bytes()
            && response[44..56] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255],
        "PCP 映射身份或结果无效"
    );
    Ok((
        Ipv4Addr::from(<[u8; 4]>::try_from(&response[56..60])?),
        u16::from_be_bytes(response[42..44].try_into()?),
        u32::from_be_bytes(response[4..8].try_into()?),
    ))
}
async fn pcp(local: Ipv4Addr, gateway: Ipv4Addr, port: u16) -> Result<Lease> {
    let nonce = conwu_core::crypto::random();
    let (ip, external, lifetime) = pcp_exchange(local, gateway, port, port, nonce, 3600).await?;
    ensure!(lifetime >= 30, "PCP 租期过短");
    Ok(Lease {
        endpoint: public_endpoint(ip, external)?,
        renew: Instant::now() + Duration::from_secs(lifetime as u64 / 2),
        expires: Instant::now() + Duration::from_secs(lifetime as u64),
        kind: Kind::Pcp(nonce),
        local,
        gateway,
        port,
    })
}
async fn pmp_exchange(
    local: Ipv4Addr,
    gateway: Ipv4Addr,
    internal: u16,
    external: u16,
    lifetime: u32,
) -> Result<(u16, u32)> {
    let mut request = [0; 12];
    request[1] = 2;
    request[4..6].copy_from_slice(&internal.to_be_bytes());
    request[6..8].copy_from_slice(&external.to_be_bytes());
    request[8..12].copy_from_slice(&lifetime.to_be_bytes());
    let response = exchange(local, gateway, &request, 16).await?;
    ensure!(
        response[..4] == [0, 130, 0, 0] && response[8..10] == internal.to_be_bytes(),
        "NAT-PMP 映射无效"
    );
    Ok((
        u16::from_be_bytes(response[10..12].try_into()?),
        u32::from_be_bytes(response[12..16].try_into()?),
    ))
}
async fn pmp(local: Ipv4Addr, gateway: Ipv4Addr, port: u16) -> Result<Lease> {
    let response = exchange(local, gateway, &[0, 0], 12).await?;
    ensure!(response[..4] == [0, 128, 0, 0], "NAT-PMP 公网地址应答无效");
    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&response[8..12])?);
    public_endpoint(ip, port)?;
    let (external, lifetime) = pmp_exchange(local, gateway, port, port, 3600).await?;
    ensure!(lifetime >= 30, "NAT-PMP 租期过短");
    Ok(Lease {
        endpoint: public_endpoint(ip, external)?,
        renew: Instant::now() + Duration::from_secs(lifetime as u64 / 2),
        expires: Instant::now() + Duration::from_secs(lifetime as u64),
        kind: Kind::Pmp,
        local,
        gateway,
        port,
    })
}
fn gateway_url(s: &str, gateway: Ipv4Addr) -> Result<url::Url> {
    let u = url::Url::parse(s)?;
    ensure!(
        u.scheme() == "http"
            && u.host_str()
                .is_some_and(|s| s.parse::<Ipv4Addr>().ok() == Some(gateway))
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none(),
        "UPnP 仅访问实际网关"
    );
    Ok(u)
}
async fn bounded(response: reqwest::Response) -> Result<String> {
    use futures_util::StreamExt;
    let response = response.error_for_status()?;
    ensure!(
        response.content_length().is_none_or(|n| n <= 65536),
        "UPnP 应答过大"
    );
    let mut stream = response.bytes_stream();
    let mut result = vec![];
    while let Some(chunk) = stream.next().await {
        result.extend_from_slice(&chunk?);
        ensure!(result.len() <= 65536, "UPnP 应答过大");
    }
    Ok(String::from_utf8(result)?)
}
async fn soap(
    client: &reqwest::Client,
    url: &url::Url,
    service: &str,
    action: &str,
    args: &str,
) -> Result<String> {
    ensure!(
        service
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":-._".contains(&b)),
        "UPnP 服务名无效"
    );
    let body = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{service}\">{args}</u:{action}></s:Body></s:Envelope>"
    );
    bounded(
        client
            .post(url.clone())
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("SOAPAction", format!("\"{service}#{action}\""))
            .body(body)
            .send()
            .await?,
    )
    .await
}
fn query(port: u16) -> String {
    format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort><NewProtocol>TCP</NewProtocol>"
    )
}
fn upnp_owned(response: &str, local: Ipv4Addr, port: u16, description: &str) -> Result<bool> {
    let doc = roxmltree::Document::parse(response)?;
    let field = |name| {
        doc.descendants()
            .find(|n| n.tag_name().name() == name)
            .and_then(|n| n.text())
            .unwrap_or("")
    };
    Ok(field("NewInternalClient") == local.to_string()
        && field("NewInternalPort") == port.to_string()
        && field("NewPortMappingDescription") == description)
}
async fn upnp_ip(client: &reqwest::Client, url: &url::Url, service: &str) -> Result<Ipv4Addr> {
    let xml = soap(client, url, service, "GetExternalIPAddress", "").await?;
    let doc = roxmltree::Document::parse(&xml)?;
    Ok(doc
        .descendants()
        .find(|n| n.tag_name().name() == "NewExternalIPAddress")
        .and_then(|n| n.text())
        .context("网关无公网地址")?
        .parse()?)
}
async fn upnp(local: Ipv4Addr, gateway: Ipv4Addr, port: u16) -> Result<Lease> {
    let socket = UdpSocket::bind((local, 0)).await?;
    socket.send_to(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n","239.255.255.250:1900").await?;
    let location = tokio::time::timeout(Duration::from_secs(2), async {
        let mut bytes = [0; 8192];
        loop {
            let (n, from) = socket.recv_from(&mut bytes).await?;
            if from.ip() != IpAddr::V4(gateway) {
                continue;
            }
            for line in std::str::from_utf8(&bytes[..n])?.lines() {
                if let Some((k, v)) = line.split_once(':') {
                    if k.eq_ignore_ascii_case("location") {
                        return gateway_url(v.trim(), gateway);
                    }
                }
            }
        }
    })
    .await??;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .local_address(IpAddr::V4(local))
        .timeout(Duration::from_secs(3))
        .build()?;
    let xml = bounded(client.get(location.clone()).send().await?).await?;
    let (url, service) = {
        let doc = roxmltree::Document::parse(&xml)?;
        let (control, service) = doc
            .descendants()
            .filter(|n| n.tag_name().name() == "service")
            .find_map(|node| {
                let kind = node
                    .children()
                    .find(|n| n.tag_name().name() == "serviceType")?
                    .text()?;
                let control = node
                    .children()
                    .find(|n| n.tag_name().name() == "controlURL")?
                    .text()?;
                if kind.starts_with("urn:schemas-upnp-org:service:WANIPConnection:")
                    || kind.starts_with("urn:schemas-upnp-org:service:WANPPPConnection:")
                {
                    Some((control, kind))
                } else {
                    None
                }
            })
            .context("网关不提供 UPnP 映射")?;
        (
            gateway_url(location.join(control)?.as_str(), gateway)?,
            service.to_string(),
        )
    };
    let ip = upnp_ip(&client, &url, &service).await?;
    let endpoint = public_endpoint(ip, port)?;
    let query = query(port);
    ensure!(
        soap(
            &client,
            &url,
            &service,
            "GetSpecificPortMappingEntry",
            &query
        )
        .await
        .is_err(),
        "此端口已有映射，拒绝覆盖"
    );
    let description = format!("ConWU Rust {}", conwu_core::id());
    let args = format!(
        "{query}<NewInternalPort>{port}</NewInternalPort><NewInternalClient>{local}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{description}</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>"
    );
    soap(&client, &url, &service, "AddPortMapping", &args).await?;
    Ok(Lease {
        endpoint,
        renew: Instant::now() + Duration::from_secs(1800),
        expires: Instant::now() + Duration::from_secs(3600),
        kind: Kind::Upnp {
            client,
            url,
            service,
            description,
        },
        local,
        gateway,
        port,
    })
}
#[cfg(target_os = "linux")]
fn route() -> Result<(Ipv4Addr, Ipv4Addr)> {
    let output = std::process::Command::new("ip")
        .args(["-j", "route", "get", "1.1.1.1"])
        .output()?;
    ensure!(output.status.success(), "默认出口查询失败");
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    Ok((
        rows[0]["prefsrc"]
            .as_str()
            .context("出口无 IPv4")?
            .parse()?,
        rows[0]["gateway"].as_str().context("出口无网关")?.parse()?,
    ))
}
#[cfg(windows)]
fn route() -> Result<(Ipv4Addr, Ipv4Addr)> {
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2},
        Networking::WinSock::{AF_INET, SOCKADDR_INET},
    };
    unsafe {
        let mut remote: SOCKADDR_INET = std::mem::zeroed();
        remote.Ipv4.sin_family = AF_INET;
        remote.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([1, 1, 1, 1]);
        let mut route: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        let mut source: SOCKADDR_INET = std::mem::zeroed();
        ensure!(
            GetBestRoute2(
                std::ptr::null(),
                0,
                std::ptr::null(),
                &remote,
                0,
                &mut route,
                &mut source
            ) == 0,
            "默认网关查询失败"
        );
        let local = Ipv4Addr::from(source.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
        let gateway = Ipv4Addr::from(route.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
        ensure!(
            !gateway.is_unspecified() && !local.is_unspecified(),
            "出口无网关"
        );
        Ok((local, gateway))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pcp_nonce_and_ports() {
        let request = pcp_wire(Ipv4Addr::new(192, 168, 1, 2), 40000, 50000, [7; 12], 3600);
        assert_eq!(&request[24..36], &[7; 12]);
        assert_eq!(&request[40..42], &40000u16.to_be_bytes());
        assert_eq!(&request[42..44], &50000u16.to_be_bytes());
        assert_eq!(request[36], 6);
    }
    #[test]
    fn upnp_urls_stay_on_gateway() {
        assert!(
            gateway_url(
                "http://192.168.1.1:80/control",
                Ipv4Addr::new(192, 168, 1, 1)
            )
            .is_ok()
        );
        assert!(gateway_url("http://example.com/control", Ipv4Addr::new(192, 168, 1, 1)).is_err());
    }
    #[tokio::test]
    async fn upnp_extends_without_deleting_and_checks_ownership() -> Result<()> {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        let owned = Arc::new(AtomicBool::new(true));
        let adds = Arc::new(AtomicUsize::new(0));
        let deletes = Arc::new(AtomicUsize::new(0));
        let (o, a, d) = (owned.clone(), adds.clone(), deletes.clone());
        let router = axum::Router::new().fallback(move |headers: axum::http::HeaderMap| {
            let (owned, adds, deletes) = (o.clone(), a.clone(), d.clone());
            async move {
                let action = headers.get("SOAPAction").unwrap().to_str().unwrap();
                if action.contains("GetSpecificPortMappingEntry") {
                    return format!("<reply><NewInternalClient>127.0.0.1</NewInternalClient><NewInternalPort>40000</NewInternalPort><NewPortMappingDescription>{}</NewPortMappingDescription></reply>", if owned.load(Ordering::Relaxed) { "fixture" } else { "another-application" });
                }
                if action.contains("GetExternalIPAddress") {
                    return "<reply><NewExternalIPAddress>203.0.113.1</NewExternalIPAddress></reply>".into();
                }
                if action.contains("AddPortMapping") { adds.fetch_add(1, Ordering::Relaxed); }
                if action.contains("DeletePortMapping") { deletes.fetch_add(1, Ordering::Relaxed); }
                "<reply/>".into()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = url::Url::parse(&format!("http://{}/control", listener.local_addr()?))?;
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let mut lease = Lease {
            endpoint: "203.0.113.1:40000".parse()?,
            renew: Instant::now(),
            expires: Instant::now(),
            local: Ipv4Addr::LOCALHOST,
            gateway: Ipv4Addr::LOCALHOST,
            port: 40000,
            kind: Kind::Upnp {
                client: crate::discovery::http_client()?,
                url,
                service: "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
                description: "fixture".into(),
            },
        };
        lease.extend().await?;
        ensure!(
            adds.load(Ordering::Relaxed) == 1 && deletes.load(Ordering::Relaxed) == 0,
            "续租不能先删映射"
        );
        ensure!(
            lease.expires > Instant::now() && lease.renew > Instant::now(),
            "续租应更新到期时间"
        );
        owned.store(false, Ordering::Relaxed);
        ensure!(lease.extend().await.is_err(), "归属变化时不能覆盖映射");
        lease.close().await?;
        ensure!(
            adds.load(Ordering::Relaxed) == 1 && deletes.load(Ordering::Relaxed) == 0,
            "不能修改或删除其他应用的映射"
        );
        server.abort();
        Ok(())
    }
}
