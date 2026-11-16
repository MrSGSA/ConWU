use crate::backend::App;
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any,
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

static ASSETS: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/../../../src/ConWU.Web/wwwroot");
struct Session {
    csrf: String,
    issued: Instant,
    seen: Instant,
    requests: HashSet<String>,
}
pub struct Panel {
    pub app: Arc<App>,
    pub origin: String,
    pub bootstrap: String,
    cookie_name: String,
    tickets: Mutex<HashMap<String, Instant>>,
    sessions: Mutex<HashMap<String, Session>>,
    rate: Mutex<(Instant, u32)>,
}
impl Panel {
    pub async fn start(
        app: Arc<App>,
        port: u16,
    ) -> Result<(Arc<Self>, tokio::task::JoinHandle<Result<()>>)> {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let port = listener.local_addr()?.port();
        let state = Arc::new(Self {
            app,
            origin: format!("http://127.0.0.1:{port}"),
            bootstrap: hex::encode(conwu_core::crypto::random::<32>()),
            cookie_name: format!("ConwuRustSession_{port}"),
            tickets: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            rate: Mutex::new((Instant::now(), 0)),
        });
        let router = Router::new()
            .fallback(any(handle))
            .layer(DefaultBodyLimit::max(256 * 1024))
            .layer(middleware::from_fn(security_headers))
            .with_state(state.clone());
        let cancel = state.app.engine.cancel.clone();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(cancel.cancelled_owned())
            .await?;
            Ok(())
        });
        Ok((state, task))
    }
    pub fn link(&self) -> String {
        let ticket = hex::encode_upper(conwu_core::crypto::random::<32>());
        let mut tickets = self.tickets.lock().unwrap();
        tickets.retain(|_, t| t.elapsed() < Duration::from_secs(60));
        if tickets.len() >= 16 {
            tickets.clear();
        }
        tickets.insert(ticket.clone(), Instant::now());
        format!("{}/#{ticket}", self.origin)
    }
    fn authenticated(&self, mut response: Response, id: &str, age: u64) -> Response {
        response.headers_mut().insert(
            header::SET_COOKIE,
            format!(
                "{}={id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={age}",
                self.cookie_name
            )
            .parse()
            .expect("generated cookie"),
        );
        response
    }
}
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (k, v) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    ] {
        headers.insert(axum::http::HeaderName::from_static(k), v.parse().unwrap());
    }
    response
}
async fn handle(
    State(panel): State<Arc<Panel>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    match process(panel, remote, request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::debug!("WebUI 请求未完成：{error}");
            (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"ok":false,"error":error.to_string()})),
            )
                .into_response()
        }
    }
}
async fn process(panel: Arc<Panel>, remote: SocketAddr, request: Request) -> Result<Response> {
    let headers = request.headers();
    let authority = panel.origin.strip_prefix("http://").unwrap();
    ensure!(
        remote.ip().is_loopback() && text(headers, "host") == authority,
        "非法面板来源"
    );
    let origin = text(headers, "origin");
    ensure!(
        origin.is_empty() || origin == panel.origin,
        "非法面板 Origin"
    );
    ensure!(
        ["", "none", "same-origin"].contains(&text(headers, "sec-fetch-site")),
        "非法跨站请求"
    );
    {
        let mut r = panel.rate.lock().unwrap();
        if r.0.elapsed() >= Duration::from_secs(10) {
            *r = (Instant::now(), 0);
        }
        r.1 += 1;
        if r.1 > 150 {
            return Ok(StatusCode::TOO_MANY_REQUESTS.into_response());
        }
    }
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();
    let post = request.method() == "POST";
    let get = request.method() == "GET";
    ensure!(
        (get || post) && (query.is_empty() || get && path == "/api/status"),
        "非法请求方法或查询"
    );
    if get && !path.starts_with("/api/") {
        let file = match path.as_str() {
            "/" => "index.html",
            "/streamlink-tokyo-45.svg" => "icon.svg",
            "/app.js" | "/workspace.js" | "/experience.js" | "/uu-takeover.js" | "/style.css"
            | "/experience.css" | "/icon.svg" => &path[1..],
            _ => return Ok(StatusCode::NOT_FOUND.into_response()),
        };
        let file = ASSETS.get_file(file).context("界面资源缺失")?;
        let content = if path.ends_with(".js") {
            "text/javascript; charset=utf-8"
        } else if path.ends_with(".css") {
            "text/css; charset=utf-8"
        } else if path.ends_with(".svg") {
            "image/svg+xml"
        } else {
            "text/html; charset=utf-8"
        };
        return Ok((
            [(header::CONTENT_TYPE, content)],
            Body::from(file.contents()),
        )
            .into_response());
    }
    if post {
        ensure!(
            origin == panel.origin
                && text(headers, "content-type").split(';').next() == Some("application/json"),
            "非法面板提交"
        );
    }
    let cookie = text(headers, "cookie")
        .split(';')
        .map(str::trim)
        .find_map(|c| c.strip_prefix(&format!("{}=", panel.cookie_name)))
        .unwrap_or("")
        .to_string();
    let csrf = text(headers, "x-streamlink-csrf").to_string();
    let body = if post {
        let bytes = axum::body::to_bytes(request.into_body(), 256 * 1024).await?;
        serde_json::from_slice::<Value>(&bytes)?
    } else {
        Value::Null
    };
    if post && matches!(path.as_str(), "/api/open" | "/api/stop") {
        let secret = body["secret"].as_str().unwrap_or("");
        if !conwu_core::crypto::eq(secret.as_bytes(), panel.bootstrap.as_bytes()) {
            return Ok(StatusCode::UNAUTHORIZED.into_response());
        }
        if path == "/api/stop" {
            panel.app.engine.cancel.cancel();
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        return Ok(axum::Json(json!({"url":panel.link()})).into_response());
    }
    if post && path == "/api/session" {
        let ticket = body["ticket"].as_str().context("缺少面板票据")?;
        let accepted = panel
            .tickets
            .lock()
            .unwrap()
            .remove(ticket)
            .is_some_and(|t| t.elapsed() < Duration::from_secs(60));
        if !accepted {
            return Ok(StatusCode::UNAUTHORIZED.into_response());
        }
        let id = hex::encode(conwu_core::crypto::random::<32>());
        let csrf = hex::encode(conwu_core::crypto::random::<32>());
        let mut sessions = panel.sessions.lock().unwrap();
        sessions.retain(|_, s| {
            s.seen.elapsed() < Duration::from_secs(1800)
                && s.issued.elapsed() < Duration::from_secs(14400)
        });
        ensure!(sessions.len() < 8, "面板会话数已满");
        sessions.insert(
            id.clone(),
            Session {
                csrf: csrf.clone(),
                issued: Instant::now(),
                seen: Instant::now(),
                requests: HashSet::new(),
            },
        );
        return Ok(panel.authenticated(
            axum::Json(json!({"csrf":csrf})).into_response(),
            &id,
            1800,
        ));
    }
    let age = {
        let mut sessions = panel.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(&cookie) else {
            return Ok(StatusCode::UNAUTHORIZED.into_response());
        };
        if session.seen.elapsed() > Duration::from_secs(1800)
            || session.issued.elapsed() > Duration::from_secs(14400)
        {
            sessions.remove(&cookie);
            return Ok(StatusCode::UNAUTHORIZED.into_response());
        }
        session.seen = Instant::now();
        if post {
            if !conwu_core::crypto::eq(csrf.as_bytes(), session.csrf.as_bytes()) {
                return Ok((
                    StatusCode::FORBIDDEN,
                    axum::Json(
                        json!({"ok":false,"code":"SessionChanged","error":"面板会话已改变"}),
                    ),
                )
                    .into_response());
            }
            if path == "/api/command" {
                let id = body["operationId"].as_str().context("缺少操作编号")?;
                ensure!(
                    session.requests.len() < 512 || session.requests.contains(id),
                    "会话请求过多"
                );
                session.requests.insert(id.into());
            }
        }
        let age = 1800.min(14400u64.saturating_sub(session.issued.elapsed().as_secs()));
        if get && path == "/api/session" {
            return Ok(panel.authenticated(
                axum::Json(json!({"csrf":session.csrf})).into_response(),
                &cookie,
                age,
            ));
        }
        age
    };
    if get && path == "/api/status" {
        let params = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
        let mut seen = HashSet::new();
        for (k, v) in &params {
            ensure!(seen.insert(k.as_ref()), "重复状态选择器");
            match k.as_ref() {
                "networkId" => ensure!(conwu_core::valid_id(v), "网络编号无效"),
                "operation" => {
                    uuid::Uuid::parse_str(v)?;
                }
                _ => anyhow::bail!("未知状态选择器"),
            }
        }
        let network = params
            .iter()
            .find(|(k, _)| k == "networkId")
            .map_or("", |(_, v)| v.as_ref());
        let operation = params
            .iter()
            .find(|(k, _)| k == "operation")
            .map(|(_, v)| v.as_ref());
        return Ok(panel.authenticated(
            axum::Json(panel.app.reply(network, operation)).into_response(),
            &cookie,
            age,
        ));
    }
    if post && path == "/api/command" {
        return Ok(panel.authenticated(
            axum::Json(panel.app.submit(body)?).into_response(),
            &cookie,
            age,
        ));
    }
    Ok(StatusCode::NOT_FOUND.into_response())
}
fn text<'a>(headers: &'a HeaderMap, key: &str) -> &'a str {
    headers.get(key).and_then(|v| v.to_str().ok()).unwrap_or("")
}
