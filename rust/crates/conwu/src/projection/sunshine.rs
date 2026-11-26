use std::{
    collections::BTreeMap,
    fs,
    io::Cursor,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use conwu_core::crypto;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::{
    SUNSHINE_PORT as PORT,
    process::{DesktopJob, close_sunshine_monitor},
};

// A separate GameStream port family keeps an existing Sunshine installation usable.
pub(super) const TCP: [u16; 3] = [PORT - 5, PORT, PORT + 21];
pub(super) const UDP: [u16; 3] = [PORT + 9, PORT + 10, PORT + 11];
pub(super) const PANEL: u16 = PORT + 1;
const STARTUP_WINDOW: Duration = Duration::from_secs(75);

pub(super) async fn game_stream_busy(local: Ipv4Addr, host: Ipv4Addr, port: u16) -> Result<bool> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .local_address(IpAddr::V4(local))
        .timeout(Duration::from_secs(3))
        .build()?;
    let mut response = client
        .get(format!("http://{host}:{port}/serverinfo"))
        .send()
        .await
        .context("无法通过 ConWU 虚拟地址访问 Sunshine")?
        .error_for_status()
        .context("Sunshine 未返回设备信息")?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len() + chunk.len() <= 32 * 1024,
            "Sunshine 设备信息过大"
        );
        body.extend_from_slice(&chunk);
    }
    let xml = roxmltree::Document::parse(std::str::from_utf8(&body)?)?;
    let root = xml.root_element();
    ensure!(
        root.has_tag_name("root")
            && root.attribute("status_code") == Some("200")
            && root
                .children()
                .any(|tag| tag.has_tag_name("uniqueid") && tag.text().is_some()),
        "对端未返回有效的 Sunshine 设备信息"
    );
    Ok(root
        .children()
        .any(|tag| tag.has_tag_name("state") && tag.text() == Some("SUNSHINE_SERVER_BUSY")))
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct Binding {
    pub record: String,
    pub network: String,
    pub local: Ipv4Addr,
    pub remote: Ipv4Addr,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub(crate) struct Status {
    pub ready: bool,
    pub message: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Report {
    pub binding: Binding,
    pub status: Status,
}

#[derive(Default)]
pub(crate) struct Hosts {
    sessions: BTreeMap<String, Session>,
}

struct Session {
    binding: Binding,
    program: PathBuf,
    status: watch::Receiver<Status>,
    approval: mpsc::Sender<String>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Hosts {
    pub(crate) fn pairing_for(
        &self,
        record: &str,
        local: Ipv4Addr,
        remote: Ipv4Addr,
    ) -> Option<mpsc::Sender<String>> {
        self.sessions
            .get(record)
            .filter(|session| {
                session.binding.local == local
                    && session.binding.remote == remote
                    && !session.task.is_finished()
            })
            .map(|session| session.approval.clone())
    }

    pub(crate) fn reports(&self) -> Vec<Report> {
        self.sessions
            .values()
            .map(|session| Report {
                binding: session.binding.clone(),
                status: session.status.borrow().clone(),
            })
            .collect()
    }

    pub(crate) fn synchronize(&mut self, data: &Path, program: &Path, bindings: Vec<Binding>) {
        self.sessions.retain(|_, session| {
            session.program == program
                && !session.task.is_finished()
                && bindings.contains(&session.binding)
        });
        for binding in bindings {
            self.sessions
                .entry(binding.record.clone())
                .or_insert_with(|| {
                    let (status, current) = watch::channel(Status::default());
                    let (approval, pending) = mpsc::channel(1);
                    let stop = CancellationToken::new();
                    let task = tokio::spawn(serve(
                        data.to_owned(),
                        program.to_owned(),
                        binding.clone(),
                        status,
                        pending,
                        stop.clone(),
                    ));
                    Session {
                        binding,
                        program: program.to_owned(),
                        status: current,
                        approval,
                        stop,
                        task,
                    }
                });
        }
    }
}

struct Admin {
    client: reqwest::Client,
    url: String,
    password: Zeroizing<String>,
}

#[derive(Deserialize)]
struct Pairing {
    id: String,
    address: Ipv4Addr,
}

impl Admin {
    fn new(certificate: &Path, local: Ipv4Addr, password: Zeroizing<String>) -> Result<Self> {
        crate::store::reject_link(certificate)?;
        let pem = fs::read(certificate)?;
        ensure!(pem.len() <= 32 * 1024, "Projection 证书超过大小限制");
        let certificate = rustls_pemfile::certs(&mut Cursor::new(pem))
            .next()
            .context("Projection 证书缺失")??;
        Ok(Self {
            client: crate::transport::pinned_http(&hex::encode(crypto::hash(
                certificate.as_ref(),
            )))?,
            url: format!("https://{local}:{PANEL}/api/pin"),
            password,
        })
    }

    async fn pending(&self, peer: Ipv4Addr) -> Result<Option<String>> {
        #[derive(Deserialize)]
        struct Reply {
            pairings: Vec<Pairing>,
        }
        let reply: Reply = self
            .client
            .get(&self.url)
            .basic_auth("projection", Some(self.password.as_str()))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let mut matching = reply
            .pairings
            .into_iter()
            .filter(|pairing| pairing.address == peer);
        let first = matching.next();
        ensure!(
            matching.next().is_none(),
            "此设备有多项待确认的配对，请关闭重复请求"
        );
        Ok(first.map(|pairing| pairing.id))
    }

    async fn approve(&self, id: &str, pin: &str) -> Result<()> {
        let reply: Value = self
            .client
            .post(&self.url)
            // Sunshine responds after the GameStream pairing finishes or its ten-second wait expires.
            .timeout(Duration::from_secs(15))
            .basic_auth("projection", Some(self.password.as_str()))
            .json(&json!({"pairing_id": id, "pin": pin, "name": "ConWU Projection"}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        ensure!(
            reply["status"] == true,
            "PIN 校验未通过，请核对播放端显示的数字"
        );
        Ok(())
    }
}

async fn serve(
    data: PathBuf,
    program: PathBuf,
    binding: Binding,
    report: watch::Sender<Status>,
    mut approvals: mpsc::Receiver<String>,
    stop: CancellationToken,
) {
    loop {
        let result = serve_once(&data, &program, &binding, &report, &mut approvals, &stop).await;
        if stop.is_cancelled() {
            break;
        }
        report.send_replace(Status {
            message: result.err().map(|error| error.to_string()),
            ..Default::default()
        });
        while approvals.try_recv().is_ok() {}
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(12)) => {}
        }
    }
}

async fn serve_once(
    data: &Path,
    program: &Path,
    binding: &Binding,
    report: &watch::Sender<Status>,
    approvals: &mut mpsc::Receiver<String>,
    stop: &CancellationToken,
) -> Result<()> {
    let identity = hex::encode(crypto::hash(binding.network.as_bytes()));
    let state = super::state_dir(data, "Sunshine", &identity)?;
    let password = Zeroizing::new(hex::encode(crypto::random::<24>()));
    let salt = hex::encode(crypto::random::<16>());
    let salted = Zeroizing::new(format!("{}{salt}", password.as_str()));
    // Sunshine's persisted credential format uses util::hex, which reverses the digest bytes.
    let mut hash = crypto::hash(salted.as_bytes());
    hash.reverse();
    let credentials = json!({
        "username": "projection",
        "salt": salt,
        "password": hex::encode_upper(hash),
    });
    super::write_state(
        &state,
        "credentials.json",
        &serde_json::to_vec(&credentials)?,
    )?;
    super::write_state(
        &state,
        "apps.json",
        br#"{"env":{},"apps":[{"name":"Desktop"}]}"#,
    )?;
    let directory = state.to_str().context("Projection 配置路径编码无效")?;
    ensure!(
        !directory.contains(['\r', '\n', '#']),
        "Projection 配置路径含保留字符"
    );
    let config = format!(
        concat!(
            "sunshine_name = Projection\naddress_family = ipv4\nbind_address = {local}\nport = {port}\n",
            "upnp = disabled\nsystem_tray = disabled\norigin_web_ui_allowed = wan\n",
            "dd_configuration_option = disabled\n",
            "install_steam_audio_drivers = disabled\n",
            "file_apps = {directory}/apps.json\nfile_state = {directory}/sunshine_state.json\n",
            "credentials_file = {directory}/credentials.json\nlog_path = {directory}/sunshine.log\n",
            "pkey = {directory}/cakey.pem\ncert = {directory}/cacert.pem\n",
        ),
        local = binding.local,
        port = PORT,
        directory = directory,
    );
    let config_path = super::write_state(&state, "host.conf", config.as_bytes())?;
    for name in [
        "sunshine_state.json",
        "sunshine.log",
        "cakey.pem",
        "cacert.pem",
    ] {
        let file = state.join(name);
        if fs::symlink_metadata(&file).is_ok() {
            crate::store::reject_link(&file)?;
        }
    }
    let job = DesktopJob::new()?;
    let directory = program.parent().context("Sunshine 运行目录无效")?;
    let mut host = job.spawn(
        program,
        directory,
        &[config_path
            .to_str()
            .context("Projection 配置路径编码无效")?],
        Stdio::null(),
        &[],
    )?;
    let pid = host.id().context("Sunshine 未能启动")?;
    let result = tokio::select! {
        _ = stop.cancelled() => Ok(()),
        result = host.wait() => {
            bail!("随包 Sunshine 进程已退出（{}）", result?);
        }
        result = monitor(binding, &state, password, report, approvals) => result,
    };
    close_sunshine_monitor(pid);
    let _ = tokio::time::timeout(Duration::from_secs(3), host.wait()).await;
    result
}

async fn monitor(
    binding: &Binding,
    state: &Path,
    password: Zeroizing<String>,
    report: &watch::Sender<Status>,
    approvals: &mut mpsc::Receiver<String>,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let ready_by = Instant::now() + STARTUP_WINDOW;
    let certificate = state.join("cacert.pem");
    while !certificate.is_file() {
        ensure!(
            Instant::now() < ready_by,
            "随包 Sunshine 未能生成本机配对证书"
        );
        interval.tick().await;
    }
    let admin = Admin::new(&certificate, binding.local, password)?;
    let mut last_response: Option<Instant> = None;
    let mut message = None;
    let mut queued_pin = None;
    loop {
        interval.tick().await;
        let pairing = match admin.pending(binding.remote).await {
            Ok(pairing) => pairing,
            Err(error) => {
                if last_response.map_or_else(
                    || Instant::now() >= ready_by,
                    |seen| seen.elapsed() >= Duration::from_secs(15),
                ) {
                    return Err(error).context("无法访问随包 Sunshine 的本机配对接口");
                }
                continue;
            }
        };
        last_response = Some(Instant::now());
        if let Ok(pin) = approvals.try_recv() {
            queued_pin = Some((Zeroizing::new(pin), Instant::now() + Duration::from_secs(8)));
        }
        if let Some((_, deadline)) = queued_pin.as_ref() {
            if Instant::now() >= *deadline {
                queued_pin = None;
                message = Some("配对请求已结束，请从播放端重试".into());
            } else if let Some(id) = pairing {
                let (pin, _) = queued_pin.take().unwrap();
                message = Some(match admin.approve(&id, &pin).await {
                    Ok(()) => "设备已完成配对".into(),
                    Err(error) => error.to_string(),
                });
            }
        }
        report.send_replace(Status {
            ready: true,
            message: message.clone(),
        });
    }
}
