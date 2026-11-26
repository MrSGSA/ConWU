use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::{Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
use zeroize::ZeroizeOnDrop;

use crate::transport::{self, TlsIdentity};
use super::display::DisplayMode;

pub(crate) mod browser;
mod clipboard;
mod desktop;
pub(crate) mod device;
mod drop_target;
mod files;
pub(crate) use clipboard::Clipboard;
pub(crate) use desktop::{FileSource, Files, inbox};
pub(crate) use files::{DroppedFiles, Job, Progress};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(7);
const MESSAGE_LIMIT: usize = 128 * 1024;
type Stream = tokio_rustls::TlsStream<TcpStream>;
type Pairing = mpsc::Sender<String>;

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, ZeroizeOnDrop)]
pub(crate) struct Binding {
    #[zeroize(skip)]
    pub record: String,
    #[zeroize(skip)]
    pub local: Ipv4Addr,
    #[zeroize(skip)]
    pub remote: Ipv4Addr,
    pub key: [u8; 32],
    #[zeroize(skip)]
    pub files: bool,
    #[zeroize(skip)]
    #[serde(default)]
    pub file_browser: bool,
    #[zeroize(skip)]
    pub clipboard: bool,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct Route {
    pub binding: Binding,
    pub port: u16,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Report {
    pub record: String,
    pub local: Ipv4Addr,
    pub remote: Ipv4Addr,
    pub port: u16,
}

#[derive(Deserialize, Serialize)]
enum Request {
    Pair(String),
    File(files::Offer),
    Drop { point: drop_target::DropPoint, count: usize },
    Clipboard,
    Display,
    Preview,
    DesktopPreview,
    Browse { location: browser::Location, after: Option<String>, #[serde(default)] query: String },
    CreateDirectory { folder: PathBuf, name: String },
    Upload { path: PathBuf, count: usize },
    Download { path: PathBuf },
}

#[derive(Deserialize, Serialize)]
enum Reply {
    Accepted,
    Resume(u64),
    Complete,
    Destination(String),
    Error(String),
    DisplayMode(DisplayMode),
    Preview(device::Preview),
    Directory(browser::Directory),
    Offer(files::Offer),
}

async fn read<T: DeserializeOwned>(io: &mut Stream) -> Result<T> {
    let size = io.read_u32().await? as usize;
    ensure!(
        (1..=MESSAGE_LIMIT).contains(&size),
        "Projection 消息长度无效"
    );
    let mut bytes = vec![0; size];
    io.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn write(io: &mut Stream, message: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(message)?;
    ensure!(bytes.len() <= MESSAGE_LIMIT, "Projection 消息过大");
    io.write_u32(bytes.len() as u32).await?;
    io.write_all(&bytes).await?;
    io.flush().await?;
    Ok(())
}

async fn connect(route: &Route) -> Result<Stream> {
    ensure!(route.port >= 1024, "等待对端 Projection 就绪");
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddrV4::new(route.binding.local, 0).into())?;
        let remote = SocketAddrV4::new(route.binding.remote, route.port);
        let socket = socket.connect(remote.into()).await?;
        transport::projection_stream(socket, &route.binding.key, None).await
    })
    .await
    .context("Projection 对端连接超时")?
}

pub(crate) async fn approve(route: &Route, pin: String) -> Result<()> {
    let mut stream = connect(route).await?;
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        write(&mut stream, &Request::Pair(pin)).await?;
        match read(&mut stream).await? {
            Reply::Accepted => Ok(()),
            Reply::Error(message) => anyhow::bail!("{message}"),
            _ => anyhow::bail!("Projection 对端回复无效"),
        }
    })
    .await
    .context("Projection 自动配对超时")?
}

pub(super) async fn display(route: &Route) -> Result<DisplayMode> {
    let mut stream = connect(route).await?;
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        write(&mut stream, &Request::Display).await?;
        match read(&mut stream).await.context("请更新两端以使用对机分辨率")? {
            Reply::DisplayMode(mode) => Ok(mode),
            Reply::Error(message) => anyhow::bail!("{message}"),
            _ => anyhow::bail!("对机没有报告显示器分辨率"),
        }
    })
    .await
    .context("等待对机显示器分辨率超时")?
}

#[derive(Default)]
pub(crate) struct Hosts {
    sessions: BTreeMap<String, Session>,
    identity: Option<TlsIdentity>,
}

struct Session {
    binding: Binding,
    port: u16,
    pairing: Arc<Mutex<Option<Pairing>>>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Hosts {
    pub(crate) fn reports(&self) -> Vec<Report> {
        self.sessions
            .values()
            .filter(|session| !session.task.is_finished())
            .map(|session| Report {
                record: session.binding.record.clone(),
                local: session.binding.local,
                remote: session.binding.remote,
                port: session.port,
            })
            .collect()
    }

    pub(crate) async fn synchronize(
        &mut self,
        routes: &[Route],
        sunshine: &super::sunshine::Hosts,
        inbox: Option<&std::path::Path>,
        clipboard: &Clipboard,
    ) -> Result<()> {
        self.sessions.retain(|_, session| {
            !session.task.is_finished()
                && routes.iter().any(|route| route.binding == session.binding)
        });
        if routes.is_empty() {
            return Ok(());
        }
        if self.identity.is_none() {
            self.identity = Some(TlsIdentity::for_projection()?);
        }
        let identity = self.identity.as_ref().unwrap();
        for route in routes {
            let binding = &route.binding;
            let pairing = sunshine.pairing_for(&binding.record, binding.local, binding.remote);
            if let Some(session) = self.sessions.get(&binding.record) {
                *session.pairing.lock().unwrap() = pairing;
                continue;
            }
            let listener = match TcpListener::bind((binding.local, 0)).await {
                Ok(listener) => listener,
                Err(error) => {
                    tracing::debug!(%error, "Projection 辅助连接监听失败");
                    continue;
                }
            };
            let port = listener.local_addr()?.port();
            let pairing = Arc::new(Mutex::new(pairing));
            let stop = CancellationToken::new();
            let task = tokio::spawn(serve(
                listener,
                binding.clone(),
                identity.clone(),
                pairing.clone(),
                inbox.map(PathBuf::from),
                clipboard.clone(),
                stop.clone(),
            ));
            self.sessions.insert(
                binding.record.clone(),
                Session {
                    binding: binding.clone(),
                    port,
                    pairing,
                    stop,
                    task,
                },
            );
        }
        Ok(())
    }
}

async fn serve(
    listener: TcpListener,
    binding: Binding,
    identity: TlsIdentity,
    pairing: Arc<Mutex<Option<Pairing>>>,
    inbox: Option<PathBuf>,
    clipboard: Clipboard,
    stop: CancellationToken,
) {
    let mut clients = JoinSet::new();
    let receiving = Arc::new(Semaphore::new(1));
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            _ = clients.join_next(), if !clients.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((socket, address)) = accepted else { break };
                if address.ip() != SocketAddr::from((binding.remote, 0)).ip() || clients.len() >= 6 {
                    continue;
                }
                let binding = binding.clone();
                let identity = identity.clone();
                let pairing = pairing.clone();
                let inbox = inbox.clone();
                let receiving = receiving.clone();
                let clipboard = clipboard.clone();
                clients.spawn(async move {
                    if let Err(error) = handle(socket, &binding, &identity, pairing, inbox, receiving, clipboard).await {
                        tracing::debug!(%error, "Projection 辅助连接已结束");
                    }
                });
            }
        }
    }
}

async fn handle(
    socket: TcpStream,
    binding: &Binding,
    identity: &TlsIdentity,
    pairing: Arc<Mutex<Option<Pairing>>>,
    inbox: Option<PathBuf>,
    receiving: Arc<Semaphore>,
    clipboard: Clipboard,
) -> Result<()> {
    let (mut stream, request) = tokio::time::timeout(CONNECT_TIMEOUT, async {
        let mut stream = transport::projection_stream(socket, &binding.key, Some(identity)).await?;
        let request = read::<Request>(&mut stream).await?;
        Ok::<_, anyhow::Error>((stream, request))
    })
    .await??;
    let result = match request {
        Request::Clipboard => return clipboard.accept(&mut stream, binding.clipboard).await,
        Request::Preview | Request::DesktopPreview => {
            let detailed = matches!(request, Request::DesktopPreview);
            let reply = match tokio::task::spawn_blocking(move || device::preview(detailed)).await? {
                Ok(preview) => Reply::Preview(preview),
                Err(error) => Reply::Error(error.to_string()),
            };
            return write(&mut stream, &reply).await;
        }
        Request::Display => {
            let reply = match DisplayMode::read(None) {
                Ok(mode) => Reply::DisplayMode(mode),
                Err(error) => Reply::Error(error.to_string()),
            };
            return write(&mut stream, &reply).await;
        }
        Request::Pair(pin) => match pairing.lock().unwrap().as_ref() {
            Some(channel) if pin.len() == 4 && pin.bytes().all(|digit| digit.is_ascii_digit()) => {
                channel
                    .try_send(pin)
                    .context("Sunshine 正在处理配对，请稍后重试")
            }
            _ => Err(anyhow::anyhow!("对端 Sunshine 暂未就绪")),
        },
        request @ (Request::Browse { .. } | Request::CreateDirectory { .. }) => {
            let reply = if binding.files && binding.file_browser {
                match tokio::time::timeout(Duration::from_secs(8), tokio::task::spawn_blocking(move || {
                    match request {
                        Request::Browse { location, after, query } => Ok(Reply::Directory(browser::list(location, after, query)?)),
                        Request::CreateDirectory { folder, name } => {
                            browser::create(&folder, &name)?;
                            Ok::<_, anyhow::Error>(Reply::Accepted)
                        }
                        _ => unreachable!(),
                    }
                })).await {
                    Ok(Ok(Ok(reply))) => reply,
                    Ok(Ok(Err(error))) => Reply::Error(error.to_string()),
                    _ => Reply::Error("对机目录繁忙，请稍后重试".into()),
                }
            } else {
                Reply::Error("请在对机 Projection 设置中授权文件传输与文件浏览".into())
            };
            return write(&mut stream, &reply).await;
        }
        Request::Download { path } => {
            let result = async {
                ensure!(binding.files && binding.file_browser, "对机尚未授权浏览和下载文件");
                let _job = tokio::time::timeout(Duration::from_secs(2), receiving.acquire())
                    .await.context("对机已有文件正在传输")??;
                let path = tokio::task::spawn_blocking(move || browser::file(&path)).await??;
                files::serve_download(&mut stream, &path).await
            }.await;
            if let Err(error) = result {
                write(&mut stream, &Reply::Error(error.to_string())).await?;
            }
            return Ok(());
        }
        request @ (Request::File(_) | Request::Drop { .. } | Request::Upload { .. }) => {
            let result = async {
                ensure!(binding.files, "对端尚未授权接收文件");
                let _job = tokio::time::timeout(Duration::from_secs(2), receiving.acquire())
                    .await.context("对端已有文件正在传输")??;
                match request {
                    Request::File(offer) => {
                        let inbox = inbox.as_deref().context("对端登录用户的下载目录不可用")?;
                        files::receive(&mut stream, inbox, &binding.record, offer, true).await
                    }
                    Request::Drop { point, count } => {
                        ensure!((1..=64).contains(&count), "每次可传输 1–64 个文件");
                        let local = binding.local;
                        ensure!(super::sunshine::game_stream_busy(local, local, super::SUNSHINE_PORT).await?,
                            "对端串流已结束，请重新连接后拖放文件");
                        let destination = drop_target::locate(point).await?;
                        receive_batch(&mut stream, &destination, &binding.record, count).await
                    }
                    Request::Upload { path, count } => {
                        ensure!(binding.file_browser, "对机尚未授权选择接收目录");
                        ensure!((1..=64).contains(&count), "每次可传输 1–64 个文件");
                        let destination = tokio::task::spawn_blocking(move || browser::folder(&path)).await??;
                        receive_batch(&mut stream, &destination, &binding.record, count).await
                    }
                    _ => unreachable!(),
                }
            }
            .await;
            if let Err(error) = result {
                write(&mut stream, &Reply::Error(error.to_string())).await?;
            }
            return Ok(());
        }
    };
    let reply = match result {
        Ok(()) => Reply::Accepted,
        Err(error) => Reply::Error(error.to_string()),
    };
    write(&mut stream, &reply).await
}

async fn receive_batch(
    stream: &mut Stream,
    destination: &std::path::Path,
    record: &str,
    count: usize,
) -> Result<()> {
    write(stream, &Reply::Destination(destination.display().to_string())).await?;
    for _ in 0..count {
        let offer = tokio::time::timeout(Duration::from_secs(600), read(stream)).await??;
        files::receive(stream, destination, record, offer, false).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn removing_an_authorized_route_closes_its_companion_connections() -> Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut hosts = Hosts::default();
        let sunshine = super::super::sunshine::Hosts::default();
        let clipboard = Clipboard::new(0);
        let mut route = Route {
            binding: Binding {
                record: "companion-test".into(),
                local: Ipv4Addr::new(127,0,0,2),
                remote: Ipv4Addr::new(127,0,0,2),
                key: conwu_core::crypto::random(),
                files: false,
                file_browser: false,
                clipboard: false,
            },
            port: 0,
        };
        hosts
            .synchronize(std::slice::from_ref(&route), &sunshine, None, &clipboard)
            .await?;
        route.port = hosts
            .reports()
            .pop()
            .context("listener was not reported")?
            .port;

        let mut stream = connect(&route).await?;
        write(&mut stream, &Request::Clipboard).await?;
        assert!(matches!(read::<Reply>(&mut stream).await?, Reply::Error(_)));

        let mut stream = connect(&route).await?;
        hosts.synchronize(&[], &sunshine, None, &clipboard).await?;
        assert!(hosts.reports().is_empty());
        assert!(
            tokio::time::timeout(CONNECT_TIMEOUT, stream.read_u8())
                .await?
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn browser_transfer_uses_the_chosen_directory_in_both_directions() -> Result<()> {
        use tokio::{fs, sync::watch};

        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                for folder in ["source", "upload", "download"] {
                    let folder = self.0.join(folder);
                    let _ = std::fs::remove_file(folder.join("样本.txt"));
                    let _ = std::fs::remove_dir(folder);
                }
                let _ = std::fs::remove_dir(&self.0);
            }
        }

        let _ = rustls::crypto::ring::default_provider().install_default();
        let fixture = Fixture(std::env::temp_dir().join(format!("conwu-{}", conwu_core::id())));
        let source = fixture.0.join("source").join("样本.txt");
        let upload = fixture.0.join("upload");
        let download = fixture.0.join("download");
        for folder in [source.parent().unwrap(), &upload, &download] {
            fs::create_dir_all(folder).await?;
        }
        fs::write(&source, b"test file").await?;
        let mut hosts = Hosts::default();
        let sunshine = super::super::sunshine::Hosts::default();
        let clipboard = Clipboard::new(0);
        let mut route = Route {
            binding: Binding {
                record: "file-browser-test".into(),
                local: Ipv4Addr::LOCALHOST,
                remote: Ipv4Addr::LOCALHOST,
                key: conwu_core::crypto::random(),
                files: true,
                file_browser: true,
                clipboard: false,
            },
            port: 0,
        };
        hosts.synchronize(std::slice::from_ref(&route), &sunshine, None, &clipboard).await?;
        route.port = hosts.reports().pop().context("listener was not reported")?.port;
        let (progress, _view) = watch::channel(Progress::choosing(Job {
            record: route.binding.record.clone(),
            id: conwu_core::id(),
        }));
        files::send_files(
            route.clone(), vec![source], files::Destination::Folder(upload.clone()), progress.clone(),
        ).await?;
        let directory = browser::execute(browser::Action::List {
            side: browser::Side::Remote,
            location: browser::Location::Directory(upload.clone()),
            after: None, query: String::new(),
        }, route.clone()).await?;
        assert_eq!(directory["entries"][0]["name"], "样本.txt");
        let filtered = browser::execute(browser::Action::List {
            side: browser::Side::Remote,
            location: browser::Location::Directory(upload.clone()),
            after: None, query: ".jpg".into(),
        }, route.clone()).await?;
        assert!(filtered["entries"].as_array().unwrap().is_empty());
        files::download(route.clone(), vec![upload.join("样本.txt")], download.clone(), progress).await?;
        assert_eq!(fs::read(download.join("样本.txt")).await?, b"test file");
        route.binding.file_browser = false;
        hosts.synchronize(std::slice::from_ref(&route), &sunshine, None, &clipboard).await?;
        route.port = hosts.reports().pop().context("listener was not reported")?.port;
        let result = browser::execute(browser::Action::List {
            side: browser::Side::Remote,
            location: browser::Location::Directory(upload),
            after: None, query: String::new(),
        }, route).await;
        assert!(result.is_err_and(|error| error.to_string().contains("授权")));
        Ok(())
    }

    #[tokio::test]
    async fn tls_channel_rejects_an_unpaired_client_and_server() -> Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let identity = TlsIdentity::for_projection()?;
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            transport::projection_stream(socket, &[7; 32], Some(&identity)).await
        });
        let socket = TcpStream::connect(address).await?;
        assert!(
            transport::projection_stream(socket, &[8; 32], None)
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(CONNECT_TIMEOUT, server)
                .await??
                .is_err()
        );
        Ok(())
    }
}
