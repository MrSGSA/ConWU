use std::{
    io::ErrorKind,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use conwu_core::crypto;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom},
    sync::watch,
    time::timeout,
};

use super::{
    CONNECT_TIMEOUT, Reply, Request, Route, Stream, connect, drop_target::DropPoint, read, write,
};

const CHUNK: usize = 64 * 1024;
const BYTES_PER_SECOND: u64 = 2_000_000;
const TRANSFER_IDLE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct Job {
    pub record: String,
    pub id: String,
}

#[derive(Deserialize)]
pub(crate) struct DroppedFiles {
    pub files: Vec<PathBuf>,
    pub point: Option<DropPoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Progress {
    pub job: Job,
    pub active: bool,
    pub item: usize,
    pub count: usize,
    pub name: String,
    pub bytes: u64,
    pub size: u64,
    pub message: String,
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub download: bool,
}

impl Progress {
    pub(crate) fn choosing(job: Job) -> Self {
        Self {
            job,
            active: true,
            item: 0,
            count: 0,
            name: String::new(),
            bytes: 0,
            size: 0,
            message: "请选择文件".into(),
            destination: None,
            source: None,
            download: false,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Offer {
    name: String,
    size: u64,
    digest: [u8; 32],
}

pub(super) fn valid_name(name: &str) -> bool {
    if name.is_empty()
        || name.encode_utf16().count() > 255
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|ch| ch.is_control() || "<>:\"/\\|?*".contains(ch))
    {
        return false;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap()
        .trim_end()
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) && !["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix)
            .is_some_and(|suffix| suffix.chars().count() == 1 && "123456789¹²³".contains(suffix))
    })
}

async fn hash_file(file: &mut File) -> Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0)).await?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; CHUNK];
    loop {
        let len = file.read(&mut buffer).await?;
        if len == 0 {
            return Ok(hash.finalize().into());
        }
        hash.update(&buffer[..len]);
    }
}

async fn receive_reply(io: &mut Stream, wait: Duration) -> Result<Reply> {
    match timeout(wait, read(io))
        .await
        .context("等待文件接收端响应超时")??
    {
        Reply::Error(error) => anyhow::bail!("{error}"),
        reply => Ok(reply),
    }
}

pub(super) enum Destination {
    Inbox,
    Drop(DropPoint),
    Folder(PathBuf),
}

pub(super) async fn send_files(
    route: Route,
    paths: Vec<PathBuf>,
    destination: Destination,
    progress: watch::Sender<Progress>,
) -> Result<()> {
    ensure!(route.binding.files, "请先为此设备启用文件传输");
    let count = paths.len();
    ensure!((1..=64).contains(&count), "每次可传输 1–64 个文件");
    let request = match destination {
        Destination::Inbox => None,
        Destination::Drop(point) => Some(Request::Drop { point, count }),
        Destination::Folder(path) => Some(Request::Upload { path, count }),
    };
    let mut batch = if let Some(request) = request {
        progress.send_modify(|state| state.message = "正在确认对机传输目录".into());
        let mut io = connect(&route).await?;
        timeout(CONNECT_TIMEOUT, write(&mut io, &request)).await??;
        let reply = timeout(Duration::from_secs(10), read(&mut io))
            .await
            .context("等待对端确认落点超时")?
            .context("对机需要支持指定接收目录的 Projection 版本")?;
        match reply {
            Reply::Destination(path) => {
                progress.send_modify(|state| state.destination = Some(path))
            }
            Reply::Error(message) => anyhow::bail!("{message}"),
            _ => anyhow::bail!("对端未确认文件落点"),
        }
        Some(io)
    } else {
        progress.send_modify(|state| state.destination = Some("下载 / ConWU Projection".into()));
        None
    };
    for (index, path) in paths.into_iter().enumerate() {
        progress.send_modify(|state| {
            state.item = index + 1;
            state.count = count;
            state.name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            state.bytes = 0;
            state.size = 0;
            state.source = Some(path.display().to_string());
            state.message = "正在校验源文件".into();
        });
        let (mut file, offer) = prepare(&path).await?;
        progress.send_modify(|state| state.size = offer.size);
        let mut file_stream;
        let io = if let Some(io) = &mut batch {
            timeout(CONNECT_TIMEOUT, write(io, &offer)).await??;
            io
        } else {
            file_stream = connect(&route).await?;
            timeout(
                CONNECT_TIMEOUT,
                write(&mut file_stream, &Request::File(offer.clone())),
            )
            .await??;
            &mut file_stream
        };
        send_open(io, &mut file, &offer, Some(&progress)).await?;
    }
    Ok(())
}

async fn prepare(path: &Path) -> Result<(File, Offer)> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| valid_name(name))
        .context("文件名不受支持")?
        .to_owned();
    ensure!(fs::metadata(path).await?.is_file(), "请选择要传输的文件");
    let mut file = File::open(path).await?;
    let size = file.metadata().await?.len();
    let digest = hash_file(&mut file).await?;
    ensure!(file.metadata().await?.len() == size, "源文件传输前已变化");
    Ok((file, Offer { name, size, digest }))
}

async fn send_open(
    io: &mut Stream,
    file: &mut File,
    offer: &Offer,
    progress: Option<&watch::Sender<Progress>>,
) -> Result<()> {
    let offset = match receive_reply(io, TRANSFER_IDLE).await? {
        Reply::Resume(offset) if offset <= offer.size => offset,
        Reply::Complete => {
            if let Some(progress) = progress {
                progress.send_modify(|state| state.bytes = offer.size);
            }
            return Ok(());
        }
        _ => anyhow::bail!("对机文件接收状态无效"),
    };
    file.seek(SeekFrom::Start(offset)).await?;
    if let Some(progress) = progress {
        progress.send_modify(|state| {
            state.bytes = offset;
            state.message = "正在发送".into();
        });
    }
    let mut sent = offset;
    let mut buffer = vec![0; CHUNK];
    while sent < offer.size {
        let size = (offer.size - sent).min(CHUNK as u64) as usize;
        file.read_exact(&mut buffer[..size])
            .await
            .context("源文件传输时已变化")?;
        tokio::time::sleep(Duration::from_secs_f64(size as f64 / BYTES_PER_SECOND as f64)).await;
        timeout(TRANSFER_IDLE, io.write_all(&buffer[..size])).await??;
        sent += size as u64;
        if let Some(progress) = progress {
            progress.send_modify(|state| state.bytes = sent);
        }
    }
    timeout(TRANSFER_IDLE, io.flush()).await??;
    if let Some(progress) = progress {
        progress.send_modify(|state| state.message = "等待对端校验".into());
    }
    ensure!(
        matches!(receive_reply(io, Duration::from_secs(600)).await?, Reply::Complete),
        "对机未确认文件接收"
    );
    Ok(())
}

pub(super) async fn serve_download(io: &mut Stream, path: &Path) -> Result<()> {
    let (mut file, offer) = prepare(path).await?;
    write(io, &Reply::Offer(offer.clone())).await?;
    send_open(io, &mut file, &offer, None).await
}

pub(super) async fn download(
    route: Route,
    paths: Vec<PathBuf>,
    destination: PathBuf,
    progress: watch::Sender<Progress>,
) -> Result<()> {
    ensure!(route.binding.files, "请先为此设备启用文件传输");
    let count = paths.len();
    ensure!((1..=64).contains(&count), "每次可传输 1–64 个文件");
    progress.send_modify(|state| {
        state.download = true;
        state.destination = Some(destination.display().to_string());
    });
    for (index, path) in paths.into_iter().enumerate() {
        let name = path.file_name().and_then(|name| name.to_str())
            .filter(|name| valid_name(name)).context("文件名不受支持")?.to_owned();
        progress.send_modify(|state| {
            state.item = index + 1;
            state.count = count;
            state.name.clone_from(&name);
            state.source = Some(path.display().to_string());
            state.bytes = 0;
            state.size = 0;
            state.message = "对机正在校验文件".into();
        });
        let mut io = connect(&route).await?;
        timeout(CONNECT_TIMEOUT, write(&mut io, &Request::Download { path })).await??;
        let Reply::Offer(offer) = receive_reply(&mut io, Duration::from_secs(600)).await? else {
            anyhow::bail!("对机未确认下载请求");
        };
        ensure!(offer.name == name, "对机提供的文件名已变化");
        progress.send_modify(|state| state.size = offer.size);
        receive_reporting(&mut io, &destination, &route.binding.record, offer, false, Some(&progress)).await?;
    }
    Ok(())
}

pub(super) async fn receive(
    io: &mut Stream,
    inbox: &Path,
    peer: &str,
    offer: Offer,
    create: bool,
) -> Result<()> {
    receive_reporting(io, inbox, peer, offer, create, None).await
}

async fn receive_reporting(
    io: &mut Stream,
    inbox: &Path,
    peer: &str,
    offer: Offer,
    create: bool,
    progress: Option<&watch::Sender<Progress>>,
) -> Result<()> {
    ensure!(valid_name(&offer.name), "文件名不受支持");
    let inbox = crate::store::Store::resolve_root(inbox)?;
    let final_path = inbox.join(&offer.name);
    if create {
        fs::create_dir_all(&inbox).await?;
    }
    crate::store::reject_link(&inbox)?;
    ensure!(inbox.is_dir(), "对端落点目录已移动");
    match fs::symlink_metadata(&final_path).await {
        Ok(metadata) => {
            crate::store::reject_link(&final_path)?;
            ensure!(
                metadata.is_file() && metadata.len() == offer.size,
                "接收目录已存在同名文件"
            );
            let mut file = File::open(&final_path).await?;
            ensure!(
                hash_file(&mut file).await? == offer.digest,
                "接收目录已存在同名文件"
            );
            if let Some(progress) = progress {
                progress.send_modify(|state| state.bytes = offer.size);
            }
            return write(io, &Reply::Complete).await;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let staging = inbox.join(".projection-incomplete");
    match fs::create_dir(&staging).await {
        Ok(()) => hide_staging(&staging)?,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    crate::store::reject_link(&staging)?;
    let transfer = crypto::hash(serde_json::to_vec(&(peer, &offer))?);
    let part = staging.join(hex::encode(transfer));
    if fs::symlink_metadata(&part).await.is_ok() {
        crate::store::reject_link(&part)?;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(&part)
        .await?;
    let mut received = file.metadata().await?.len();
    if received > offer.size {
        file.set_len(0).await?;
        received = 0;
    }
    file.seek(SeekFrom::Start(received)).await?;
    if let Some(progress) = progress {
        progress.send_modify(|state| {
            state.bytes = received;
            state.message = "正在接收".into();
        });
    }
    write(io, &Reply::Resume(received)).await?;
    let mut buffer = vec![0; CHUNK];
    while received < offer.size {
        let size = (offer.size - received).min(CHUNK as u64) as usize;
        let count = timeout(TRANSFER_IDLE, io.read(&mut buffer[..size])).await??;
        ensure!(count != 0, "文件传输提前结束");
        file.write_all(&buffer[..count]).await?;
        received += count as u64;
        if let Some(progress) = progress {
            progress.send_modify(|state| state.bytes = received);
        }
    }
    file.flush().await?;
    if hash_file(&mut file).await? != offer.digest {
        file.set_len(0).await?;
        anyhow::bail!("文件校验失败，请重新发送");
    }
    file.sync_all().await?;
    drop(file);
    move_new(&part, &final_path)?;
    let _ = fs::remove_dir(&staging).await;
    write(io, &Reply::Complete).await
}

fn hide_staging(path: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_HIDDEN, SetFileAttributesW};

    let wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN) } == 0 {
        return Err(std::io::Error::last_os_error()).context("无法隐藏接收临时文件夹");
    }
    Ok(())
}

fn move_new(from: &Path, to: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

    let from = from
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let to = to
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } == 0 {
        return Err(std::io::Error::last_os_error()).context("无法保存接收到的文件");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            // TestDirectory is a freshly generated child of this invocation's TEMP.
            let inbox = self.0.join("received");
            let parts = inbox.join(".projection-incomplete");
            if let Ok(entries) = std::fs::read_dir(&parts) {
                for entry in entries.flatten() {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
            let _ = std::fs::remove_dir(parts);
            let _ = std::fs::remove_file(inbox.join("校验.bin"));
            let _ = std::fs::remove_dir(inbox);
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    #[tokio::test]
    async fn interrupted_transfer_resumes_and_duplicate_delivery_is_idempotent() -> Result<()> {
        use std::net::Ipv4Addr;
        use tokio::net::TcpListener;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory =
            TestDirectory(std::env::temp_dir().join(format!("conwu-{}", conwu_core::id())));
        fs::create_dir(&directory.0).await?;
        let inbox = directory.0.join("received");
        let peer = Ipv4Addr::LOCALHOST;
        let listener = TcpListener::bind((peer, 0)).await?;
        let route = Route {
            port: listener.local_addr()?.port(),
            binding: super::super::Binding {
                record: "transfer-test".into(),
                local: peer,
                remote: peer,
                key: crypto::random(),
                files: true,
                file_browser: false,
                clipboard: false,
            },
        };
        let target = route.clone();
        let destination = inbox.clone();
        let identity = crate::transport::TlsIdentity::for_projection()?;
        let server = tokio::spawn(async move {
            for attempt in 0..3 {
                let (socket, _) = listener.accept().await?;
                let mut io = crate::transport::projection_stream(
                    socket,
                    &target.binding.key,
                    Some(&identity),
                )
                .await?;
                let Request::File(offer) = read(&mut io).await? else {
                    anyhow::bail!("unexpected request")
                };
                let result =
                    receive(&mut io, &destination, &target.binding.record, offer, true).await;
                if attempt == 0 {
                    ensure!(result.is_err(), "incomplete data was accepted");
                } else {
                    result?;
                }
            }
            Ok::<_, anyhow::Error>(())
        });
        let data = b"Projection resumes partial files";
        let offer = Offer {
            name: "校验.bin".into(),
            size: data.len() as u64,
            digest: crypto::hash(data),
        };
        let final_path = inbox.join(&offer.name);
        let mut io = connect(&route).await?;
        write(&mut io, &Request::File(offer.clone())).await?;
        assert!(matches!(read(&mut io).await?, Reply::Resume(0)));
        io.write_all(&data[..11]).await?;
        io.flush().await?;
        io.shutdown().await?;
        drop(io);
        assert!(!final_path.exists());

        let mut io = connect(&route).await?;
        write(&mut io, &Request::File(offer.clone())).await?;
        assert!(matches!(read(&mut io).await?, Reply::Resume(11)));
        io.write_all(&data[11..]).await?;
        io.flush().await?;
        assert!(matches!(read(&mut io).await?, Reply::Complete));
        assert_eq!(fs::read(&final_path).await?, data);

        let mut io = connect(&route).await?;
        write(&mut io, &Request::File(offer)).await?;
        assert!(matches!(read(&mut io).await?, Reply::Complete));
        server.await??;
        Ok(())
    }

    #[test]
    fn names_are_single_windows_files() {
        for name in [
            "../escape",
            "other\\note",
            "note.txt:stream",
            "a.",
            "b ",
            "COM¹.dat",
            "CON",
        ] {
            assert!(!valid_name(name), "{name}");
        }
        for name in ["普通文件 1.zip", ".gitignore", "README.md", "COM10.dat"] {
            assert!(valid_name(name), "{name}");
        }
    }
}
