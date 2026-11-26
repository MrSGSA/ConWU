use std::{
    collections::BTreeMap,
    fs,
    os::windows::fs::MetadataExt,
    path::{Component, Path, PathBuf, Prefix},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use windows_sys::Win32::{
    Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, GetDriveTypeW, GetLogicalDrives},
    UI::Shell::{FOLDERID_Desktop, FOLDERID_Downloads},
};

use super::{
    Reply, Request, Route, connect, desktop::known_folder, files::valid_name, read, write,
};

const PAGE_SIZE: usize = 32;
const DIRECTORY_BYTES: usize = 48 * 1024;
const INCOMPLETE: &str = ".projection-incomplete";

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", content = "path", rename_all = "camelCase")]
pub(crate) enum Location {
    Desktop,
    Downloads,
    Drives,
    Directory(PathBuf),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Side {
    Local,
    Remote,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub(crate) enum Action {
    Preview,
    List {
        side: Side,
        location: Location,
        after: Option<String>,
        #[serde(default)]
        query: String,
    },
    Create {
        side: Side,
        folder: PathBuf,
        name: String,
    },
    Copy {
        from: Side,
        paths: Vec<PathBuf>,
        destination: PathBuf,
    },
    Clear,
}


#[derive(Deserialize, Serialize)]
pub(crate) struct Query {
    pub id: String,
    pub route: Route,
    pub action: Action,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QueryResult {
    pub id: String,
    pub value: Option<Value>,
    pub error: Option<String>,
}

impl QueryResult {
    pub fn new(id: String, result: Result<Value>) -> Self {
        match result {
            Ok(value) => Self {
                id,
                value: Some(value),
                error: None,
            },
            Err(error) => Self {
                id,
                value: None,
                error: Some(error.to_string()),
            },
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Directory {
    path: Option<PathBuf>,
    parent: Location,
    entries: Vec<Entry>,
    next: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    name: String,
    path: PathBuf,
    directory: bool,
    size: u64,
    modified: Option<u64>,
}

fn drive_type(drive: u8) -> u32 {
    unsafe { GetDriveTypeW([u16::from(drive), b':' as u16, b'\\' as u16, 0].as_ptr()) }
}

fn local_path(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    let drive = components
        .next()
        .and_then(|part| match part {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => Some(drive),
                _ => None,
            },
            _ => None,
        })
        .context("请选择本机磁盘上的文件")?;
    // Removable, fixed, optical and RAM drives have local filesystem paths.
    ensure!(
        matches!(drive_type(drive), 2 | 3 | 5 | 6),
        "请选择本机磁盘上的文件"
    );
    ensure!(matches!(components.next(), Some(Component::RootDir))
        && components.all(|part| matches!(part, Component::Normal(name) if
            name.to_str().is_some_and(|name| valid_name(name) && !name.eq_ignore_ascii_case(INCOMPLETE)))),
        "文件路径无效");
    let path = crate::store::Store::resolve_root(path)?;
    Ok(crate::platform::filesystem_argument(&path)?.into())
}

pub(super) fn folder(path: &Path) -> Result<PathBuf> {
    let path = local_path(path)?;
    ensure!(path.is_dir(), "目录已移动或不可访问");
    Ok(path)
}

pub(super) fn file(path: &Path) -> Result<PathBuf> {
    let path = local_path(path)?;
    ensure!(path.is_file(), "文件已移动或不可访问");
    Ok(path)
}

pub(super) fn list(location: Location, after: Option<String>, query: String) -> Result<Directory> {
    ensure!(query.chars().count() <= 128, "搜索名称过长");
    let query = query.to_lowercase();
    let path = match location {
        Location::Desktop => known_folder(&FOLDERID_Desktop).context("桌面目录不可用")?,
        Location::Downloads => known_folder(&FOLDERID_Downloads).context("下载目录不可用")?,
        Location::Drives => {
            let mask = unsafe { GetLogicalDrives() };
            let entries = (b'A'..=b'Z')
                .filter(|&letter| {
                    mask & (1 << (letter - b'A')) != 0
                        && matches!(drive_type(letter), 2 | 3 | 5 | 6)
                })
                .filter(|letter| format!("{}:", char::from(*letter)).to_lowercase().contains(&query))
                .map(|letter| Entry {
                    name: format!("{}:", char::from(letter)),
                    path: PathBuf::from(format!("{}:\\", char::from(letter))),
                    directory: true,
                    size: 0,
                    modified: None,
                })
                .collect();
            return Ok(Directory {
                path: None,
                parent: Location::Drives,
                entries,
                next: None,
            });
        }
        Location::Directory(path) => path,
    };
    let path = folder(&path)?;
    let parent = path.parent().map_or(Location::Drives, |parent| {
        Location::Directory(parent.into())
    });
    let mut entries = BTreeMap::new();
    for entry in fs::read_dir(&path)?.filter_map(Result::ok) {
        let Some(name) = entry.file_name().into_string().ok() else {
            continue;
        };
        if !name.to_lowercase().contains(&query) || !valid_name(&name)
            || name.eq_ignore_ascii_case(INCOMPLETE)
            || after.as_ref().is_some_and(|after| &name <= after)
            || (entries.len() > PAGE_SIZE
                && entries
                    .last_key_value()
                    .is_some_and(|(key, _)| &name >= key))
        {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            continue;
        }
        let directory = metadata.is_dir();
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs());
        entries.insert(
            name.clone(),
            Entry {
                name,
                path: entry.path(),
                directory,
                size: if directory { 0 } else { metadata.len() },
                modified,
            },
        );
        if entries.len() > PAGE_SIZE + 1 {
            entries.pop_last();
        }
    }
    let next = if entries.len() > PAGE_SIZE {
        entries.pop_last();
        entries.last_key_value().map(|(name, _)| name.clone())
    } else {
        None
    };
    let mut directory = Directory {
        path: Some(path),
        parent,
        entries: entries.into_values().collect(),
        next,
    };
    while serde_json::to_vec(&directory)?.len() > DIRECTORY_BYTES {
        ensure!(directory.entries.len() > 1, "目录路径过长");
        directory.entries.pop();
        directory.next = directory.entries.last().map(|entry| entry.name.clone());
    }
    Ok(directory)
}

pub(super) fn create(parent: &Path, name: &str) -> Result<()> {
    ensure!(
        valid_name(name) && !name.eq_ignore_ascii_case(INCOMPLETE),
        "文件夹名称无效"
    );
    fs::create_dir(folder(parent)?.join(name)).context("无法创建文件夹")
}

pub(crate) async fn execute(action: Action, route: Route) -> Result<Value> {
    let request = match action {
        Action::Preview => Request::DesktopPreview,
        Action::List {
            side: Side::Local,
            location,
            after, query,
        } => {
            return Ok(serde_json::to_value(
                tokio::task::spawn_blocking(move || list(location, after, query)).await??,
            )?);
        }
        Action::List {
            side: Side::Remote,
            location,
            after, query,
        } => Request::Browse { location, after, query },
        Action::Create {
            side: Side::Local,
            folder,
            name,
        } => {
            tokio::task::spawn_blocking(move || create(&folder, &name)).await??;
            return Ok(json!(true));
        }
        Action::Create {
            side: Side::Remote,
            folder,
            name,
        } => Request::CreateDirectory { folder, name },
        Action::Copy { .. } | Action::Clear => anyhow::bail!("文件操作需要本机传输队列"),
    };
    let mut stream = connect(&route).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        write(&mut stream, &request).await?;
        let reply = match read(&mut stream).await {
            Err(error) if matches!(request, Request::DesktopPreview) &&
                error.downcast_ref::<std::io::Error>().is_some_and(|e| matches!(e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset)) => {
                // Older companions close the stream on an unknown request.
                let mut legacy = connect(&route).await?;
                write(&mut legacy, &Request::Preview).await?;
                read(&mut legacy).await?
            }
            result => result.context("请确认对机版本支持此操作")?,
        };
        match reply {
            Reply::Preview(preview) if matches!(request, Request::DesktopPreview) => Ok(serde_json::to_value(preview)?),
            Reply::Directory(directory) => Ok(serde_json::to_value(directory)?),
            Reply::Accepted => Ok(json!(true)),
            Reply::Error(error) => anyhow::bail!("{error}"),
            _ => anyhow::bail!("对机响应无效"),
        }
    })
    .await
    .context("等待对机响应超时")?
}
