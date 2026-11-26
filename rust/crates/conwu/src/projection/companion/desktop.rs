use std::{collections::VecDeque, ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf, ptr};

use anyhow::{Context, Result, ensure};
use tokio::{sync::watch, task::JoinHandle};
use windows_sys::Win32::{
    Foundation::HWND,
    System::Com::CoTaskMemFree,
    UI::{
        Controls::Dialogs::{
            CDN_INITDONE, CommDlgExtendedError, GetOpenFileNameW, OFN_ALLOWMULTISELECT,
            OFN_ENABLEHOOK, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST,
            OFNOTIFYW, OPENFILENAMEW,
        },
        Shell::{FOLDERID_Downloads, SHGetKnownFolderPath},
        WindowsAndMessaging::{
            GetForegroundWindow, GetParent, IsWindowVisible, SetForegroundWindow, WM_NOTIFY,
        },
    },
};
use windows_sys::core::GUID;

use super::{DroppedFiles, Job, Progress, Route, browser, files::{self, Destination}};

pub(crate) enum FileSource {
    Picker(Option<usize>),
    Drop(DroppedFiles),
    Browser { from: browser::Side, paths: Vec<PathBuf>, destination: PathBuf },
}

#[derive(Default)]
pub(crate) struct Files {
    active: Option<Transfer>,
    queued: VecDeque<Queued>,
    finished: VecDeque<Progress>,
}

struct Queued {
    route: Route,
    job: Job,
    source: FileSource,
}

struct Transfer {
    route: Route,
    state: watch::Receiver<Progress>,
    task: JoinHandle<()>,
}

impl Drop for Transfer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Files {
    pub(crate) fn reports(&mut self) -> Vec<Progress> {
        if self.active.as_ref().is_some_and(|active| active.task.is_finished()) {
            let active = self.active.take().unwrap();
            self.finish(active.state.borrow().clone());
        }
        let active = self.active.iter().map(|transfer| transfer.state.borrow().clone());
        let waiting = self.queued.iter().map(|item| {
            let mut state = Progress::choosing(item.job.clone());
            state.message = "等待传输".into();
            if let FileSource::Browser { paths, destination, .. } = &item.source {
                state.count = paths.len();
                state.destination = Some(destination.display().to_string());
                state.name = paths.first().and_then(|path| path.file_name()).unwrap_or_default().to_string_lossy().into_owned();
            }
            state
        });
        active.chain(waiting).chain(self.finished.iter().cloned()).collect()
    }

    fn finish(&mut self, state: Progress) {
        self.finished.push_front(state);
        self.finished.truncate(16);
    }

    pub(crate) fn clear_finished(&mut self, record: &str) {
        self.finished.retain(|state| state.job.record != record);
    }

    pub(crate) fn failed(&mut self, job: Job, error: anyhow::Error) {
        let mut state = Progress::choosing(job);
        state.active = false;
        state.message = error.to_string();
        self.finish(state);
    }

    pub(crate) fn reconcile(&mut self, routes: &[Route], stop: &[String]) {
        let canceled = |job: &Job| stop.contains(&job.id);
        if self.active.as_ref().is_some_and(|active| {
            canceled(&active.state.borrow().job) || !routes.contains(&active.route)
        }) {
            let transfer = self.active.take().unwrap();
            let mut state = transfer.state.borrow().clone();
            state.active = false;
            state.message = if canceled(&state.job) {
                "已取消文件传输".into()
            } else {
                "直连或授权已变化，可重新选择同一文件续传".into()
            };
            self.finish(state);
        }
        let mut kept = VecDeque::new();
        for item in std::mem::take(&mut self.queued) {
            let cancel = canceled(&item.job);
            if !cancel && routes.contains(&item.route) {
                kept.push_back(item);
            } else {
                self.failed(item.job, anyhow::anyhow!(if cancel { "已取消文件传输" } else { "直连或授权已变化" }));
            }
        }
        self.queued = kept;
        self.advance();
    }

    pub(crate) fn start(&mut self, job: Job, source: FileSource, routes: &[Route]) -> Result<()> {
        ensure!(self.queued.len() < 8, "等待中的文件传输已满");
        let route = routes
            .iter()
            .find(|route| route.binding.record == job.record && route.binding.files && route.port != 0)
            .cloned()
            .context("文件传输需要对端就绪且双方分别授权")?;
        self.queued.push_back(Queued { route, job, source });
        self.advance();
        Ok(())
    }

    fn advance(&mut self) {
        if self.active.is_some() {
            return;
        }
        let Some(Queued { route, job, source }) = self.queued.pop_front() else { return };
        let state = Progress::choosing(job);
        let (status, state) = watch::channel(state);
        let target = route.clone();
        let task = tokio::spawn(async move {
            let transfer = async {
                let (paths, destination) = match source {
                    FileSource::Picker(owner) => {
                        let owner = owner.context("请在 ConWU 桌面窗口内选择文件")?;
                        (
                            tokio::task::spawn_blocking(move || pick_files(owner)).await??,
                            Destination::Inbox,
                        )
                    }
                    FileSource::Drop(batch) => (
                        batch.files,
                        Destination::Drop(batch.point.context("请把文件拖到远控画面内")?),
                    ),
                    FileSource::Browser { from: browser::Side::Local, paths, destination } => {
                        let paths = tokio::task::spawn_blocking(move || {
                            paths.iter().map(|path| browser::file(path)).collect::<Result<Vec<_>>>()
                        }).await??;
                        (paths, Destination::Folder(destination))
                    }
                    FileSource::Browser { from: browser::Side::Remote, paths, destination } => {
                        let destination = tokio::task::spawn_blocking(move || browser::folder(&destination)).await??;
                        files::download(target, paths, destination, status.clone()).await?;
                        return Ok(true);
                    }
                };
                if paths.is_empty() {
                    return Ok::<_, anyhow::Error>(false);
                }
                files::send_files(target, paths, destination, status.clone()).await?;
                Ok(true)
            }
            .await;
            status.send_modify(|state| {
                state.active = false;
                state.message = match transfer {
                    Ok(true) => "文件传输完成".into(),
                    Ok(false) => "已取消选取文件".into(),
                    Err(error) => format!("文件传输中断 · {error}"),
                };
            });
        });
        self.active = Some(Transfer { route, state, task });
    }
}

pub(crate) fn inbox() -> Option<PathBuf> {
    known_folder(&FOLDERID_Downloads).map(|dir| dir.join("ConWU Projection"))
}

pub(super) fn known_folder(folder: &GUID) -> Option<PathBuf> {
    let mut path = ptr::null_mut();
    let status = unsafe { SHGetKnownFolderPath(folder, 0, ptr::null_mut(), &mut path) };
    if status < 0 || path.is_null() {
        return None;
    }
    unsafe {
        let len = (0..32768).find(|&index| *path.add(index) == 0);
        let directory = len
            .map(|len| PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(path, len))));
        CoTaskMemFree(path.cast());
        directory.filter(|dir| dir.is_absolute())
    }
}

fn pick_files(owner: usize) -> Result<Vec<PathBuf>> {
    unsafe extern "system" fn show(window: HWND, message: u32, _: usize, data: isize) -> usize {
        if message == WM_NOTIFY && data != 0 {
            let notification = unsafe { &*(data as *const OFNOTIFYW) };
            if notification.hdr.code == CDN_INITDONE && !notification.lpOFN.is_null() {
                let owner = unsafe { (*notification.lpOFN).hwndOwner };
                let popup = unsafe { GetParent(window) };
                if !popup.is_null() && unsafe { GetForegroundWindow() } == owner {
                    unsafe { SetForegroundWindow(popup) };
                }
            }
        }
        0
    }

    let owner = owner as HWND;
    ensure!(
        unsafe { IsWindowVisible(owner) != 0 },
        "ConWU 桌面窗口已关闭"
    );
    let mut buffer = vec![0u16; 32768];
    let title = "Projection · 选择要发送的文件"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut dialog = OPENFILENAMEW {
        lStructSize: size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner,
        lpstrFile: buffer.as_mut_ptr(),
        nMaxFile: buffer.len() as u32,
        lpstrTitle: title.as_ptr(),
        Flags: OFN_EXPLORER
            | OFN_ENABLEHOOK
            | OFN_FILEMUSTEXIST
            | OFN_PATHMUSTEXIST
            | OFN_NOCHANGEDIR
            | OFN_ALLOWMULTISELECT,
        lpfnHook: Some(show),
        ..Default::default()
    };
    if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
        let error = unsafe { CommDlgExtendedError() };
        ensure!(error == 0, "无法选择文件（{error}）");
        return Ok(Vec::new());
    }
    let mut entries = buffer
        .split(|unit| *unit == 0)
        .take_while(|entry| !entry.is_empty());
    let first = entries.next().context("没有选中的文件")?;
    let path = PathBuf::from(OsString::from_wide(first));
    ensure!(path.is_absolute(), "文件路径无效");
    let names = entries.map(OsString::from_wide).collect::<Vec<_>>();
    if names.is_empty() {
        return Ok(vec![path]);
    }
    ensure!(names.len() <= 64, "每次可传输最多 64 个文件");
    Ok(names.into_iter().map(|name| path.join(name)).collect())
}
