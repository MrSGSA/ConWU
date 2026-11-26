use std::{ptr, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::{sync::Semaphore, time::timeout};
use windows_sys::Win32::{
    Foundation::{GlobalFree, HWND},
    System::{
        DataExchange::{
            CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
            OpenClipboard, SetClipboardData,
        },
        Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock},
    },
};

use super::{CONNECT_TIMEOUT, Reply, Request, Route, Stream, connect, read, write};

const MAX_TEXT: usize = 16 * 1024;
const TEXT: u32 = 13; // CF_UNICODETEXT

#[derive(Clone)]
pub(crate) struct Clipboard {
    owner: usize,
    active: Arc<Semaphore>,
}

impl Clipboard {
    pub(crate) fn new(owner: usize) -> Self {
        Self {
            owner,
            active: Arc::new(Semaphore::new(1)),
        }
    }

    pub(crate) async fn sync(&self, route: Route) -> Result<()> {
        let _slot = self.active.try_acquire().context("已有剪贴板同步会话")?;
        let mut io = connect(&route).await?;
        timeout(CONNECT_TIMEOUT, async {
            write(&mut io, &Request::Clipboard).await?;
            match read(&mut io).await? {
                Reply::Accepted => Ok(()),
                Reply::Error(message) => anyhow::bail!("{message}"),
                _ => anyhow::bail!("对端剪贴板回复无效"),
            }
        })
        .await??;
        let mut text = Text::new(self.owner);
        loop {
            timeout(CONNECT_TIMEOUT, async {
                write(&mut io, &text.changed()).await?;
                if let Some(update) = read::<Option<String>>(&mut io).await? {
                    text.apply(update).await?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await??;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub(super) async fn accept(&self, io: &mut Stream, allowed: bool) -> Result<()> {
        let slot = self.active.try_acquire();
        if !allowed || slot.is_err() {
            return write(io, &Reply::Error("对端剪贴板未授权或正在使用".into())).await;
        }
        // Hold the permit for the entire session, across all authorized networks.
        let _slot = slot.unwrap();
        let mut text = Text::new(self.owner);
        write(io, &Reply::Accepted).await?;
        loop {
            timeout(CONNECT_TIMEOUT, async {
                let update: Option<String> = read(io).await?;
                let response = if let Some(update) = update {
                    text.apply(update).await?;
                    None
                } else {
                    text.changed()
                };
                write(io, &response).await
            })
            .await??;
        }
    }
}

struct Open;
impl Drop for Open {
    fn drop(&mut self) {
        unsafe { CloseClipboard() };
    }
}

struct Text {
    owner: usize,
    sequence: u32,
}

impl Text {
    fn new(owner: usize) -> Self {
        Self {
            owner,
            sequence: unsafe { GetClipboardSequenceNumber() },
        }
    }

    fn open(&self) -> Option<Open> {
        (unsafe { OpenClipboard(self.owner as HWND) } != 0).then_some(Open)
    }

    fn changed(&mut self) -> Option<String> {
        let sequence = unsafe { GetClipboardSequenceNumber() };
        if sequence == self.sequence {
            return None;
        }
        let _open = self.open()?;
        // Capture the sequence while holding the clipboard so that a simultaneous
        // local copy cannot be mistaken for our last synchronized update.
        self.sequence = unsafe { GetClipboardSequenceNumber() };
        unsafe {
            let memory = GetClipboardData(TEXT);
            if memory.is_null() {
                return None;
            }
            let size = (GlobalSize(memory) / size_of::<u16>()).min(MAX_TEXT + 1);
            let pointer = GlobalLock(memory);
            if pointer.is_null() {
                return None;
            }
            let chars = std::slice::from_raw_parts(pointer.cast::<u16>(), size);
            let result = chars
                .iter()
                .position(|&unit| unit == 0)
                .and_then(|end| String::from_utf16(&chars[..end]).ok());
            GlobalUnlock(memory);
            result
        }
    }

    async fn apply(&mut self, value: String) -> Result<()> {
        let text = value.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        ensure!(
            text.len() <= MAX_TEXT + 1 && !value.contains('\0'),
            "剪贴板文本无效"
        );
        for _ in 0..5 {
            if let Some(_open) = self.open() {
                unsafe {
                    let memory = GlobalAlloc(GMEM_MOVEABLE, size_of_val(text.as_slice()));
                    ensure!(!memory.is_null(), "无法分配剪贴板内存");
                    let pointer = GlobalLock(memory);
                    if pointer.is_null() {
                        GlobalFree(memory);
                        anyhow::bail!("无法写入剪贴板");
                    }
                    ptr::copy_nonoverlapping(text.as_ptr(), pointer.cast::<u16>(), text.len());
                    GlobalUnlock(memory);
                    if EmptyClipboard() == 0 || SetClipboardData(TEXT, memory).is_null() {
                        GlobalFree(memory);
                        anyhow::bail!("无法更新剪贴板");
                    }
                    self.sequence = GetClipboardSequenceNumber();
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        anyhow::bail!("剪贴板暂被其他程序占用")
    }
}
