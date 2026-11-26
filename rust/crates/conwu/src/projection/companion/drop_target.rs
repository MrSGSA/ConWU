use std::{
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use windows::{
    Win32::{
        Foundation::POINT as AutomationPoint,
        System::{
            Com::{
                CLSCTX_ALL, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
                CoTaskMemFree, CoUninitialize, IServiceProvider,
            },
            Variant::VARIANT,
        },
        UI::{
            Accessibility::{
                CUIAutomation, IUIAutomation, UIA_DataItemControlTypeId, UIA_ListItemControlTypeId,
            },
            Shell::{
                IFolderView, IPersistFolder2, IShellBrowser, IShellWindows, SHGetNameFromIDList,
                SID_STopLevelBrowser, SIGDN_FILESYSPATH, ShellWindows,
            },
        },
    },
    core::Interface,
};
use windows_sys::Win32::{
    Foundation::{HWND, POINT, RECT},
    Graphics::Gdi::{GetMonitorInfoW, MONITOR_DEFAULTTONULL, MONITORINFO, MonitorFromPoint},
    UI::{
        HiDpi::{
            DPI_AWARENESS_CONTEXT, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
            SetThreadDpiAwarenessContext,
        },
        Shell::FOLDERID_Desktop,
        WindowsAndMessaging::{
            FindWindowExW, GA_ROOT, GetAncestor, GetClassNameW, GetCursorPos, GetShellWindow,
            GetSystemMetrics, GetWindowRect, IsWindowVisible, SM_CMONITORS, WindowFromPoint,
        },
    },
};

#[derive(Clone, Copy, Deserialize, Serialize)]
pub(crate) struct DropPoint {
    x: u16,
    y: u16,
    width: u16,
    height: u16,
}

impl DropPoint {
    fn on_monitor(self, monitor: RECT) -> Option<POINT> {
        let width = f64::from(monitor.right - monitor.left);
        let height = f64::from(monitor.bottom - monitor.top);
        let frame_width = f64::from(self.width);
        let frame_height = f64::from(self.height);
        if width <= 0.0 || height <= 0.0 {
            return None;
        }
        // Sunshine fits the captured monitor into the requested stream dimensions.
        let scale = (frame_width / width).min(frame_height / height);
        let x = (f64::from(self.x) * frame_width / 65535.0 - (frame_width - width * scale) / 2.0)
            / scale;
        let y = (f64::from(self.y) * frame_height / 65535.0
            - (frame_height - height * scale) / 2.0)
            / scale;
        ((0.0..width).contains(&x) && (0.0..height).contains(&y)).then(|| POINT {
            x: monitor.left + x.floor() as i32,
            y: monitor.top + y.floor() as i32,
        })
    }
}

pub(super) struct DpiScope(DPI_AWARENESS_CONTEXT);
impl DpiScope {
    pub(super) fn physical_pixels() -> Self {
        Self(unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) })
    }
}
impl Drop for DpiScope {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { SetThreadDpiAwarenessContext(self.0) };
        }
    }
}

struct ComScope;
impl Drop for ComScope {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

pub(super) async fn locate(point: DropPoint) -> Result<PathBuf> {
    ensure!(
        (320..=8192).contains(&point.width) && (200..=8192).contains(&point.height),
        "远控落点的画面尺寸无效"
    );
    tokio::time::timeout(
        Duration::from_secs(4),
        tokio::task::spawn_blocking(move || {
            let _dpi = DpiScope::physical_pixels();
            let target = screen_point(point)?;
            let hit = unsafe { WindowFromPoint(target) };
            ensure!(!hit.is_null(), "请把文件拖到对端桌面或资源管理器的文件区域");
            let root = unsafe { GetAncestor(hit, GA_ROOT) };
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()? };
            let _com = ComScope;
            let folder = if is_desktop(root) {
                super::desktop::known_folder(&FOLDERID_Desktop).context("对端桌面目录不可用")?
            } else {
                explorer_folder(root, target)?
            };
            let path = folder_icon(&folder, target).unwrap_or(folder);
            let verified = crate::store::Store::resolve_root(&path)?;
            ensure!(verified.is_dir(), "对端落点目录已关闭或移动");
            Ok(path)
        }),
    )
    .await
    .context("对端文件夹没有及时响应")??
}

fn screen_point(drop: DropPoint) -> Result<POINT> {
    let single_monitor = unsafe { GetSystemMetrics(SM_CMONITORS) } == 1;
    for _ in 0..16 {
        let mut cursor = POINT::default();
        if unsafe { GetCursorPos(&mut cursor) } != 0 {
            let monitor = unsafe { MonitorFromPoint(cursor, MONITOR_DEFAULTTONULL) };
            let mut info = MONITORINFO {
                cbSize: size_of::<MONITORINFO>() as u32,
                ..Default::default()
            };
            if !monitor.is_null() && unsafe { GetMonitorInfoW(monitor, &mut info) } != 0 {
                if let Some(target) = drop.on_monitor(info.rcMonitor) {
                    if single_monitor
                        || (target.x.abs_diff(cursor.x) <= 3 && target.y.abs_diff(cursor.y) <= 3)
                    {
                        return Ok(target);
                    }
                }
                if single_monitor {
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    anyhow::bail!("无法确定对端画面落点，请拖到桌面或文件夹的可见区域")
}

fn is_desktop(root: HWND) -> bool {
    if root.is_null() {
        return false;
    }
    if root == unsafe { GetShellWindow() } {
        return true;
    }
    let mut class = [0u16; 32];
    let len = unsafe { GetClassNameW(root, class.as_mut_ptr(), class.len() as i32) };
    let view: Vec<_> = "SHELLDLL_DefView".encode_utf16().chain(Some(0)).collect();
    len > 0
        && String::from_utf16_lossy(&class[..len as usize]) == "WorkerW"
        && !unsafe { FindWindowExW(root, std::ptr::null_mut(), view.as_ptr(), std::ptr::null()) }
            .is_null()
}

fn explorer_folder(root: HWND, point: POINT) -> Result<PathBuf> {
    unsafe {
        let windows: IShellWindows = CoCreateInstance(&ShellWindows, None, CLSCTX_ALL)?;
        for index in 0..windows.Count()? {
            let view = (|| {
                let provider = windows
                    .Item(&VARIANT::from(index))?
                    .cast::<IServiceProvider>()?;
                let browser: IShellBrowser = provider.QueryService(&SID_STopLevelBrowser)?;
                browser.QueryActiveShellView()
            })();
            let Ok(view) = view else { continue };
            let Ok(window) = view.GetWindow() else {
                continue;
            };
            let mut bounds = RECT::default();
            if GetAncestor(window.0, GA_ROOT) != root
                || IsWindowVisible(window.0) == 0
                || GetWindowRect(window.0, &mut bounds) == 0
                || !(bounds.left..bounds.right).contains(&point.x)
                || !(bounds.top..bounds.bottom).contains(&point.y)
            {
                continue;
            }
            let folder: IPersistFolder2 = view.cast::<IFolderView>()?.GetFolder()?;
            let id = folder.GetCurFolder()?;
            let path = SHGetNameFromIDList(id, SIGDN_FILESYSPATH);
            CoTaskMemFree(Some(id.cast()));
            let path = path.context("请拖到对端资源管理器的本地文件夹")?;
            let result = path.to_string();
            CoTaskMemFree(Some(path.0.cast()));
            return Ok(PathBuf::from(result?));
        }
    }
    anyhow::bail!("请把文件拖到对端桌面或资源管理器的文件区域")
}

fn folder_icon(folder: &Path, point: POINT) -> Option<PathBuf> {
    unsafe {
        let automation: IUIAutomation = CoCreateInstance(&CUIAutomation, None, CLSCTX_ALL).ok()?;
        let mut element = automation
            .ElementFromPoint(AutomationPoint {
                x: point.x,
                y: point.y,
            })
            .ok()?;
        let walker = automation.ControlViewWalker().ok()?;
        for _ in 0..4 {
            let kind = element.CurrentControlType().ok()?;
            if kind == UIA_ListItemControlTypeId || kind == UIA_DataItemControlTypeId {
                let name = element.CurrentName().ok()?.to_string();
                let mut parts = Path::new(&name).components();
                if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
                    return None;
                }
                let target = folder.join(name);
                return target.is_dir().then_some(target);
            }
            element = walker.GetParentElement(&element).ok()?;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_coordinates_account_for_stream_bars_and_monitor_offsets() {
        let monitor = RECT {
            left: -1280,
            right: 0,
            top: 0,
            bottom: 1024,
        };
        let center = DropPoint {
            x: 32768,
            y: 32768,
            width: 1920,
            height: 1080,
        };
        let target = center.on_monitor(monitor).unwrap();
        assert_eq!((target.x, target.y), (-640, 512));
        let left_bar = DropPoint { x: 0, ..center };
        assert!(left_bar.on_monitor(monitor).is_none());
    }
}
