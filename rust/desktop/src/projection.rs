use std::{io, ptr, sync::Mutex};

use serde::{Deserialize, Serialize};
use tauri::{State, WebviewWindow};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM},
    Graphics::Gdi::{CombineRgn, CreateRectRgn, CreateRoundRectRgn, DeleteObject, RGN_DIFF, SetWindowRgn},
    System::LibraryLoader::GetModuleHandleW,
    UI::{Input::KeyboardAndMouse::{EnableWindow, IsWindowEnabled}, WindowsAndMessaging::*},
};

use crate::window_lease::wide;

const SURFACE_CLASS: &str = "ConWU.Projection.Surface";
const VIEWER_CLASS: &str = "ConWUProjectionWindow";
const SESSION_ENDED: &str = "ConWU.Projection.SessionEnded";
const STOPPING: &str = "ConWU.Projection.Stopping";
const MOONLIGHT: &str = "ConWU.Projection.Moonlight";
const WAIT_FOR_FRAME: &str = "ConWU.Projection.WaitForFrame";
const INPUT_BLOCKED: &str = "ConWU.Projection.InputBlocked";
const VIDEO_WIDTH: &str = "ConWU.Projection.VideoWidth";
const VIDEO_HEIGHT: &str = "ConWU.Projection.VideoHeight";
const FULLSCREEN: &str = "ConWU.Projection.Fullscreen";
const PENDING_FULLSCREEN: &str = "ConWU.Projection.PendingFullscreen";
const SYNC_SURFACE: u32 = WM_APP + 85;
const SYNC_VIEWER: u32 = WM_APP + 86;
const TOGGLE_FULLSCREEN: u32 = WM_APP + 87;
const SYNC_INPUT: u32 = WM_APP + 88;
const TOGGLE_STATS: u32 = WM_APP + 89;

#[derive(Clone, Deserialize, PartialEq, Eq)]
struct Cutout { left: i32, top: i32, right: i32, bottom: i32 }

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Placement {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    #[serde(default)]
    radius: i32,
    #[serde(default)]
    cutouts: Vec<Cutout>,
    #[serde(default = "default_visible")]
    show_viewer: bool,
    #[serde(default = "default_visible")]
    accept_input: bool,
}
fn default_visible() -> bool { true }

fn clip_dialogs(hwnd: HWND, p: &Placement) -> Result<(), String> {
    unsafe {
        let radius = p.radius.clamp(0, p.width.min(p.height) / 2);
        if p.cutouts.is_empty() && radius == 0 {
            if SetWindowRgn(hwnd, ptr::null_mut(), 1) == 0 { return Err("无法恢复播放区".into()); }
            return Ok(());
        }
        let region = if radius == 0 {
            CreateRectRgn(0, 0, p.width, p.height)
        } else {
            CreateRoundRectRgn(0, 0, p.width, p.height, radius * 2, radius * 2)
        };
        if region.is_null() { return Err("无法创建播放区".into()); }
        for c in &p.cutouts {
            let (left, top, right, bottom) = (c.left.max(0), c.top.max(0), c.right.min(p.width), c.bottom.min(p.height));
            if left >= right || top >= bottom { continue; }
            let hole = CreateRectRgn(left, top, right, bottom);
            if hole.is_null() || CombineRgn(region, region, hole, RGN_DIFF) == 0 {
                if !hole.is_null() { DeleteObject(hole); }
                DeleteObject(region);
                return Err("无法调整弹窗遮挡区域".into());
            }
            DeleteObject(hole);
        }
        if SetWindowRgn(hwnd, region, 1) == 0 {
            DeleteObject(region);
            return Err("无法设置播放区".into());
        }
        // Windows owns the region after a successful SetWindowRgn call.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Graphics::Gdi::{GetWindowRgn, PtInRegion};

    #[test]
    fn dialogs_only_cover_their_overlap_with_the_player() {
        unsafe {
            let hwnd = CreateWindowExW(0, wide("STATIC").unwrap().as_ptr(), ptr::null(), WS_POPUP,
                0, 0, 200, 100, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null());
            assert!(!hwnd.is_null());
            let mut p = Placement { x:0, y:0, width:200, height:100, radius:0, show_viewer:true, accept_input:true, cutouts:vec![
                Cutout {left:40, top:-20, right:90, bottom:80}, Cutout {left:220, top:0, right:245, bottom:100},
            ] };
            clip_dialogs(hwnd, &p).unwrap();
            let r = CreateRectRgn(0, 0, 0, 0);
            assert!(GetWindowRgn(hwnd, r) > 0);
            assert_eq!(PtInRegion(r, 50, 50), 0);
            assert_ne!(PtInRegion(r, 30, 50), 0);
            assert_ne!(PtInRegion(r, 198, 50), 0);
            p.cutouts.clear();
            p.radius = 12;
            clip_dialogs(hwnd, &p).unwrap();
            assert!(GetWindowRgn(hwnd, r) > 0);
            assert_eq!(PtInRegion(r, 0, 0), 0);
            assert_ne!(PtInRegion(r, 30, 0), 0);
            p.radius = 0;
            clip_dialogs(hwnd, &p).unwrap();
            assert_eq!(GetWindowRgn(hwnd, r), 0);
            DeleteObject(r);
            DestroyWindow(hwnd);
        }
    }

    #[test]
    fn live_frame_remains_selected_until_the_replacement_is_ready() {
        unsafe {
            let class = wide("STATIC").unwrap();
            let create = |parent, style| CreateWindowExW(
                0, class.as_ptr(), ptr::null(), style, 0, 0, 200, 100,
                parent, ptr::null_mut(), ptr::null_mut(), ptr::null(),
            );
            let parent = create(ptr::null_mut(), WS_POPUP);
            let host = create(parent, WS_CHILD);
            assert!(!parent.is_null() && !host.is_null());
            let live = create(host, WS_CHILD | WS_VISIBLE);
            let frozen = create(host, WS_CHILD | WS_VISIBLE);
            assert!(!live.is_null() && !frozen.is_null());
            set_flag(live, MOONLIGHT, true);
            set_flag(frozen, MOONLIGHT, true);
            set_flag(frozen, WAIT_FOR_FRAME, true);
            SetWindowPos(frozen, HWND_TOP, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE);
            assert_eq!(viewer(host), live);
            SetPropW(frozen, wide(VIDEO_WIDTH).unwrap().as_ptr(), 1920 as _);
            SetPropW(frozen, wide(VIDEO_HEIGHT).unwrap().as_ptr(), 1080 as _);
            assert!(viewer_size(frozen).is_none());
            set_flag(frozen, WAIT_FOR_FRAME, false);
            assert_eq!(viewer(host), frozen);
            assert_eq!(viewer_size(frozen), Some([1920, 1080]));
            set_flag(frozen, SESSION_ENDED, true);
            SetWindowLongPtrW(host, GWLP_USERDATA, 1);
            surface_proc(host, SYNC_SURFACE, 0, 0);
            assert!(window_shown(host));
            SetWindowLongPtrW(host, GWLP_USERDATA, 0);
            surface_proc(host, SYNC_SURFACE, 0, 0);
            assert!(!window_shown(host));
            DestroyWindow(parent);
        }
    }
}

#[derive(Serialize)]
pub struct ViewerState {
    attached: bool,
    ended: bool,
    stopping: bool,
    fullscreen: bool,
    video: Option<[u32; 2]>,
}

#[derive(Default)]
struct PlacementState {
    bounds: Option<Placement>,
    fullscreen: bool,
    interactive: bool,
}

pub struct Surface {
    origin: String,
    hwnd: isize,
    placement: Mutex<PlacementState>,
}

fn viewer(host: HWND) -> HWND {
    let class = wide(VIEWER_CLASS).unwrap();
    unsafe {
        let mut child = ptr::null_mut();
        let mut waiting: HWND = ptr::null_mut();
        loop {
            child = FindWindowExW(host, child, ptr::null(), ptr::null());
            if child.is_null() {
                break;
            }
            if is_moonlight(child) {
                if viewer_ready(child) && window_shown(child) {
                    return child;
                }
                if waiting.is_null() {
                    waiting = child;
                }
            }
        }
        if waiting.is_null() {
            FindWindowExW(host, ptr::null_mut(), class.as_ptr(), ptr::null())
        } else {
            waiting
        }
    }
}

fn is_moonlight(child: HWND) -> bool {
    !child.is_null() && unsafe { !GetPropW(child, wide(MOONLIGHT).unwrap().as_ptr()).is_null() }
}

fn viewer_ready(child: HWND) -> bool {
    !child.is_null() && unsafe { GetPropW(child, wide(WAIT_FOR_FRAME).unwrap().as_ptr()).is_null() }
}

fn window_shown(hwnd: HWND) -> bool {
    unsafe { GetWindowLongW(hwnd, GWL_STYLE) as u32 & WS_VISIBLE != 0 }
}

fn release_player_input(host: HWND) {
    unsafe {
        let mut child = ptr::null_mut();
        loop {
            child = FindWindowExW(host, child, ptr::null(), ptr::null());
            if child.is_null() { break; }
            PostMessageW(child, WM_CANCELMODE, 0, 0);
        }
    }
}

fn viewer_size(child: HWND) -> Option<[u32; 2]> {
    if !viewer_ready(child) {
        return None;
    }
    let [width, height] = [VIDEO_WIDTH, VIDEO_HEIGHT].map(|key| unsafe {
        GetPropW(child, wide(key).unwrap().as_ptr()) as usize
    });
    if (1..=16384).contains(&width) && (1..=16384).contains(&height) {
        Some([width as u32, height as u32])
    } else {
        None
    }
}

unsafe fn set_flag(hwnd: HWND, property: &str, on: bool) {
    let property = wide(property).unwrap();
    unsafe {
        if on {
            SetPropW(hwnd, property.as_ptr(), 1 as _);
        } else {
            RemovePropW(hwnd, property.as_ptr());
        }
    }
}

unsafe extern "system" fn surface_proc(
    hwnd: HWND,
    message: u32,
    wp: WPARAM,
    lp: LPARAM,
) -> LRESULT {
    unsafe {
        match message {
            SYNC_SURFACE => {
                let child = viewer(hwnd);
                // Keep the frozen view until WebView2 has painted its idle UI.
                let visible = viewer_ready(child) && GetWindowLongPtrW(hwnd, GWLP_USERDATA) != 0;
                let enabled = visible && GetPropW(hwnd, wide(INPUT_BLOCKED).unwrap().as_ptr()).is_null();
                if enabled != (IsWindowEnabled(hwnd) != 0) {
                    if !enabled { release_player_input(hwnd); }
                    EnableWindow(hwnd, enabled as i32);
                }
                let shown = window_shown(hwnd);
                if visible != shown {
                    // Already on the owner thread. Apply the latest intent now;
                    // a queued SW_SHOWNA can otherwise run after a page switch.
                    SetWindowPos(hwnd, if visible { HWND_TOP } else { HWND_BOTTOM }, 0, 0, 0, 0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE |
                        if visible { SWP_SHOWWINDOW } else { SWP_HIDEWINDOW });
                }
                if is_moonlight(child) {
                    // Resize and release capture on the thread owning the player.
                    // SetWindowPos can otherwise wait on the cross-process child.
                    PostMessageW(child, SYNC_INPUT, 0, 0);
                } else if !child.is_null() {
                    PostMessageW(child, SYNC_VIEWER, visible as WPARAM, 0);
                }
                return 0;
            }
            WM_NCHITTEST if GetWindowLongPtrW(hwnd, GWLP_USERDATA) == 0 || IsWindowEnabled(hwnd) == 0
                || !viewer_ready(viewer(hwnd)) => {
                return HTTRANSPARENT as LRESULT;
            }
            TOGGLE_FULLSCREEN => {
                let child = wp as HWND;
                if GetParent(child) == hwnd && is_moonlight(child) && IsWindowVisible(hwnd) != 0 {
                    let pending = GetPropW(hwnd, wide(PENDING_FULLSCREEN).unwrap().as_ptr()).is_null();
                    set_flag(hwnd, PENDING_FULLSCREEN, pending);
                }
                return 0;
            }
            WM_PARENTNOTIFY if matches!(wp as u32 & 0xffff, WM_DESTROY | WM_CREATE) => {
                PostMessageW(hwnd, SYNC_SURFACE, 0, 0);
            }
            WM_NCDESTROY => {
                let child = viewer(hwnd);
                if !child.is_null() {
                    PostMessageW(child, WM_CANCELMODE, 0, 0);
                    PostMessageW(child, WM_CLOSE, 0, 0);
                }
                set_flag(hwnd, PENDING_FULLSCREEN, false);
                set_flag(hwnd, FULLSCREEN, false);
                set_flag(hwnd, INPUT_BLOCKED, false);
            }
            _ => {}
        }
        DefWindowProcW(hwnd, message, wp, lp)
    }
}

impl Surface {
    pub fn new(window: &WebviewWindow, origin: String) -> Result<Self, Box<dyn std::error::Error>> {
        let class_name = wide(SURFACE_CLASS)?;
        let parent = window.hwnd()?.0 as HWND;
        unsafe {
            let instance = GetModuleHandleW(ptr::null());
            let class = WNDCLASSW {
                lpfnWndProc: Some(surface_proc),
                hInstance: instance,
                lpszClassName: class_name.as_ptr(),
                ..Default::default()
            };
            if RegisterClassW(&class) == 0 {
                return Err(io::Error::last_os_error().into());
            }
            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                ptr::null(),
                WS_CHILD | WS_DISABLED | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                0,
                0,
                1,
                1,
                parent,
                ptr::null_mut(),
                instance,
                ptr::null(),
            );
            if hwnd.is_null() {
                return Err(io::Error::last_os_error().into());
            }
            set_flag(hwnd, INPUT_BLOCKED, true);
            Ok(Self {
                origin,
                hwnd: hwnd as isize,
                placement: Mutex::default(),
            })
        }
    }

    pub fn close(&self) {
        let child = viewer(self.hwnd as HWND);
        if !child.is_null() {
            unsafe {
                PostMessageW(child, WM_CANCELMODE, 0, 0);
                PostMessageW(child, WM_CLOSE, 0, 0);
            }
        }
    }

    pub fn focus_changed(&self, focused: bool) {
        unsafe {
            let hwnd = self.hwnd as HWND;
            if !focused && GetForegroundWindow() != GetAncestor(hwnd, GA_ROOT) {
                release_player_input(hwnd);
            }
            PostMessageW(hwnd, SYNC_SURFACE, 0, 0);
        }
    }

    fn place(
        &self,
        window: &WebviewWindow,
        parent: HWND,
        placement: Option<Placement>,
        close_ended: bool,
        fullscreen: Option<bool>,
        toggle_stats: bool,
    ) -> Result<ViewerState, String> {
        let hwnd = self.hwnd as HWND;
        unsafe {
            let mut bounds = RECT::default();
            if GetClientRect(parent, &mut bounds) == 0 || GetParent(hwnd) != parent {
                return Err("Projection 播放区已关闭".into());
            }
            let child = viewer(hwnd);
            let attached = !child.is_null();
            let mut last = self.placement.lock().unwrap();
            let ready = viewer_ready(child);
            let ended = attached && !GetPropW(child, wide(SESSION_ENDED).unwrap().as_ptr()).is_null();
            let stopping = attached && !GetPropW(child, wide(STOPPING).unwrap().as_ptr()).is_null();
            let visible = placement.as_ref().is_some_and(|p| p.show_viewer) && !(close_ended && ended);
            let interactive = ready && !stopping && !ended && visible
                && placement.as_ref().is_some_and(|p| p.accept_input && p.cutouts.is_empty());
            let input_changed = interactive != last.interactive;
            if input_changed {
                set_flag(hwnd, INPUT_BLOCKED, !interactive);
                last.interactive = interactive;
            }
            if !interactive && (input_changed || !visible && window_shown(hwnd)) {
                release_player_input(hwnd);
            }
            if !visible || !ready {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                if window_shown(hwnd) { PostMessageW(hwnd, SYNC_SURFACE, 0, 0); }
            }

            let toggle = !RemovePropW(hwnd, wide(PENDING_FULLSCREEN).unwrap().as_ptr()).is_null();
            let fullscreen = visible && placement.as_ref().is_some_and(|p| p.cutouts.is_empty())
                && is_moonlight(child) && ready
                && fullscreen.unwrap_or(last.fullscreen ^ toggle);
            let mode_changed = fullscreen != last.fullscreen;
            if mode_changed {
                window.set_fullscreen(fullscreen).map_err(|error| error.to_string())?;
                last.fullscreen = fullscreen;
                set_flag(hwnd, FULLSCREEN, fullscreen);
            }
            let placement = if fullscreen {
                Some(Placement { x: 0, y: 0, width: bounds.right, height: bounds.bottom, radius:0, cutouts: vec![], show_viewer:true, accept_input:interactive })
            } else {
                placement
            };
            let changed = last.bounds != placement;
            if changed {
                if let Some(ref p) = placement {
                    if !(1..=32768).contains(&p.width) || !(1..=32768).contains(&p.height)
                        || p.x >= bounds.right || p.y >= bounds.bottom || p.x.saturating_add(p.width) <= 0
                        || p.y.saturating_add(p.height) <= 0 || p.cutouts.len() > 32
                    {
                        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                        ShowWindow(hwnd, SW_HIDE);
                        last.bounds = None;
                        return Err("Projection 播放区已超出窗口".into());
                    }
                    clip_dialogs(hwnd, p)?;
                    if SetWindowPos(hwnd, if visible && ready { HWND_TOP } else { HWND_BOTTOM },
                        p.x, p.y, p.width, p.height, SWP_NOACTIVATE)
                        == 0
                    {
                        return Err("无法调整 Projection 播放区".into());
                    }
                }
                last.bounds = placement;
            }
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, visible as isize);
            if close_ended && ended && PostMessageW(child, WM_CLOSE, 0, 0) == 0 {
                return Err("无法关闭已结束的 Projection 会话".into());
            }
            if toggle_stats && interactive && is_moonlight(child) {
                PostMessageW(child, TOGGLE_STATS, 0, 0);
            }
            if changed || mode_changed || input_changed || window_shown(hwnd) != (ready && visible) {
                PostMessageW(hwnd, SYNC_SURFACE, 0, 0);
            }
            Ok(ViewerState { attached, ended, stopping, fullscreen, video: viewer_size(child) })
        }
    }
}

#[tauri::command]
pub fn projection_surface(
    window: WebviewWindow,
    surface: State<'_, Surface>,
    placement: Option<Placement>,
    close_ended: Option<bool>,
    fullscreen: Option<bool>,
    toggle_stats: Option<bool>,
) -> Result<ViewerState, String> {
    let url = window.url().map_err(|error| error.to_string())?;
    if window.label() != "conwu"
        || url.origin().ascii_serialization() != surface.origin
        || url.path() != "/"
    {
        return Err("非法 Projection 播放区来源".into());
    }
    let hwnd = window.hwnd().map_err(|error| error.to_string())?;
    surface.place(&window, hwnd.0 as HWND, placement, close_ended.unwrap_or(false), fullscreen, toggle_stats.unwrap_or(false))
}
