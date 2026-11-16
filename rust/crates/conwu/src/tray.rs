#[cfg(windows)]
pub fn start(
    panel: std::sync::Arc<crate::web::Panel>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::task::spawn_blocking(move || windows::run(panel))
}
#[cfg(windows)]
mod windows {
    use crate::web::Panel;
    use anyhow::{Result, ensure};
    use std::sync::Arc;
    use windows_sys::Win32::{
        Foundation::*,
        System::LibraryLoader::GetModuleHandleW,
        UI::{Shell::*, WindowsAndMessaging::*},
    };
    const CALLBACK: u32 = WM_APP + 31;
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }
    unsafe extern "system" fn window(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        // SAFETY: the window is confined to its creating thread. Its Panel Arc
        // outlives the message pump and is released only after DestroyWindow.
        let pointer = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const Arc<Panel>;
        if !pointer.is_null() {
            let panel = unsafe { &*pointer };
            match message {
                CALLBACK => {
                    if lparam as u32 == WM_LBUTTONDBLCLK {
                        let _ = crate::platform::open_browser(&panel.link());
                    } else if lparam as u32 == WM_RBUTTONUP {
                        let menu = unsafe { CreatePopupMenu() };
                        if !menu.is_null() {
                            unsafe {
                                AppendMenuW(menu, MF_STRING, 1, wide("打开 WebUI").as_ptr());
                                AppendMenuW(
                                    menu,
                                    MF_STRING,
                                    2,
                                    wide("退出 Rust 实验后台").as_ptr(),
                                );
                                let mut point: POINT = std::mem::zeroed();
                                GetCursorPos(&mut point);
                                SetForegroundWindow(hwnd);
                                let selection = TrackPopupMenu(
                                    menu,
                                    TPM_RETURNCMD | TPM_RIGHTBUTTON,
                                    point.x,
                                    point.y,
                                    0,
                                    hwnd,
                                    std::ptr::null(),
                                );
                                DestroyMenu(menu);
                                if selection == 1 {
                                    let _ = crate::platform::open_browser(&panel.link());
                                } else if selection == 2 {
                                    panel.app.engine.cancel.cancel();
                                    DestroyWindow(hwnd);
                                }
                            }
                        }
                    }
                    return 0;
                }
                WM_TIMER => {
                    if panel.app.engine.cancel.is_cancelled() {
                        unsafe { DestroyWindow(hwnd) };
                    }
                    return 0;
                }
                WM_CLOSE => {
                    unsafe { DestroyWindow(hwnd) };
                    return 0;
                }
                WM_DESTROY => {
                    unsafe { PostQuitMessage(0) };
                    return 0;
                }
                _ => {}
            }
        }
        unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
    }
    pub fn run(panel: Arc<Panel>) -> Result<()> {
        unsafe {
            let instance = GetModuleHandleW(std::ptr::null());
            let name = wide("ConWURustExperimentTray");
            let mut class: WNDCLASSW = std::mem::zeroed();
            class.lpfnWndProc = Some(window);
            class.hInstance = instance;
            class.lpszClassName = name.as_ptr();
            ensure!(RegisterClassW(&class) != 0, "无法注册实验托盘窗口");
            let hwnd = CreateWindowExW(
                0,
                name.as_ptr(),
                wide("ConWU").as_ptr(),
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                std::ptr::null(),
            );
            ensure!(!hwnd.is_null(), "无法创建实验托盘窗口");
            let context = Box::new(panel);
            SetWindowLongPtrW(
                hwnd,
                GWLP_USERDATA,
                (&*context as *const Arc<Panel>) as isize,
            );
            let mut icon: NOTIFYICONDATAW = std::mem::zeroed();
            icon.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            icon.hWnd = hwnd;
            icon.uID = 1;
            icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            icon.uCallbackMessage = CALLBACK;
            icon.hIcon = LoadIconW(instance, 101usize as *const u16);
            if icon.hIcon.is_null() {
                icon.hIcon = LoadIconW(std::ptr::null_mut(), IDI_APPLICATION);
            }
            let tip = wide("ConWU");
            icon.szTip[..tip.len()].copy_from_slice(&tip);
            if Shell_NotifyIconW(NIM_ADD, &icon) == 0 {
                DestroyWindow(hwnd);
                UnregisterClassW(name.as_ptr(), instance);
                anyhow::bail!("无法添加实验托盘图标")
            }
            SetTimer(hwnd, 1, 500, None);
            let mut message: MSG = std::mem::zeroed();
            while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            Shell_NotifyIconW(NIM_DELETE, &icon);
            UnregisterClassW(name.as_ptr(), instance);
            drop(context);
            Ok(())
        }
    }
}
