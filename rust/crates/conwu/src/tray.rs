#[cfg(windows)]
pub fn start(
    panel: std::sync::Arc<crate::web::Panel>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::task::spawn_blocking(move || windows::run(windows::Context::Embedded(panel)))
}
#[cfg(windows)]
pub async fn client(data: std::path::PathBuf, open: bool) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Handle::current();
    if open {
        let response = service_link(&data).await?;
        crate::platform::open_browser(
            response["url"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("面板地址缺失"))?,
        )?;
    }
    tokio::task::spawn_blocking(move || windows::run(windows::Context::Service { data, runtime }))
        .await?
}
#[cfg(windows)]
async fn service_link(data: &std::path::Path) -> anyhow::Result<serde_json::Value> {
    crate::platform::start_client_service().await?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
    loop {
        match crate::control::call(data, &serde_json::json!({"method":"open"})).await {
            Ok(response) => return Ok(response),
            Err(error) if std::time::Instant::now() >= deadline => return Err(error),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
        }
    }
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
    static TASKBAR_CREATED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    pub enum Context {
        Embedded(Arc<Panel>),
        Service {
            data: std::path::PathBuf,
            runtime: tokio::runtime::Handle,
        },
    }
    impl Context {
        fn open(&self) {
            match self {
                Self::Embedded(panel) => {
                    let _ = crate::platform::open_browser(&panel.link());
                }
                Self::Service { data, runtime } => {
                    if let Ok(response) = runtime.block_on(super::service_link(data)) {
                        if let Some(url) = response["url"].as_str() {
                            let _ = crate::platform::open_browser(url);
                        }
                    }
                }
            }
        }
        fn stopped(&self) -> bool {
            match self {
                Self::Embedded(panel) => panel.app.engine.cancel.is_cancelled(),
                Self::Service { .. } => false,
            }
        }
        fn title(&self) -> String {
            match self {
                Self::Embedded(_) => "ConWU foreground".into(),
                Self::Service { data, .. } => crate::control::name(data).unwrap_or_default(),
            }
        }
    }
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }
    fn notification(hwnd: HWND) -> NOTIFYICONDATAW {
        unsafe {
            let instance = GetModuleHandleW(std::ptr::null());
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
            icon
        }
    }
    unsafe extern "system" fn window(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        // SAFETY: the window is confined to its creating thread. Its Panel Arc
        // outlives the message pump and is released only after DestroyWindow.
        let pointer = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const Context;
        if !pointer.is_null() {
            let panel = unsafe { &*pointer };
            if TASKBAR_CREATED.get().is_some_and(|id| *id == message) {
                let icon = notification(hwnd);
                if unsafe { Shell_NotifyIconW(NIM_ADD, &icon) } == 0
                    && unsafe { Shell_NotifyIconW(NIM_MODIFY, &icon) } == 0 {
                    tracing::warn!("Windows 任务栏重建后暂未恢复 ConWU 托盘图标");
                }
                return 0;
            }
            match message {
                CALLBACK => {
                    if lparam as u32 == WM_LBUTTONDBLCLK {
                        panel.open();
                    } else if lparam as u32 == WM_RBUTTONUP {
                        let menu = unsafe { CreatePopupMenu() };
                        if !menu.is_null() {
                            unsafe {
                                AppendMenuW(menu, MF_STRING, 1, wide("打开 WebUI").as_ptr());
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
                                    panel.open();
                                }
                            }
                        }
                    }
                    return 0;
                }
                WM_TIMER => {
                    if panel.stopped() {
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
    pub fn run(panel: Context) -> Result<()> {
        unsafe {
            let instance = GetModuleHandleW(std::ptr::null());
            let name = wide("ConWURustExperimentTray");
            let title = wide(&panel.title());
            if !FindWindowW(name.as_ptr(), title.as_ptr()).is_null() {
                return Ok(());
            }
            let mut class: WNDCLASSW = std::mem::zeroed();
            class.lpfnWndProc = Some(window);
            class.hInstance = instance;
            class.lpszClassName = name.as_ptr();
            ensure!(RegisterClassW(&class) != 0, "无法注册实验托盘窗口");
            let hwnd = CreateWindowExW(
                0,
                name.as_ptr(),
                title.as_ptr(),
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
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, (&*context as *const Context) as isize);
            let taskbar = *TASKBAR_CREATED.get_or_init(|| RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()));
            ensure!(taskbar != 0, "无法监听 Windows 任务栏重建消息");
            ChangeWindowMessageFilterEx(hwnd, taskbar, MSGFLT_ALLOW, std::ptr::null_mut());
            let icon = notification(hwnd);
            if Shell_NotifyIconW(NIM_ADD, &icon) == 0 && Shell_NotifyIconW(NIM_MODIFY, &icon) == 0 {
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
