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
        crate::platform::open_panel(
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
fn projection_window(executable: &str, origin: &str) -> Option<usize> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::Path, ptr};
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        },
        UI::WindowsAndMessaging::{FindWindowW, GetWindowThreadProcessId},
    };

    let port = origin.strip_prefix("http://127.0.0.1:")?.parse::<u16>().ok()?;
    let class: Vec<_> = format!("ConWU.Desktop.{port}").encode_utf16().chain(Some(0)).collect();
    let expected = Path::new(executable).canonicalize().ok()?;
    unsafe {
        let window = FindWindowW(class.as_ptr(), ptr::null());
        if window.is_null() {
            return None;
        }
        let mut pid = 0;
        GetWindowThreadProcessId(window, &mut pid);
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let mut image = vec![0u16; 32768];
        let mut count = image.len() as u32;
        let found = QueryFullProcessImageNameW(process, 0, image.as_mut_ptr(), &mut count);
        CloseHandle(process);
        if found == 0 {
            return None;
        }
        let actual = std::path::PathBuf::from(OsString::from_wide(&image[..count as usize])).canonicalize().ok()?;
        if !actual.to_string_lossy().eq_ignore_ascii_case(&expected.to_string_lossy()) {
            return None;
        }
        Some(window as usize)
    }
}

#[cfg(windows)]
fn projection_surface(window: usize) -> Option<usize> {
    use windows_sys::Win32::UI::WindowsAndMessaging::FindWindowExW;

    let class: Vec<_> = "ConWU.Projection.Surface".encode_utf16().chain(Some(0)).collect();
    let child = unsafe {
        FindWindowExW(window as _, std::ptr::null_mut(), class.as_ptr(), std::ptr::null())
    };
    (!child.is_null()).then_some(child as usize)
}

#[cfg(windows)]
async fn projection_desktop(data: std::path::PathBuf, owner: usize) {
    use crate::projection::{self, companion, moonlight, sunshine};
    use crate::projection::companion::browser::{self, Action, Query, QueryResult};
    use serde_json::json;
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, watch};
    use tokio_util::sync::CancellationToken;

    struct Moonlight {
        target: moonlight::Target,
        progress: watch::Receiver<moonlight::Stage>,
        surface: usize,
        stop: CancellationToken,
        task: tokio::task::JoinHandle<anyhow::Result<()>>,
        valid_until: Instant,
    }

    impl Drop for Moonlight {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    struct ClipboardTask {
        route: companion::Route,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for ClipboardTask {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn running(child: &mut Option<Child>) -> bool {
        let running = child.as_mut().is_some_and(|child| matches!(child.try_wait(), Ok(None)));
        if !running { *child = None; }
        running
    }

    let mut host = None;
    let mut external: Option<Moonlight> = None;
    let mut external_error = None;
    let mut bundled_path = None;
    let mut sunshine_hosts = sunshine::Hosts::default();
    let mut companion_hosts = companion::Hosts::default();
    let inbox = companion::inbox();
    let clipboard = companion::Clipboard::new(owner);
    let mut clipboard_task: Option<ClipboardTask> = None;
    let mut next_clipboard = Instant::now();
    let mut files = companion::Files::default();
    let (file_results, mut completed_queries) = mpsc::channel::<QueryResult>(2);
    let mut file_replies = Vec::new();
    let (file_drop, mut drops) = mpsc::channel::<(moonlight::Target, companion::DroppedFiles)>(4);
    let mut sunshine_valid_until = Instant::now();
    let mut next_start = Instant::now();
    loop {
        let host_open = running(&mut host);
        if external.as_ref().is_some_and(|session| session.task.is_finished()) {
            let mut finished = external.take().unwrap();
            external_error = match (&mut finished.task).await {
                Ok(result) => result.err().map(|error| error.to_string()),
                Err(error) => Some(format!("Moonlight 会话异常结束：{error}")),
            };
        }
        let report = moonlight::Report {
            available: bundled_path.is_some(),
            target: external.as_ref().map(|session| session.target.clone()),
            stage: external.as_ref().map(|session| *session.progress.borrow()).unwrap_or_default(),
            error: external_error.clone(),
        };
        let host_reports = sunshine_hosts.reports();
        while file_replies.len() < 2 {
            let Ok(reply) = completed_queries.try_recv() else { break };
            file_replies.push(reply);
        }
        let request = json!({
            "method":"projection-desktop",
            "moonlight":report,"sunshine":host_reports,
            "companions":companion_hosts.reports(),"files":files.reports(),"fileResults":file_replies,
        });
        let mut delay = Duration::from_secs(3);
        if external.is_some() || !host_reports.is_empty() {
            delay = Duration::from_millis(400);
        }
        let work = tokio::time::timeout(Duration::from_millis(900), crate::control::call(&data, &request))
            .await.ok().and_then(Result::ok).filter(|work| work["ok"] == true);
        if let Some(session) = &mut external {
            if !moonlight::surface_open(session.surface) {
                session.stop.cancel();
            } else if let Some(work) = &work {
                if work["stopMoonlight"] == false {
                    session.valid_until = Instant::now() + Duration::from_secs(2);
                } else {
                    session.stop.cancel();
                }
            } else if Instant::now() >= session.valid_until {
                session.stop.cancel();
            }
        }
        if let Some(work) = work {
            file_replies.clear();
            bundled_path = work["moonlightExecutable"].as_str().map(PathBuf::from);
            if let Some(url) = work["desktopUrl"].as_str() {
                if let Err(error) = crate::platform::open_projection_desktop(url) {
                    tracing::warn!(%error, "无法打开 ConWU 桌面窗口");
                }
            }
            if let Some(program) = work["sunshineExecutable"].as_str() {
                delay = Duration::from_millis(400);
                if let Ok(bindings) = serde_json::from_value(work["bindings"].clone()) {
                    sunshine_hosts.synchronize(&data, std::path::Path::new(program), bindings);
                    sunshine_valid_until = Instant::now() + Duration::from_secs(3);
                }
            } else {
                sunshine_hosts = sunshine::Hosts::default();
            }
            let routes: Vec<companion::Route> = serde_json::from_value(work["companions"].clone()).unwrap_or_default();
            if let Err(error) = companion_hosts.synchronize(&routes, &sunshine_hosts, inbox.as_deref(), &clipboard).await {
                tracing::debug!(%error, "Projection 辅助连接未能启动");
            }
            let stop_files: Vec<String> = serde_json::from_value(work["stopFiles"].clone()).unwrap_or_default();
            files.reconcile(&routes, &stop_files);
            let queries: Vec<Query> = serde_json::from_value(work["fileQueries"].clone()).unwrap_or_default();
            for query in queries {
                let result = if !routes.contains(&query.route) {
                    Err(anyhow::anyhow!("对机直连或权限已变化"))
                } else {
                    match query.action {
                        Action::Copy { from, paths, destination } => {
                            let job = companion::Job { record: query.route.binding.record.clone(), id: query.id.clone() };
                            let source = companion::FileSource::Browser { from, paths, destination };
                            files.start(job, source, &routes).map(|()| json!(query.id))
                        }
                        Action::Clear => {
                            files.clear_finished(&query.route.binding.record);
                            Ok(json!(true))
                        }
                        action => {
                            let results = file_results.clone();
                            tokio::spawn(async move {
                                let result = browser::execute(action, query.route).await;
                                let _ = results.send(QueryResult::new(query.id, result)).await;
                            });
                            continue;
                        }
                    }
                };
                let results = file_results.clone();
                tokio::spawn(async move { let _ = results.send(QueryResult::new(query.id, result)).await; });
            }
            let panel_window = || {
                let path = work["desktopExecutable"].as_str()?;
                projection_window(path, work["panelOrigin"].as_str()?)
            };
            if let Ok(job) = serde_json::from_value::<companion::Job>(work["sendFile"].clone()) {
                if let Err(error) = files.start(job.clone(), companion::FileSource::Picker(panel_window()), &routes) {
                    files.failed(job, error);
                }
            }
            let playing = external.as_ref().filter(|session| {
                !session.stop.is_cancelled() && matches!(*session.progress.borrow(), moonlight::Stage::Playing)
            });
            while let Ok((target, batch)) = drops.try_recv() {
                if let Some(session) = playing.filter(|session| session.target == target) {
                    let job = companion::Job { record: session.target.record.clone(), id: conwu_core::id() };
                    if let Err(error) = files.start(job.clone(), companion::FileSource::Drop(batch), &routes) {
                        files.failed(job, error);
                    }
                }
            }
            let clipboard_route = playing.and_then(|session| routes.iter().find(|route| {
                route.port != 0 && route.binding.clipboard && route.binding.record == session.target.record
            }));
            if clipboard_task.as_ref().is_some_and(|active| {
                active.task.is_finished() || clipboard_route != Some(&active.route)
            }) {
                clipboard_task = None;
            }
            if let Some(route) = clipboard_route.filter(|_| clipboard_task.is_none() && Instant::now() >= next_clipboard) {
                next_clipboard = Instant::now() + Duration::from_secs(4);
                let route = route.clone();
                let target = route.clone();
                let clipboard = clipboard.clone();
                let task = tokio::spawn(async move {
                    if let Err(error) = clipboard.sync(target).await {
                        tracing::debug!(%error, "Projection 剪贴板连接未能继续");
                    }
                });
                clipboard_task = Some(ClipboardTask { route, task });
            }
            if work["listen"] == false {
                // Closing the legacy host's stdin releases its listeners.
                if let Some(child) = &mut host {
                    child.stdin.take();
                }
            }
            let launch = &work["launch"];
            if external.is_none() && !launch["moonlight"].is_null() {
                let start = || -> anyhow::Result<Moonlight> {
                    use anyhow::Context as _;

                    let target: moonlight::Target = serde_json::from_value(launch["moonlight"].clone())?;
                    let video = serde_json::from_value(launch["video"].clone())?;
                    let surface = panel_window().and_then(projection_surface)
                        .context("ConWU 桌面播放区已关闭")?;
                    let program = bundled_path.clone().context("Projection 同窗播放组件不可用")?;
                    let directory = projection::state_dir(&data, "Moonlight", "client")?;
                    let stop = CancellationToken::new();
                    let (progress, observer) = watch::channel(moonlight::Stage::default());
                    let companion = routes.iter().find(|route| route.binding.record == target.record
                        && route.binding.local == target.local && route.binding.remote == target.remote
                        && route.port != 0).cloned().context("对端 Projection 自动连接组件尚未就绪")?;
                    let task = tokio::spawn(moonlight::play(program, directory, target.clone(), video, surface, progress, stop.clone(), companion, file_drop.clone()));
                    Ok(Moonlight { target, progress: observer, surface, stop, task, valid_until: Instant::now() + Duration::from_secs(2) })
                };
                match start() {
                    Ok(session) => {
                        external = Some(session);
                        external_error = None;
                    }
                    Err(error) => external_error = Some(error.to_string()),
                }
            }
            if let Some(executable) = work["executable"].as_str() {
                delay = Duration::from_millis(400);
                let command = |kind| {
                    let mut command = Command::new(executable);
                    command.arg(kind).arg(&data).arg(crate::instance::service_name()).creation_flags(0x08000000);
                    command
                };
                if work["listen"] == true && !host_open && Instant::now() >= next_start {
                    next_start = Instant::now() + Duration::from_secs(2);
                    match command("--conwu-host").stdin(Stdio::piped()).spawn() {
                        Ok(child) => host = Some(child),
                        Err(error) => tracing::warn!(%error, "Projection 监听进程启动失败"),
                    }
                }
            }
        }
        if Instant::now() >= sunshine_valid_until {
            sunshine_hosts = sunshine::Hosts::default();
            companion_hosts = companion::Hosts::default();
            files.reconcile(&[], &[]);
            clipboard_task = None;
        }
        tokio::time::sleep(delay).await;
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
                    let _ = crate::platform::open_panel(&panel.link());
                }
                Self::Service { data, runtime } => {
                    if let Ok(response) = runtime.block_on(super::service_link(data)) {
                        if let Some(url) = response["url"].as_str() {
                            let _ = crate::platform::open_panel(url);
                        }
                    }
                }
            }
        }
        fn exit(&self) {
            let origin = match self {
                Self::Embedded(panel) => {
                    panel.app.engine.cancel.cancel();
                    Some(panel.origin.clone())
                }
                Self::Service { runtime, data } => runtime.block_on(tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    crate::control::call(data, &serde_json::json!({"method":"panel-origin"})),
                )).ok().and_then(Result::ok).and_then(|reply| reply["origin"].as_str().map(str::to_owned)),
            };
            let Some(origin) = origin else { return };
            let Ok(exe) = std::env::current_exe() else { return };
            let Some(root) = exe.parent() else { return };
            for path in ["components/ConWU-Desktop.exe", "app/components/ConWU-Desktop.exe"] {
                if let Some(window) = root.join(path).to_str().and_then(|path| super::projection_window(path, &origin)) {
                    unsafe { PostMessageW(window as HWND, WM_CLOSE, 0, 0); }
                    break;
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
                Self::Embedded(panel) => {
                    crate::control::name(&panel.app.store.root).unwrap_or_default()
                }
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
                                AppendMenuW(menu, MF_STRING, 1, wide("打开 ConWU").as_ptr());
                                AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
                                AppendMenuW(menu, MF_STRING, 2, wide("退出 ConWU").as_ptr());
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
                                } else if selection == 2 {
                                    panel.exit();
                                    DestroyWindow(hwnd);
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
            let identity = panel.title();
            let lease_name = format!(
                r"Local\ConWU.Tray.{}",
                identity.rsplit('.').next().unwrap_or("foreground")
            );
            let Some(_lease) = crate::desktop::TrayLease::acquire(&lease_name)? else {
                return Ok(());
            };
            let title = wide(&identity);
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
            let projection = match context.as_ref() {
                Context::Service { data, runtime } => Some(runtime.spawn(super::projection_desktop(data.clone(), hwnd as usize))),
                Context::Embedded(_) => None,
            };
            let mut message: MSG = std::mem::zeroed();
            while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            if let Some(projection) = projection { projection.abort(); }
            Shell_NotifyIconW(NIM_DELETE, &icon);
            UnregisterClassW(name.as_ptr(), instance);
            drop(context);
            Ok(())
        }
    }
}
