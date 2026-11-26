use crate::backend::App;
use anyhow::{Result, ensure};
static SERVICE_CANCEL: std::sync::OnceLock<tokio_util::sync::CancellationToken> =
    std::sync::OnceLock::new();
pub fn service_cancel() -> tokio_util::sync::CancellationToken {
    SERVICE_CANCEL
        .get_or_init(tokio_util::sync::CancellationToken::new)
        .clone()
}
pub async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {r=tokio::signal::ctrl_c()=>r?,_=term.recv()=>{}}
    }
    #[cfg(windows)]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
pub fn service_registered() -> bool {
    #[cfg(windows)]
    {
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .and_then(|manager| {
                manager.open_service(crate::instance::service_name(), ServiceAccess::QUERY_STATUS)
            })
            .is_ok()
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("systemctl")
            .args([
                "show",
                "--property=LoadState",
                "--value",
                crate::instance::linux_unit(),
            ])
            .output()
            .is_ok_and(|o| {
                o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "loaded"
            })
    }
}
pub fn is_service_process() -> bool {
    #[cfg(windows)]
    {
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .and_then(|manager| {
                manager.open_service(crate::instance::service_name(), ServiceAccess::QUERY_STATUS)
            })
            .and_then(|service| service.query_status())
            .is_ok_and(|status| status.process_id == Some(std::process::id()))
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("systemctl")
            .args([
                "show",
                "--property=MainPID",
                "--value",
                crate::instance::linux_unit(),
            ])
            .output()
            .is_ok_and(|out| {
                out.status.success()
                    && String::from_utf8_lossy(&out.stdout)
                        .trim()
                        .parse::<u32>()
                        .ok()
                        == Some(std::process::id())
            })
    }
}
#[cfg(windows)]
pub async fn start_client_service() -> Result<()> {
    use windows_service::{
        Error,
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    use windows_sys::Win32::Foundation::ERROR_SERVICE_ALREADY_RUNNING;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let name = crate::instance::service_name();
    let service = manager.open_service(&name, ServiceAccess::QUERY_STATUS)?;
    let status = service.query_status()?.current_state;
    if matches!(status, ServiceState::Running | ServiceState::StartPending) {
        return Ok(());
    }
    let service = manager.open_service(&name, ServiceAccess::START)?;
    match service.start::<&str>(&[]) {
        Ok(()) => Ok(()),
        Err(Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_ALREADY_RUNNING as i32) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}
pub async fn configure_startup(app: &App, enabled: bool) -> Result<()> {
    if app.engine.memory {
        return Ok(());
    }
    ensure!(
        service_registered(),
        "请先注册独立的 Rust 实验后台服务，再设置开机启动"
    );
    let result = tokio::task::spawn_blocking(move || -> Result<()> {
        #[cfg(windows)]
        configure_windows_startup(enabled)?;
        #[cfg(target_os = "linux")]
        {
            let mut command = std::process::Command::new("systemctl");
            command.args([
                if enabled { "enable" } else { "disable" },
                crate::instance::linux_unit(),
            ]);
            command.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
            ensure!(command.status()?.success(), "实验服务的启动设置保存失败");
        }
        Ok(())
    })
    .await?;
    result
}
#[cfg(windows)]
pub(crate) fn windows_launcher(exe: std::path::PathBuf) -> std::path::PathBuf {
    exe.parent()
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.eq_ignore_ascii_case("app")))
        .and_then(|p| p.parent())
        .map(|p| p.join("ConWU.exe"))
        .filter(|p| p.is_file())
        .unwrap_or(exe)
}

#[cfg(windows)]
pub(crate) fn configure_windows_startup(enabled: bool) -> Result<()> {
    use std::os::windows::process::CommandExt;
    let command = if enabled {
        let launcher = windows_launcher(std::env::current_exe()?);
        let launcher = filesystem_argument(&launcher)?;
        let launcher = launcher.to_str().ok_or_else(|| anyhow::anyhow!("开机程序路径不是有效 Unicode"))?;
        let args = crate::instance::validation()
            .map(|id| format!("--validation-instance {id} --startup"))
            .unwrap_or_else(|| "--startup".into());
        Some(format!("\"{launcher}\" {args}"))
    } else {
        None
    };
    crate::desktop::update_startup(&crate::instance::startup_name(), command.as_deref(), || {
        let output = std::process::Command::new("sc.exe")
            .args(["config", &crate::instance::service_name(), "start=", if enabled { "auto" } else { "demand" }])
            .creation_flags(0x08000000).output()?;
        if output.status.success() { Ok(()) }
        else { Err(std::io::Error::other(format!("后台自启动设置失败：{} {}",
            String::from_utf8_lossy(&output.stdout).trim(), String::from_utf8_lossy(&output.stderr).trim()))) }
    })?;
    Ok(())
}
pub fn start(app: std::sync::Arc<App>) {
    if app.engine.memory {
        return;
    }
    let tracker = app.engine.tracker.clone();
    tracker.spawn(async move {
        loop {
            let registered=tokio::task::spawn_blocking(service_registered).await.unwrap_or(false);
            let auto=app.db.read().unwrap().device_settings["autoStart"].as_bool().unwrap_or(false);
            *app.desktop.write().unwrap()=serde_json::json!({"serviceRegistered":registered,"serviceState":if registered{"后台服务已注册"}else{"前台后台进程"},"autoStart":auto});
            tokio::select!{_=app.engine.cancel.cancelled()=>break,_=tokio::time::sleep(std::time::Duration::from_secs(10))=>{}}
        }
    });
}
#[cfg(windows)]
pub fn dispatch_service() -> Result<()> {
    scm::dispatch()
}
#[cfg(windows)]
mod scm {
    use super::*;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    define_windows_service!(ffi_main, entry);
    pub fn dispatch() -> Result<()> {
        service_dispatcher::start(crate::instance::service_name(), ffi_main)?;
        Ok(())
    }
    fn entry(_: Vec<std::ffi::OsString>) {
        if let Err(e) = run() {
            tracing::error!("Rust 实验服务退出：{e}");
        }
    }
    fn run() -> Result<()> {
        let stop = service_cancel();
        let handler =
            service_control_handler::register(crate::instance::service_name(), move |control| {
                match control {
                    ServiceControl::Stop | ServiceControl::Shutdown => {
                        stop.cancel();
                        ServiceControlHandlerResult::NoError
                    }
                    ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            })?;
        let status = |state| ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        };
        handler.set_service_status(status(ServiceState::Running))?;
        let result =
            tokio::runtime::Runtime::new()?.block_on(crate::run(crate::environment_command()?));
        let mut stopped = status(ServiceState::Stopped);
        if result.is_err() {
            stopped.exit_code = ServiceExitCode::ServiceSpecific(1);
        }
        handler.set_service_status(stopped)?;
        result
    }
}
pub async fn install(app: &App) -> Result<()> {
    // This command is never run by boot, tests, or update detection.
    let executable = std::env::current_exe()?;
    let data = app.store.root.clone();
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let command = format!(
            "\"{}\" run --data \"{}\" --service",
            executable.display(),
            data.display()
        );
        ensure!(
            std::process::Command::new("sc.exe")
                .args([
                    "create",
                    &crate::instance::service_name(),
                    "binPath=",
                    &command,
                    "start=",
                    "auto",
                    "DisplayName=",
                    "ConWU Rust 实验后台"
                ])
                .creation_flags(0x08000000)
                .status()?
                .success(),
            "实验服务注册失败"
        );
    }
    #[cfg(target_os = "linux")]
    {
        let unit = format!(
            "[Unit]\nDescription=ConWU Rust experiment\nAfter=network-online.target\n[Service]\nExecStart={} run --data {} --no-open\nRestart=on-failure\nRestartSec=2\n[Install]\nWantedBy=multi-user.target\n",
            systemd_quote(&executable.to_string_lossy()),
            systemd_quote(&data.to_string_lossy())
        );
        app.store
            .write(crate::instance::linux_unit(), unit.as_bytes(), true)?;
        ensure!(
            std::process::Command::new("systemctl")
                .arg("link")
                .arg(app.store.root.join(crate::instance::linux_unit()))
                .status()?
                .success(),
            "实验服务链接失败"
        );
    }
    let auto = app.db.read().unwrap().device_settings["autoStart"]
        .as_bool()
        .unwrap_or(false);
    configure_startup(app, auto).await?;
    app.log(
        "INFO",
        "独立实验服务已注册；当前实例退出后可由服务启动，正式版服务未修改",
    );
    Ok(())
}
#[cfg(target_os = "linux")]
fn systemd_quote(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}
#[cfg(windows)]
pub(crate) fn filesystem_argument(path: &std::path::Path) -> Result<std::ffi::OsString> {
    use std::{
        os::windows::ffi::{OsStrExt, OsStringExt},
        path::{Component, Prefix},
    };
    ensure!(path.is_absolute(), "Windows 文件参数必须为绝对路径");
    let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    ensure!(!wide.contains(&0), "Windows 文件参数含无效字符");
    // MSI and the existing MinGW worker's stdio parser reject verbatim paths.
    // Preserve UTF-16 and normalize only real filesystem prefixes.
    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::VerbatimDisk(_) => Ok(std::ffi::OsString::from_wide(&wide[4..])),
            Prefix::VerbatimUNC(_, _) => {
                let mut plain = vec![b'\\' as u16, b'\\' as u16];
                plain.extend_from_slice(&wide[8..]);
                Ok(std::ffi::OsString::from_wide(&plain))
            }
            Prefix::Disk(_) | Prefix::UNC(_, _) => Ok(path.as_os_str().to_owned()),
            _ => anyhow::bail!("Windows 文件参数不允许设备命名空间"),
        },
        _ => anyhow::bail!("Windows 文件参数缺少卷或共享名称"),
    }
}
pub fn open_panel(url: &str) -> Result<()> {
    ensure!(url.starts_with("http://127.0.0.1:"), "只允许打开本机面板");
    #[cfg(windows)]
    match launch_desktop_panel(url, false) {
        Ok(true) => return Ok(()),
        Ok(false) => {},
        Err(error) => tracing::warn!(%error, "ConWU 桌面窗口启动失败"),
    }
    open_browser(url)
}

#[cfg(windows)]
pub(crate) fn open_projection_desktop(url: &str) -> Result<()> {
    ensure!(url.starts_with("http://127.0.0.1:"), "只允许打开本机面板");
    ensure!(launch_desktop_panel(url, true)?, "缺少 ConWU 桌面组件");
    Ok(())
}

#[cfg(windows)]
fn launch_desktop_panel(url: &str, desktop_only: bool) -> Result<bool> {
    use anyhow::Context;
    use std::{io::Write, os::windows::process::CommandExt, process::{Command, Stdio}};

    let executable = std::env::current_exe()?;
    let parent = executable.parent().context("缺少 ConWU 程序目录")?;
    let Some(desktop) = ["components/ConWU-Desktop.exe", "app/components/ConWU-Desktop.exe"]
        .into_iter().map(|child| parent.join(child)).find(|path| path.is_file()) else {
        return Ok(false);
    };
    for part in desktop.ancestors() {
        crate::store::reject_link(part)?;
    }
    let mut child = Command::new(desktop)
        .arg("--panel")
        .args(desktop_only.then_some("--desktop-only"))
        .stdin(Stdio::piped())
        .creation_flags(0x08000000)
        .spawn()?;
    // A launch following a tray click can restore an already open desktop window.
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow(child.id());
    }
    let input = child.stdin.take().context("缺少 ConWU 桌面窗口通道");
    if let Err(error) = input.and_then(|mut pipe| Ok(pipe.write_all(url.as_bytes())?)) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok(true)
}

pub fn open_browser(url: &str) -> Result<()> {
    ensure!(
        url.starts_with("http://127.0.0.1:"),
        "只允许打开本机实验面板"
    );
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", url])
            .creation_flags(0x08000000)
            .spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    Ok(())
}
