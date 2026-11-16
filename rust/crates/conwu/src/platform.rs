use crate::backend::App;
use anyhow::{Result, ensure};
static SERVICE_CANCEL: std::sync::OnceLock<tokio_util::sync::CancellationToken> =
    std::sync::OnceLock::new();
pub fn service_cancel() -> tokio_util::sync::CancellationToken {
    SERVICE_CANCEL
        .get_or_init(tokio_util::sync::CancellationToken::new)
        .clone()
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
                manager.open_service("ConWURustExperiment", ServiceAccess::QUERY_STATUS)
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
                "conwu-rust-experiment.service",
            ])
            .output()
            .is_ok_and(|o| {
                o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "loaded"
            })
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
        let mut command =
            std::process::Command::new(if cfg!(windows) { "sc.exe" } else { "systemctl" });
        command.args(if cfg!(windows) {
            vec![
                "config",
                "ConWURustExperiment",
                "start=",
                if enabled { "auto" } else { "demand" },
            ]
        } else {
            vec![
                if enabled { "enable" } else { "disable" },
                "conwu-rust-experiment.service",
            ]
        });
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        command
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        ensure!(command.status()?.success(), "实验服务的启动设置保存失败");
        Ok(())
    })
    .await?;
    result
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
            *app.desktop.write().unwrap()=serde_json::json!({"serviceRegistered":registered,"serviceState":if registered{"实验后台服务已注册"}else{"前台实验后台"},"autoStart":auto});
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
    use clap::Parser;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    const NAME: &str = "ConWURustExperiment";
    define_windows_service!(ffi_main, entry);
    pub fn dispatch() -> Result<()> {
        service_dispatcher::start(NAME, ffi_main)?;
        Ok(())
    }
    fn entry(_: Vec<std::ffi::OsString>) {
        if let Err(e) = run() {
            tracing::error!("Rust 实验服务退出：{e}");
        }
    }
    fn run() -> Result<()> {
        let stop = service_cancel();
        let handler = service_control_handler::register(NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop.cancel();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
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
            tokio::runtime::Runtime::new()?.block_on(crate::run(crate::Cli::parse().command));
        handler.set_service_status(status(ServiceState::Stopped))?;
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
                    "ConWURustExperiment",
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
            .write("conwu-rust-experiment.service", unit.as_bytes(), true)?;
        ensure!(
            std::process::Command::new("systemctl")
                .arg("link")
                .arg(app.store.root.join("conwu-rust-experiment.service"))
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
