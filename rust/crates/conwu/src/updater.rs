//! Local update worker. The default experimental build cannot invoke it;
//! `local-install` is an explicit build-time gate, separate from downloading.
use crate::store::Store;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Clone, Serialize, Deserialize)]
pub struct Plan {
    pub product: String,
    pub nonce: String,
    pub parent: u32,
    pub version: String,
    pub previous_version: String,
    pub package: PathBuf,
    pub sha256: String,
    pub program: PathBuf,
    pub worker: PathBuf,
    pub service: bool,
    #[serde(default)]
    pub service_name: String,
}
pub fn hash_file(path: &Path) -> Result<String> {
    crate::store::reject_link(path)?;
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 65536];
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
pub fn package_marker(program: &Path) -> Result<serde_json::Value> {
    let path = program.join(".conwu-rust-package");
    crate::store::reject_link(program)?;
    crate::store::reject_link(&path)?;
    ensure!(std::fs::metadata(&path)?.len() <= 262144, "安装标识过大");
    let marker: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    ensure!(
        marker["product"] == crate::instance::product(),
        "不能覆盖其他产品的安装"
    );
    ensure!(
        marker["os"] == std::env::consts::OS && marker["arch"] == std::env::consts::ARCH,
        "安装包平台或架构不符"
    );
    Ok(marker)
}
pub fn prepare(
    app: &crate::backend::App,
    package: &Path,
    sha256: &str,
    version: &str,
) -> Result<()> {
    ensure!(
        cfg!(feature = "local-install") && !app.engine.memory,
        "此实验构建未开放实际安装"
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    let base = executable.parent().context("安装目录缺失")?;
    let program = if base.join(".conwu-rust-package").is_file() {
        base.to_owned()
    } else {
        base.parent().context("缺少程序根目录")?.to_owned()
    };
    package_marker(&program)?;
    ensure!(
        !app.store.root.starts_with(&program) && !program.starts_with(&app.store.root),
        "程序与数据目录必须独立"
    );
    ensure!(
        hash_file(package)?.eq_ignore_ascii_case(sha256),
        "安装包校验失败"
    );
    #[cfg(windows)]
    validate_msi(package, Some(version))?;
    let worker = app.store.root.join("updates").join(if cfg!(windows) {
        "conwu-update-worker.exe"
    } else {
        "conwu-update-worker"
    });
    if worker.exists() {
        crate::store::reject_link(&worker)?;
    }
    std::fs::copy(&executable, &worker)?;
    let plan = Plan {
        product: crate::instance::product(),
        nonce: hex::encode(conwu_core::crypto::random::<32>()),
        parent: std::process::id(),
        version: version.into(),
        previous_version: crate::model::VERSION.into(),
        package: package.canonicalize()?,
        sha256: sha256.into(),
        program,
        worker: worker.clone(),
        service: crate::platform::is_service_process(),
        service_name: crate::instance::service_name(),
    };
    app.store.write_secret(
        "update-plan.private.json",
        &serde_json::to_vec(&plan)?,
        false,
    )?;
    let mut command = std::process::Command::new(&worker);
    if let Some(id) = crate::instance::validation() {
        command.arg("--validation-instance").arg(id);
    }
    command
        .arg("apply-update")
        .arg("--data")
        .arg(&app.store.root)
        .arg("--nonce")
        .arg(&plan.nonce)
        .arg("--parent")
        .arg(plan.parent.to_string());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    #[cfg(target_os = "linux")]
    if plan.service {
        // A normal child belongs to the old service's control group and would
        // be killed by KillMode=control-group before it can finish the update.
        let status = std::process::Command::new("systemd-run")
            .args(["--no-block", "--collect", "--service-type=exec", "--unit"])
            .arg(format!("conwu-local-update-{}", &plan.nonce[..12]))
            .arg(format!(
                "--property=ExecStartPre=/usr/bin/systemctl stop {}",
                crate::instance::linux_unit()
            ))
            .arg("--")
            .arg(&worker)
            .args(command.get_args())
            .status()?;
        ensure!(
            status.success(),
            "无法启动独立的本地更新服务；当前后台继续运行"
        );
    } else {
        command.spawn()?;
    }
    #[cfg(not(target_os = "linux"))]
    command.spawn()?;
    app.engine.cancel.cancel();
    Ok(())
}
pub async fn apply(data: PathBuf, nonce: String, parent: u32) -> Result<()> {
    ensure!(cfg!(feature = "local-install"), "实验构建未开放实际安装");
    ensure!(
        parent > 1 && parent != std::process::id(),
        "更新进程编号无效"
    );
    // Parent exits gracefully and releases its exclusive Store lease before any
    // replacement. No network access or download occurs from this point on.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let store = loop {
        match Store::open(&data) {
            Ok(store) => break store,
            Err(e) => {
                if std::time::Instant::now() >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    };
    let plan: Plan = serde_json::from_slice(&store.read_secret("update-plan.private.json")?)?;
    ensure!(
        plan.product == crate::instance::product()
            && plan.parent == parent
            && conwu_core::crypto::eq(nonce.as_bytes(), plan.nonce.as_bytes())
            && std::env::current_exe()?.canonicalize()? == plan.worker.canonicalize()?,
        "更新计划身份不符"
    );
    ensure!(
        plan.package.starts_with(store.root.join("updates"))
            && hash_file(&plan.package)?.eq_ignore_ascii_case(&plan.sha256),
        "本地安装包被改变"
    );
    package_marker(&plan.program)?;
    #[cfg(target_os = "linux")]
    let _backup = {
        let backup = store.root.join("update-rollback");
        if backup.exists() {
            safe_remove(&backup, &store.root)?;
        }
        crate::recovery::copy(&store.root, &backup.join("settings"), true)?;
        std::fs::write(backup.join("version.txt"), &plan.previous_version)?;
        backup
    };
    // Windows MSI custom actions and its readiness probe must be able to open
    // the same data store. Holding the old parent's lease during msiexec would
    // force every update to fail; MSI owns its own rollback transaction.
    let root = store.root.clone();
    store.write("last-update.json",&serde_json::to_vec(&serde_json::json!({"supported":true,"state":"Installing","message":"正在执行本地安装","canInstall":false,"version":plan.version}))?,false)?;
    drop(store);
    let installation = install(&plan).await;
    let installed = installation.is_ok();
    let mut result = installation;
    if result.is_ok() {
        result = restart(&plan);
        if result.is_ok() {
            result = healthy(&root, Some(&plan.version), plan.service).await;
        }
    }
    #[cfg(target_os = "linux")]
    if result.is_err() && installed {
        // Stop the failed candidate before opening settings or moving files.
        let recovery = async {
            stop_candidate(&plan, &root).await?;
            rollback_linux(&plan)?;
            // Keep the latest signed revocation/PKARR state from the failed boot.
            // Current Rust formats are backwards compatible; restoring an older
            // database here could reuse a published sequence or revive a member.
            restart(&plan)?;
            healthy(&root, Some(&plan.previous_version), plan.service).await
        }
        .await;
        if let Err(error) = recovery {
            result = Err(error.context("新版本失败，自动恢复上一版尚未完成"));
        }
    }
    if result.is_err() && !installed {
        let recovery = async {
            restart(&plan)?;
            healthy(&root, Some(&plan.previous_version), plan.service).await
        }
        .await;
        if let Err(error) = recovery {
            result = Err(error.context("安装失败，原后台尚未恢复"));
        }
    }
    let message = result
        .as_ref()
        .map(|_| "更新已完成，后台与网络已恢复")
        .unwrap_or("本地安装未完成，已保留上一版本与设置");
    crate::store::write_update_record(
        &root,
        &serde_json::json!({"supported":true,"state":if result.is_ok(){"Installed"}else{"Error"},"message":message,"detail":result.as_ref().err().map(|e|crate::logging::redact(&e.to_string())),"canInstall":false,"version":plan.version,"attempt":plan.nonce}),
    )?;
    result
}
async fn healthy(root: &Path, version: Option<&str>, service: bool) -> Result<()> {
    #[cfg(windows)]
    let _ = service;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(240);
    loop {
        #[cfg(target_os = "linux")]
        if service {
            let state = std::process::Command::new("systemctl")
                .args([
                    "show",
                    "--property=ActiveState",
                    "--value",
                    crate::instance::linux_unit(),
                ])
                .output()?;
            ensure!(
                String::from_utf8_lossy(&state.stdout).trim() != "failed",
                "更新后的后台服务启动失败"
            );
        }
        if let Ok(client) = crate::cli::Client::open(root) {
            if let Ok(reply) = client.call(serde_json::json!({"method":"status"})).await {
                let status = &reply["status"];
                if status["serviceReady"] == true
                    && version.is_none_or(|v| status["version"] == v)
                    && (status["deviceSettings"]["coordinator"]["enabled"] != true
                        || status["coordinator"]["running"] == true)
                    && status["networks"].as_array().is_some_and(|networks| {
                        networks.iter().all(|n| {
                            n["enabled"] != true
                                || n["status"]["networkId"].as_str().is_none_or(str::is_empty)
                                || n["status"]["adapter"]["ready"] == true
                        })
                    })
                {
                    return Ok(());
                }
            }
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "更新后的后台或虚拟网卡未就绪"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
#[cfg(target_os = "linux")]
async fn stop_candidate(plan: &Plan, root: &Path) -> Result<()> {
    if plan.service {
        ensure!(
            std::process::Command::new("systemctl")
                .args(["stop", crate::instance::linux_unit()])
                .status()?
                .success(),
            "停止新后台失败"
        );
    } else if let Ok(client) = crate::cli::Client::open(root) {
        let _ = client.shutdown().await;
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(75);
    loop {
        if Store::open(root).is_ok() {
            return Ok(());
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "新后台仍在使用配置，未回退文件"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}
#[cfg(target_os = "linux")]
fn rollback_linux(plan: &Plan) -> Result<()> {
    let parent = plan.program.parent().context("缺少程序父目录")?;
    let previous = parent.join("conwu-rust-previous");
    ensure!(
        package_marker(&previous)?["version"] == plan.previous_version,
        "上一版程序身份不符"
    );
    let failed = parent.join("conwu-rust-failed");
    if failed.exists() {
        package_marker(&failed)?;
        safe_remove(&failed, parent)?;
    }
    package_marker(&plan.program)?;
    std::fs::rename(&plan.program, &failed)?;
    std::fs::rename(&previous, &plan.program)?;
    Ok(())
}
pub fn safe_remove(path: &Path, root: &Path) -> Result<()> {
    let root = Store::resolve_root(root)?;
    let absolute = Store::resolve_root(path)?;
    ensure!(
        absolute.starts_with(&root) && absolute != root,
        "拒绝越界清理更新目录"
    );
    crate::store::reject_link(&absolute)?;
    if absolute.is_dir() {
        for entry in std::fs::read_dir(&absolute)? {
            safe_remove(&entry?.path(), &root)?;
        }
        std::fs::remove_dir(absolute)?;
    } else {
        std::fs::remove_file(absolute)?;
    }
    Ok(())
}
#[cfg(windows)]
fn msi_path(path: &Path) -> Result<std::ffi::OsString> {
    crate::platform::filesystem_argument(path)
}
#[cfg(all(windows, test))]
#[test]
fn msi_arguments_keep_unicode_and_normalize_only_filesystem_prefixes() -> Result<()> {
    for (before, after) in [
        (
            r"\\?\C:\ProgramData\ConWU\更新 包.msi",
            r"C:\ProgramData\ConWU\更新 包.msi",
        ),
        (r"\\?\UNC\host\share\更新.msi", r"\\host\share\更新.msi"),
        (r"D:\ConWU\包.msi", r"D:\ConWU\包.msi"),
    ] {
        ensure!(msi_path(Path::new(before))? == std::ffi::OsStr::new(after));
    }
    ensure!(msi_path(Path::new(r"\\?\GLOBALROOT\Device\volume\x.msi")).is_err());
    ensure!(msi_path(Path::new(r"relative\x.msi")).is_err());
    Ok(())
}
#[cfg(windows)]
async fn install(plan: &Plan) -> Result<()> {
    use std::os::windows::process::CommandExt;
    validate_msi(&plan.package, Some(&plan.version))?;
    let log = plan.worker.with_file_name("install-msi.log");
    if log.exists() {
        crate::store::reject_link(&log)?;
    }
    let status = tokio::task::spawn_blocking({
        let package = msi_path(&plan.package)?;
        let log = msi_path(&log)?;
        move || {
            std::process::Command::new("msiexec.exe")
                .arg("/i")
                .arg(package)
                .args(["/qn", "/norestart"])
                .arg("/l*v")
                .arg(log)
                .creation_flags(0x08000000)
                .status()
        }
    })
    .await??;
    ensure!(
        matches!(status.code(), Some(0 | 3010)),
        "MSI 安装失败（退出码 {:?}），已保留回退资料与 install-msi.log",
        status.code()
    );
    Ok(())
}
#[cfg(target_os = "linux")]
async fn install(plan: &Plan) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let parent = plan.program.parent().context("安装父目录缺失")?;
    let staging = parent.join("conwu-rust-next");
    let previous = parent.join("conwu-rust-previous");
    if staging.exists() {
        package_marker(&staging)?;
        safe_remove(&staging, parent)?;
    }
    std::fs::create_dir(&staging)?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(std::fs::File::open(
        &plan.package,
    )?));
    let (mut count, mut total) = (0, 0u64);
    for entry in archive.entries()? {
        let mut entry = entry?;
        count += 1;
        total += entry.size();
        ensure!(
            count <= 4096 && total <= 512 * 1024 * 1024,
            "安装归档超过限制"
        );
        let path = entry.path()?.into_owned();
        ensure!(
            path.components()
                .all(|c| matches!(c, std::path::Component::Normal(_))),
            "归档路径无效"
        );
        let kind = entry.header().entry_type();
        ensure!(kind.is_file() || kind.is_dir(), "安装归档不能含链接或设备");
        ensure!(entry.unpack_in(&staging)?, "归档不能越过安装目录");
        if kind.is_file() {
            let executable = entry.header().mode()? & 0o111 != 0;
            std::fs::set_permissions(
                staging.join(path),
                std::fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
            )?;
        }
    }
    let marker = package_marker(&staging)?;
    ensure!(
        marker["version"] == plan.version
            && marker["os"] == "linux"
            && marker["arch"] == std::env::consts::ARCH,
        "安装包版本或平台不符"
    );
    ensure!(staging.join("conwu").is_file(), "归档中缺少 Rust 后台");
    if previous.exists() {
        package_marker(&previous)?;
        safe_remove(&previous, parent)?;
    }
    std::fs::rename(&plan.program, &previous)?;
    if let Err(e) = std::fs::rename(&staging, &plan.program) {
        let _ = std::fs::rename(&previous, &plan.program);
        return Err(e.into());
    }
    Ok(())
}
fn restart(plan: &Plan) -> Result<()> {
    if plan.service {
        let service = if plan.service_name.is_empty() {
            crate::instance::service_name()
        } else {
            plan.service_name.clone()
        };
        #[cfg(windows)]
        {
            use windows_service::{
                service::{ServiceAccess, ServiceState},
                service_manager::{ServiceManager, ServiceManagerAccess},
            };
            if ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .and_then(|manager| manager.open_service(&service, ServiceAccess::QUERY_STATUS))
                .and_then(|service| service.query_status())
                .is_ok_and(|s| s.current_state == ServiceState::Running)
            {
                return Ok(());
            }
        }
        let mut command =
            std::process::Command::new(if cfg!(windows) { "sc.exe" } else { "systemctl" });
        #[cfg(target_os = "linux")]
        {
            let state = std::process::Command::new("systemctl")
                .args([
                    "show",
                    "--property=ActiveState",
                    "--value",
                    crate::instance::linux_unit(),
                ])
                .output()?;
            ensure!(state.status.success(), "无法查询本机后台的启动状态");
            // A healthy stopped unit may already have been garbage-collected
            // by systemd. reset-failed then reports "not loaded", although
            // starting the installed unit is valid. Reset only an actual
            // failure, including StartLimit after a failed candidate.
            if state.stdout.trim_ascii() == b"failed" {
                ensure!(
                    std::process::Command::new("systemctl")
                        .args(["reset-failed", crate::instance::linux_unit()])
                        .status()?
                        .success(),
                    "无法清除本机后台的启动失败计数"
                );
            }
        }
        command.args(if cfg!(windows) {
            vec!["start", &service]
        } else {
            vec!["restart", crate::instance::linux_unit()]
        });
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        ensure!(
            command.status()?.success(),
            "后台服务恢复未完成，请查看更新记录"
        );
    } else {
        let executable = plan
            .program
            .join(if cfg!(windows) { "conwu.exe" } else { "conwu" });
        let data = plan
            .package
            .parent()
            .and_then(Path::parent)
            .context("数据目录缺失")?;
        let mut command = std::process::Command::new(executable);
        command.arg("run").arg("--data").arg(data).arg("--no-open");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        command.spawn()?;
    }
    Ok(())
}
#[cfg(windows)]
pub(crate) fn validate_msi(path: &Path, version: Option<&str>) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "msi")]
    unsafe extern "system" {
        fn MsiOpenDatabaseW(path: *const u16, persist: *const u16, result: *mut u32) -> u32;
        fn MsiDatabaseOpenViewW(db: u32, sql: *const u16, view: *mut u32) -> u32;
        fn MsiViewExecute(view: u32, record: u32) -> u32;
        fn MsiViewFetch(view: u32, record: *mut u32) -> u32;
        fn MsiRecordGetStringW(record: u32, field: u32, value: *mut u16, length: *mut u32) -> u32;
        fn MsiCloseHandle(handle: u32) -> u32;
    }
    struct Handle(u32);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                MsiCloseHandle(self.0);
            }
        }
    }
    let wide = |s: &std::ffi::OsStr| s.encode_wide().chain(Some(0)).collect::<Vec<_>>();
    unsafe {
        let mut db = 0;
        ensure!(
            MsiOpenDatabaseW(wide(path.as_os_str()).as_ptr(), std::ptr::null(), &mut db) == 0,
            "安装包不是有效 MSI"
        );
        let db = Handle(db);
        let mut properties = vec![
            ("UpgradeCode", crate::instance::product()),
            ("ProductName", crate::instance::product_name()),
        ];
        if let Some(v) = version {
            properties.push(("STREAMLINK_DISPLAY_VERSION", v.to_owned()));
        }
        for (property, expected) in properties {
            let query = format!("SELECT `Value` FROM `Property` WHERE `Property` = '{property}'");
            let mut view = 0;
            ensure!(
                MsiDatabaseOpenViewW(db.0, wide(std::ffi::OsStr::new(&query)).as_ptr(), &mut view)
                    == 0,
                "安装包缺少产品属性"
            );
            let view = Handle(view);
            ensure!(MsiViewExecute(view.0, 0) == 0, "安装包属性查询失败");
            let mut record = 0;
            ensure!(
                MsiViewFetch(view.0, &mut record) == 0,
                "安装包缺少 Rust 身份"
            );
            let record = Handle(record);
            let mut value = [0u16; 256];
            let mut length = 255;
            ensure!(
                MsiRecordGetStringW(record.0, 1, value.as_mut_ptr(), &mut length) == 0
                    && String::from_utf16_lossy(&value[..length as usize])
                        .eq_ignore_ascii_case(&expected),
                "拒绝覆盖其他产品的 MSI"
            );
        }
    }
    Ok(())
}
