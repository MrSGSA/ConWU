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
pub const PRODUCT: &str = "{2B716DCB-5CD7-4EEC-91E4-749BC09027A1}";
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
    ensure!(marker["product"] == PRODUCT, "不能覆盖非 Rust 实验安装");
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
    let program = executable.parent().context("安装目录缺失")?.to_owned();
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
    validate_msi(package)?;
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
        product: PRODUCT.into(),
        nonce: hex::encode(conwu_core::crypto::random::<32>()),
        parent: std::process::id(),
        version: version.into(),
        previous_version: crate::model::VERSION.into(),
        package: package.canonicalize()?,
        sha256: sha256.into(),
        program,
        worker: worker.clone(),
        service: crate::platform::service_registered(),
    };
    app.store.write_secret(
        "update-plan.private.json",
        &serde_json::to_vec(&plan)?,
        false,
    )?;
    let mut command = std::process::Command::new(worker);
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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
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
        plan.product == PRODUCT
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
    let backup = store.root.join("update-rollback");
    if backup.exists() {
        safe_remove(&backup, &store.root)?;
    }
    std::fs::create_dir(&backup)?;
    for file in std::fs::read_dir(&store.root)? {
        let path = file?.path();
        crate::store::reject_link(&path)?;
        let name = path.file_name().unwrap().to_string_lossy();
        if path.is_file()
            && (name.starts_with("database.")
                || name == "stream-private.pem"
                || name == "pkarr-checkpoints.json"
                || name == "coordinator.json")
        {
            std::fs::copy(&path, backup.join(path.file_name().unwrap()))?;
        }
    }
    std::fs::write(backup.join("version.txt"), &plan.previous_version)?;
    let result = install(&plan).await;
    if result.is_err() {
        restore(&store, &backup)?;
    }
    let message = result
        .as_ref()
        .map(|_| "安装已完成，正在恢复后台")
        .unwrap_or("本地安装未完成，已保留上一版本与设置");
    store.write("last-update.json",&serde_json::to_vec(&serde_json::json!({"supported":true,"state":if result.is_ok(){"Installed"}else{"Error"},"message":message,"canInstall":false,"version":plan.version}))?,false)?;
    drop(store);
    restart(&plan)?;
    result
}
fn restore(store: &Store, backup: &Path) -> Result<()> {
    for entry in std::fs::read_dir(backup)? {
        let path = entry?.path();
        crate::store::reject_link(&path)?;
        let name = path.file_name().unwrap().to_string_lossy();
        if name != "version.txt" {
            store.write(&name, &std::fs::read(&path)?, false)?;
        }
    }
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
async fn install(plan: &Plan) -> Result<()> {
    use std::os::windows::process::CommandExt;
    validate_msi(&plan.package)?;
    let status = tokio::task::spawn_blocking({
        let package = plan.package.clone();
        move || {
            std::process::Command::new("msiexec.exe")
                .arg("/i")
                .arg(package)
                .args(["/qn", "/norestart"])
                .creation_flags(0x08000000)
                .status()
        }
    })
    .await??;
    ensure!(
        matches!(status.code(), Some(0 | 3010)),
        "MSI 安装失败，已保留回退资料"
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
        let mut command =
            std::process::Command::new(if cfg!(windows) { "sc.exe" } else { "systemctl" });
        command.args(if cfg!(windows) {
            vec!["start", "ConWURustExperiment"]
        } else {
            vec!["restart", "conwu-rust-experiment.service"]
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
fn validate_msi(path: &Path) -> Result<()> {
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
        for (property, expected) in [
            ("UpgradeCode", PRODUCT),
            ("ProductName", "ConWU Rust Experiment"),
        ] {
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
                        .eq_ignore_ascii_case(expected),
                "拒绝覆盖其他产品的 MSI"
            );
        }
    }
    Ok(())
}
