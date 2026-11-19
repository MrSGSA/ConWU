//! MSI lifecycle executed as SYSTEM. SCM rollback is provided by the existing
//! native installer transaction; this module owns only Rust data/UI grants.
use crate::{cli, instance, store::Store};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use windows_service::{
    service::{ServiceAccess, ServiceState},
    service_manager::{ServiceManager, ServiceManagerAccess},
};

#[derive(Serialize, Deserialize)]
struct Authorization {
    transaction: String,
    before: Option<String>,
    after: String,
}
fn transaction(value: &str) -> Result<String> {
    let id = uuid::Uuid::parse_str(value)?;
    ensure!(!id.is_nil(), "安装事务无效");
    Ok(format!("msi-authorization-{}.json", id.simple()))
}
fn program() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let app = exe.parent().context("缺少应用目录")?;
    let root = app.parent().context("缺少安装目录")?.to_owned();
    crate::updater::package_marker(&root)?;
    Ok(root)
}
fn verify_bundle(root: &Path) -> Result<()> {
    let path = root.join("SHA256SUMS");
    crate::store::reject_link(&path)?;
    ensure!(
        std::fs::metadata(&path)?.len() <= 2 * 1024 * 1024,
        "安装清单过大"
    );
    let contents = std::fs::read_to_string(path)?;
    let mut count = 0;
    for line in contents.lines() {
        let (digest, name) = line.split_once("  ").context("安装清单格式无效")?;
        ensure!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "安装摘要无效"
        );
        let relative = Path::new(name);
        ensure!(
            !relative.is_absolute()
                && relative
                    .components()
                    .all(|p| matches!(p, std::path::Component::Normal(_)))
                && !name.contains(':'),
            "安装清单路径无效"
        );
        let file = root.join(relative);
        for part in file.ancestors().take_while(|p| *p != root) {
            crate::store::reject_link(part)?;
        }
        ensure!(
            crate::updater::hash_file(&file)?.eq_ignore_ascii_case(digest),
            "安装组件校验失败：{name}"
        );
        count += 1;
        ensure!(count <= 4096, "安装清单文件过多");
    }
    ensure!(count >= 10, "安装清单不完整");
    Ok(())
}
fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .creation_flags(0x08000000)
        .output()?;
    ensure!(
        output.status.success(),
        "系统安装步骤 {program} 失败（{:?}）：{} {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}
fn service(access: ServiceAccess) -> Result<windows_service::service::Service> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    Ok(manager.open_service(instance::service_name(), access)?)
}
fn require_stopped() -> Result<()> {
    ensure!(
        service(ServiceAccess::QUERY_STATUS)?
            .query_status()?
            .current_state
            == ServiceState::Stopped,
        "后台尚未停止，未修改配置或设备"
    );
    Ok(())
}
pub(crate) fn legacy_root() -> PathBuf {
    let root = PathBuf::from(std::env::var_os("ProgramData").unwrap());
    if let Some(id) = instance::validation() {
        root.join("StreamLink-Validation").join(id)
    } else {
        root.join("StreamLink-PersonalFeature")
    }
}
fn validate_sid(sid: &str) -> Result<()> {
    ensure!(
        sid.len() <= 192
            && (sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-"))
            && sid
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'S' | b'-')),
        "安装必须授权实际登录用户"
    );
    Ok(())
}
fn service_ui_grant(sid: &str) -> Result<()> {
    // Daily users may start their service and query it, without changing its
    // image/account or reading the service's private data directory.
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            s: *const u16,
            rev: u32,
            out: *mut *mut std::ffi::c_void,
            size: *mut u32,
        ) -> i32;
        fn OpenSCManagerW(
            machine: *const u16,
            database: *const u16,
            access: u32,
        ) -> *mut std::ffi::c_void;
        fn OpenServiceW(
            manager: *mut std::ffi::c_void,
            name: *const u16,
            access: u32,
        ) -> *mut std::ffi::c_void;
        fn SetServiceObjectSecurity(
            service: *mut std::ffi::c_void,
            information: u32,
            descriptor: *const std::ffi::c_void,
        ) -> i32;
        fn CloseServiceHandle(handle: *mut std::ffi::c_void) -> i32;
    }
    let text = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;LCRPLO;;;{sid})")
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let name = instance::service_name()
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    unsafe {
        let mut sd = std::ptr::null_mut();
        ensure!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut sd,
                std::ptr::null_mut()
            ) != 0,
            "无法生成后台用户权限"
        );
        let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), 1);
        let svc = if manager.is_null() {
            std::ptr::null_mut()
        } else {
            OpenServiceW(manager, name.as_ptr(), 0x40000)
        };
        let ok = !svc.is_null() && SetServiceObjectSecurity(svc, 4, sd) != 0;
        if !svc.is_null() {
            CloseServiceHandle(svc);
        }
        if !manager.is_null() {
            CloseServiceHandle(manager);
        }
        windows_sys::Win32::Foundation::LocalFree(sd);
        ensure!(ok, "无法授权本机用户启动后台");
    }
    Ok(())
}
fn drivers(root: &Path) -> Result<()> {
    let components = root.join("app/components");
    let dll = components.join("WinDivert.dll");
    let library: libloading::Library =
        unsafe { libloading::os::windows::Library::load_with_flags(&dll, 0x100 | 0x1000)? }.into();
    type Open = unsafe extern "C" fn(*const i8, i32, i16, u64) -> *mut std::ffi::c_void;
    type Close = unsafe extern "C" fn(*mut std::ffi::c_void) -> i32;
    unsafe {
        let open: Open = *library.get(b"WinDivertOpen\0")?;
        let close: Close = *library.get(b"WinDivertClose\0")?;
        let handle = open(c"false".as_ptr(), 0, 0, 0);
        ensure!(
            handle != (-1isize as *mut std::ffi::c_void),
            "官方WinDivert驱动安装失败：{}",
            std::io::Error::last_os_error()
        );
        close(handle);
    }
    // Mimic now uses WinDivert by default. An optional XDP experiment must
    // not make an otherwise healthy installation depend on WLAN XDP queues
    // or rebind a shared driver during an update.
    Ok(())
}
fn configure(sid: &str, attempt: &str) -> Result<()> {
    require_stopped()?;
    let root = program()?;
    verify_bundle(&root)?;
    let store = Store::open(&cli::default_data())?;
    if !store.checked_file("database.private.json")?.is_file() {
        let legacy = legacy_root();
        if legacy.join("profile.dpapi").is_file() {
            crate::migration::import(&legacy, &store)?;
        } else {
            let mut db = crate::model::Database::default();
            db.device_settings["autoStart"] = json!(instance::validation().is_none());
            store.save(&db)?;
        }
    }
    let db = store.load()?;
    for network in &db.networks {
        network.settings.validate()?;
        if let Some(p) = &network.profile {
            p.validate()?;
        }
    }
    let file = transaction(attempt)?;
    ensure!(
        !store.checked_file(&file)?.exists(),
        "上次安装授权事务尚未完成"
    );
    let before = if store.checked_file("ui-user.sid")?.is_file() {
        Some(
            std::fs::read_to_string(store.checked_file("ui-user.sid")?)?
                .trim()
                .to_owned(),
        )
    } else {
        None
    };
    let selected = before.as_deref().unwrap_or(sid);
    validate_sid(selected)?;
    let auth = Authorization {
        transaction: attempt.into(),
        before: before.clone(),
        after: selected.into(),
    };
    store.write(&file, &serde_json::to_vec(&auth)?, false)?;
    store.write("ui-user.sid", auth.after.as_bytes(), false)?;
    drivers(&root)?;
    crate::platform::configure_windows_startup(db.device_settings["autoStart"] == true)?;
    run(
        "sc.exe",
        &[
            "failure",
            &instance::service_name(),
            "reset=",
            "86400",
            "actions=",
            "restart/5000/restart/15000/restart/60000",
        ],
    )?;
    service_ui_grant(&auth.after)?;
    Ok(())
}
async fn stop() -> Result<()> {
    let service = service(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
    }
    let deadline = Instant::now() + Duration::from_secs(75);
    while service.query_status()?.current_state != ServiceState::Stopped {
        ensure!(Instant::now() < deadline, "安装回退等待后台停止超时");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}
async fn rollback(attempt: &str) -> Result<()> {
    let file = transaction(attempt)?;
    let data = cli::default_data();
    if !data.join(&file).is_file() {
        return crate::maintenance::rollback(attempt);
    }
    stop().await?;
    let store = Store::open(&data)?;
    let record: Authorization =
        serde_json::from_slice(&std::fs::read(store.checked_file(&file)?)?)?;
    ensure!(record.transaction == attempt, "授权恢复事务不符");
    let current = std::fs::read_to_string(store.checked_file("ui-user.sid")?).ok();
    ensure!(
        current.as_deref().map(str::trim) == Some(record.after.as_str())
            || current.as_deref().map(str::trim) == record.before.as_deref(),
        "授权已被其他操作修改"
    );
    if let Some(before) = record.before {
        store.write("ui-user.sid", before.as_bytes(), false)?;
    } else if store.checked_file("ui-user.sid")?.is_file() {
        std::fs::remove_file(store.checked_file("ui-user.sid")?)?;
    }
    std::fs::remove_file(store.checked_file(&file)?)?;
    drop(store);
    crate::maintenance::rollback(attempt)
}
fn commit(attempt: &str) -> Result<()> {
    // VerifyReady has started the service. Never take its database lease here.
    let root = Store::resolve_root(&cli::default_data())?;
    for ancestor in root.ancestors() {
        crate::store::reject_link(ancestor)?;
    }
    let file = root.join(transaction(attempt)?);
    if file.exists() {
        crate::store::reject_link(&file)?;
        std::fs::remove_file(file)?;
    }
    crate::maintenance::commit(attempt)
}
async fn ready() -> Result<()> {
    let service = service(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
    if service.query_status()?.current_state != ServiceState::Running {
        service.start::<&str>(&[])?;
    }
    // Several saved adapters may each need Windows' bounded class-setup
    // settling/retry, while the local panel is already available.
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        if let Ok(reply) =
            crate::control::call(&cli::default_data(), &json!({"method":"status"})).await
        {
            if (reply["status"]["deviceSettings"]["coordinator"]["enabled"] != true
                || reply["status"]["coordinator"]["running"] == true)
                && reply["status"]["networks"].as_array().is_some_and(|rows| {
                    rows.iter().all(|n| {
                        n["enabled"] != true
                            || n["status"]["networkId"].as_str().is_none_or(str::is_empty)
                            || n["status"]["adapter"]["ready"] == true
                    })
                })
            {
                return Ok(());
            }
        }
        ensure!(
            Instant::now() < deadline,
            "安装后的后台或虚拟网卡未就绪，触发MSI回退"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
pub async fn execute(action: &str, args: &[String]) -> Result<()> {
    let result = match (action, args) {
        ("snapshot", [program, package, product, attempt, location]) => {
            crate::maintenance::snapshot(
                Path::new(program),
                Path::new(package),
                product,
                attempt,
                location,
            )
        }
        ("configure", [sid, attempt]) => configure(sid, attempt),
        ("rollback", [attempt]) => rollback(attempt).await,
        ("commit", [attempt]) => commit(attempt),
        ("ready", []) => ready().await,
        _ => anyhow::bail!("安装参数无效"),
    };
    if let Err(error) = &result {
        let root = cli::default_data();
        if root.join(".conwu-rust-owned").is_file() {
            let _ = (|| -> Result<()> {
                use std::io::Write;
                let logs = root.join("logs");
                std::fs::create_dir_all(&logs)?;
                crate::store::reject_link(&logs)?;
                let path = logs.join("installer-error.log");
                if path.exists() {
                    crate::store::reject_link(&path)?;
                }
                let mut output = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                writeln!(
                    output,
                    "{} {action}: {}",
                    crate::coordination_store::timestamp(conwu_core::unix_seconds()),
                    crate::logging::redact(&error.to_string())
                )?;
                Ok(())
            })();
        }
    }
    result
}
