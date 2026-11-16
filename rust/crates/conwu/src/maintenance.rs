//! MSI-owned durable predecessor and full MSI maintenance source. Invoked by
//! the embedded new binary after SCM stop, before replacing installed files.
use crate::{cli, store::Store};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
struct Pending {
    attempt: String,
    product_code: String,
    incoming_name: String,
    incoming_sha256: String,
    repair: bool,
    had_program: bool,
}
fn root() -> Result<Store> {
    let data = cli::default_data();
    let record = data.join("maintenance-path.json");
    let path = if record.is_file() {
        crate::store::reject_link(&record)?;
        ensure!(
            std::fs::metadata(&record)?.len() <= 8192,
            "维护路径记录过大"
        );
        serde_json::from_slice::<PathBuf>(&std::fs::read(&record)?)?
    } else {
        data.join("maintenance")
    };
    Store::open(&path)
}
fn pending(store: &Store, attempt: &str) -> Result<Pending> {
    let value: Pending =
        serde_json::from_slice(&std::fs::read(store.checked_file("pending.json")?)?)?;
    ensure!(value.attempt == attempt, "安装快照属于另一事务");
    Ok(value)
}
fn uuid(value: &str) -> Result<()> {
    ensure!(
        !uuid::Uuid::parse_str(value)?.is_nil(),
        "安装事务或产品标识无效"
    );
    Ok(())
}
pub fn snapshot(
    program: &Path,
    incoming: &Path,
    product: &str,
    attempt: &str,
    location: &str,
) -> Result<()> {
    uuid(attempt)?;
    uuid(product)?;
    let program = Store::resolve_root(program)?;
    let expected = PathBuf::from(std::env::var_os("ProgramFiles").context("缺少ProgramFiles")?);
    let expected = if let Some(id) = crate::instance::validation() {
        expected.join("StreamLink-Validation").join(id).join("msi")
    } else {
        expected.join("StreamLink")
    };
    ensure!(
        program == Store::resolve_root(&expected)?,
        "快照目标不是本产品的安装目录"
    );
    crate::updater::validate_msi(incoming, None)?;
    let data = Store::open(&cli::default_data())?;
    if !data.checked_file("maintenance-path.json")?.exists() && !location.is_empty() {
        let path = Store::resolve_root(Path::new(location))?;
        ensure!(
            !path.starts_with(&program) && !program.starts_with(&path),
            "维护源不能位于程序目录"
        );
        let _private = Store::open(&path)?;
        data.write("maintenance-path.json", &serde_json::to_vec(&path)?, false)?;
    }
    let store = root()?;
    ensure!(
        !store.checked_file("pending.json")?.exists(),
        "上次安装快照事务尚未完成"
    );
    let current = store.root.join("current");
    let incoming_sha256 = crate::updater::hash_file(incoming)?;
    let repair = current.join("source.json").is_file() && {
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(current.join("source.json"))?)?;
        record["sha256"] == incoming_sha256
    };
    let candidate = store.root.join("pending");
    if candidate.exists() {
        crate::updater::safe_remove(&candidate, &store.root)?;
    }
    std::fs::create_dir(&candidate)?;
    let incoming_name = incoming
        .file_name()
        .and_then(|v| v.to_str())
        .context("MSI文件名无效")?
        .to_owned();
    std::fs::create_dir(candidate.join("new-source"))?;
    std::fs::copy(incoming, candidate.join("new-source").join(&incoming_name))?;
    let value = Pending {
        attempt: attempt.into(),
        product_code: product.into(),
        incoming_name,
        incoming_sha256,
        repair,
        had_program: program.join("app/ConWU.Service.exe").is_file(),
    };
    // Publish the transaction before potentially long copies. A partial copy
    // is never promoted to a completed predecessor after a failed install.
    store.write("pending.json", &serde_json::to_vec(&value)?, false)?;
    if !repair && value.had_program {
        crate::recovery::copy(&program, &candidate.join("program"), false)?;
        let source = if data.root.join("database.private.json").is_file() {
            data.root.clone()
        } else {
            crate::installer::legacy_root()
        };
        if source.is_dir() {
            crate::recovery::copy(&source, &candidate.join("settings"), true)?;
        }
        if current.is_dir() {
            crate::recovery::copy(&current, &candidate.join("installer"), false)?;
        } else {
            let old = installed_source()?
                .context("找不到上一版的完整MSI源，请先恢复其原始安装包再更新")?;
            std::fs::create_dir(candidate.join("installer"))?;
            std::fs::copy(
                &old,
                candidate.join("installer").join(old.file_name().unwrap()),
            )?;
        }
        store.write(
            "snapshot-info.json",
            &serde_json::to_vec(&serde_json::json!({
                "program":program,"settings":source,"transaction":attempt
            }))?,
            false,
        )?;
    }
    std::fs::write(candidate.join("complete"), b"complete\n")?;
    Ok(())
}
fn installed_source() -> Result<Option<PathBuf>> {
    #[link(name = "msi")]
    unsafe extern "system" {
        fn MsiEnumRelatedProductsW(
            upgrade: *const u16,
            reserved: u32,
            index: u32,
            product: *mut u16,
        ) -> u32;
        fn MsiGetProductInfoW(
            product: *const u16,
            property: *const u16,
            value: *mut u16,
            count: *mut u32,
        ) -> u32;
        fn MsiSourceListGetInfoW(
            product: *const u16,
            sid: *const u16,
            context: u32,
            options: u32,
            property: *const u16,
            value: *mut u16,
            count: *mut u32,
        ) -> u32;
    }
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let upgrade = wide(&crate::instance::product());
    for index in 0..32 {
        let mut product = [0u16; 39];
        let result =
            unsafe { MsiEnumRelatedProductsW(upgrade.as_ptr(), 0, index, product.as_mut_ptr()) };
        if result == 259 {
            break;
        }
        ensure!(result == 0, "无法读取已安装产品的维护源");
        let (mut folder, mut name) = ([0u16; 32768], [0u16; 1024]);
        let (mut flen, mut nlen) = (32767, 1023);
        unsafe {
            if MsiGetProductInfoW(
                product.as_ptr(),
                wide("InstallSource").as_ptr(),
                folder.as_mut_ptr(),
                &mut flen,
            ) != 0
                || MsiSourceListGetInfoW(
                    product.as_ptr(),
                    std::ptr::null(),
                    4,
                    0,
                    wide("PackageName").as_ptr(),
                    name.as_mut_ptr(),
                    &mut nlen,
                ) != 0
            {
                continue;
            }
        }
        let name = String::from_utf16_lossy(&name[..nlen as usize]);
        ensure!(
            Path::new(&name)
                .file_name()
                .is_some_and(|s| s == name.as_str()),
            "原MSI文件名无效"
        );
        let file = PathBuf::from(String::from_utf16_lossy(&folder[..flen as usize])).join(name);
        if file.is_file() {
            return Ok(Some(Store::resolve_root(&file)?));
        }
    }
    Ok(None)
}
pub fn rollback(attempt: &str) -> Result<()> {
    let store = root()?;
    if !store.checked_file("pending.json")?.exists() {
        return Ok(());
    }
    pending(&store, attempt)?;
    // MSI restores files and the SCM transaction restores its prior running
    // state. Settings have not changed schema during this MSI transaction.
    let candidate = store.root.join("pending");
    if candidate.exists() {
        crate::updater::safe_remove(&candidate, &store.root)?;
    }
    std::fs::remove_file(store.checked_file("pending.json")?)?;
    Ok(())
}
pub fn commit(attempt: &str) -> Result<()> {
    let store = root()?;
    let value = pending(&store, attempt)?;
    let candidate = store.root.join("pending");
    ensure!(candidate.join("complete").is_file(), "安装快照未完成");
    let source = candidate.join("new-source");
    ensure!(
        crate::updater::hash_file(&source.join(&value.incoming_name))? == value.incoming_sha256,
        "维护MSI被改变"
    );
    std::fs::write(
        source.join("source.json"),
        serde_json::to_vec(&serde_json::json!({
            "productCode":value.product_code,"name":value.incoming_name,"sha256":value.incoming_sha256
        }))?,
    )?;
    let current = store.root.join("current");
    if current.exists() {
        crate::updater::safe_remove(&current, &store.root)?;
    }
    std::fs::rename(&source, &current)?;
    register_source(&value.product_code, &current)?;
    if !value.repair && value.had_program {
        let previous = store.root.join("previous");
        if previous.exists() {
            crate::updater::safe_remove(&previous, &store.root)?;
        }
        std::fs::rename(&candidate, previous)?;
    } else {
        crate::updater::safe_remove(&candidate, &store.root)?;
    }
    std::fs::remove_file(store.checked_file("pending.json")?)?;
    Ok(())
}
fn register_source(product: &str, directory: &Path) -> Result<()> {
    #[link(name = "msi")]
    unsafe extern "system" {
        fn MsiSourceListAddSourceExW(
            product: *const u16,
            sid: *const u16,
            context: u32,
            options: u32,
            source: *const u16,
            index: u32,
        ) -> u32;
        fn MsiSourceListForceResolutionExW(
            product: *const u16,
            sid: *const u16,
            context: u32,
            options: u32,
        ) -> u32;
    }
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let product = wide(product);
    let path = wide(&format!("{}\\", directory.display()));
    unsafe {
        ensure!(
            MsiSourceListAddSourceExW(product.as_ptr(), std::ptr::null(), 4, 1, path.as_ptr(), 1)
                == 0,
            "无法登记完整MSI维护源"
        );
        ensure!(
            MsiSourceListForceResolutionExW(product.as_ptr(), std::ptr::null(), 4, 0) == 0,
            "无法刷新MSI维护源"
        );
    }
    Ok(())
}
