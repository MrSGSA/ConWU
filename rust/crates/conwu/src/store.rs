use crate::model::Database;
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub struct Store {
    pub root: PathBuf,
    _lease: File,
}
impl Store {
    pub fn resolve_root(path: &Path) -> Result<PathBuf> {
        let absolute = std::path::absolute(path)?;
        ensure!(
            !absolute
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
            "数据目录不能含上级路径分量"
        );
        for parent in absolute.ancestors() {
            if fs::symlink_metadata(parent).is_ok() {
                reject_link(parent)?;
            }
        }
        let mut ancestor = absolute.as_path();
        let mut suffix = Vec::new();
        while !ancestor.exists() {
            suffix.push(ancestor.file_name().context("数据路径无效")?.to_owned());
            ancestor = ancestor.parent().context("数据路径没有根目录")?;
        }
        let mut resolved = ancestor.canonicalize()?;
        for part in suffix.into_iter().rev() {
            resolved.push(part);
        }
        Ok(resolved)
    }
    pub fn checked_file(&self, name: &str) -> Result<PathBuf> {
        ensure!(
            Path::new(name).file_name().is_some_and(|n| n == name) && !name.contains(['/', '\\']),
            "文件名无效"
        );
        let path = self.root.join(name);
        if path.exists() {
            reject_link(&path)?;
        }
        Ok(path)
    }
    pub fn open(root: &Path) -> Result<Self> {
        let root = Self::resolve_root(root)?;
        for parent in root.ancestors().filter(|p| p.exists()) {
            reject_link(parent)?;
        }
        fs::create_dir_all(&root)?;
        if fs::read_dir(&root)?.next().is_some() {
            ensure!(
                root.join(".conwu-rust-owned").is_file(),
                "此目录已有数据且不属于 Rust 实验，请使用新的空目录"
            );
        }
        for parent in root.ancestors() {
            reject_link(parent)?;
        }
        private_directory(&root)?;
        let marker = root.join(".conwu-rust-owned");
        if !marker.exists() {
            fs::write(&marker, b"ConWU Rust experimental data v1\n")?;
        }
        let lease = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join("instance.lock"))?;
        lease
            .try_lock_exclusive()
            .context("此实验数据目录已有后台运行")?;
        Ok(Self {
            root,
            _lease: lease,
        })
    }
    pub fn load(&self) -> Result<Database> {
        let file = self.root.join("database.private.json");
        if !file.exists() {
            return Ok(Database::default());
        }
        reject_link(&file)?;
        ensure!(
            fs::metadata(&file)?.len() <= 8 * 1024 * 1024,
            "配置文件超过限制"
        );
        let bytes = self.read_secret("database.private.json")?;
        Ok(serde_json::from_slice(&bytes)?)
    }
    pub fn save(&self, value: &Database) -> Result<()> {
        self.write_secret(
            "database.private.json",
            &serde_json::to_vec_pretty(value)?,
            true,
        )
    }
    pub fn read_secret(&self, name: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let path = self.checked_file(name)?;
        ensure!(
            fs::metadata(&path)?.len() <= 8 * 1024 * 1024,
            "私密文件过大"
        );
        let bytes = zeroize::Zeroizing::new(fs::read(path)?);
        #[cfg(windows)]
        if bytes.starts_with(b"CWD1") {
            return Ok(zeroize::Zeroizing::new(dpapi(&bytes[4..], false, &[])?));
        }
        // Plain v1 experiment data is accepted once; the next save protects it.
        Ok(bytes)
    }
    pub fn write_secret(&self, name: &str, data: &[u8], backup: bool) -> Result<()> {
        #[cfg(windows)]
        {
            let protected = dpapi(data, true, &[])?;
            let mut bytes = b"CWD1".to_vec();
            bytes.extend_from_slice(&protected);
            return self.write(name, &bytes, backup);
        }
        #[cfg(not(windows))]
        self.write(name, data, backup)
    }
    pub fn write(&self, name: &str, data: &[u8], backup: bool) -> Result<()> {
        ensure!(
            Path::new(name).file_name().is_some_and(|n| n == name) && !name.contains(['/', '\\']),
            "配置文件名无效"
        );
        let final_path = self.root.join(name);
        if final_path.exists() {
            reject_link(&final_path)?;
        }
        let previous = self.root.join(format!("{name}.previous"));
        if previous.exists() {
            reject_link(&previous)?;
        }
        ensure!(
            !final_path.exists() || !fs::symlink_metadata(&final_path)?.file_type().is_symlink(),
            "配置文件不能为链接"
        );
        let temp = self.root.join(format!("{name}.{}.tmp", conwu_core::id()));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        struct Temporary(PathBuf);
        impl Drop for Temporary {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }
        let _cleanup = Temporary(temp.clone());
        let mut output = options.open(&temp)?;
        output.write_all(data)?;
        output.sync_all()?;
        drop(output);
        if backup && final_path.exists() {
            self.write(&format!("{name}.previous"), &fs::read(&final_path)?, false)?;
        }
        #[cfg(windows)]
        if final_path.exists() {
            replace_windows(&temp, &final_path)?;
            return Ok(());
        }
        fs::rename(&temp, &final_path)?;
        #[cfg(unix)]
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}
#[cfg(windows)]
pub(crate) fn dpapi(bytes: &[u8], protect: bool, entropy: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CryptProtectData, CryptUnprotectData,
        },
    };
    ensure!(bytes.len() <= 8 * 1024 * 1024, "私密数据过大");
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let extra = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr().cast_mut(),
    };
    let extra = if entropy.is_empty() {
        std::ptr::null()
    } else {
        &extra
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
    // SAFETY: input lives through the synchronous API call; output is copied,
    // zeroed and freed using DPAPI's allocator on both success and failure.
    let status = unsafe {
        if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                extra,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                extra,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    ensure!(
        status != 0,
        "系统密钥保护失败：{}",
        std::io::Error::last_os_error()
    );
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        use zeroize::Zeroize;
        std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize).zeroize();
        LocalFree(output.pbData.cast());
    }
    Ok(result)
}
pub(crate) fn reject_link(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "实验数据不能经过符号链接"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "实验数据不能经过重解析点"
        );
    }
    Ok(())
}
#[cfg(unix)]
pub(crate) fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(windows)]
pub(crate) fn private_directory(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let sid = current_sid()?;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            result: *mut *mut std::ffi::c_void,
            size: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorDacl(
            descriptor: *const std::ffi::c_void,
            present: *mut i32,
            acl: *mut *mut std::ffi::c_void,
            defaulted: *mut i32,
        ) -> i32;
        fn SetNamedSecurityInfoW(
            name: *mut u16,
            kind: u32,
            information: u32,
            owner: *const std::ffi::c_void,
            group: *const std::ffi::c_void,
            dacl: *const std::ffi::c_void,
            sacl: *const std::ffi::c_void,
        ) -> u32;
    }
    // Replace the DACL atomically. A previous interactive import must not
    // leave its explicit user ACE behind when SYSTEM takes over the service.
    let user = if sid == "S-1-5-18" {
        String::new()
    } else {
        format!("(A;OICI;FA;;;{sid})")
    };
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){user}")
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } != 0,
        "无法创建私密目录权限"
    );
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    let valid =
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
            != 0
            && present != 0;
    let mut name = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let status = if valid {
        unsafe {
            SetNamedSecurityInfoW(
                name.as_mut_ptr(),
                1,
                0x80000004,
                std::ptr::null(),
                std::ptr::null(),
                acl,
                std::ptr::null(),
            )
        }
    } else {
        87
    };
    unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor) };
    ensure!(status == 0, "无法保护私密目录：Windows错误 {status}");
    Ok(())
}
#[cfg(windows)]
pub(crate) fn current_sid() -> Result<String> {
    use std::os::windows::process::CommandExt;
    // The directory is experimental and newly owned; never ACL a production root.
    let who = std::process::Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .creation_flags(0x08000000)
        .output()?;
    ensure!(who.status.success(), "无法读取本机用户身份");
    let sid = String::from_utf8_lossy(&who.stdout)
        .split(',')
        .nth(1)
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .to_owned();
    ensure!(
        sid.starts_with("S-1-")
            && sid
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'S' | b'-')),
        "用户 SID 无效"
    );
    Ok(sid)
}
#[cfg(windows)]
fn replace_windows(from: &Path, to: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both UTF-16 strings are owned and NUL terminated for the call.
    ensure!(
        unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 1 | 8) } != 0,
        "配置原子替换失败：{}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
